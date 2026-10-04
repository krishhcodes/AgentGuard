"""Security alerts: tell a reviewer when confidential data was about to leave (or be read without permission).

A listener on the audit log. When the guard or the egress gate stops a call whose rules concern confidential
data, it builds a REDACTED alert (rule ids, destination, decision, the source file's name) and sends it to
SECURITY_ALERT_EMAIL. It never includes file contents, email bodies or evidence snippets. Without SMTP settings
it runs in dry-run mode: the alert is only written to runs/_alerts.jsonl and shown in the UI. Delivery runs on a
background thread, so it adds no latency, and a failure never breaks a run.
"""

from __future__ import annotations

import json
import os
import re
import smtplib
import threading
import time
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path

from dotenv import dotenv_values

from agentguard.config import ROOT

# Rules that mean "confidential data is being read without permission, or is heading out".
ALERT_RULES = {
    "CONFIDENTIAL_EGRESS": "confidential data heading to a destination",
    "SECRET_PATTERN_EGRESS": "secret-shaped data heading to a destination",
    "EGRESS_CONTROL": "sensitive data flagged at the last gate before sending",
    "SESSION_SLOW_EXFIL": "small sends adding up to a leak across the session",
    "CONFIDENTIAL_NOT_AUTHORIZED": "attempt to read a confidential file the user never asked for",
}
_CANARY = re.compile(r"CANARY-[A-Z]+-[0-9a-f]{6}")
_SAFE_EVIDENCE_KEYS = ("source", "method", "destination", "domain", "signals", "domains")  # never "snippet"
MAX_PER_RUN = 5
COOLDOWN_S = 30.0  # the same scenario+rules is not re-sent within this window (repeated demo clicks)
_last_sent: dict[tuple, float] = {}


@dataclass
class AlertConfig:
    to: str = ""
    smtp_user: str = ""
    smtp_password: str = ""
    host: str = "smtp.gmail.com"
    port: int = 465

    @property
    def real(self) -> bool:
        return bool(self.to and self.smtp_user and self.smtp_password)

    @classmethod
    def from_env(cls) -> AlertConfig:
        env = {**dotenv_values(ROOT / ".env"), **os.environ}
        g = lambda k: (env.get(k) or "").strip()  # noqa: E731
        if env.get("AGENTGUARD_ALERTS_SEND") == "0":  # evals and tests: record alerts, never send
            return cls()
        return cls(to=g("SECURITY_ALERT_EMAIL"), smtp_user=g("SMTP_USER"),
                   smtp_password=g("SMTP_APP_PASSWORD").replace(" ", ""))  # Google shows it in groups of 4


def redact(text: str, policy=None) -> str:
    text = _CANARY.sub("[REDACTED]", str(text))
    for rx in (getattr(policy, "_secret_res", None) or []):
        text = rx.sub("[REDACTED]", text)
    return text


def is_alert_event(event: dict) -> bool:
    if event.get("event") == "guard_decision" and event.get("decision") in ("BLOCK", "ASK"):
        pass
    elif event.get("event") == "human_decision" and "EGRESS_CONTROL" in (event.get("rules") or []):
        pass
    else:
        return False
    return bool(ALERT_RULES.keys() & set(event.get("rules") or []))


def build_alert(event: dict, policy=None) -> dict:
    rules = [r for r in (event.get("rules") or []) if r in ALERT_RULES]
    ev = []
    for item in event.get("evidence") or []:
        ev.append({k: item[k] for k in _SAFE_EVIDENCE_KEYS if k in item})
    dest = (event.get("args") or {}).get("to") or ""
    lines = [
        "AgentGuard stopped a call that involved confidential data.",
        "",
        f"What happened : {'; '.join(ALERT_RULES[r] for r in rules)}",
        f"Decision      : {event.get('decision')} ({event.get('layer')})",
        f"Tool          : {event.get('tool')}",
        f"Destination   : {redact(dest, policy) or '-'}",
        f"Rules         : {', '.join(rules)}",
        f"Run / scenario: {event.get('run_id')} / {event.get('scenario_id') or '-'}",
        f"Why           : {redact(event.get('reason') or '', policy)[:300]}",
    ]
    if ev:
        lines.append(f"Evidence      : {redact(json.dumps(ev, ensure_ascii=False), policy)[:400]}")
    lines += ["", "This alert is redacted: it contains no file contents, email bodies or secrets."]
    return {"subject": f"[AgentGuard] {event.get('decision')}: {rules[0]}", "body": "\n".join(lines),
            "rules": rules, "tool": event.get("tool"), "decision": event.get("decision"),
            "run_id": event.get("run_id"), "scenario_id": event.get("scenario_id"), "destination": dest}


class AlertAuthError(Exception):
    """The SMTP server refused the sender's credentials."""


def send_email(cfg: AlertConfig, alert: dict) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = cfg.smtp_user, cfg.to, alert["subject"]
    msg.set_content(alert["body"])
    with smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=15) as s:
        try:
            s.login(cfg.smtp_user, cfg.smtp_password)
        except (smtplib.SMTPAuthenticationError, smtplib.SMTPServerDisconnected) as e:
            # Gmail answers 535 BadCredentials (smtplib sometimes reports it as a dropped connection).
            raise AlertAuthError("login rejected: check SMTP_USER and that SMTP_APP_PASSWORD is an app password "
                                 "created for that same account") from e
        s.send_message(msg)


class AlertDispatcher:
    """Audit-log listener: one per run. Dedupes, caps, records to runs/_alerts.jsonl, sends on a thread."""

    def __init__(self, policy, runs_dir: Path, cfg: AlertConfig | None = None):
        self.policy = policy
        self.log = Path(runs_dir) / "_alerts.jsonl"
        self.cfg = cfg if cfg is not None else AlertConfig.from_env()
        self.seen: set[tuple] = set()
        self.threads: list[threading.Thread] = []

    def observe(self, event) -> None:
        e = event if isinstance(event, dict) else event.model_dump(mode="json")
        if not is_alert_event(e):
            return
        key = (e.get("run_id"), e.get("tool"), tuple(sorted(e.get("rules") or [])), (e.get("args") or {}).get("to"))
        if key in self.seen or len(self.seen) >= MAX_PER_RUN:
            return
        self.seen.add(key)
        cool = (e.get("scenario_id"), key[2])
        now = time.monotonic()
        if self.cfg.real and now - _last_sent.get(cool, -1e9) < COOLDOWN_S:
            return
        _last_sent[cool] = now
        alert = build_alert(e, self.policy)
        mode = "sending" if self.cfg.real else "dry-run"
        self._record(alert, mode)
        if self.cfg.real:
            t = threading.Thread(target=self._deliver, args=(alert,), daemon=False)
            t.start()
            self.threads.append(t)

    def _deliver(self, alert: dict) -> None:
        try:
            send_email(self.cfg, alert)
            self._record(alert, "sent")
        except AlertAuthError as e:
            self._record(alert, f"failed: {e}")
        except Exception as e:  # never break a run; the error text carries no secrets
            self._record(alert, f"failed: {type(e).__name__}")

    def _record(self, alert: dict, status: str) -> None:
        try:
            self.log.parent.mkdir(parents=True, exist_ok=True)
            row = {k: alert[k] for k in ("run_id", "scenario_id", "rules", "tool", "decision", "destination", "subject")}
            with open(self.log, "a", encoding="utf-8") as f:
                f.write(json.dumps({**row, "status": status}, ensure_ascii=False) + "\n")
        except OSError:
            pass


def read_alerts(runs_dir: Path, limit: int = 30) -> list[dict]:
    path = Path(runs_dir) / "_alerts.jsonl"
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, ValueError):
        return []
    return rows[-limit:][::-1]
