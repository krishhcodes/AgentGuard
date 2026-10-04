"""Session Monitor (ARCHITECTURE: monitoring layer).

The Action Guard judges one call at a time. Some attacks only show up across many calls: a few small
sends that are each approved, a probe that keeps trying blocked actions, one leak split across
recipients. The monitor is a deterministic *fold over audit events* (so it is literally based on the
audit log): it keeps per-session counters and, when a proposed call would push the session over a
threshold, it escalates that call. It can only tighten a decision (ALLOW -> ASK -> BLOCK), never loosen
one (P8: defences only add), and it ignores recipients the user named in the request, so ordinary
tasks never trip it.

State survives across runs of the same session: each run's audit file is replayed when the next run
of that session starts (`runs/_sessions/<session_id>.json` lists the runs).
"""

from __future__ import annotations

import json
from pathlib import Path

from agentguard.guard.rules import ALLOW, ASK, BLOCK, GuardDecision, RuleHit

_RANK = {ALLOW: 0, ASK: 1, BLOCK: 2}
_EGRESS_OR_WRITE = {"send_email", "write_record", "search_web"}


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip() if "@" in addr else ""


class SessionMonitor:
    def __init__(self, policy, session_id: str):
        self.cfg = policy.session
        self.internal = {d.lower() for d in policy.internal_domains}
        self.session_id = session_id
        self.blocked_or_denied = 0
        self.confidential_read = False
        self.unauth_chars: dict[str, int] = {}  # external domain -> chars sent without user authorisation
        self.events_seen = 0

    # ---- fold: audit events in, state out ----------------------------------------------------
    def observe(self, event) -> None:
        e = event if isinstance(event, dict) else event.model_dump(mode="json")
        self.events_seen += 1
        kind, decision = e.get("event"), e.get("decision")
        if kind == "guard_decision" and decision == "BLOCK":
            self.blocked_or_denied += 1
        elif kind == "human_decision" and decision == "DENIED":
            self.blocked_or_denied += 1
        elif kind == "tool_executed":
            data = e.get("data") or {}
            if data.get("confidential_read"):
                self.confidential_read = True
            to = data.get("egress_to")
            if to and not data.get("egress_authorized"):
                dom = _domain(to)
                if dom and dom not in self.internal:
                    self.unauth_chars[dom] = self.unauth_chars.get(dom, 0) + int(data.get("egress_chars") or 0)

    def replay(self, audit_path: Path) -> None:
        try:
            for line in audit_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self.observe(json.loads(line))
        except (OSError, ValueError):
            pass  # a missing or damaged log must never break a run

    # ---- assessment: may tighten a proposed call --------------------------------------------
    def signals(self, call: dict, authorized_recipients: set[str]) -> list[RuleHit]:
        c = self.cfg
        if not c.enabled:
            return []
        hits: list[RuleHit] = []
        tool, args = call.get("name"), call.get("args") or {}
        if tool in _EGRESS_OR_WRITE and self.blocked_or_denied >= c.probing_blocks:
            heavy = self.blocked_or_denied >= 2 * c.probing_blocks
            hits.append(RuleHit(
                rule_id="SESSION_PROBING", decision=BLOCK if heavy else ASK, severity="high",
                reason=f"{self.blocked_or_denied} calls in this session were already blocked or denied; "
                       "further egress/write is held (probing / throttling)",
                evidence=[{"blocked_or_denied": self.blocked_or_denied, "session": self.session_id}]))
        if tool == "send_email":
            to = str(args.get("to", "")).lower()
            dom = _domain(to)
            if dom and dom not in self.internal and to not in authorized_recipients:
                projected = self.unauth_chars.get(dom, 0) + len(str(args.get("body", "")))
                if self.confidential_read and projected > c.slow_exfil_chars:
                    hits.append(RuleHit(
                        rule_id="SESSION_SLOW_EXFIL", decision=ASK, severity="high",
                        reason=f"{projected} chars would have gone to {dom}, which the user never named, in "
                               "this session after a confidential file was read",
                        evidence=[{"domain": dom, "projected_chars": projected, "budget": c.slow_exfil_chars}]))
                domains = set(self.unauth_chars) | {dom}
                if len(domains) >= c.fan_out_domains:
                    hits.append(RuleHit(
                        rule_id="SESSION_FAN_OUT", decision=ASK, severity="warn",
                        reason=f"{len(domains)} different external domains, none named by the user, in one session",
                        evidence=[{"domains": sorted(domains)}]))
        return hits

    def escalate(self, call: dict, decision: GuardDecision, authorized_recipients: set[str]) -> GuardDecision:
        hits = self.signals(call, authorized_recipients)
        if not hits:
            return decision
        top = max([decision.decision] + [h.decision for h in hits], key=lambda d: _RANK.get(d, 0))
        return decision.model_copy(update={"decision": top, "rule_hits": [*decision.rule_hits, *hits]})


# ---- session persistence ---------------------------------------------------------------------
def _index(runs_dir: Path, session_id: str) -> Path:
    safe = "".join(ch for ch in session_id if ch.isalnum() or ch in "-_")[:64] or "session"
    return runs_dir / "_sessions" / f"{safe}.json"


def open_session(policy, runs_dir: Path, session_id: str, run_id: str, persist: bool = True) -> SessionMonitor:
    """Replay every earlier run of this session, then register the new run. With persist=False the
    session is just this run (nothing is read or written beyond the run's own audit log)."""
    monitor = SessionMonitor(policy, session_id)
    if not persist:
        return monitor
    idx = _index(runs_dir, session_id)
    runs: list[str] = []
    try:
        runs = json.loads(idx.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    for prior in runs:
        monitor.replay(runs_dir / prior / "audit.jsonl")
    try:
        idx.parent.mkdir(parents=True, exist_ok=True)
        idx.write_text(json.dumps([*runs, run_id]), encoding="utf-8")
    except OSError:
        pass
    return monitor
