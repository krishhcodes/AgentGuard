"""Egress Control: the last deterministic gate before anything leaves (ARCHITECTURE: egress control).

Runs AFTER the Action Guard and the human gate, on every call that is about to execute (ALLOW, or APPROVED
by a human who may simply have trusted the agent). One question only: does this call carry sensitive,
tainted data to a destination the user did not name? If so it asks the human once more, with an
escalated prompt. It can only add friction (never loosen a verdict) and uses no LLM.
"""

from __future__ import annotations

import re

from agentguard.guard.rules import ASK, RuleHit, _egress_view
from agentguard.text import text_views

# Personal-data shapes beyond the policy's secret patterns (account/IBAN/keys are in policy.secret_patterns).
_PII = (
    ("a national-ID-shaped number", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("a payment-card-shaped number", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
)


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip() if "@" in addr else ""


def egress_risk(call: dict, scope, policy, ledger=None, monitor=None) -> RuleHit | None:
    tool, args = call.get("name"), call.get("args") or {}
    if tool not in ("send_email", "search_web"):
        return None
    eg = _egress_view(tool, args, scope)
    if eg is None or eg["authorised"]:
        return None  # the user named this destination
    if tool == "send_email" and _domain(str(args.get("to", ""))) in {d.lower() for d in policy.internal_domains}:
        return None  # internal destination
    text = "\n".join(text_views(eg["text"]).all_texts())
    why: list[str] = []
    if policy.matched_secrets(text):
        why.append("secret-shaped data")
    why += [label for label, rx in _PII if rx.search(text)]
    if ledger is not None:
        flow = ledger.confidential_overlap(eg["text"], sink=eg["sink"])
        if flow.matched:
            why.append(f"content from {flow.source or 'a confidential file'}")
        elif ledger.has_confidential_read:
            why.append("a confidential file was read earlier in this task")
    if not why and monitor is not None and getattr(monitor, "confidential_read", False):
        why.append("a confidential file was read earlier in this session")
    if not why:
        return None
    dest = str(args.get("to") or "the web")
    return RuleHit(
        rule_id="EGRESS_CONTROL", decision=ASK, severity="high",
        reason=f"ESCALATED second check: this {tool} sends data tied to {', '.join(why)} to {dest}, a destination "
               "you did not name. Confirm again that it should leave.",
        evidence=[{"destination": dest, "signals": why}])
