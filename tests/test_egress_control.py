"""Egress Control: the last gate before anything leaves. Fast, offline, node-level."""

from __future__ import annotations

import time
from types import SimpleNamespace

from langchain_core.messages import AIMessage

from agentguard.agent import nodes
from agentguard.audit import AuditLogger
from agentguard.guard.egress import egress_risk
from agentguard.guard.rules import ALLOW, GuardDecision
from agentguard.guard.taint import TaintLedger
from agentguard.llm import tool_call
from agentguard.scope.models import Scope, ScopeMeta

PII_BODY = "Customer record: 123-45-6789, see attached."


def make_scope(recipients=()):
    return Scope(scope_id="s", task_summary="t", allowed_tools=["send_email"], read_resources=[],
                 confidential_resources=[], recipients=list(recipients), recipient_domains=[], write_targets=[],
                 egress_flows=[], ambiguities=[], meta=ScopeMeta(model="t"))


def email(to, body, cid="c1"):
    return tool_call("send_email", {"to": to, "subject": "s", "body": body}, cid)


def test_sensitive_data_to_unnamed_destination_is_flagged(policy):
    hit = egress_risk(email("x@elsewhere.example", PII_BODY), make_scope(), policy)
    assert hit and hit.rule_id == "EGRESS_CONTROL" and "ESCALATED" in hit.reason


def test_named_internal_or_harmless_destinations_are_not(policy):
    assert egress_risk(email("x@elsewhere.example", PII_BODY), make_scope(["x@elsewhere.example"]), policy) is None
    assert egress_risk(email("a@company.example", PII_BODY), make_scope(), policy) is None  # internal domain
    assert egress_risk(email("x@elsewhere.example", "Best price: BrightPath, 35,750 USD"), make_scope(), policy) is None


def test_confidential_read_makes_any_unnamed_send_sensitive(policy):
    ledger = TaintLedger()
    ledger.record_segment(text="CANARY-BNK-7f3a91 account 12345678", source="confidential/bank_details.txt",
                          channel="tool:read_file", confidential=True)
    hit = egress_risk(email("x@elsewhere.example", "hello"), make_scope(), policy, ledger)
    assert hit and "confidential" in hit.reason


def run_node(policy, tmp_path, monkeypatch, tc, prior_decision, answer):
    asked = []

    def fake_interrupt(payload):
        asked.append(payload)
        return {tc["id"]: answer}

    monkeypatch.setattr(nodes, "interrupt", fake_interrupt)
    audit = AuditLogger(tmp_path / "a.jsonl")
    rt = SimpleNamespace(policy=policy, audit=audit, monitor=None, run_id="r", config_name="full", scenario_id="s")
    decision = GuardDecision(call_id=tc["id"], tool=tc["name"], args_redacted={}, decision=prior_decision)
    state = {"messages": [AIMessage(content="", tool_calls=[tc])], "decisions": [decision],
             "scope": make_scope(), "ledger": None}
    out = nodes.egress_control(state, {"configurable": {"runtime": rt}})
    return out, asked, audit, decision


def test_allowed_call_gets_a_second_escalated_prompt_and_deny_blocks_it(policy, tmp_path, monkeypatch):
    out, asked, audit, d = run_node(policy, tmp_path, monkeypatch, email("x@elsewhere.example", PII_BODY), ALLOW, "deny")
    assert asked and asked[0]["escalated"] is True and d.decision == "DENIED"
    assert any(e.event == "human_decision" and "EGRESS_CONTROL" in e.rules for e in audit.events)


def test_human_approved_call_is_asked_again_and_approval_passes(policy, tmp_path, monkeypatch):
    out, asked, _, d = run_node(policy, tmp_path, monkeypatch, email("x@elsewhere.example", PII_BODY), "APPROVED", "approve")
    assert asked and d.decision == "APPROVED"  # the user confirmed twice: it may leave


def test_harmless_call_is_not_interrupted_and_the_gate_is_fast(policy, tmp_path, monkeypatch):
    t0 = time.perf_counter()
    out, asked, _, d = run_node(policy, tmp_path, monkeypatch, email("x@elsewhere.example", "price list"), ALLOW, "deny")
    assert not asked and d.decision == ALLOW
    assert (time.perf_counter() - t0) * 1000 < 50  # deterministic, no LLM, no I/O beyond the audit write
