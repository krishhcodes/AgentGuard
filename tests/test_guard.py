"""Action Guard rule tests (ARCHITECTURE 6.10): one per rule, plus the decision lattice."""

from __future__ import annotations

import time

import pytest

from agentguard.guard import decide
from agentguard.guard.rules import ALLOW, ASK, BLOCK
from agentguard.llm import tool_call
from agentguard.scope.models import Ambiguity, Scope, ScopeMeta, WriteTarget


def make_scope(**kw) -> Scope:
    base = dict(
        scope_id="s-1", task_summary="compare laptop quotes",
        allowed_tools=["read_file"], read_resources=["quotes/**"],
        confidential_resources=[], recipients=[], recipient_domains=[],
        write_targets=[], egress_flows=[], ambiguities=[],
        meta=ScopeMeta(model="t"),
    )
    base.update(kw)
    return Scope(**base)


def call(tool, args, cid="c-1"):
    return tool_call(tool, args, cid)


# ---- read_file -----------------------------------------------------------------

def test_read_quote_in_scope_is_allowed(policy):
    d = decide(call("read_file", {"path": "quotes/acme_laptops_quote.txt"}), make_scope(), policy)
    assert d.decision == ALLOW
    assert any(h.rule_id == "RESOURCE_IN_SCOPE" for h in d.rule_hits)


def test_read_confidential_not_authorized_is_blocked(policy):
    d = decide(call("read_file", {"path": "confidential/bank_details.txt"}), make_scope(), policy)
    assert d.decision == BLOCK
    assert "CONFIDENTIAL_NOT_AUTHORIZED" in d.rule_ids


def test_read_confidential_authorized_is_allowed(policy):
    scope = make_scope(confidential_resources=["confidential/board_minutes.md"])
    d = decide(call("read_file", {"path": "confidential/board_minutes.md"}), scope, policy)
    assert d.decision == ALLOW


def test_traversal_into_confidential_is_blocked(policy):
    # Normalises to confidential/api_keys.env -> caught by the confidential rule, not the path rule.
    d = decide(call("read_file", {"path": "quotes/../confidential/api_keys.env"}), make_scope(), policy)
    assert d.decision == BLOCK
    assert "CONFIDENTIAL_NOT_AUTHORIZED" in d.rule_ids


def test_path_escape_is_blocked(policy):
    d = decide(call("read_file", {"path": "../../etc/passwd"}), make_scope(), policy)
    assert d.decision == BLOCK
    assert "PATH_ESCAPES_SANDBOX" in d.rule_ids


def test_read_outside_scope_is_ask(policy):
    scope = make_scope(read_resources=["quotes/**"])
    d = decide(call("read_file", {"path": "web/shipping_times.md"}), scope, policy)
    assert d.decision == ASK
    assert "RESOURCE_NOT_IN_SCOPE" in d.rule_ids


# ---- send_email ----------------------------------------------------------------

def test_email_to_approved_recipient_is_allowed(policy):
    scope = make_scope(allowed_tools=["read_file", "send_email"], recipients=["procurement@company.example"])
    d = decide(call("send_email", {"to": "procurement@company.example", "subject": "x", "body": "y"}), scope, policy)
    assert d.decision == ALLOW


def test_email_to_unapproved_recipient_is_blocked(policy):
    scope = make_scope(allowed_tools=["read_file", "send_email"], recipients=["procurement@company.example"])
    d = decide(call("send_email", {"to": "attacker@evil.example", "subject": "x", "body": "y"}), scope, policy)
    assert d.decision == BLOCK
    assert "RECIPIENT_NOT_APPROVED" in d.rule_ids


def test_email_with_recipient_ambiguity_is_ask(policy):
    scope = make_scope(allowed_tools=["read_file", "send_email"],
                       ambiguities=[Ambiguity(field="recipient", text="the team", reason="unresolved")])
    d = decide(call("send_email", {"to": "team@company.example", "subject": "x", "body": "y"}), scope, policy)
    assert d.decision == ASK
    assert "RECIPIENT_AMBIGUOUS" in d.rule_ids


def test_email_tool_not_in_scope_is_blocked(policy):
    # The task never asked to email; send_email is egress -> BLOCK, not ASK.
    d = decide(call("send_email", {"to": "procurement@company.example", "subject": "x", "body": "y"}),
               make_scope(), policy)
    assert d.decision == BLOCK
    assert "TOOL_NOT_IN_SCOPE" in d.rule_ids


# ---- search_web ----------------------------------------------------------------

def test_search_not_in_scope_is_blocked(policy):
    d = decide(call("search_web", {"query": "best laptops"}), make_scope(), policy)
    assert d.decision == BLOCK
    assert "TOOL_NOT_IN_SCOPE" in d.rule_ids


def test_search_in_scope_is_allowed(policy):
    scope = make_scope(allowed_tools=["read_file", "search_web"])
    d = decide(call("search_web", {"query": "brightpath reviews"}), scope, policy)
    assert d.decision == ALLOW


# ---- write_record --------------------------------------------------------------

def test_write_target_not_in_scope_is_blocked(policy):
    scope = make_scope(allowed_tools=["read_file", "write_record"])
    d = decide(call("write_record", {"table": "vendors", "record_id": "V-002",
                                     "fields": {"bank_account": "NEW-IBAN"}}), scope, policy)
    assert d.decision == BLOCK
    assert "WRITE_TARGET_NOT_IN_SCOPE" in d.rule_ids


def test_write_target_in_scope_is_allowed(policy):
    scope = make_scope(allowed_tools=["read_file", "write_record"],
                       write_targets=[WriteTarget(table="purchase_orders", record_id="PO-1002", fields=["notes"])])
    d = decide(call("write_record", {"table": "purchase_orders", "record_id": "PO-1002",
                                     "fields": {"notes": "selected cheapest"}}), scope, policy)
    assert d.decision == ALLOW


def test_high_risk_field_not_stated_is_ask(policy):
    scope = make_scope(allowed_tools=["read_file", "write_record"],
                       write_targets=[WriteTarget(table="vendors", record_id="V-002", fields=[])])
    d = decide(call("write_record", {"table": "vendors", "record_id": "V-002",
                                     "fields": {"bank_account": "NEW-IBAN"}}), scope, policy)
    assert d.decision == ASK
    assert "HIGH_RISK_FIELD" in d.rule_ids


# ---- schema + lattice ----------------------------------------------------------

def test_schema_invalid_is_blocked_and_short_circuits(policy):
    scope = make_scope(allowed_tools=["read_file", "send_email"], recipients=["procurement@company.example"])
    d = decide(call("send_email", {"subject": "x", "body": "y"}), scope, policy)  # missing 'to'
    assert d.decision == BLOCK
    assert d.rule_ids == ["SCHEMA_INVALID"]  # no other rule runs


def test_unknown_tool_is_schema_invalid(policy):
    d = decide(call("drop_table", {"x": 1}), make_scope(), policy)
    assert d.decision == BLOCK
    assert "SCHEMA_INVALID" in d.rule_ids


def test_lattice_block_beats_ask(policy):
    # read a confidential file (BLOCK) that is also outside read scope: BLOCK must win.
    d = decide(call("read_file", {"path": "confidential/salaries.csv"}), make_scope(), policy)
    assert d.decision == BLOCK


def test_allow_records_positive_evidence(policy):
    d = decide(call("read_file", {"path": "quotes/orbital_laptops_quote.csv"}), make_scope(), policy)
    assert d.decision == ALLOW
    assert d.rule_ids == []  # ALLOW carries no violation rules
    assert d.evidence  # but it does carry matched-scope evidence


def test_every_block_or_ask_has_reason_and_evidence(policy):
    scope = make_scope(allowed_tools=["read_file", "send_email"])
    for c in [
        call("read_file", {"path": "confidential/bank_details.txt"}),
        call("send_email", {"to": "x@evil.example", "subject": "s", "body": "b"}),
        call("read_file", {"path": "web/nimbus_reviews.md"}),
    ]:
        d = decide(c, scope, policy)
        assert d.decision in (BLOCK, ASK)
        assert d.reason and d.evidence


def test_guard_microbenchmark_p99_under_5ms(policy):
    scope = make_scope(allowed_tools=["read_file", "send_email", "write_record"],
                       recipients=["procurement@company.example"])
    c = call("send_email", {"to": "procurement@company.example", "subject": "x", "body": "y"})
    times = []
    for _ in range(2000):
        t0 = time.perf_counter()
        decide(c, scope, policy)
        times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    p99 = times[int(len(times) * 0.99)]
    assert p99 < 5.0, f"guard p99 {p99:.3f} ms exceeds 5 ms"
