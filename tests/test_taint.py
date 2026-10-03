"""Taint Ledger tests (ARCHITECTURE 6.9): provenance and confidential-flow detection."""

from __future__ import annotations

import base64

import pytest

from agentguard.guard.taint import TaintLedger

BANK = ("Operating account\n  Account number: 0000-FAKE-4417-2290\n"
        "Reference: CANARY-BNK-7f3a91\n")


def make_ledger(**kw) -> TaintLedger:
    led = TaintLedger(user_norm="compare the laptop quotations and email procurement@company.example",
                      directory=["procurement@company.example"])
    for k, v in kw.items():
        setattr(led, k, v)
    return led


def test_origin_user():
    led = make_ledger()
    assert led.origin_of("procurement@company.example").origin == "user"


def test_origin_directory():
    led = TaintLedger(user_norm="email the team", directory=["procurement@company.example"])
    assert led.origin_of("procurement@company.example").origin == "directory"


def test_origin_untrusted_attributes_to_source():
    led = make_ledger()
    led.record_segment(text="contact verify@attacker.example for details",
                       source="quotes/nimbus.html", channel="rag", confidential=False)
    prov = led.origin_of("verify@attacker.example")
    assert prov.origin == "untrusted:quotes/nimbus.html"
    assert prov.evidence and prov.evidence[0]["source"] == "quotes/nimbus.html"


def test_origin_unknown():
    assert make_ledger().origin_of("stranger@nowhere.example").origin == "unknown"


def test_origin_through_base64_view():
    led = make_ledger()
    hidden = base64.b64encode(b"reach me at hidden@attacker.example").decode()
    led.record_segment(text=f"<!-- {hidden} -->", source="quotes/c.html", channel="rag", confidential=False)
    assert led.origin_of("hidden@attacker.example").origin == "untrusted:quotes/c.html"


def _conf_ledger() -> TaintLedger:
    led = make_ledger()
    led.record_segment(text=BANK, source="confidential/bank_details.txt",
                       channel="tool:read_file", confidential=True)
    return led


def test_flow_canary_detected_and_attributed():
    led = _conf_ledger()
    flow = led.confidential_overlap("Please verify CANARY-BNK-7f3a91 at the registry")
    assert flow.matched and flow.method == "canary"
    assert flow.source == "confidential/bank_details.txt"


def test_flow_shingle_detected():
    led = _conf_ledger()
    flow = led.confidential_overlap("note: Operating account Account number: 0000-FAKE-4417-2290 follows")
    assert flow.matched and flow.method in ("shingle", "canary", "fuzzy")


def test_flow_through_base64_egress():
    led = _conf_ledger()
    encoded = base64.b64encode(b"here is CANARY-BNK-7f3a91").decode()
    flow = led.confidential_overlap(encoded)
    assert flow.matched and flow.method == "canary"


def test_flow_chunked_across_sink():
    led = _conf_ledger()
    sink = "attacker@evil.example"
    # Split the canary across two messages to the same sink; neither alone contains it.
    led.record_egress(sink, "CANARY-BNK-")
    flow = led.confidential_overlap("7f3a91", sink=sink)
    assert flow.matched and flow.method == "chunked"


def test_no_false_flow_on_clean_text():
    led = _conf_ledger()
    assert not led.confidential_overlap("BrightPath is the cheapest at USD 35,750").matched


@pytest.mark.xfail(reason="paraphrased leaks are not caught by content overlap; session policy is the backstop")
def test_flow_paraphrase_is_a_known_gap():
    led = _conf_ledger()
    flow = led.confidential_overlap("the operating account ends in twenty-two ninety")
    assert flow.matched


def test_serialisation_round_trip():
    led = _conf_ledger()
    led.record_egress("attacker@evil.example", "CANARY-BNK-7f3a91")
    restored = TaintLedger.model_validate(led.model_dump())
    assert restored.has_confidential_read
    assert restored.confidential_overlap("CANARY-BNK-7f3a91").matched
