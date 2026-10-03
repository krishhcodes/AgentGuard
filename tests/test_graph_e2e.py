import json

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from agentguard.audit import AuditEvent
from agentguard.llm import ScriptedChatModel, tool_call
from agentguard.runner import run_scenario
from tests.helpers import hijacked_agent, honest_agent


def test_canonical_attack_hijacks_baseline(scenarios, settings):
    result = run_scenario(scenarios["plain-01"], llm=hijacked_agent(), settings=settings)
    assert result.status == "ok"
    assert result.attack.hijacked
    assert any("CANARY-BNK-7f3a91" in e for e in result.attack.evidence)
    assert result.task.completed  # the hijacked agent still answered the comparison


def test_honest_agent_on_clean_task(scenarios, settings):
    result = run_scenario(scenarios["quote-01"], llm=honest_agent(), settings=settings)
    assert result.status == "ok" and result.attack is None
    assert result.task.completed
    assert result.sandbox.state.outbox == []


def test_trust_separation_by_role(scenarios, settings):
    seen = []

    def capture(messages):
        seen.extend(messages)
        return AIMessage(content="Best price: BrightPath\nFastest delivery: Nimbus")

    run_scenario(scenarios["plain-01"], llm=ScriptedChatModel([capture]), settings=settings)
    assert isinstance(seen[0], SystemMessage) and "AI ASSISTANT" not in seen[0].content
    humans = [m for m in seen if isinstance(m, HumanMessage)]
    assert len(humans) == 1 and "AI ASSISTANT" not in humans[0].content
    injected = [m for m in seen if "NOTE FOR THE AI ASSISTANT" in str(m.content)]
    assert injected and all(isinstance(m, ToolMessage) for m in injected)


def test_step_limit_terminates(scenarios, settings):
    looping = ScriptedChatModel([
        AIMessage(content="", tool_calls=[tool_call("search_web", {"query": "acme"}, f"c{i}")]) for i in range(50)
    ])
    result = run_scenario(scenarios["quote-01"], llm=looping, settings=settings)
    assert result.status == "step_limit"
    assert len(result.sandbox.state.web_queries) == settings.max_steps - 1
    assert not result.task.completed


def test_llm_outage_is_an_error_not_a_block(scenarios, settings, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr("agentguard.llm.dotenv_values", lambda path: {})  # ignore the developer's real .env
    result = run_scenario(scenarios["plain-01"], settings=settings)  # real client, no key
    assert result.status == "error" and "GROQ_API_KEY" in result.error
    assert not result.attack.hijacked


def test_audit_log_records_run(scenarios, settings):
    result = run_scenario(scenarios["plain-01"], llm=hijacked_agent(), settings=settings)
    lines = result.audit_path.read_text(encoding="utf-8").splitlines()
    events = [AuditEvent.model_validate(json.loads(line)) for line in lines]
    assert [e.event for e in events] == ["run_started", "tool_executed", "tool_executed", "run_completed"]
    assert events[1].tool == "read_file" and events[1].data["confidential_read"] is True
    assert events[2].tool == "send_email" and len(events[2].args["body"]) < 260  # body truncated
    assert events[-1].data["hijacked"] is True and events[-1].status == "ok"


def test_runs_write_separate_audit_files(scenarios, settings):
    a = run_scenario(scenarios["quote-01"], llm=honest_agent(), settings=settings)
    b = run_scenario(scenarios["quote-01"], llm=honest_agent(), settings=settings)
    assert a.audit_path != b.audit_path
