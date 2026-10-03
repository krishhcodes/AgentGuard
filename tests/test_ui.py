import json

from langchain_core.messages import AIMessage
from streamlit.testing.v1 import AppTest

from agentguard.config import ROOT, Settings
from agentguard.llm import LLMClient, ScriptedChatModel, load_role_config, tool_call
from agentguard.policy import load_policy
from agentguard.runner import run_scenario
from agentguard.sandbox import ToolRegistry
from tests.helpers import hijacked_agent


def test_ui_replays_canonical_attack(tmp_path, monkeypatch, scenarios):
    # Record a run (scripted agent standing in for the live model), then replay it in the UI.
    cache, runs = tmp_path / "cache", tmp_path / "runs"
    cfg = load_role_config("agent")
    recorder = LLMClient("agent", cfg.model, ToolRegistry(load_policy()).specs(), "record", cache,
                         inner=hijacked_agent())
    run_scenario(scenarios["plain-01"], llm=recorder, settings=Settings(runs, cache, "record"))

    monkeypatch.setenv("AGENTGUARD_CACHE_DIR", str(cache))
    monkeypatch.setenv("AGENTGUARD_RUNS_DIR", str(runs))
    monkeypatch.setenv("AGENTGUARD_LLM_MODE", "replay")
    at = AppTest.from_file(str(ROOT / "ui" / "app.py"), default_timeout=60)
    at.run()
    assert not at.exception
    at.sidebar.selectbox[0].set_value("plain-01").run()
    at.sidebar.button[0].click().run()
    assert not at.exception
    assert any("HIJACKED" in e.value for e in at.error)
    # Evidence (attacker-controlled text) is plain text, not markdown inside the banner.
    assert not any("CANARY" in e.value for e in at.error)
    assert any("CANARY-BNK-7f3a91" in t.value for t in at.text)


def _record_guarded_ambig(cache, runs, scenarios):
    """Record scope + agent responses for a guard_only ambig-01 run (an ASK), for UI replay."""
    agent_cfg, scope_cfg = load_role_config("agent"), load_role_config("scope")
    agent = ScriptedChatModel([
        AIMessage(content="", tool_calls=[tool_call(
            "send_email", {"to": "team@company.example", "subject": "Summary", "body": "BrightPath"}, "e1")]),
        AIMessage(content="Best price: BrightPath Systems"),
    ])
    proposal = {"task_summary": "compare and send", "allowed_tools": ["read_file", "send_email"],
                "recipients": [], "confidential_paths": [], "write_targets": [], "needs_web_search": False}
    specs = ToolRegistry(load_policy()).specs()
    agent_rec = LLMClient("agent", agent_cfg.model, specs, "record", cache, inner=agent)
    scope_rec = LLMClient("scope", scope_cfg.model, [], "record", cache,
                          inner=_const_llm(json.dumps(proposal)))
    # Record the APPROVE path so the UI's approve in replay replays cleanly to completion.
    run_scenario(scenarios["ambig-01-the-team"], config="guard_only", llm=agent_rec, scope_llm=scope_rec,
                 human=lambda p: {a["call_id"]: "approve" for a in p["asks"]}, settings=Settings(runs, cache, "record"))


def _const_llm(content):
    return ScriptedChatModel([(lambda _m, c=content: AIMessage(content=c))] * 8)


def test_ui_resolves_ask_via_approve_button(tmp_path, monkeypatch, scenarios):
    cache, runs = tmp_path / "cache", tmp_path / "runs"
    _record_guarded_ambig(cache, runs, scenarios)

    monkeypatch.setenv("AGENTGUARD_CACHE_DIR", str(cache))
    monkeypatch.setenv("AGENTGUARD_RUNS_DIR", str(runs))
    monkeypatch.setenv("AGENTGUARD_LLM_MODE", "replay")
    at = AppTest.from_file(str(ROOT / "ui" / "app.py"), default_timeout=60)
    at.run()
    at.sidebar.selectbox[0].set_value("ambig-01-the-team")
    at.toggle[0].set_value(False)  # Content Firewall off -> protected config is guard_only (the recorded run)
    at.run()
    at.sidebar.button[0].click().run()
    assert not at.exception
    # The guard paused on an ASK: an approval form is shown.
    assert any("awaiting human" in m.value or "needs a human decision" in m.value
               for m in list(at.warning) + list(at.markdown))
    # Approve it and submit. Set the form radio and click submit in the SAME run cycle: an
    # intermediate .run() would reset the unsubmitted form widget back to its default.
    at.radio(key="ask-e1").set_value("approve")
    [b for b in at.button if "Submit" in b.label][0].click()
    at.run()
    assert not at.exception
    assert any("APPROVED" in m.value for m in at.markdown)  # decision chip updated after resume
    # The ASK was resolved from the UI and the approved action was actually performed.
    guard = at.session_state["guard_result"]
    assert any(e.to == "team@company.example" for e in guard.sandbox.state.outbox)
    assert any(ev.event == "human_decision" and ev.decision == "APPROVED" for ev in guard.events)


def test_demo_path_button_sets_scenario_and_layers(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTGUARD_CACHE_DIR", str(tmp_path / "c"))
    monkeypatch.setenv("AGENTGUARD_RUNS_DIR", str(tmp_path / "r"))
    monkeypatch.setenv("AGENTGUARD_LLM_MODE", "replay")
    at = AppTest.from_file(str(ROOT / "ui" / "app.py"), default_timeout=60)
    at.run()
    beat = [b for b in at.sidebar.button if "Firewall off" in b.label][0]
    beat.click().run()
    assert not at.exception
    assert at.session_state["sid"] == "plain-01"
    assert at.session_state["fw_on"] is False and at.session_state["guard_on"] is True
