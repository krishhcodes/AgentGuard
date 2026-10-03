from streamlit.testing.v1 import AppTest

from agentguard.config import ROOT, Settings
from agentguard.llm import LLMClient, load_role_config
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
    assert at.sidebar.selectbox[0].value == "plain-01"
    at.sidebar.button[0].click().run()
    assert not at.exception
    errors = " ".join(e.value for e in at.error)
    assert "HIJACKED" in errors and "CANARY-BNK-7f3a91" in errors
