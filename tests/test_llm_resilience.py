import pytest
from langchain_core.messages import AIMessage, HumanMessage

from agentguard.llm import LLMClient, LLMUnavailable, ScriptedChatModel, rate_limit_wait
from agentguard.runner import run_scenario
from tests.helpers import COMPARISON_ANSWER

GROQ_429 = ("Error code: 429 - {'error': {'message': 'Rate limit reached for model `openai/gpt-oss-20b` ... "
            "Please try again in 172.5ms. Need more tokens?', 'code': 'rate_limit_exceeded'}}")


class RateLimitError(Exception):
    pass


class Flaky:
    def __init__(self, failures, error):
        self.failures, self.error, self.calls = failures, error, 0

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error
        return AIMessage(content="ok")


def test_rate_limit_wait_parses_groq_messages():
    assert rate_limit_wait(Exception(GROQ_429)) == pytest.approx(0.6725)
    assert rate_limit_wait(Exception("rate_limit_exceeded. Please try again in 7.2s.")) == pytest.approx(7.7)
    assert rate_limit_wait(RateLimitError("slow down")) == 5.0
    assert rate_limit_wait(Exception("invalid api key")) is None


def test_client_retries_rate_limits_then_succeeds(tmp_path):
    inner = Flaky(2, RateLimitError(GROQ_429))
    client = LLMClient("agent", "m", [], "off", tmp_path, inner=inner)
    waits = []
    client._sleep = waits.append
    assert client.invoke([HumanMessage("x")]).content == "ok"
    assert inner.calls == 3 and len(waits) == 2


def test_client_gives_up_after_max_attempts(tmp_path):
    client = LLMClient("agent", "m", [], "off", tmp_path, inner=Flaky(99, RateLimitError(GROQ_429)))
    client._sleep = lambda s: None
    with pytest.raises(LLMUnavailable):
        client.invoke([HumanMessage("x")])


def test_non_rate_limit_errors_fail_immediately(tmp_path):
    inner = Flaky(1, ValueError("bad request"))
    client = LLMClient("agent", "m", [], "off", tmp_path, inner=inner)
    with pytest.raises(LLMUnavailable):
        client.invoke([HumanMessage("x")])
    assert inner.calls == 1


def test_key_added_to_env_file_after_start_is_picked_up(monkeypatch):
    from agentguard.llm import RoleConfig, _build_live_model

    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr("agentguard.llm.dotenv_values", lambda path: {"GROQ_API_KEY": "gsk_test_dummy"})
    model = _build_live_model(RoleConfig(provider="groq", model="openai/gpt-oss-20b"))
    assert model is not None  # built without a network call


def test_agent_retries_one_blank_reply(scenarios, settings):
    llm = ScriptedChatModel([AIMessage(content=""), AIMessage(content=COMPARISON_ANSWER)])
    result = run_scenario(scenarios["quote-01"], llm=llm, settings=settings)
    assert result.task.completed and llm.calls == 2
