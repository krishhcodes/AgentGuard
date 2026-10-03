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


# ---- multi-key rotation (5-key free-tier budget) --------------------------------

TPD_429 = "Error code: 429 - rate_limit_exceeded: limit tokens per day. Please try again in 7m12s."


def test_classify_rate_limit_tpd_vs_tpm():
    from agentguard.llm import classify_rate_limit

    assert classify_rate_limit(Exception(TPD_429))[0] == "tpd"
    assert classify_rate_limit(Exception("429 rate_limit try again in 172.5ms"))[0] == "tpm"
    assert classify_rate_limit(Exception("1h reset per day"))[0] is None  # not a rate-limit error
    assert classify_rate_limit(Exception("invalid api key")) == ("auth", 0.0)  # dead key: rotate past it
    assert classify_rate_limit(Exception("connection reset")) == (None, 0.0)


def test_load_groq_keys_dedupes_and_orders(monkeypatch):
    from agentguard.llm import load_groq_keys

    monkeypatch.setattr("agentguard.llm.dotenv_values", lambda path: {})
    names = ["GROQ_API_KEY", "GROQ_API_KEYS"] + [f"GROQ_API_KEY{i}" for i in range(1, 9)] \
        + [f"GROQ_API_KEY_{i}" for i in range(1, 9)]
    for n in names:  # clear the developer's real multi-key env so only the test's keys count
        monkeypatch.delenv(n, raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "k0")
    monkeypatch.setenv("GROQ_API_KEYS", "k0, k1 k2")
    monkeypatch.setenv("GROQ_API_KEY_2", "k3")
    assert load_groq_keys() == ["k0", "k1", "k2", "k3"]


def _per_key_live(monkeypatch, tmp_path, keys, failing):
    """Wire a LLMClient over a fake _LazyLive whose per-key models fail (429 TPD) for `failing` keys."""
    import agentguard.llm as llm

    ring = llm._KeyRing(list(keys))
    monkeypatch.setattr(llm, "groq_key_ring", lambda: ring)

    class PerKey:
        def __init__(self, key):
            self.key = key

        def bind_tools(self, tools):
            return self

        def invoke(self, messages):
            if self.key in failing:
                raise RateLimitError(TPD_429)
            return AIMessage(content=f"ok:{self.key}")

    monkeypatch.setattr(llm, "_build_live_model", lambda cfg, key=None: PerKey(key))
    lazy = llm._LazyLive(llm.RoleConfig(provider="groq", model="m"))
    client = llm.LLMClient("agent", "m", [], "off", tmp_path, inner=lazy)
    client._sleep = lambda s: None
    return client, ring


def test_rotates_to_next_key_on_daily_cap(monkeypatch, tmp_path):
    client, ring = _per_key_live(monkeypatch, tmp_path, ["k1", "k2", "k3"], failing={"k1"})
    out = client.invoke([HumanMessage("x")])
    assert out.content == "ok:k2"  # k1 was daily-capped; rotated to k2
    assert ring.idx == 1


def test_raises_when_all_keys_daily_capped(monkeypatch, tmp_path):
    client, ring = _per_key_live(monkeypatch, tmp_path, ["k1", "k2"], failing={"k1", "k2"})
    with pytest.raises(LLMUnavailable):
        client.invoke([HumanMessage("x")])
    assert ring.idx == 0  # walked every key, then reset so a long-lived process retries from the first


def test_invalid_api_key_is_classified_and_rotated_past(monkeypatch, tmp_path):
    import agentguard.llm as llm

    class AuthenticationError(Exception):
        pass

    err = AuthenticationError("Error code: 401 - {'error': {'code': 'invalid_api_key'}}")
    assert llm.classify_rate_limit(err)[0] == "auth"

    ring = llm._KeyRing(["bad", "good"])
    monkeypatch.setattr(llm, "groq_key_ring", lambda: ring)

    class PerKey:
        def __init__(self, key):
            self.key = key

        def bind_tools(self, tools):
            return self

        def invoke(self, messages):
            if self.key == "bad":
                raise err
            return AIMessage(content="ok")

    monkeypatch.setattr(llm, "_build_live_model", lambda cfg, key=None: PerKey(key))
    client = llm.LLMClient("agent", "m", [], "off", tmp_path, inner=llm._LazyLive(llm.RoleConfig(provider="groq", model="m")))
    assert client.invoke([HumanMessage("x")]).content == "ok" and ring.idx == 1


def test_patient_mode_waits_for_the_daily_window_then_succeeds(monkeypatch, tmp_path):
    import agentguard.llm as llm

    monkeypatch.setenv("AGENTGUARD_PATIENT_S", "3600")
    ring = llm._KeyRing(["k1"])
    monkeypatch.setattr(llm, "groq_key_ring", lambda: ring)
    calls = {"n": 0}

    class Capped:
        def bind_tools(self, tools):
            return self

        def invoke(self, messages):
            calls["n"] += 1
            if calls["n"] <= 2:
                raise RateLimitError(TPD_429)  # "... per day ... try again in 7m12s"
            return AIMessage(content="ok")

    monkeypatch.setattr(llm, "_build_live_model", lambda cfg, key=None: Capped())
    client = llm.LLMClient("agent", "m", [], "off", tmp_path, inner=llm._LazyLive(llm.RoleConfig(provider="groq", model="m")))
    sleeps = []
    client._sleep = sleeps.append
    assert client.invoke([HumanMessage("x")]).content == "ok"
    assert len(sleeps) == 2 and all(30 <= s <= 900 for s in sleeps)


def test_default_is_fail_fast_when_all_keys_capped(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENTGUARD_PATIENT_S", raising=False)
    client, _ = _per_key_live(monkeypatch, tmp_path, ["k1"], failing={"k1"})
    with pytest.raises(LLMUnavailable):
        client.invoke([HumanMessage("x")])
