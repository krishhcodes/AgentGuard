import pytest
from langchain_core.messages import AIMessage, HumanMessage

from agentguard.llm import CacheMiss, LLMClient, ScriptedChatModel, cache_key, tool_call

TOOLS = [{"type": "function", "function": {"name": "read_file", "parameters": {}}}]


def _reply():
    return AIMessage(content="", tool_calls=[tool_call("read_file", {"path": "quotes/a.txt"}, "call-9")])


def test_record_then_replay_round_trip(tmp_path):
    msgs = [HumanMessage("hello")]
    recorder = LLMClient("agent", "m1", TOOLS, "record", tmp_path, inner=ScriptedChatModel([_reply()]))
    recorded = recorder.invoke(msgs)
    replayer = LLMClient("agent", "m1", TOOLS, "replay", tmp_path, inner=None)
    replayed = replayer.invoke(msgs)
    assert replayed.tool_calls == recorded.tool_calls


def test_replay_miss_raises_instead_of_calling_live(tmp_path):
    inner = ScriptedChatModel([_reply()])
    client = LLMClient("agent", "m1", TOOLS, "replay", tmp_path, inner=inner)
    with pytest.raises(CacheMiss):
        client.invoke([HumanMessage("never recorded")])
    assert inner.calls == 0


def test_cache_key_depends_on_model_tools_and_messages():
    m = [HumanMessage("x")]
    k = cache_key("agent", "m1", m, TOOLS)
    assert k != cache_key("agent", "m2", m, TOOLS)
    assert k != cache_key("agent", "m1", m, [])
    assert k != cache_key("agent", "m1", [HumanMessage("y")], TOOLS)
    assert k == cache_key("agent", "m1", [HumanMessage("x", id="random-id")], TOOLS)


def test_off_mode_writes_nothing(tmp_path):
    LLMClient("agent", "m1", TOOLS, "off", tmp_path, inner=ScriptedChatModel([_reply()])).invoke([HumanMessage("x")])
    assert not any(tmp_path.rglob("*.json"))
