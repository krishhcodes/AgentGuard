"""Graph nodes. Baseline and protected graphs share these (ARCHITECTURE P8).

Trust separation by role: the system prompt is a SystemMessage, the user request is a
HumanMessage, and ALL untrusted content (retrieval and tool outputs) arrives as
ToolMessages. Retrieval uses a synthetic `retrieve_context` call written by this code;
the agent is never given that tool.
"""

from __future__ import annotations

import time

from langchain_core.messages import AIMessage, SystemMessage, ToolMessage
from langchain_core.runnables import RunnableConfig

from agentguard.agent.prompts import BASELINE_SYSTEM_PROMPT
from agentguard.agent.state import AgentState, RawSegment, Runtime
from agentguard.audit import AuditEvent
from agentguard.audit.events import preview_args, truncate
from agentguard.llm import LLMUnavailable

RETRIEVE_TOOL = "retrieve_context"
RETRIEVE_CALL_ID = "ctx-0"


def _rt(config: RunnableConfig) -> Runtime:
    return config["configurable"]["runtime"]


def retrieve(state: AgentState, config: RunnableConfig) -> dict:
    rt = _rt(config)
    chunks = rt.retriever.search(state["user_request"], k=rt.settings.retrieval_k)
    call = AIMessage(
        content="",
        tool_calls=[{"name": RETRIEVE_TOOL, "args": {"query": state["user_request"]}, "id": RETRIEVE_CALL_ID}],
    )
    segments = [
        RawSegment(
            text=c.text,
            source=c.source,
            channel="rag",
            confidential=False,
            tool_call_id=RETRIEVE_CALL_ID,
            tool_name=RETRIEVE_TOOL,
        )
        for c in chunks
    ]
    return {"messages": [call], "pending_untrusted": segments}


def _render_group(segments: list[RawSegment]) -> str:
    if segments[0]["channel"] == "rag":
        return "\n\n".join(f"--- source: {s['source']} ---\n{s['text']}" for s in segments)
    return segments[0]["text"]


def ingest_untrusted(state: AgentState, config: RunnableConfig) -> dict:
    """M0: raw passthrough. Untrusted content enters the context unmodified (the vulnerability)."""
    groups: dict[str, list[RawSegment]] = {}
    for seg in state["pending_untrusted"]:
        groups.setdefault(seg["tool_call_id"], []).append(seg)
    messages = [
        ToolMessage(content=_render_group(segs), tool_call_id=call_id, name=segs[0]["tool_name"])
        for call_id, segs in groups.items()
    ]
    # Retrieval with zero hits still needs a ToolMessage answering the synthetic call.
    answered = set(groups)
    last_ai = next((m for m in reversed(state["messages"]) if isinstance(m, AIMessage)), None)
    if last_ai is not None:
        for tc in last_ai.tool_calls:
            if tc["id"] not in answered and tc["name"] == RETRIEVE_TOOL:
                messages.append(ToolMessage(content="No relevant documents found.", tool_call_id=tc["id"], name=RETRIEVE_TOOL))
    return {"messages": messages, "pending_untrusted": []}


def _is_blank(message: AIMessage) -> bool:
    return not message.tool_calls and not str(message.content).strip()


def agent(state: AgentState, config: RunnableConfig) -> dict:
    rt = _rt(config)
    try:
        prompt = [SystemMessage(BASELINE_SYSTEM_PROMPT), *state["messages"]]
        response = rt.llm.invoke(prompt)
        if _is_blank(response):  # occasional empty generation: retry once
            response = rt.llm.invoke(prompt)
    except LLMUnavailable as e:
        return {"status": "error", "final_answer": None, "step": state["step"] + 1,
                "messages": [AIMessage(content=f"[agent error] {e}")]}
    return {"messages": [response], "step": state["step"] + 1}


def route_after_agent(state: AgentState, config: RunnableConfig) -> str:
    if state.get("status") == "error":
        return "finalize"
    last = state["messages"][-1]
    if isinstance(last, AIMessage) and last.tool_calls:
        if state["step"] >= _rt(config).settings.max_steps:
            return "finalize"
        return "execute_tools"
    return "finalize"


def execute_tools(state: AgentState, config: RunnableConfig) -> dict:
    """The only node that performs tool side effects."""
    rt = _rt(config)
    last = state["messages"][-1]
    segments: list[RawSegment] = []
    for tc in last.tool_calls:
        started = time.perf_counter()
        result = rt.registry.execute(rt.sandbox, tc["name"], tc["args"])
        elapsed = (time.perf_counter() - started) * 1000
        confidential = False
        source = f"tool:{tc['name']}"
        if tc["name"] == "read_file" and isinstance(tc["args"].get("path"), str):
            resolved, _ = rt.sandbox.resolve_path(tc["args"]["path"])
            if resolved:
                source = resolved
                confidential = rt.sandbox.is_confidential(resolved) and not result.startswith("Error:")
        rt.audit.emit(
            AuditEvent(
                run_id=rt.run_id,
                config=rt.config_name,
                scenario_id=rt.scenario_id,
                layer="tools",
                event="tool_executed",
                tool=tc["name"],
                args=preview_args(tc["args"]),
                result_preview=truncate(result, 200),
                data={"call_id": tc["id"], "confidential_read": confidential},
                latency_ms={"tool": round(elapsed, 3)},
            )
        )
        segments.append(
            RawSegment(
                text=result,
                source=source,
                channel=f"tool:{tc['name']}",
                confidential=confidential,
                tool_call_id=tc["id"],
                tool_name=tc["name"],
            )
        )
    return {"pending_untrusted": segments}


def finalize(state: AgentState, config: RunnableConfig) -> dict:
    if state.get("status") == "error":
        return {"final_answer": None}
    last = state["messages"][-1]
    if isinstance(last, AIMessage) and last.tool_calls:
        return {"status": "step_limit", "final_answer": None}
    content = last.content if isinstance(last, AIMessage) else ""
    if isinstance(content, list):  # some providers return content blocks
        content = "".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in content)
    return {"status": "ok", "final_answer": content}
