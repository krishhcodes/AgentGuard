"""Graph nodes. Baseline and protected graphs share these (ARCHITECTURE P8).

Trust separation by role: the system prompt is a SystemMessage, the user request is a
HumanMessage, and ALL untrusted content (retrieval and tool outputs) arrives as
ToolMessages. Retrieval uses a synthetic `retrieve_context` call written by this code;
the agent is never given that tool.
"""

from __future__ import annotations

import json
import time

from langchain_core.messages import AIMessage, SystemMessage, ToolMessage
from langchain_core.runnables import RunnableConfig
from langgraph.types import interrupt

from agentguard.agent.prompts import BASELINE_SYSTEM_PROMPT
from agentguard.agent.state import AgentState, RawSegment, Runtime
from agentguard.audit import AuditEvent
from agentguard.audit.events import preview_args, truncate
from agentguard.guard import rules as guard_rules
from agentguard.llm import LLMUnavailable
from agentguard.scope import extract_scope as run_scope_extractor

RETRIEVE_TOOL = "retrieve_context"
RETRIEVE_CALL_ID = "ctx-0"


def _rt(config: RunnableConfig) -> Runtime:
    return config["configurable"]["runtime"]


def extract_scope(state: AgentState, config: RunnableConfig) -> dict:
    """Compute the authorised Scope from the trusted user request only (invariant P1)."""
    rt = _rt(config)
    scope = extract_scope_fn(state, rt)
    rt.audit.emit(AuditEvent(
        run_id=rt.run_id, config=rt.config_name, scenario_id=rt.scenario_id,
        layer="scope", event="scope_extracted", scope_ref=scope.scope_id,
        reason=scope.task_summary,
        data={"allowed_tools": scope.allowed_tools, "recipients": scope.recipients,
              "confidential_resources": scope.confidential_resources,
              "write_targets": [w.model_dump() for w in scope.write_targets],
              "ambiguities": [a.model_dump() for a in scope.ambiguities],
              "fallback_used": scope.meta.fallback_used, "dropped_items": scope.meta.dropped_items},
        latency_ms={"scope": scope.meta.latency_ms},
    ))
    return {"scope": scope, "timings": {"scope": [scope.meta.latency_ms]}}


def extract_scope_fn(state: AgentState, rt: Runtime):
    model_name = getattr(rt.scope_llm, "model_name", "scope")
    return run_scope_extractor(state["user_request"], rt.policy, rt.scope_llm,
                               scope_id=f"scope-{state['run_id']}", model_name=model_name)


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


def _proposed_calls(state: AgentState) -> list[dict]:
    last = state["messages"][-1]
    return list(last.tool_calls) if isinstance(last, AIMessage) and last.tool_calls else []


def route_after_agent(state: AgentState, config: RunnableConfig) -> str:
    if state.get("status") == "error":
        return "finalize"
    if _proposed_calls(state):
        if state["step"] >= _rt(config).settings.max_steps:
            return "finalize"
        return "execute_tools"
    return "finalize"


def route_after_agent_guarded(state: AgentState, config: RunnableConfig) -> str:
    if state.get("status") == "error":
        return "finalize"
    if _proposed_calls(state):
        if state["step"] >= _rt(config).settings.max_steps:
            return "finalize"
        return "action_guard"
    return "finalize"


def action_guard(state: AgentState, config: RunnableConfig) -> dict:
    """Decide ALLOW / BLOCK / ASK for every proposed tool call (deterministic; P2, P5)."""
    rt = _rt(config)
    scope = state["scope"]
    decisions: list[guard_rules.GuardDecision] = []
    guard_times: list[float] = []
    for call in _proposed_calls(state):
        started = time.perf_counter()
        decision = guard_rules.decide(call, scope, rt.policy)
        decision.latency_ms = round((time.perf_counter() - started) * 1000, 3)
        guard_times.append(decision.latency_ms)
        decisions.append(decision)
        rt.audit.emit(AuditEvent(
            run_id=rt.run_id, config=rt.config_name, scenario_id=rt.scenario_id,
            layer="action_guard", event="guard_decision", tool=decision.tool,
            args=decision.args_redacted, decision=decision.decision,
            rules=decision.rule_ids, reason=decision.reason, evidence=decision.evidence,
            scope_ref=decision.scope_ref, data={"call_id": decision.call_id},
            latency_ms={"guard": decision.latency_ms},
        ))
    return {"decisions": decisions, "timings": {"guard": guard_times}}


def route_after_guard(state: AgentState, config: RunnableConfig) -> str:
    return "human_gate" if any(d.decision == guard_rules.ASK for d in state["decisions"]) else "execute_tools"


def human_gate(state: AgentState, config: RunnableConfig) -> dict:
    """Pause on ASK decisions and resume with approve/deny. Re-execution safe: nothing happens
    before interrupt(), because LangGraph re-runs this node from the top on resume (P / 6.11)."""
    decisions = state["decisions"]
    asks = [
        {"call_id": d.call_id, "tool": d.tool, "args": d.args_redacted,
         "rules": d.rule_ids, "reason": d.reason, "evidence": d.evidence}
        for d in decisions if d.decision == guard_rules.ASK
    ]
    answers = interrupt({"asks": asks}) or {}  # {call_id: "approve"|"deny"}; default below is deny
    rt = _rt(config)
    for d in decisions:
        if d.decision != guard_rules.ASK:
            continue
        approved = str(answers.get(d.call_id, "deny")).lower() == "approve"
        d.decision = "APPROVED" if approved else "DENIED"
        rt.audit.emit(AuditEvent(
            run_id=rt.run_id, config=rt.config_name, scenario_id=rt.scenario_id,
            layer="human_gate", event="human_decision", tool=d.tool, args=d.args_redacted,
            decision=d.decision, rules=d.rule_ids, reason=d.reason, scope_ref=d.scope_ref,
            data={"call_id": d.call_id},
        ))
    return {"decisions": decisions}


_PERMITTED = {guard_rules.ALLOW, "APPROVED"}


def execute_tools(state: AgentState, config: RunnableConfig) -> dict:
    """The only node that performs tool side effects. In guarded configs it runs a call only when
    a matching GuardDecision permits it (invariant P3); blocked/denied calls get a synthetic
    observation so the agent keeps working on the user's real task."""
    rt = _rt(config)
    last = state["messages"][-1]
    guarded = state["flags"]["guard"]
    by_call = {d.call_id: d for d in state.get("decisions", [])} if guarded else {}
    segments: list[RawSegment] = []
    for tc in last.tool_calls:
        if guarded:
            decision = by_call.get(tc["id"])
            if decision is None or decision.decision not in _PERMITTED:
                rules = decision.rule_ids if decision else ["NO_DECISION"]
                note = (f"[blocked by policy: {', '.join(rules) or 'not authorised'}] the requested "
                        f"{tc['name']} call was not performed. Continue the user's original task without it.")
                segments.append(RawSegment(text=note, source="guard", channel=f"tool:{tc['name']}",
                                           confidential=False, tool_call_id=tc["id"], tool_name=tc["name"]))
                continue
        started = time.perf_counter()
        # Idempotency: a naive agent can loop on the same call. Don't repeat the side effect;
        # return a note instead. Keyed on (name, args), so distinct attack steps are unaffected,
        # and it applies in every config so it never biases ablations.
        key = f"{tc['name']}:{json.dumps(tc['args'], sort_keys=True, ensure_ascii=False)}"
        duplicate = key in rt.sandbox.state.executed_calls
        if duplicate:
            result = (f"[already executed earlier in this run; not repeated] "
                      f"previous result: {rt.sandbox.state.executed_calls[key]}")
        else:
            result = rt.registry.execute(rt.sandbox, tc["name"], tc["args"])
            rt.sandbox.state.executed_calls[key] = truncate(result, 200)
        elapsed = (time.perf_counter() - started) * 1000
        confidential = False
        source = f"tool:{tc['name']}"
        if not duplicate and tc["name"] == "read_file" and isinstance(tc["args"].get("path"), str):
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
                data={"call_id": tc["id"], "confidential_read": confidential, "duplicate": duplicate},
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
