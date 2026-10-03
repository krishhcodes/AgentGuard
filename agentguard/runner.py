"""Run one scenario end to end: fresh sandbox -> graph -> oracle/checkers -> audit.

Baseline runs are a single graph.invoke. Guarded runs may pause at human_gate (an ASK
interrupt); the runner resumes them with answers from a `human` callback (stdin in the CLI,
SimulatedHuman in the harness, the UI in M3).
"""

from __future__ import annotations

import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from langchain_core.messages import BaseMessage, HumanMessage
from langgraph.types import Command

from agentguard.agent.graph import CONFIGS, build_graph
from agentguard.agent.state import Runtime, config_flags
from agentguard.audit import AuditEvent, AuditLogger
from agentguard.audit.events import truncate
from agentguard.config import Settings, load_settings
from agentguard.eval.checkers import CheckContext, TaskVerdict, check_task
from agentguard.eval.oracle import AttackVerdict, OracleContext, judge_attack
from agentguard.eval.suites import ScenarioSpec
from agentguard.llm import LLMClient
from agentguard.policy import Policy, load_policy
from agentguard.rag.retriever import Retriever
from agentguard.sandbox import Sandbox, ToolRegistry

DEFAULT_CONFIG = "baseline"
# human: (interrupt_payload) -> {call_id: "approve"|"deny"}. Absent -> deny all (fail closed).
Human = Callable[[dict], dict]
MAX_INTERRUPT_ROUNDS = 50


@dataclass
class RunResult:
    run_id: str
    scenario_id: str
    config: str
    user_request: str
    status: str  # ok | step_limit | error
    final_answer: str | None
    messages: list[BaseMessage]
    sandbox: Sandbox
    attack: AttackVerdict | None
    task: TaskVerdict | None
    audit_path: Path
    events: list[AuditEvent]
    error: str | None
    duration_s: float
    scope: Any = None  # Scope | None
    decisions: list[dict] = field(default_factory=list)  # final per-call guard verdicts
    timings: dict[str, list[float]] = field(default_factory=dict)


def new_run_id() -> str:
    return f"r-{datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}"


def _build_agent_llm(spec: ScenarioSpec, config: str, settings: Settings, registry: ToolRegistry):
    if config == "compromised_agent":
        from agentguard.eval.human import build_compromised_agent  # local: avoids an eval import cycle
        return build_compromised_agent(spec)
    return LLMClient.from_config("agent", registry.specs(), settings.llm_mode, settings.cache_dir)


def _collect_decisions(events: list[AuditEvent]) -> list[dict]:
    """Reconstruct per-call verdicts from the audit trail. `guard_decision` keeps the guard's
    original verdict (an ASK stays visible for the FPR metric even if the human later approved);
    `decision` is the final verdict after any human override."""
    by_call: dict[str, dict] = {}
    for e in events:
        cid = e.data.get("call_id")
        if e.event == "guard_decision" and cid:
            by_call[cid] = {"call_id": cid, "tool": e.tool, "args": e.args or {},
                            "guard_decision": e.decision, "decision": e.decision, "rules": list(e.rules)}
        elif e.event == "human_decision" and cid in by_call:
            by_call[cid]["decision"] = e.decision
    return list(by_call.values())


def run_scenario(
    spec: ScenarioSpec,
    *,
    config: str = DEFAULT_CONFIG,
    user_request: str | None = None,
    llm: Any = None,
    scope_llm: Any = None,
    human: Human | None = None,
    settings: Settings | None = None,
    policy: Policy | None = None,
) -> RunResult:
    if config not in CONFIGS:
        raise ValueError(f"unknown config {config!r}; available: {CONFIGS}")
    settings = settings or load_settings()
    policy = policy or load_policy()
    flags = config_flags(config)
    request = (user_request or spec.user_request).strip()
    run_id = new_run_id()
    sandbox = Sandbox(policy, overlay=spec.overlay)
    registry = ToolRegistry(policy)
    if llm is None:
        llm = _build_agent_llm(spec, config, settings, registry)
    if scope_llm is None and flags["guard"]:
        scope_llm = LLMClient.from_config("scope", [], settings.llm_mode, settings.cache_dir)
    audit = AuditLogger(settings.runs_dir / run_id / "audit.jsonl")
    rt = Runtime(
        run_id=run_id, config_name=config, scenario_id=spec.id, settings=settings,
        sandbox=sandbox, registry=registry, retriever=Retriever(sandbox.corpus_documents()),
        llm=llm, audit=audit, policy=policy, scope_llm=scope_llm,
    )
    audit.emit(AuditEvent(run_id=run_id, config=config, scenario_id=spec.id, layer="runner",
                          event="run_started", data={"user_request": truncate(request, 500),
                                                     "llm_mode": settings.llm_mode, "flags": flags}))
    started = time.perf_counter()
    initial = {
        "run_id": run_id, "flags": flags, "user_request": request,
        "messages": [HumanMessage(request)], "pending_untrusted": [],
        "scope": None, "decisions": [], "step": 0, "status": "ok",
        "final_answer": None, "timings": {},
    }
    thread = {"configurable": {"runtime": rt, "thread_id": run_id}, "recursion_limit": 100}
    error = None
    try:
        graph = build_graph(config)
        final = graph.invoke(initial, thread)
        rounds = 0
        while isinstance(final, dict) and final.get("__interrupt__"):
            rounds += 1
            if rounds > MAX_INTERRUPT_ROUNDS:
                raise RuntimeError("too many human_gate interrupts (possible loop)")
            payload = final["__interrupt__"][0].value
            answers = human(payload) if human else {a["call_id"]: "deny" for a in payload.get("asks", [])}
            final = graph.invoke(Command(resume=answers), thread)
        status, answer, messages = final["status"], final["final_answer"], final["messages"]
        if status == "error":
            error = messages[-1].content if messages else "agent error"
    except Exception:  # keep the UI/harness alive; the error is recorded, never counted as blocked
        status, answer, messages, final = "error", None, [], {}
        error = traceback.format_exc()
    duration = time.perf_counter() - started

    ctx = OracleContext(sandbox=sandbox, user_request=request)
    attack = judge_attack(spec.success_predicate, ctx) if spec.success_predicate else None
    task = check_task(spec.expected, CheckContext(answer, sandbox)) if spec.expected else None
    decisions = _collect_decisions(audit.events)
    audit.emit(
        AuditEvent(
            run_id=run_id, config=config, scenario_id=spec.id, layer="runner", event="run_completed",
            status=status,
            reason=truncate(error, 500) if error else None,
            data={
                "hijacked": attack.hijacked if attack else None,
                "oracle_evidence": attack.evidence if attack else [],
                "task_completed": task.completed if task else None,
                "task_failures": task.failed_checks if task else [],
                "final_answer_preview": truncate(answer or "", 300),
                "decisions": decisions,
            },
            latency_ms={"run_total": round(duration * 1000, 1)},
        )
    )
    return RunResult(
        run_id, spec.id, config, request, status, answer, messages, sandbox, attack, task,
        audit.path, audit.events, error, duration,
        scope=(final.get("scope") if isinstance(final, dict) else None),
        decisions=decisions,
        timings=(final.get("timings", {}) if isinstance(final, dict) else {}),
    )
