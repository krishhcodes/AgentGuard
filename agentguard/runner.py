"""Run one scenario end to end: fresh sandbox -> graph -> oracle/checkers -> audit."""

from __future__ import annotations

import time
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from langchain_core.messages import BaseMessage, HumanMessage

from agentguard.agent.graph import build_graph
from agentguard.agent.state import Runtime
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

CONFIGS = ("baseline",)  # grows as defences land (guard_only, firewall_only, full, ...)
DEFAULT_CONFIG = "baseline"


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


def new_run_id() -> str:
    return f"r-{datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}"


def run_scenario(
    spec: ScenarioSpec,
    *,
    config: str = DEFAULT_CONFIG,
    user_request: str | None = None,
    llm: Any = None,
    settings: Settings | None = None,
    policy: Policy | None = None,
) -> RunResult:
    if config not in CONFIGS:
        raise ValueError(f"unknown config {config!r}; available: {CONFIGS}")
    settings = settings or load_settings()
    policy = policy or load_policy()
    request = (user_request or spec.user_request).strip()
    run_id = new_run_id()
    sandbox = Sandbox(policy, overlay=spec.overlay)
    registry = ToolRegistry(policy)
    if llm is None:
        llm = LLMClient.from_config("agent", registry.specs(), settings.llm_mode, settings.cache_dir)
    audit = AuditLogger(settings.runs_dir / run_id / "audit.jsonl")
    rt = Runtime(
        run_id=run_id,
        config_name=config,
        scenario_id=spec.id,
        settings=settings,
        sandbox=sandbox,
        registry=registry,
        retriever=Retriever(sandbox.corpus_documents()),
        llm=llm,
        audit=audit,
    )
    audit.emit(AuditEvent(run_id=run_id, config=config, scenario_id=spec.id, layer="runner",
                          event="run_started", data={"user_request": truncate(request, 500),
                                                     "llm_mode": settings.llm_mode}))
    started = time.perf_counter()
    initial = {
        "run_id": run_id,
        "user_request": request,
        "messages": [HumanMessage(request)],
        "pending_untrusted": [],
        "step": 0,
        "status": "ok",
        "final_answer": None,
    }
    error = None
    try:
        final = build_graph(config).invoke(initial, {"configurable": {"runtime": rt}, "recursion_limit": 100})
        status, answer, messages = final["status"], final["final_answer"], final["messages"]
        if status == "error":
            error = messages[-1].content if messages else "agent error"
    except Exception:  # keep the UI/harness alive; the error is recorded, never counted as blocked
        status, answer, messages = "error", None, []
        error = traceback.format_exc()
    duration = time.perf_counter() - started

    ctx = OracleContext(sandbox=sandbox, user_request=request)
    attack = judge_attack(spec.success_predicate, ctx) if spec.success_predicate else None
    task = check_task(spec.expected, CheckContext(answer, sandbox)) if spec.expected else None
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
            },
            latency_ms={"run_total": round(duration * 1000, 1)},
        )
    )
    return RunResult(run_id, spec.id, config, request, status, answer, messages, sandbox, attack, task,
                     audit.path, audit.events, error, duration)
