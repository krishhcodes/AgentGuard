"""Run one scenario end to end: fresh sandbox -> graph -> oracle/checkers -> audit.

Baseline runs are a single graph.invoke. Guarded runs may pause at human_gate (an ASK
interrupt); the runner resumes them with answers from a `human` callback (stdin in the CLI,
SimulatedHuman in the harness, the UI in M3).
"""

from __future__ import annotations

import hashlib
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
from agentguard.firewall import make_nonce
from agentguard.eval.checkers import CheckContext, TaskVerdict, check_task
from agentguard.eval.oracle import AttackVerdict, OracleContext, judge_attack
from agentguard.eval.suites import ScenarioSpec
from agentguard.firewall.classifier import Classifier
from agentguard.llm import LLMClient
from agentguard.monitor import open_session
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


def _run_nonce(spec, request: str, settings: Settings) -> str:
    """Spotlight nonce. Random per run when nothing is cached; deterministic (scenario + request) when the
    LLM cache is on, because a random nonce sits inside the agent's prompt and would make every spotlighted
    request unique, so a recorded run could never be replayed. Forged delimiters are escaped by spotlight()
    regardless, so the nonce is not what protects the boundary."""
    if settings.llm_mode == "off":
        return make_nonce()
    return hashlib.sha256(f"{spec.id}|{request}".encode("utf-8")).hexdigest()[:8]


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


@dataclass
class _RunContext:
    spec: ScenarioSpec
    config: str
    request: str
    run_id: str
    sandbox: Sandbox
    audit: AuditLogger
    rt: Runtime
    graph: Any
    thread: dict
    initial: dict
    started: float


def _setup_run(
    spec: ScenarioSpec, *, config: str, user_request: str | None,
    llm: Any, scope_llm: Any, settings: Settings, policy: Policy, classifier_llm: Any = None,
    session_id: str | None = None,
) -> _RunContext:
    flags = config_flags(config)
    request = (user_request or spec.user_request).strip()
    run_id = new_run_id()
    sandbox = Sandbox(policy, overlay=spec.overlay)
    registry = ToolRegistry(policy)
    if llm is None:
        llm = _build_agent_llm(spec, config, settings, registry)
    if scope_llm is None and flags["guard"]:
        scope_llm = LLMClient.from_config("scope", [], settings.llm_mode, settings.cache_dir)
        scope_llm.warm()
    classifier = None
    if flags["classifier"]:
        classifier_llm = classifier_llm or LLMClient.from_config(
            "classifier", [], settings.llm_mode, settings.cache_dir)
        if hasattr(classifier_llm, "warm"):
            classifier_llm.warm()
        classifier = Classifier(classifier_llm)
    audit = AuditLogger(settings.runs_dir / run_id / "audit.jsonl")
    monitor = None
    if flags["guard"]:  # the monitor rides on the guard: it only ever tightens a guard decision
        monitor = open_session(policy, settings.runs_dir, session_id or run_id, run_id,
                               persist=session_id is not None)
        audit.listeners.append(monitor.observe)
    rt = Runtime(
        run_id=run_id, config_name=config, scenario_id=spec.id, settings=settings,
        sandbox=sandbox, registry=registry, retriever=Retriever(sandbox.corpus_documents()),
        llm=llm, audit=audit, policy=policy, scope_llm=scope_llm, nonce=_run_nonce(spec, request, settings), classifier=classifier, monitor=monitor,
    )
    audit.emit(AuditEvent(run_id=run_id, config=config, scenario_id=spec.id, layer="runner",
                          event="run_started", data={"user_request": truncate(request, 500),
                                                     "llm_mode": settings.llm_mode, "flags": flags}))
    initial = {
        "run_id": run_id, "flags": flags, "user_request": request,
        "messages": [HumanMessage(request)], "pending_untrusted": [],
        "scope": None, "ledger": None, "decisions": [], "step": 0, "status": "ok",
        "final_answer": None, "timings": {},
    }
    thread = {"configurable": {"runtime": rt, "thread_id": run_id}, "recursion_limit": 100}
    return _RunContext(spec, config, request, run_id, sandbox, audit, rt,
                       build_graph(config), thread, initial, time.perf_counter())


def _finalize(ctx: _RunContext, final: Any, error: str | None, status: str,
              answer: str | None, messages: list) -> RunResult:
    duration = time.perf_counter() - ctx.started
    octx = OracleContext(sandbox=ctx.sandbox, user_request=ctx.request)
    attack = judge_attack(ctx.spec.success_predicate, octx) if ctx.spec.success_predicate else None
    task = check_task(ctx.spec.expected, CheckContext(answer, ctx.sandbox)) if ctx.spec.expected else None
    decisions = _collect_decisions(ctx.audit.events)
    ctx.audit.emit(AuditEvent(
        run_id=ctx.run_id, config=ctx.config, scenario_id=ctx.spec.id, layer="runner",
        event="run_completed", status=status, reason=truncate(error, 500) if error else None,
        data={
            "hijacked": attack.hijacked if attack else None,
            "oracle_evidence": attack.evidence if attack else [],
            "task_completed": task.completed if task else None,
            "task_failures": task.failed_checks if task else [],
            "final_answer_preview": truncate(answer or "", 300),
            "decisions": decisions,
        },
        latency_ms={"run_total": round(duration * 1000, 1)},
    ))
    return RunResult(
        ctx.run_id, ctx.spec.id, ctx.config, ctx.request, status, answer, messages, ctx.sandbox,
        attack, task, ctx.audit.path, ctx.audit.events, error, duration,
        scope=(final.get("scope") if isinstance(final, dict) else None),
        decisions=decisions,
        timings=(final.get("timings", {}) if isinstance(final, dict) else {}),
    )


def run_scenario(
    spec: ScenarioSpec,
    *,
    config: str = DEFAULT_CONFIG,
    user_request: str | None = None,
    llm: Any = None,
    scope_llm: Any = None,
    classifier_llm: Any = None,
    session_id: str | None = None,
    human: Human | None = None,
    settings: Settings | None = None,
    policy: Policy | None = None,
) -> RunResult:
    if config not in CONFIGS:
        raise ValueError(f"unknown config {config!r}; available: {CONFIGS}")
    settings = settings or load_settings()
    policy = policy or load_policy()
    ctx = _setup_run(spec, config=config, user_request=user_request, llm=llm,
                     scope_llm=scope_llm, settings=settings, policy=policy,
                     classifier_llm=classifier_llm, session_id=session_id)
    error = None
    try:
        final = ctx.graph.invoke(ctx.initial, ctx.thread)
        rounds = 0
        while isinstance(final, dict) and final.get("__interrupt__"):
            rounds += 1
            if rounds > MAX_INTERRUPT_ROUNDS:
                raise RuntimeError("too many human_gate interrupts (possible loop)")
            payload = final["__interrupt__"][0].value
            answers = human(payload) if human else {a["call_id"]: "deny" for a in payload.get("asks", [])}
            final = ctx.graph.invoke(Command(resume=answers), ctx.thread)
        status, answer, messages = final["status"], final["final_answer"], final["messages"]
        if status == "error":
            error = messages[-1].content if messages else "agent error"
    except Exception:  # keep the UI/harness alive; the error is recorded, never counted as blocked
        status, answer, messages, final = "error", None, [], {}
        error = traceback.format_exc()
    return _finalize(ctx, final, error, status, answer, messages)


class RunSession:
    """A resumable run for the UI: step the graph, surface a pending ASK, resume on a button click.

    The graph and its MemorySaver live inside this object (held in st.session_state), so the
    human-in-the-loop interrupt survives Streamlit reruns. CLI/harness use run_scenario instead.
    """

    PENDING, DONE = "pending", "done"

    def __init__(self, spec: ScenarioSpec, *, config: str, user_request: str | None = None,
                 llm: Any = None, scope_llm: Any = None, classifier_llm: Any = None,
                 session_id: str | None = None,
                 settings: Settings | None = None, policy: Policy | None = None):
        if config not in CONFIGS:
            raise ValueError(f"unknown config {config!r}; available: {CONFIGS}")
        settings = settings or load_settings()
        policy = policy or load_policy()
        self.ctx = _setup_run(spec, config=config, user_request=user_request, llm=llm,
                              scope_llm=scope_llm, settings=settings, policy=policy,
                     classifier_llm=classifier_llm, session_id=session_id)
        self.state: Any = None
        self.error: str | None = None
        self.pending_payload: dict | None = None

    def _drive(self, final: Any) -> str:
        self.state = final
        if isinstance(final, dict) and final.get("__interrupt__"):
            self.pending_payload = final["__interrupt__"][0].value
            return self.PENDING
        self.pending_payload = None
        return self.DONE

    def start(self) -> str:
        try:
            return self._drive(self.ctx.graph.invoke(self.ctx.initial, self.ctx.thread))
        except Exception:
            self.error = traceback.format_exc()
            return self.DONE

    def resume(self, answers: dict) -> str:
        try:
            return self._drive(self.ctx.graph.invoke(Command(resume=answers), self.ctx.thread))
        except Exception:
            self.error = traceback.format_exc()
            return self.DONE

    @property
    def pending(self) -> dict | None:
        return self.pending_payload

    @property
    def events(self) -> list[AuditEvent]:
        return self.ctx.audit.events  # live trail, including decisions made before the pause

    def result(self) -> RunResult:
        if self.error:
            return _finalize(self.ctx, {}, self.error, "error", None, [])
        final = self.state
        status, answer, messages = final["status"], final["final_answer"], final["messages"]
        error = (messages[-1].content if messages else "agent error") if status == "error" else None
        return _finalize(self.ctx, final, error, status, answer, messages)
