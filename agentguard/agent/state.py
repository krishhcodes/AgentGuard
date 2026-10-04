"""LangGraph state. Runtime objects (sandbox, LLM, audit logger) are NOT in state; they
travel in config["configurable"]["runtime"] so the state stays serialisable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages

from agentguard.audit import AuditLogger
from agentguard.config import Settings
from agentguard.guard.rules import GuardDecision
from agentguard.guard.taint import TaintLedger
from agentguard.rag.retriever import Retriever
from agentguard.sandbox import Sandbox, ToolRegistry
from agentguard.scope.models import Scope


class GuardFlags(TypedDict):
    firewall: bool
    classifier: bool
    spotlight: bool
    guard: bool


# config name -> which layers are active. Defence layers only ADD nodes (ARCHITECTURE P8/5.5).
# firewall/classifier/spotlight land in M5/M6; their flags exist here but no config turns them on yet.
CONFIG_FLAGS: dict[str, GuardFlags] = {
    "baseline": {"firewall": False, "classifier": False, "spotlight": False, "guard": False},
    "guard_only": {"firewall": False, "classifier": False, "spotlight": False, "guard": True},
    # compromised_agent = guard on, driven by a ScriptedChatModel that always emits the attack's calls.
    "compromised_agent": {"firewall": False, "classifier": False, "spotlight": False, "guard": True},
    # M5/M6 configs. regex_only = the deterministic firewall stages (F0-F2); the others add the F3 classifier.
    "regex_only": {"firewall": True, "classifier": False, "spotlight": False, "guard": False},
    "firewall_only": {"firewall": True, "classifier": True, "spotlight": True, "guard": False},
    "full": {"firewall": True, "classifier": True, "spotlight": True, "guard": True},
    "warning_prompt_only": {"firewall": False, "classifier": False, "spotlight": True, "guard": False},
}


def config_flags(config: str) -> GuardFlags:
    if config not in CONFIG_FLAGS:
        raise ValueError(f"unknown config {config!r}; available: {sorted(CONFIG_FLAGS)}")
    return dict(CONFIG_FLAGS[config])  # copy, so per-run state never mutates the table


def _merge_timings(old: dict | None, new: dict | None) -> dict:
    merged = {k: list(v) for k, v in (old or {}).items()}
    for k, v in (new or {}).items():
        merged.setdefault(k, []).extend(v)
    return merged


class RawSegment(TypedDict):
    """A piece of untrusted content waiting to enter the agent's context."""

    text: str
    source: str  # e.g. quotes/nimbus_laptops_quote.html#0, or tool:search_web
    channel: str  # rag | tool:<name>
    confidential: bool
    tool_call_id: str
    tool_name: str


class AgentState(TypedDict):
    run_id: str
    flags: GuardFlags  # T0; which defence layers are active this run
    user_request: str  # T1
    messages: Annotated[list[AnyMessage], add_messages]
    pending_untrusted: list[RawSegment]  # U; replaced (not appended) by each producer
    scope: Scope | None  # T2; set by extract_scope when guard is on
    ledger: TaintLedger | None  # provenance + confidential-flow memory (guard on), M4
    decisions: list[GuardDecision]  # guard verdicts for the latest proposed calls (replaced each turn)
    step: int
    status: str  # ok | step_limit | error
    final_answer: str | None
    timings: Annotated[dict[str, list[float]], _merge_timings]  # per-layer added latency (ms)


@dataclass
class Runtime:
    run_id: str
    config_name: str
    scenario_id: str | None
    settings: Settings
    sandbox: Sandbox
    registry: ToolRegistry
    retriever: Retriever
    llm: Any  # agent LLMClient-like: .invoke(messages) -> AIMessage (U* output)
    audit: AuditLogger
    policy: Any = None  # Policy (T0); used by extract_scope, action_guard and the firewall
    scope_llm: Any = None  # scope-role LLMClient-like; None -> extractor uses its fallback
    nonce: str = ""  # per-run spotlight nonce (M5)
    monitor: Any = None  # SessionMonitor (guard on): folds audit events across the session
    classifier: Any = None  # firewall F3 Classifier (per-run call budget), M6
