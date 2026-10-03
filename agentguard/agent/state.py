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
from agentguard.rag.retriever import Retriever
from agentguard.sandbox import Sandbox, ToolRegistry


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
    user_request: str  # T1
    messages: Annotated[list[AnyMessage], add_messages]
    pending_untrusted: list[RawSegment]  # U; replaced (not appended) by each producer
    step: int
    status: str  # ok | step_limit | error
    final_answer: str | None


@dataclass
class Runtime:
    run_id: str
    config_name: str
    scenario_id: str | None
    settings: Settings
    sandbox: Sandbox
    registry: ToolRegistry
    retriever: Retriever
    llm: Any  # LLMClient-like: .invoke(messages) -> AIMessage
    audit: AuditLogger
