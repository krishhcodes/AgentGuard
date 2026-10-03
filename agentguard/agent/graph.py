"""Graph construction.

`build_graph(config)` assembles the graph for a named configuration from shared nodes
(ARCHITECTURE P8: defences only ADD nodes). The baseline is a plain ReAct loop; guarded
configs insert extract_scope -> ... -> action_guard -> human_gate and compile with a
checkpointer so the human-in-the-loop interrupt can resume.
"""

from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph import END, START, StateGraph

from agentguard.agent import nodes
from agentguard.agent.state import AgentState, config_flags

CONFIGS = ("baseline", "guard_only", "compromised_agent", "regex_only", "firewall_only", "full",
           "warning_prompt_only")

# The checkpointed state holds our pydantic Scope / GuardDecision objects; register them so the
# checkpointer serialises them explicitly instead of via the deprecated fallback.
_CHECKPOINT_SERDE = JsonPlusSerializer(allowed_msgpack_modules=[
    ("agentguard.scope.models", "Scope"),
    ("agentguard.guard.rules", "GuardDecision"),
    ("agentguard.guard.rules", "RuleHit"),
    ("agentguard.guard.taint", "TaintLedger"),
    ("agentguard.guard.taint", "LedgerEntry"),
    ("agentguard.guard.taint", "ConfidentialBody"),
])


def build_graph(config: str = "baseline"):
    flags = config_flags(config)  # validates the config name
    return _build_guarded_graph() if flags["guard"] else _build_baseline_graph()


def _build_baseline_graph():
    g = StateGraph(AgentState)
    g.add_node("retrieve", nodes.retrieve)
    g.add_node("ingest_untrusted", nodes.ingest_untrusted)
    g.add_node("agent", nodes.agent)
    g.add_node("execute_tools", nodes.execute_tools)
    g.add_node("finalize", nodes.finalize)

    g.add_edge(START, "retrieve")
    g.add_edge("retrieve", "ingest_untrusted")
    g.add_edge("ingest_untrusted", "agent")
    g.add_conditional_edges("agent", nodes.route_after_agent, ["execute_tools", "finalize"])
    g.add_edge("execute_tools", "ingest_untrusted")
    g.add_edge("finalize", END)
    return g.compile()


def _build_guarded_graph():
    g = StateGraph(AgentState)
    g.add_node("extract_scope", nodes.extract_scope)
    g.add_node("retrieve", nodes.retrieve)
    g.add_node("ingest_untrusted", nodes.ingest_untrusted)
    g.add_node("agent", nodes.agent)
    g.add_node("action_guard", nodes.action_guard)
    g.add_node("human_gate", nodes.human_gate)
    g.add_node("execute_tools", nodes.execute_tools)
    g.add_node("finalize", nodes.finalize)

    g.add_edge(START, "extract_scope")
    g.add_edge("extract_scope", "retrieve")
    g.add_edge("retrieve", "ingest_untrusted")
    g.add_edge("ingest_untrusted", "agent")
    g.add_conditional_edges("agent", nodes.route_after_agent_guarded, ["action_guard", "finalize"])
    g.add_conditional_edges("action_guard", nodes.route_after_guard, ["human_gate", "execute_tools"])
    g.add_edge("human_gate", "execute_tools")
    g.add_edge("execute_tools", "ingest_untrusted")
    g.add_edge("finalize", END)
    # A checkpointer is required for interrupt()/resume at human_gate; MemorySaver is per-run.
    return g.compile(checkpointer=MemorySaver(serde=_CHECKPOINT_SERDE))
