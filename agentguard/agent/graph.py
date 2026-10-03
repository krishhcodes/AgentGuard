"""Graph construction.

`build_graph(config)` assembles the graph for a named configuration from shared nodes.
Only "baseline" exists until defences land (guard_only, firewall_only, full add nodes).
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from agentguard.agent import nodes
from agentguard.agent.state import AgentState

CONFIGS = ("baseline",)


def build_graph(config: str = "baseline"):
    if config != "baseline":
        raise ValueError(f"config {config!r} is not implemented yet; available: {CONFIGS}")
    return _build_baseline_graph()


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
