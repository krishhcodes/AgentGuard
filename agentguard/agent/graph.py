"""Graph construction. M0 has one variant: the unprotected baseline."""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from agentguard.agent import nodes
from agentguard.agent.state import AgentState


def build_baseline_graph():
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
