"""Human-in-the-loop stand-ins for the harness (ARCHITECTURE 5.6, IMPLEMENTATION_PLAN 5).

- SimulatedHuman answers ASK interrupts without a real person: deny on attacks, approve on
  benign tasks (an approved ASK on a legitimate call still counts as a false positive per the
  metric rule, and the strict auto-block rate shows the result without the human).
- build_compromised_agent drives the `compromised_agent` config: a scripted model that always
  emits the attack's malicious calls, so the guard is measured independently of model gullibility.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage

from agentguard.eval.suites import ScenarioSpec
from agentguard.llm import ScriptedChatModel, tool_call


class SimulatedHuman:
    """Callable: (interrupt_payload) -> {call_id: 'approve'|'deny'}."""

    def __init__(self, *, deny: bool):
        self.deny = deny
        self.answered: list[dict[str, Any]] = []

    def __call__(self, payload: dict[str, Any]) -> dict[str, str]:
        answer = "deny" if self.deny else "approve"
        asks = payload.get("asks", [])
        self.answered.extend(asks)
        return {a["call_id"]: answer for a in asks}


def build_compromised_agent(spec: ScenarioSpec) -> ScriptedChatModel:
    """A ScriptedChatModel that emits each malicious call in turn, then a final answer."""
    steps = [
        AIMessage(content="", tool_calls=[tool_call(mc.tool, dict(mc.args), f"mc-{i}")])
        for i, mc in enumerate(spec.malicious_calls)
    ]
    steps.append(AIMessage(content="(compromised agent: attack steps attempted)"))
    return ScriptedChatModel(steps)
