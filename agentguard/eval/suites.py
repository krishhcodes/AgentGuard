"""Scenario specs (attacks and benign tasks), loaded and validated from suites/**.yaml."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from agentguard.config import SUITES_DIR
from agentguard.eval.checkers import validate_expected
from agentguard.eval.oracle import validate_predicate
from agentguard.sandbox.tools import TOOL_ARG_MODELS

Category = Literal["plain", "encoded", "fake_system", "tool_response", "multi_step", "benign"]


class ToolCallSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    args: dict[str, Any]


class DecisionExpectation(BaseModel):
    """What the Action Guard should decide for a benign call (consumed from M2 on).

    Authored in M1 for ambiguous and looks-scary-but-legit benign tasks so the FPR metric
    can tell an expected ASK (not a false positive) from an over-block.
    """

    model_config = ConfigDict(extra="forbid")

    tool: str
    decision: Literal["ALLOW", "ASK"]
    note: str = ""


class ScenarioSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    split: Literal["dev", "unseen", "benign", "demo"]
    category: Category
    description: str = ""
    user_request: str
    overlay: dict[str, str] = {}
    success_predicate: dict[str, Any] | None = None  # attacks: harmful outcome (oracle)
    expected: list[dict[str, Any]] = []  # legitimate task result (checkers)
    expected_decisions: list[DecisionExpectation] = []  # benign guard expectations (M2+)
    malicious_calls: list[ToolCallSpec] = []  # the attacker's desired calls, in order

    @property
    def is_attack(self) -> bool:
        return self.split != "benign"

    @model_validator(mode="after")
    def _validate(self) -> ScenarioSpec:
        if self.is_attack:
            if self.success_predicate is None:
                raise ValueError(f"attack {self.id} needs a success_predicate")
            if not self.overlay:
                raise ValueError(f"attack {self.id} needs an overlay carrying the injection")
            if self.category == "benign":
                raise ValueError(f"attack {self.id} cannot have category 'benign'")
        elif not self.expected:
            raise ValueError(f"benign task {self.id} needs expected checks")
        if self.success_predicate is not None:
            validate_predicate(self.success_predicate)
        validate_expected(self.expected)
        for call in self.malicious_calls:
            if call.tool not in TOOL_ARG_MODELS:
                raise ValueError(f"{self.id}: malicious call uses unknown tool {call.tool!r}")
        return self


def load_scenario_file(path: Path) -> ScenarioSpec:
    with open(path, encoding="utf-8") as f:
        return ScenarioSpec.model_validate(yaml.safe_load(f))


def load_scenarios(root: Path = SUITES_DIR) -> dict[str, ScenarioSpec]:
    scenarios: dict[str, ScenarioSpec] = {}
    for path in sorted(root.rglob("*.yaml")):
        spec = load_scenario_file(path)
        if spec.id in scenarios:
            raise ValueError(f"duplicate scenario id {spec.id!r} in {path}")
        scenarios[spec.id] = spec
    return scenarios
