"""Policy (T0): the declarative source of truth for tools and data classification.

Invalid policy refuses to load (fail closed at boot).
"""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict

from agentguard.config import CONFIG_DIR

RiskClass = Literal["read", "egress", "write"]


class ToolPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk: RiskClass
    critical_args: list[str]
    description: str


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    internal_domains: list[str]
    confidential_globs: list[str]
    tools: dict[str, ToolPolicy]

    def is_confidential(self, path: str) -> bool:
        return any(fnmatch(path, pattern) for pattern in self.confidential_globs)


def load_policy(path: Path | None = None) -> Policy:
    path = path or CONFIG_DIR / "policy.yaml"
    with open(path, encoding="utf-8") as f:
        return Policy.model_validate(yaml.safe_load(f))
