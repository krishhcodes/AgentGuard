"""Policy (T0): the declarative source of truth for tools and data classification.

Invalid policy refuses to load (fail closed at boot).
"""

from __future__ import annotations

import re
from fnmatch import fnmatch
from functools import cached_property
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


class FirewallPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    t_low: float = 2
    t_high: float = 3
    quarantine_fraction: float = 0.5
    weights: dict[str, float] = {}


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    internal_domains: list[str]
    confidential_globs: list[str]
    tools: dict[str, ToolPolicy]
    directory: dict[str, str] = {}  # alias phrase (lowercased key) -> email, M2+
    high_risk_fields: list[str] = []  # write fields escalated to ASK unless the user stated them, M2+
    secret_patterns: list[str] = []  # regexes for secret-shaped egress data, M4+
    firewall: FirewallPolicy = FirewallPolicy()  # content-firewall thresholds/weights, M5+

    def is_confidential(self, path: str) -> bool:
        return any(fnmatch(path, pattern) for pattern in self.confidential_globs)

    @cached_property
    def _secret_res(self) -> list[re.Pattern]:
        return [re.compile(p) for p in self.secret_patterns]

    def matched_secrets(self, text: str) -> list[str]:
        """Distinct secret-pattern hits in `text`, de-duplicated, preserving order."""
        seen: set[str] = set()
        out: list[str] = []
        for rx in self._secret_res:
            for m in rx.findall(text or ""):
                m = m if isinstance(m, str) else m[0]
                if m and m not in seen:
                    seen.add(m)
                    out.append(m)
        return out


def load_policy(path: Path | None = None) -> Policy:
    path = path or CONFIG_DIR / "policy.yaml"
    with open(path, encoding="utf-8") as f:
        return Policy.model_validate(yaml.safe_load(f))
