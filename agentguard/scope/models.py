"""Scope data model (T2): what the trusted user request authorises.

A Scope is computed from the user request + policy ONLY (invariant P1), validated
deterministically, and treated as immutable for the run. The Action Guard checks every
proposed tool call against it.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class WriteTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    table: str
    record_id: str | None = None
    fields: list[str] = []  # field names the user named; empty = any field on this record


class EgressFlow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str  # confidential path the user named
    recipient: str  # recipient the user named


class Ambiguity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str  # recipient | tool | resource | write_target
    text: str  # the phrase that could not be resolved, e.g. "the team"
    reason: str


class ScopeMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str
    latency_ms: float = 0.0
    fallback_used: bool = False
    dropped_items: list[str] = []


class Scope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope_id: str
    task_summary: str
    allowed_tools: list[str] = []
    read_resources: list[str] = []  # globs, e.g. "quotes/**"
    confidential_resources: list[str] = []  # only paths the user literally named
    recipients: list[str] = []  # literal addresses, or alias-resolved from the user text
    recipient_domains: list[str] = []  # only if the user literally named a domain
    write_targets: list[WriteTarget] = []
    egress_flows: list[EgressFlow] = []
    ambiguities: list[Ambiguity] = []
    meta: ScopeMeta

    def ambiguity_for(self, field: str) -> Ambiguity | None:
        return next((a for a in self.ambiguities if a.field == field), None)

    def ambiguous_tool(self, tool: str) -> Ambiguity | None:
        return next((a for a in self.ambiguities if a.field == "tool" and a.text == tool), None)
