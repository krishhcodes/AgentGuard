"""Audit event schema. M0 records run lifecycle and tool executions; decision events
(scope_extracted, content_scanned, guard_decision, human_decision, layer_error) are
added with the layers that produce them.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

EventType = Literal[
    "run_started", "scope_extracted", "content_scanned", "guard_decision", "human_decision",
    "tool_executed", "layer_error", "run_completed",
]
Layer = Literal["runner", "scope", "firewall", "action_guard", "human_gate", "tools"]
RunStatus = Literal["ok", "step_limit", "error"]
Decision = Literal["ALLOW", "ASK", "BLOCK", "APPROVED", "DENIED"]

SNIPPET_MAX = 300
PREVIEW_MAX = 200


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + f"...[+{len(text) - limit} chars]"


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ts: str = Field(default_factory=utc_now)
    run_id: str
    config: str
    scenario_id: str | None = None
    layer: Layer
    event: EventType
    tool: str | None = None
    args: dict[str, Any] | None = None
    result_preview: str | None = None
    status: RunStatus | None = None
    reason: str | None = None
    # Decision events (guard_decision, human_decision). PS3 D4 mapping: rules -> "rule violated",
    # evidence[].snippet -> "triggering content snippet", decision -> "decision".
    decision: Decision | None = None
    rules: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    scope_ref: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    latency_ms: dict[str, float] = Field(default_factory=dict)


def preview_args(args: dict[str, Any]) -> dict[str, Any]:
    """Truncate long argument values (email bodies) for the log."""
    return {k: truncate(v, PREVIEW_MAX) if isinstance(v, str) else v for k, v in args.items()}


def write_schema(path: Path) -> None:
    path.write_text(json.dumps(AuditEvent.model_json_schema(), indent=2), encoding="utf-8")
