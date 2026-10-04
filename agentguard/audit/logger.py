"""Append-only JSONL audit log, one file per run, plus an in-memory copy for the UI."""

from __future__ import annotations

import json
from pathlib import Path

from agentguard.audit.events import AuditEvent


class AuditWriteError(RuntimeError):
    pass


class AuditLogger:
    def __init__(self, path: Path):
        self.path = path
        self.events: list[AuditEvent] = []
        self.listeners: list = []  # e.g. the Session Monitor folds each event as it is written
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise AuditWriteError(f"cannot create audit directory {path.parent}: {e}") from e

    def emit(self, event: AuditEvent) -> AuditEvent:
        # json.dumps escapes control characters and newlines, so untrusted text can't forge lines.
        line = json.dumps(event.model_dump(mode="json"), ensure_ascii=False)
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as e:
            raise AuditWriteError(f"cannot write audit log {self.path}: {e}") from e
        self.events.append(event)
        for fn in self.listeners:
            try:
                fn(event)
            except Exception:  # a monitor bug must never break the audit trail or the run
                pass
        return event
