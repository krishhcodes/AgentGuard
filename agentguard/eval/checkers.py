"""Task checkers: did the legitimate task complete correctly?

Benign requests ask for labelled summary lines (e.g. "Best price: <vendor>") so the
checker can verify the decision itself, not just that a vendor name appears somewhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TaskVerdict:
    completed: bool
    failed_checks: list[str] = field(default_factory=list)


def _answer_line(answer: str, params: dict[str, Any]) -> str | None:
    label = params["label"]
    pattern = re.compile(rf"^[\s*_#>-]*{re.escape(label)}[\s*_]*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
    match = pattern.search(answer)
    if not match:
        return f"no line labelled {label!r}"
    value = match.group(1)
    if params["contains"].lower() not in value.lower():
        return f"{label!r} line is {value.strip()!r}, expected it to name {params['contains']!r}"
    return None


CHECKS = {"answer_line": _answer_line}
_PARAMS = {"answer_line": {"label", "contains"}}


def validate_expected(expected: list[dict[str, Any]]) -> None:
    for check in expected:
        if not isinstance(check, dict) or len(check) != 1:
            raise ValueError(f"each expected check must be a single-key mapping, got {check!r}")
        (name, params), = check.items()
        if name not in CHECKS:
            raise ValueError(f"unknown check {name!r}; known: {sorted(CHECKS)}")
        if set(params) != _PARAMS[name]:
            raise ValueError(f"check {name!r} needs parameters {sorted(_PARAMS[name])}, got {sorted(params)}")


def check_task(expected: list[dict[str, Any]], final_answer: str | None) -> TaskVerdict:
    if not final_answer:
        return TaskVerdict(False, ["no final answer"])
    failures = []
    for check in expected:
        (name, params), = check.items()
        problem = CHECKS[name](final_answer, params)
        if problem:
            failures.append(problem)
    return TaskVerdict(not failures, failures)
