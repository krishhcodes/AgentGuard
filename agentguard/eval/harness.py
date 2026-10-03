"""Evaluation harness: run suites x configs x repeats, collect RunRecords, write runs.csv.

M1 scope: only the `baseline` config exists, so the harness measures the unprotected
agent. Later milestones add configs without changing this code. Runs are sequential; the
LLM client already backs off on rate limits (important on Groq's free tier). Errored runs
are recorded and excluded from rates, never counted as blocked.
"""

from __future__ import annotations

import csv
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from agentguard.config import Settings, load_settings
from agentguard.eval.metrics import RunRecord
from agentguard.eval.suites import ScenarioSpec, load_scenarios
from agentguard.policy import Policy, load_policy
from agentguard.runner import RunResult, run_scenario

LlmFactory = Callable[[ScenarioSpec, str], Any]  # (spec, config) -> llm, for offline tests


def record_from_result(spec: ScenarioSpec, config: str, repeat: int, result: RunResult) -> RunRecord:
    return RunRecord(
        scenario_id=spec.id,
        split=spec.split,
        category=spec.category,
        config=config,
        repeat=repeat,
        status=result.status,
        is_attack=spec.is_attack,
        hijacked=(result.attack.hijacked if result.attack else None),
        task_completed=(result.task.completed if result.task else None),
        # Defence outcomes stay False under baseline (no guard/firewall exists yet).
        blocked=False,
        escalated_denied=False,
        benign_false_positive=False,
        duration_s=round(result.duration_s, 2),
    )


def _write_csv(path: Path, records: list[RunRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(asdict(records[0]).keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in records:
            writer.writerow(asdict(r))


def run_suite(
    *,
    configs: list[str],
    splits: list[str],
    repeats: int = 3,
    settings: Settings | None = None,
    policy: Policy | None = None,
    scenarios: dict[str, ScenarioSpec] | None = None,
    llm_factory: LlmFactory | None = None,
    out_csv: Path | None = None,
    delay_s: float = 0.0,
    progress: Callable[[str], None] | None = None,
) -> list[RunRecord]:
    settings = settings or load_settings()
    policy = policy or load_policy()
    scenarios = scenarios or load_scenarios()
    selected = [s for s in scenarios.values() if s.split in splits]
    if not selected:
        raise ValueError(f"no scenarios for splits {splits}")
    records: list[RunRecord] = []
    total = len(configs) * len(selected) * repeats
    i = 0
    for config in configs:
        for spec in selected:
            for rep in range(1, repeats + 1):
                i += 1
                result = run_scenario(
                    spec, config=config,
                    llm=(llm_factory(spec, config) if llm_factory else None),
                    settings=settings, policy=policy,
                )
                rec = record_from_result(spec, config, rep, result)
                records.append(rec)
                if progress:
                    tag = (f"hijacked={rec.hijacked}" if rec.is_attack else f"task_ok={rec.task_completed}")
                    progress(f"[{i}/{total}] {config} {spec.id} rep{rep}: {rec.status} {tag} {rec.duration_s:.1f}s")
                if out_csv:  # write after every run so a crash keeps partial data
                    _write_csv(out_csv, records)
                if delay_s and i < total:
                    time.sleep(delay_s)
    return records
