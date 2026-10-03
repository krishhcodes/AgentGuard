"""Latency harness (M6): per-run layer timings flow into RunRecords and latency.csv rows."""

from agentguard.eval.metrics import RunRecord
from agentguard.eval.report import _percentile, latency_rows, render_markdown, write_latency_csv


def rec(config, scope=0.0, fw=0.0, clf=0.0, guard=0.0, **kw):
    base = dict(scenario_id="s", split="dev", category="plain", config=config, repeat=1, status="ok",
                is_attack=False, hijacked=None, task_completed=True)
    base.update(kw)
    return RunRecord(**base, lat_scope_ms=scope, lat_firewall_ms=fw, lat_classifier_ms=clf, lat_guard_ms=guard)


def test_percentile_nearest_rank():
    assert _percentile([10, 20, 30, 40], 0.5) == 20
    assert _percentile([10, 20, 30, 40], 0.95) == 40
    assert _percentile([], 0.5) != _percentile([], 0.5)  # nan


def test_latency_rows_report_per_layer_and_total():
    records = [rec("full", scope=300, fw=5, clf=400, guard=2), rec("full", scope=500, fw=7, clf=0, guard=3),
               rec("baseline")]
    rows = {(r["config"], r["layer"]): r for r in latency_rows(records)}
    assert ("baseline", "TOTAL") not in rows  # the undefended baseline adds nothing
    assert rows[("full", "scope")]["p95_ms"] == 500
    assert rows[("full", "TOTAL")]["p95_ms"] == 707 and rows[("full", "TOTAL")]["p50_ms"] == 510
    assert rows[("full", "classifier")]["p95_ms"] == 400


def test_latency_csv_and_m6_gate_section(tmp_path):
    records = [rec("full", scope=300, fw=5, clf=400, guard=2, interventions=2, interventions_explained=2),
               rec("baseline")]
    write_latency_csv(records, tmp_path / "latency.csv")
    assert "TOTAL" in (tmp_path / "latency.csv").read_text()
    md = render_markdown(records)
    assert "Gate checks (M6" in md and "target p95 < 2000 ms: PASS" in md
    assert "interventions with reason and evidence: 2/2" in md
