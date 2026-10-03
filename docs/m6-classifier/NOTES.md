# M6: LLM instruction classifier + PS3 performance gates (2026-10-04)

`gpt-oss-20b`, temp 0. Final numbers: [RESULTS.md](RESULTS.md) (`full`, dev + benign, 29 runs, 0 errored).
Earlier run before the fix below: [RESULTS-before-fix.md](RESULTS-before-fix.md) (116 runs, all gated configs).

## PS3 gates (dev) - all PASS

| Gate | Target | Result |
|---|---|---|
| `full` dev catch rate | >= 85% | **94%** [72-99%] (15/16) |
| `full` dev ASR | (baseline 62%) | **0%** [0-19%] |
| Task completion on attacked (poisoned-but-legitimate) tasks | >= 90% | **94%** (15/16); was 75% before the fix |
| Benign completion (`full`) | >= 90% | **100%** (13/13) |
| Action-level FPR (`full`) | <= 10% | **0%** [0-23%] |
| Content FPR (clean segments removed) | <= 2% | **0%** (0/222) |
| Interventions with reason + evidence | 100% | **18/18** |
| Added latency p95 | < 2 s | **655 ms** (p50 22 ms) |

Catch rate counts an attributable defence event (a guard block or a firewall removal), not a counterfactual
hijack: the baseline model is hijacked by 62% of dev attacks, so some "catches" are on attacks the model would
have ignored. ASR (0% vs 62%) is the outcome measure; 69% of dev attacks are stopped by the guard alone
(`guard_only`), the firewall lifts the catch to 94%, and a fully hijacked agent behind the guard is 100% blocked.

## Latency (critical path, per layer; `latency.csv`)

| layer | p50 | p95 | note |
|---|---|---|---|
| firewall F0-F2 | 21 ms | 24 ms | |
| action guard | ~0 ms | ~1 ms | |
| classifier F3 | 0 ms | 632 ms | only ambiguous spans reach it; most runs make no call |
| scope extractor | (hidden) | (hidden) | raw p50 0.6 s / p95 5.6 s, but it **runs in parallel with the agent's first turn**, so it adds only what exceeds that turn |

Levers used (ARCHITECTURE s8): parallel scope, one-off warm-up ping, `reasoning_effort: low` on scope and classifier,
hard timeouts (scope 4 s -> safe default scope; classifier 3 s -> FLAG). The raw scope tail (5.6 s) is Groq provider
latency and cold start; the timeout bounds it and the parallelism hides it.

## The utility fix (found by the eval, disclosed)

Under the firewall, attacked tasks completed 75% (dev) and 25% (unseen v1) vs 94-100% without it. Cause: a quote with
one injected paragraph was withheld whole (QUARANTINE when >50% of its text was malicious), so the agent lost the
vendor's price. Fix: remove only the offending list item, and quarantine only when >90% is malicious
(`quarantine_fraction` 0.5 -> 0.9, `firewall/pipeline.py`). Motivated by the **dev** numbers (75% vs 94%), then
confirmed on unseen. Because it was made after the unseen set was first run, the unseen set was re-run and **both
runs are reported** (`../m7-unseen/`).

## What M6 added
- `firewall/classifier.py`: batched ambiguous spans, random delimiters, strict JSON, schema violation / timeout ->
  `FW-CLASSIFIER-ANOMALY` + FLAG, <= 2 calls per run, cached.
- Config `regex_only`; `latency.csv`; PS3 gate report. Guard refusal notices are exempt from the firewall (they are
  system text); invalid Groq keys are rotated past; `--patient` waits out the daily token window.
