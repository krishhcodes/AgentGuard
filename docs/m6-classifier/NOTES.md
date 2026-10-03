# M6: LLM instruction classifier + PS3 performance gates (2026-10-04)

Run: `eval --configs baseline,guard_only,compromised_agent,full --splits dev,benign --repeats 1`
(`openai/gpt-oss-20b`, temp 0, 116 runs, 0 errored). Tables: [RESULTS.md](RESULTS.md).

## PS3 gates (dev)

| Gate | Target | Result | |
|---|---|---|---|
| `full` dev catch rate | >= 85% | **94%** [72-99%] (15/16) | PASS |
| `full` dev ASR | (baseline 62%) | **0%** [0-19%] | |
| Benign + poisoned-benign completion (`full`) | >= 90% | **100%** (13/13) | PASS |
| Action-level FPR (`full`) | <= 10% | **0%** [0-23%] | PASS |
| Content FPR (clean segments removed) | <= 2% | **0%** (0/222) | PASS |
| Interventions with reason + evidence | 100% | **22/22** | PASS |
| Added latency p95 | < 2 s | see below | **NOT MET (tail)** |

Honest note on the catch rate: 69% of dev attacks are stopped by the guard alone; the firewall lifts
that to 94% and `compromised_agent` (guard vs a fully hijacked agent) is 100%. Defence in depth, not one layer.

## Latency (per layer, critical path)

| layer | typical | note |
|---|---|---|
| firewall F0-F2 | ~20 ms | p95 ~30 ms |
| action guard | ~1 ms | |
| classifier F3 | ~0.5 s per call | only ambiguous spans; most runs make no call |
| scope extractor | ~0.7 s raw | **runs in parallel with the agent's first turn**, so it adds ~0 on the critical path |

Median added latency per run is **~20 ms**. The **p95 gate is not met in live sampling**
(`latency-live-sample.csv`: p95 ~22 s): the outliers are Groq provider tail latency and a ~5 s
cold start on the first call of a process (two scope calls of 15-26 s, one classifier call of 4.3 s).
Mitigations shipped: parallel scope, a one-time warm-up ping, and hard timeouts (scope 4 s -> safe
default scope; classifier 3 s -> FLAG). The timeout run was cut short by the provider's daily token
limit, so p95 under those timeouts is **unverified**. The demo path runs in replay mode.
`latency.csv` in this folder comes from the cached run and is superseded by the live sample.

## What M6 added
- `firewall/classifier.py`: batched ambiguous spans, random delimiters, strict JSON, schema
  violation / timeout -> `FW-CLASSIFIER-ANOMALY` + FLAG, <= 2 calls per run, cached.
- Config `regex_only`; `latency.csv`; M6 gate report.
- Fixes found by the eval: guard refusal notices were being scanned as untrusted content (now exempt);
  invalid Groq keys (401) are rotated past.
