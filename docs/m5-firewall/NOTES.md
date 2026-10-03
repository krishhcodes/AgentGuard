# M5: Content Firewall (deterministic stages) + spotlighting (2026-10-04)

Source: [RESULTS-ablation-run.md](RESULTS-ablation-run.md) (203 runs, `openai/gpt-oss-20b`, temp 0).
This run pre-dates two fixes made in M6 (guard notices no longer firewalled; content-FP metric no
longer counts poisoned web results), so its content-FPR of 8/452 overstates false positives.
The corrected figure is **0/222** (see `../m6-classifier/RESULTS.md`).

## Ablation (dev split, 16 attacks)

| config | what it is | ASR | catch |
|---|---|---|---|
| baseline | no defence | **62%** | 0% |
| warning_prompt_only | spotlight + system clause, nothing scanned | 44% | 0% |
| regex_only | deterministic firewall (F0-F2), no spotlight, no guard | **6%** | 88% |
| firewall_only | firewall + F3 classifier + spotlight | 0% | 94% |

- Spotlighting alone helps only a little (62% -> 44%): a prompt warning is not a defence.
- The deterministic firewall alone removes most injections (62% -> 6%) while keeping quote fields.
- Benign task completion with the firewall on: 92%.

## What was built
Normalise -> decode -> heuristics (9 rule families, weights in `policy.yaml`) -> PASS / FLAG /
SANITIZE / QUARANTINE; hidden HTML and decoded channels are dropped; fail-closed on scan errors.
Per-run-nonce spotlight delimiters with forged-delimiter escaping.

## Known limitation
Regexes catch instruction *families*, not paraphrase. Anything they miss is the classifier's job (M6)
and ultimately the Action Guard's (defence in depth).
