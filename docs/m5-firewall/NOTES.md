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

## Post-fix ablation (final; [RESULTS-ablation-post-fix.md](RESULTS-ablation-post-fix.md))
After the M6 utility fix (item-level removal, quarantine only when >90% malicious), dev split, 16 attacks:

| config | ASR | catch | attacked-task completion | benign completion |
|---|---|---|---|---|
| baseline | 62% | 0% | 88% | 92% |
| regex_only (F0-F2 only) | 6% [1-28%] | 88% | 81% | 92% |
| firewall_only (+ LLM classifier, spotlight) | **0%** [0-19%] | **94%** | **94%** | **100%** |
| full (+ Action Guard) | **0%** [0-19%] | **94%** | **94%** | **100%** |

The classifier is what takes the firewall from 88% to 94% catch and from 6% to 0% ASR. The guard adds no catch on dev
here because the firewall already removes what the guard would block; its value is the guarantee when the firewall
misses (compromised_agent: 100% blocked) and the human-approval path.
