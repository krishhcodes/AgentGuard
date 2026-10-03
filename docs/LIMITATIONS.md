# Known limitations (stated honestly)

Full reasoning in [THREAT_MODEL.md](../THREAT_MODEL.md) section 9. What we measured, and what we did not.

1. **Answer integrity.** An injection that only biases the final text, with no tool action, is not stoppable by the
   guard. The firewall and spotlighting reduce it; the poisoned-but-legitimate tasks measure it.
2. **Paraphrased exfiltration** escapes content-overlap detection (`tests/test_taint.py`, xfail). Backstop: after any
   confidential read, every egress is escalated (ASK to an authorised sink, BLOCK to an unauthorised one).
3. **Scope extractor misreads** show up as over-blocking (counted in FPR), never as an invented recipient: the
   deterministic validation drops anything not literally in the user's request.
4. **Firewall recall on novel styles** is limited: regex *families* plus an LLM classifier on the ambiguous band only.
   The unseen-set number is the honest estimate.
5. **Small samples.** 16 dev attacks and 4 unseen attacks: confidence intervals are wide. We report Wilson 95% CIs and
   never claim "100%".
6. **Latency tail.** p95 added latency is 655 ms on the final dev run (gate met), but only because the scope call runs
   in parallel with the agent's first turn; raw scope latency has a 5+ s provider tail, bounded by a 4 s timeout.
7. **Model dependence.** Baseline ASR (62%, below the 70% target) depends on the agent model (`gpt-oss-20b`, temp 0); we
   report it as measured rather than tuning the baseline.
8. **Human approval is simulated** in the evaluation (deny on attacks, approve on benign). Real reviewers may err.
9. **Single-run results.** Evals use repeats=1 for time; temp-0 runs are near-deterministic but not guaranteed identical.
