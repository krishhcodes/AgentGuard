# Session Monitor

**Problem.** The Action Guard judges each call on its own. Some compromises only appear across many calls: a few small
sends that are each approved, a probe that keeps retrying blocked actions, one leak spread over several recipients.

**What it is.** A deterministic fold over the **audit log** (`agentguard/monitor/session.py`). It is subscribed to the
audit logger, so every event (`guard_decision`, `human_decision`, `tool_executed`) updates per-session counters. Before
the guard returns a verdict, the monitor may **escalate** it (ALLOW -> ASK, or -> BLOCK for heavy probing). It can only
tighten, never loosen (defences only add), and it never calls an LLM.

| Rule | Fires when | Verdict |
|---|---|---|
| `SESSION_PROBING` | >= 3 blocked/denied calls already in the session and the next call is egress/write | ASK (BLOCK at >= 6) |
| `SESSION_SLOW_EXFIL` | after a confidential read, the unauthorised chars sent to one external domain would exceed 600 | ASK |
| `SESSION_FAN_OUT` | >= 3 different external domains, none named by the user, in one session | ASK |

Recipients the user named in the request are exempt, so ordinary tasks never trip it. Thresholds are in
`config/policy.yaml` (`session:`).

**Across runs.** With a `session_id` (the UI gives each browser tab one; "New session" resets it) each run's audit file
is replayed when the next run starts (`runs/_sessions/<id>.json` lists the runs). Without one, the session is just the run.

**Tests.** `tests/test_session_monitor.py` (7 fast offline tests, including one end-to-end through the real graph).

**Disclosure.** Added after the frozen evaluations; the reported dev and unseen numbers were produced without it. It is
additive and cannot change an ALLOW on a benign single-run task (benign runs have no blocked calls and no unauthorised
external sends), but it was not re-measured with live runs.
