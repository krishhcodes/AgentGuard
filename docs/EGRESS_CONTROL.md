# Egress Control

The last deterministic gate before anything leaves (`agentguard/guard/egress.py`, graph node `egress_control`).

```
agent -> Action Guard -> [Ask human] -> Egress Control -> execute tools
```

It runs after the guard and after the human gate, on every call that is about to execute: **ALLOWed by the guard, or
APPROVED by a human who may simply have trusted the agent.** One question only: *does this call carry sensitive data to a
destination the user did not name?* If yes, the human is asked **once more, with an escalated prompt**
("ESCALATED second check: ..."). Approve -> it runs; deny -> it is blocked. It can only add friction, never loosen a
verdict, and uses no LLM.

- **Sensitive** = secret-shaped data (policy patterns), personal-data shapes (national-ID, card), content overlapping a
  confidential file, or a confidential read earlier in the task / session.
- **Unnamed destination** = not a recipient the user wrote in the request, and not an internal domain. The web is always
  unnamed.
- Applies to `send_email` and `search_web` (the egress tools).

**Latency.** Pure Python over the call's own text: well under 1 ms per call (asserted < 50 ms in the tests), so it does
not move the p95 budget.

**Tests.** `tests/test_egress_control.py` (6 fast offline tests: flagged, exempt, confidential-read, deny, human-approved
then asked again, harmless call not interrupted and fast).

**Honest limits.** Many cases are already BLOCKed earlier by the guard's own egress rules, so this gate mostly stays
dormant: it is the fail-safe for (1) calls a human approved without scrutiny and (2) anything the earlier rules let
through. A batch of calls proposed in one turn is judged against the ledger as it stood at guard time (a confidential
read and a send in the same batch is a known gap). Added after the frozen evaluations; the reported dev and unseen
numbers were produced without it, and it was not re-measured with live runs.
