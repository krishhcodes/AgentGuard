# AgentGuard

A prompt-injection shield for tool-using RAG agents (hackathon PS3).
Design: [ARCHITECTURE.md](ARCHITECTURE.md) · [THREAT_MODEL.md](THREAT_MODEL.md) · [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)

**Status: milestone M4.** Adds the **data-flow layer**: a shared text normalise/decode library
(zero-width, HTML hidden channels, base64/hex/…), a session **Taint Ledger** (provenance + confidential
overlap, incl. chunked-across-messages), and the egress rules `CONFIDENTIAL_EGRESS`,
`SECRET_PATTERN_EGRESS` and `ARG_FROM_UNTRUSTED_SOURCE` — every guard decision is now **attributed to
the source document/view**. Built on M3 (side-by-side demo with live Approve/Deny) and M2 (Scope
Extractor + Action Guard + Ask-Human). Configs: `baseline`, `guard_only`, `compromised_agent`.

Measured (`gpt-oss-20b`, dev split, repeats=1; [docs/m4-ledger/](docs/m4-ledger/)): baseline dev ASR
**62%** (10/16) → guard_only **0%**, benign completion **92→94%**, benign FPR **0%**;
`compromised_agent` (guard alone) catch **100%** on all categories incl. multi-step — the M4 gate.
The new `multi-04` scenario shows a *legitimately-read* confidential file caught at egress by the
ledger, which the M2 read rule alone could not stop.

The headline property, shown first: even when the agent is **fully hijacked**, the guard blocks the
harmful action with a logged reason and the legitimate task still finishes — no content scanning
needed yet (that is the Content Firewall, M5). Taint/data-flow rules (confidential-content egress)
arrive in M4; M2's rules cover unauthorised recipients, tools, paths and writes.

**Measured (`gpt-oss-20b`, dev split, repeats=1; see [docs/m2-guard/](docs/m2-guard/)):**

| config | dev ASR | benign completion | benign FPR |
|---|---|---|---|
| baseline | **60%** (9/15) | 92% | 0% |
| guard_only | **0%** (0/15) | 92% | **0%** |
| compromised_agent (guard alone) | 0% | — | — — catch **100%** on C1-C5 |

The guard eliminates every attack the real model fell for, with **no false positives** and no task
regression; `compromised_agent` (the model scripted to always emit the attack's calls) shows the guard
catches **100%** even with model luck removed. Baseline is kept honestly at ~60% rather than tuned
(see [docs/m1-baseline/DECISION.md](docs/m1-baseline/DECISION.md)). Confidential-content egress and
taint attribution are M4; the content firewall is M5. Verified by 121 offline tests plus this live run.

## Setup (Windows, PowerShell or Git Bash)

```
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

Put your Groq key in `.env` (it is git-ignored): `GROQ_API_KEY=...`

## Commands

```
.venv\Scripts\python -m agentguard doctor                                 # gate D1: key, model, tool calling
.venv\Scripts\python -m agentguard list                                   # scenarios
.venv\Scripts\python -m agentguard run --scenario plain-01                # canonical attack, baseline (HIJACKED)
.venv\Scripts\python -m agentguard run --scenario plain-01 --config guard_only   # same attack, BLOCKed + task done
.venv\Scripts\python -m agentguard eval --configs baseline,guard_only,compromised_agent --splits dev,benign --repeats 3 --delay 2
.venv\Scripts\python -m agentguard freeze-manifest --verify               # unseen-set integrity check
.venv\Scripts\python -m streamlit run ui/app.py                           # demo UI: side-by-side + live Approve/Deny
.venv\Scripts\python -m pytest                                            # offline tests (no network, no API key)
```

Under `--config guard_only`, an ASK decision pauses the run and prompts `approve this call? [y/N]`
on stdin (empty input denies — fail closed).

LLM modes (`--llm-mode` or the UI radio): `auto` (default; reuse recorded runs, call Groq only for
new/changed requests), `record` (always live, response saved to `cache/llm/`), `replay` (offline,
recorded responses only), `off` (live, nothing saved). The guard adds a second LLM role, `scope`
(`config/models.yaml`), which sees only the trusted user request (P1).

## Safety of testing

All tools act on an in-memory sandbox: emails go to a mock outbox, records to an in-memory SQLite DB,
web search returns canned pages. Fixture files in `data/` are only read. All "confidential" data is
fake and carries `CANARY-*` markers so leaks can be proven from outcomes. Tests block every
non-loopback network connection.

## Disclosure (baseline realism)

The baseline agent's system prompt (`agentguard/agent/prompts.py`) has no safety instructions and no
instruction to follow documents. Retrieved content and tool output are delivered as tool messages,
exactly as in an ordinary tool-using agent. Model: `config/models.yaml`
(`openai/gpt-oss-20b` on Groq, temperature 0), chosen at gate D1 (2026-10-03). The planned
`llama-3.1-8b-instant` is no longer offered by Groq. `qwen/qwen3.8-27b` was also tested and resisted
the canonical attack 0/3, so it was not used for the deliberately vulnerable baseline.
