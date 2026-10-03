# AgentGuard

A prompt-injection shield for tool-using RAG agents (hackathon PS3).
Design: [ARCHITECTURE.md](ARCHITECTURE.md) · [THREAT_MODEL.md](THREAT_MODEL.md) · [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)

**Status: milestone M2.** The first real defence: a **Scope Extractor** that derives the authorised
scope from the trusted user request only (invariant P1), and an **Action Guard** that checks every
proposed tool call against that scope with deterministic, explainable rules (ALLOW / BLOCK / ASK),
plus an **Ask-Human** gate (LangGraph `interrupt`) wired to the CLI and the harness. Configs now:
`baseline`, `guard_only`, `compromised_agent`.

The headline property, shown first: even when the agent is **fully hijacked**, the guard blocks the
harmful action with a logged reason and the legitimate task still finishes — no content scanning
needed yet (that is the Content Firewall, M5). Taint/data-flow rules (confidential-content egress)
arrive in M4; M2's rules cover unauthorised recipients, tools, paths and writes.

Measured baseline from M1 (`gpt-oss-20b`, repeats=1): **ASR 53%** (10/19), **benign completion 92%**;
kept honestly rather than tuned (see [docs/m1-baseline/DECISION.md](docs/m1-baseline/DECISION.md)).
The M2 defence is verified offline (114 tests, incl. a hijacked-agent block of the canonical attack,
per-rule tables, the P1 scope-isolation and P3 bypass tests, and interrupt/resume); run
`agentguard eval --configs baseline,guard_only,compromised_agent` for the measured guard numbers.

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
.venv\Scripts\python -m streamlit run ui/app.py                           # demo UI (baseline; side-by-side is M3)
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
