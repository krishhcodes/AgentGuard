# AgentGuard

A prompt-injection shield for tool-using RAG agents (hackathon PS3).
Design: [ARCHITECTURE.md](ARCHITECTURE.md) · [THREAT_MODEL.md](THREAT_MODEL.md) · [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)

**Status: milestone M1 (in progress).** The vulnerable system from M0, plus the attack/benign suites
and the evaluation harness. **No defences exist yet** — the threat is measured before anything is built
to stop it. Suite so far: 15 attacks (11 dev + 4 unseen, across all 5 categories) and 10 benign tasks
(clean, tool-using, looks-scary-but-legit, ambiguous). The full 28-attack / 20-benign set and the live
baseline gate run (D2: baseline hijacked >= 70%) are the remaining M1 steps.

## Setup (Windows, PowerShell or Git Bash)

```
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

Put your Groq key in `.env` (it is git-ignored): `GROQ_API_KEY=...`

## Commands

```
.venv\Scripts\python -m agentguard doctor                       # gate D1: key, model, tool calling
.venv\Scripts\python -m agentguard list                         # scenarios
.venv\Scripts\python -m agentguard run --scenario plain-01      # canonical attack, CLI trace
.venv\Scripts\python -m agentguard eval --configs baseline --splits dev,benign --repeats 3 --delay 2
.venv\Scripts\python -m agentguard freeze-manifest --verify     # unseen-set integrity check
.venv\Scripts\python -m streamlit run ui/app.py                 # demo UI (Run + Evaluation results tabs)
.venv\Scripts\python -m pytest                                  # offline tests (no network, no API key)
```

LLM modes (`--llm-mode` or the UI radio): `record` (default; live call, response saved to `cache/llm/`),
`replay` (offline, recorded responses only), `off` (live, nothing saved).

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
