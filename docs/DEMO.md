# Demo runbook (5 minutes)

Start: `.venv\Scripts\python -m streamlit run ui/app.py` then open http://localhost:8501.
**Safe default: set the sidebar "LLM mode" to *Replay* (offline, recorded runs).** Replay cannot fail on stage;
the screen is labelled REPLAY. `Auto` reuses recordings and only calls Groq for something new.

The sidebar has a **Demo path** with one button per beat (sets the scenario and the layer toggles), then press **Run**.

| Time | Beat (button) | Say / show |
|---|---|---|
| 0:00-0:30 | **1 · Hidden instruction** | "Your procurement agent just emailed your bank details to an attacker, and nobody asked it to." Open the **Inside the document** tab: the quote looks clean; the hidden base64 line is revealed, then removed. |
| 0:30-2:00 | **2 · Side by side** (`plain-01`) | Left (unprotected): HIJACKED banner, canary in the outbox. Right: firewall sanitised the injected paragraph, prices kept, the comparison is delivered, task completed. |
| 2:00-3:00 | **3 · Firewall off: guard holds** | Agent is hijacked and proposes the email; the Action Guard BLOCKs it with the rule ids and the source document as evidence. "Even if detection fails, the action cannot happen." |
| 3:00-3:40 | **4 · Ask a human** (`ambig-01-the-team`) | Approval card with evidence -> **Approve** -> email goes to the resolved alias. Then the **Audit log** tab: every allow, block and approval with its evidence. |
| 3:40-4:30 | **Evaluation results** tab | Baseline ASR 62%; `full` dev ASR 0% (catch 94%); benign completion 100%; FPR 0%; unseen numbers with CIs; **say the honest bits**: p95 latency gate not met under live API tail latency (median ~20 ms), unseen set is only 4 attacks. |
| 4:30-5:00 | Close | "We authorise actions, not just classify text. Deterministic, explainable, runs locally, and we publish the misses." |

## If something goes wrong
- API/Wi-Fi down: LLM mode -> **Replay**. Nothing else changes.
- A replay says "no recorded response": press the beat button again, or switch to `Auto` once while online to record it.
- Streamlit dead: `python -m agentguard run --scenario plain-01 --config full --llm-mode replay` prints the same story in the terminal.

## Likely judge questions (answers are in `docs/`)
- *What does it miss?* `docs/LIMITATIONS.md` and the `misses.csv` of the frozen run.
- *Is the firewall overfit to your attacks?* Rule families, not strings; the unseen set was written before any defence existed and is hash-locked (`suites/attacks/unseen/MANIFEST.sha256`, `results/UNSEEN_RUNS.log`).
- *Why 62% baseline, not higher?* Reported as measured, not tuned (`docs/m1-baseline/DECISION.md`).
