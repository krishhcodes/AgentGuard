# Deploying the demo on Streamlit Community Cloud

- **Main file path:** `ui/app.py`
- **Python version:** 3.12 (Advanced settings)
- **Requirements:** `requirements.txt` at the repo root (pinned to the tested versions)
- **Secrets (optional):** see `.streamlit/secrets.toml.example`. With no Groq key the app starts in **Replay** mode and
  runs entirely from the recorded demo runs in `cache/llm/` (committed, ~3 MB). No key is needed to demo.
- **Live mode** needs `GROQ_API_KEY_1` (and more keys for headroom). Each Groq key has a daily token limit.
- **Alerts:** real email needs `SECURITY_ALERT_EMAIL`, `SMTP_USER`, `SMTP_APP_PASSWORD` (a Google *app password* for the
  sender account). Otherwise alerts stay in dry-run and show in the Audit log tab.
- The cloud filesystem is ephemeral: run logs under `runs/` reset when the app restarts. The replay cache is part of the repo.
- If GitHub push protection flags the fake key in `data/confidential/api_keys.env` (`sk_test_...`), it is demo data: choose
  "It's used in tests" on the push-protection page.
