"""AgentGuard demo UI. M0: a single pane showing the unprotected baseline agent.

All untrusted content (documents, tool output, the agent's answer) is rendered with
st.text / st.code / dataframes, never as markdown or HTML.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage  # noqa: E402

from agentguard.config import load_settings  # noqa: E402
from agentguard.eval.suites import load_scenarios  # noqa: E402
from agentguard.runner import run_scenario  # noqa: E402

st.set_page_config(page_title="AgentGuard", layout="wide")

MODES = {"auto": "Auto (reuse recorded runs; call Groq only for new)",
         "record": "Live (Groq), recorded for replay", "replay": "Replay (offline, recorded runs)",
         "off": "Live (Groq), not recorded"}


@st.cache_data
def _scenarios():
    return load_scenarios()


def render_trace(result) -> None:
    step = 0
    for m in result.messages:
        if isinstance(m, HumanMessage):
            st.markdown("**User request** (trusted)")
            st.text(m.content)
        elif isinstance(m, AIMessage):
            if m.tool_calls:
                for tc in m.tool_calls:
                    if tc["name"] == "retrieve_context":
                        st.markdown("**Retrieval** (RAG over vendor quotations)")
                        continue
                    step += 1
                    st.markdown(f"**Step {step}: agent calls `{tc['name']}`**")
                    st.code(json.dumps(tc["args"], indent=2, ensure_ascii=False), language="json")
            elif m.content:
                st.markdown("**Agent error**" if result.status == "error" else "**Final answer**")
                st.text(m.content)
        elif isinstance(m, ToolMessage):
            label = "retrieved chunks" if m.name == "retrieve_context" else f"result of {m.name}"
            with st.expander(f"Untrusted content: {label} ({len(str(m.content))} chars)"):
                st.text(m.content)


def render_effects(result) -> None:
    state = result.sandbox.state
    st.markdown("**Outbox** (mock email; nothing is really sent)")
    if state.outbox:
        st.dataframe(pd.DataFrame([vars(e) for e in state.outbox]), use_container_width=True)
    else:
        st.caption("No emails sent.")
    st.markdown("**File reads**")
    if state.read_log:
        st.dataframe(pd.DataFrame([vars(r) for r in state.read_log]), use_container_width=True)
    else:
        st.caption("No files read.")
    st.markdown("**Database writes**")
    if state.db_mutations:
        st.dataframe(pd.DataFrame([{**vars(m), "fields": json.dumps(m.fields)} for m in state.db_mutations]),
                     use_container_width=True)
    else:
        st.caption("No records written.")
    st.markdown("**Web searches**")
    if state.web_queries:
        st.dataframe(pd.DataFrame({"query": state.web_queries}), use_container_width=True)
    else:
        st.caption("No web searches.")


def render_verdict(result) -> None:
    if result.error:
        hint = " Switch to Replay mode, or check the API key." if "CacheMiss" in result.error or "GROQ" in result.error else ""
        st.warning(f"Run error ({result.status}).{hint}")
        st.text(result.error[-1500:])
    if result.attack is not None:
        if result.attack.hijacked:
            # Evidence contains attacker-controlled text (addresses, subjects): render as plain
            # text, never markdown, so nothing becomes a link or formatting.
            st.error("HIJACKED: the agent carried out the attacker's instruction.")
            st.text("\n".join(f"- {e}" for e in result.attack.evidence))
        elif result.status != "error":
            st.success("No harmful effect: the attack did not succeed on this run.")
    if result.task is not None and result.status != "error":
        if result.task.completed:
            st.success("Legitimate task completed correctly.")
        else:
            st.info("Legitimate task not completed correctly: " + "; ".join(result.task.failed_checks))


scenarios = _scenarios()
settings = load_settings()

with st.sidebar:
    st.header("Scenario")
    # Canonical attack first, then other attacks, then benign tasks.
    ids = sorted(scenarios, key=lambda i: (i != "plain-01", not scenarios[i].is_attack, i))
    sid = st.selectbox("Attack or task", ids, format_func=lambda i: f"{i}: {scenarios[i].title}")
    spec = scenarios[sid]
    st.caption(f"split: {spec.split} · category: {spec.category}")
    if spec.description:
        st.caption(spec.description)
    request = st.text_area("User request (trusted)", value=spec.user_request.strip(), height=150, key=f"req-{sid}")
    mode = st.radio("LLM mode", list(MODES), index=list(MODES).index(settings.llm_mode),
                    format_func=MODES.get)
    run = st.button("Run", type="primary", use_container_width=True)

def render_results_tab() -> None:
    import pandas as pd

    results_root = ROOT / "results"
    runs = sorted(results_root.glob("*/summary.csv")) if results_root.exists() else []
    if not runs:
        st.info("No evaluation results yet. Run `python -m agentguard eval` to measure the suite.")
        return
    latest = runs[-1]
    st.caption(f"Latest evaluation: {latest.parent.name}")
    st.dataframe(pd.read_csv(latest), use_container_width=True)
    md = latest.parent / "RESULTS.md"
    if md.exists():
        with st.expander("Full report (RESULTS.md)"):
            st.markdown(md.read_text(encoding="utf-8"))


st.title("AgentGuard")
st.caption("Milestone M1: the unprotected baseline agent, measured across the attack and benign suites.")

run_tab, results_tab = st.tabs(["Run a scenario", "Evaluation results"])

with run_tab:
    if run:
        with st.spinner("Running the agent..."):
            st.session_state["result"] = run_scenario(spec, user_request=request, settings=load_settings(mode))
    result = st.session_state.get("result")
    if result is None:
        st.info("Pick a scenario in the sidebar and press Run.")
    else:
        st.subheader(f"Unprotected agent · {result.scenario_id}")
        st.caption(f"run {result.run_id} · status {result.status} · {result.duration_s:.1f}s")
        render_verdict(result)
        trace_t, effects_t, audit_t = st.tabs(["Trace", "Sandbox effects", "Audit log"])
        with trace_t:
            render_trace(result)
        with effects_t:
            render_effects(result)
        with audit_t:
            st.caption(f"{result.audit_path}")
            for event in result.events:
                st.json(event.model_dump(mode="json"), expanded=False)

with results_tab:
    render_results_tab()
