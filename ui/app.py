"""AgentGuard demo UI.

M3: the unprotected baseline and the guard-protected agent run side by side on the same scenario,
with live Approve/Deny for ASK decisions and an audit-log tab.

All untrusted content (documents, tool output, agent answers, decision reasons/evidence) is rendered
with st.text / st.code / st.json, never as markdown or HTML, so nothing attacker-controlled can
become a link or inject formatting. Only AgentGuard's own fixed labels use markdown.
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
from agentguard.runner import RunSession, run_scenario  # noqa: E402

st.set_page_config(page_title="AgentGuard", layout="wide")

MODES = {"auto": "Auto (reuse recorded runs; call Groq only for new)",
         "record": "Live (Groq), recorded for replay", "replay": "Replay (offline, recorded runs)",
         "off": "Live (Groq), not recorded"}

DECISION_STYLE = {  # fixed labels only (safe for markdown); reasons/args are rendered as plain text
    "ALLOW": ("🟢", "ALLOW"), "APPROVED": ("🟢", "APPROVED (human)"),
    "BLOCK": ("🔴", "BLOCK"), "DENIED": ("🔴", "DENIED (human)"),
    "ASK": ("🟠", "ASK — awaiting human"),
}


@st.cache_data
def _scenarios():
    return load_scenarios()


# ---- trace / effects rendering (shared by both columns) -------------------------

def render_trace(messages, status) -> None:
    step = 0
    for m in messages:
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
                st.markdown("**Agent error**" if status == "error" else "**Final answer**")
                st.text(m.content)
        elif isinstance(m, ToolMessage):
            label = "retrieved chunks" if m.name == "retrieve_context" else f"result of {m.name}"
            with st.expander(f"Untrusted content: {label} ({len(str(m.content))} chars)"):
                st.text(m.content)


def render_outbox(sandbox, *, leaked_hint: bool) -> None:
    out = sandbox.state.outbox
    st.markdown("**Outbox** (mock; nothing is really sent)")
    if out:
        st.dataframe(pd.DataFrame([vars(e) for e in out]), width='stretch')
    else:
        st.caption("No emails sent." + (" The guard blocked the exfiltration." if leaked_hint else ""))


def _decisions_from_events(events) -> list[dict]:
    """Latest verdict per call, with the human override folded in, in first-seen order."""
    order: list[str] = []
    by: dict[str, dict] = {}
    for e in events:
        cid = e.data.get("call_id")
        if e.event == "guard_decision" and cid:
            if cid not in by:
                order.append(cid)
            by[cid] = {"tool": e.tool, "args": e.args or {}, "decision": e.decision,
                       "rules": list(e.rules), "reason": e.reason or "", "evidence": e.evidence}
        elif e.event == "human_decision" and cid in by:
            by[cid]["decision"] = e.decision
    return [by[c] for c in order]


def render_decisions(events) -> None:
    decisions = _decisions_from_events(events)
    if not decisions:
        return
    st.markdown("**Action Guard decisions**")
    for d in decisions:
        emoji, label = DECISION_STYLE.get(d["decision"], ("•", d["decision"]))
        rules = f" · rules: {', '.join(d['rules'])}" if d["rules"] else ""
        st.markdown(f"{emoji} **{label}** `{d['tool']}`{rules}")  # labels/rules are fixed, safe
        if d["reason"]:
            st.text(d["reason"])  # reason embeds attacker-influenced args -> plain text only


def render_verdict(result) -> None:
    if result.error:
        st.warning("Run error (recorded; never counted as blocked).")
        st.text(result.error[-1200:])
        return
    if result.attack is not None:
        if result.attack.hijacked:
            st.error("HIJACKED — the agent carried out the attacker's instruction.")
            st.text("\n".join(f"- {e}" for e in result.attack.evidence))  # evidence is untrusted
        else:
            st.success("No harmful effect — the attack did not succeed.")
    if result.task is not None and result.status != "error":
        if result.task.completed:
            st.success("Legitimate task completed correctly.")
        else:
            st.info("Legitimate task not completed: " + "; ".join(result.task.failed_checks))


# ---- approval card (human-in-the-loop) ------------------------------------------

def render_approval_card(session: RunSession) -> None:
    payload = session.pending or {"asks": []}
    st.warning("The guard needs a human decision before continuing.")
    with st.form("approval"):
        choices: dict[str, str] = {}
        for ask in payload["asks"]:
            st.markdown(f"**`{ask['tool']}`** — rules: {', '.join(ask['rules']) or '—'}")
            st.text(ask["reason"])  # untrusted-influenced
            st.json(ask["args"], expanded=False)  # data view, no markdown/link rendering
            choices[ask["call_id"]] = st.radio(
                "Decision", ["deny", "approve"], horizontal=True, key=f"ask-{ask['call_id']}",
                format_func=lambda s: s.capitalize())
        submitted = st.form_submit_button("Submit decision(s)", type="primary")
    if submitted:
        status = session.resume(choices)
        if status == RunSession.DONE:
            st.session_state["guard_result"] = session.result()
        st.rerun()


# ---- run orchestration ----------------------------------------------------------

def _clear_run_state() -> None:
    for k in ("baseline_result", "guard_session", "guard_result"):
        st.session_state.pop(k, None)


def start_run(spec, request: str, mode: str, guard_on: bool) -> None:
    _clear_run_state()
    # Baseline is a plain run (no interrupts). Its errors are captured in the RunResult, so a
    # protected-run failure can never blank this column.
    st.session_state["baseline_result"] = run_scenario(
        spec, config="baseline", user_request=request, settings=load_settings(mode))
    if guard_on:
        session = RunSession(spec, config="guard_only", user_request=request, settings=load_settings(mode))
        status = session.start()
        st.session_state["guard_session"] = session
        st.session_state["guard_result"] = session.result() if status == RunSession.DONE else None


def render_baseline_column(result) -> None:
    st.subheader("🔴 Unprotected")
    st.caption(f"baseline · {result.run_id} · {result.status} · {result.duration_s:.1f}s")
    render_verdict(result)
    render_outbox(result.sandbox, leaked_hint=False)
    with st.expander("Step trace", expanded=False):
        render_trace(result.messages, result.status)


def render_guard_column() -> None:
    st.subheader("🟢 Protected (Action Guard)")
    session = st.session_state.get("guard_session")
    result = st.session_state.get("guard_result")
    if session is None:
        st.info("Enable the Action Guard in the sidebar to see the protected run.")
        return
    if result is None and session.pending is not None:  # paused on an ASK
        st.caption("paused · awaiting human approval")
        render_decisions(session.events)
        render_approval_card(session)
        return
    st.caption(f"guard_only · {result.run_id} · {result.status} · {result.duration_s:.1f}s")
    render_verdict(result)
    render_decisions(result.events)
    render_outbox(result.sandbox, leaked_hint=True)
    with st.expander("Step trace", expanded=False):
        render_trace(result.messages, result.status)


def render_audit_tab() -> None:
    results = [r for r in (st.session_state.get("guard_result"), st.session_state.get("baseline_result")) if r]
    if not results:
        st.info("Run a scenario to see its audit log.")
        return
    for result in results:
        st.markdown(f"**{result.config}** · run `{result.run_id}` · {result.audit_path}")
        for event in result.events:
            st.json(event.model_dump(mode="json"), expanded=False)


def render_results_tab() -> None:
    results_root = ROOT / "results"
    runs = sorted(results_root.glob("*/summary.csv")) if results_root.exists() else []
    if not runs:
        st.info("No evaluation results yet. Run `python -m agentguard eval` to measure the suite.")
        return
    latest = runs[-1]
    st.caption(f"Latest evaluation: {latest.parent.name}")
    st.dataframe(pd.read_csv(latest), width='stretch')
    md = latest.parent / "RESULTS.md"
    if md.exists():
        with st.expander("Full report (RESULTS.md)"):
            st.markdown(md.read_text(encoding="utf-8"))


# ---- page -----------------------------------------------------------------------

scenarios = _scenarios()
settings = load_settings()

with st.sidebar:
    st.header("Scenario")
    ids = sorted(scenarios, key=lambda i: (i != "plain-01", not scenarios[i].is_attack, i))
    sid = st.selectbox("Attack or task", ids, format_func=lambda i: f"{i}: {scenarios[i].title}")
    spec = scenarios[sid]
    st.caption(f"split: {spec.split} · category: {spec.category}")
    if spec.description:
        st.caption(spec.description)
    request = st.text_area("User request (trusted)", value=spec.user_request.strip(), height=150, key=f"req-{sid}")
    guard_on = st.toggle("Action Guard (protected column)", value=True)
    mode = st.radio("LLM mode", list(MODES), index=list(MODES).index(settings.llm_mode), format_func=MODES.get)
    if st.button("Run", type="primary", width='stretch'):
        with st.spinner("Running baseline and protected agents..."):
            start_run(spec, request, mode, guard_on)

st.title("AgentGuard")
st.caption("Milestone M3: unprotected vs guard-protected agent, side by side, with live human approval.")
if mode == "replay":
    st.caption("REPLAY mode — responses come from recorded runs (offline).")

live_tab, audit_tab, results_tab = st.tabs(["Live attack", "Audit log", "Evaluation results"])

with live_tab:
    if "baseline_result" not in st.session_state:
        st.info("Pick a scenario in the sidebar and press Run.")
    else:
        left, right = st.columns(2)
        with left:
            render_baseline_column(st.session_state["baseline_result"])
        with right:
            render_guard_column()

with audit_tab:
    render_audit_tab()

with results_tab:
    render_results_tab()
