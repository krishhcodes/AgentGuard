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

import html  # noqa: E402
import uuid  # noqa: E402

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage  # noqa: E402

from agentguard.config import load_settings  # noqa: E402
from agentguard.eval.suites import load_scenarios  # noqa: E402
from agentguard.runner import RunSession, run_scenario  # noqa: E402

st.set_page_config(page_title="AgentGuard", page_icon="🛡️", layout="wide")
from ui import theme  # noqa: E402

theme.inject()

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


def _outbox_note(events) -> str:
    """Name the layer that actually stopped the attack (the guard only if it really blocked something)."""
    guard_blocked = any(e.event == "guard_decision" and e.decision == "BLOCK" for e in events)
    fw_removed = any(e.event == "content_scanned" and e.data.get("action") in ("SANITIZE", "QUARANTINE")
                     for e in events)
    if guard_blocked:
        return " The guard blocked the exfiltration."
    if fw_removed:
        return " The firewall removed the injected instruction before the agent saw it."
    return ""


def render_outbox(sandbox, *, note: str = "") -> None:
    out = sandbox.state.outbox
    st.markdown("**Outbox** (mock; nothing is really sent)")
    if out:
        st.dataframe(pd.DataFrame([vars(e) for e in out]), width='stretch')
    else:
        st.caption("No emails sent." + note)


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
    st.markdown(theme.section("Action Guard decisions", "gavel"), unsafe_allow_html=True)
    for d in decisions:
        _, label = DECISION_STYLE.get(d["decision"], ("•", d["decision"]))
        rules = f' <span class="ag-rules">{html.escape(", ".join(d["rules"]))}</span>' if d["rules"] else ""
        st.markdown(f'{theme.chip(label, d["decision"].lower())}<span class="ag-tool">{html.escape(str(d["tool"]))}</span>'
                    f'{rules}', unsafe_allow_html=True)  # fixed labels; tool/rule ids are escaped
        if d["reason"]:
            st.text(d["reason"])  # reason embeds attacker-influenced args -> plain text only
        for ev in d.get("evidence", []):  # M4: attribute the decision to the source document/view
            src, snip = ev.get("source"), ev.get("snippet")
            if src:
                line = f"triggered by: {src}" + (f" ({ev['method']})" if ev.get("method") else "")
                st.text(line + (f" — {snip}" if snip else ""))  # source + snippet are untrusted


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


def protected_config(guard_on: bool, firewall_on: bool) -> str | None:
    if guard_on and firewall_on:
        return "full"
    if guard_on:
        return "guard_only"
    if firewall_on:
        return "firewall_only"  # spotlight is implied by the firewall config
    return None


def _session_id() -> str:
    """One monitoring session per browser tab: the Session Monitor accumulates across runs until reset."""
    return st.session_state.setdefault("session_id", uuid.uuid4().hex[:8])


def _new_session() -> None:
    st.session_state.pop("session_id", None)


def start_run(spec, request: str, mode: str, guard_on: bool, firewall_on: bool) -> None:
    _clear_run_state()
    # Baseline is a plain run (no interrupts). Its errors are captured in the RunResult, so a
    # protected-run failure can never blank this column.
    st.session_state["baseline_result"] = run_scenario(
        spec, config="baseline", user_request=request, settings=load_settings(mode))
    config = protected_config(guard_on, firewall_on)
    st.session_state["protected_config"] = config
    if config:
        session = RunSession(spec, config=config, user_request=request, settings=load_settings(mode),
                             session_id=_session_id())
        status = session.start()
        st.session_state["guard_session"] = session
        st.session_state["guard_result"] = session.result() if status == RunSession.DONE else None


def render_baseline_column(result) -> None:
    st.markdown(theme.column_head("Unprotected", "baseline agent", ok=False), unsafe_allow_html=True)
    st.caption(f"baseline · {result.run_id} · {result.status} · {result.duration_s:.1f}s")
    render_verdict(result)
    render_outbox(result.sandbox)
    with st.expander("Step trace", expanded=False):
        render_trace(result.messages, result.status)


def render_firewall_summary(events) -> None:
    scans = [e for e in events if e.event == "content_scanned" and e.data.get("action") != "PASS"]
    if not scans:
        return
    st.markdown(theme.section("Content Firewall", "cleaning_services"), unsafe_allow_html=True)
    for e in scans:
        action = e.data.get("action")
        rule_txt = html.escape(", ".join(e.rules) or "-")
        st.markdown(f'{theme.chip(str(action), str(action).lower())}<span class="ag-rules">{rule_txt}</span>',
                    unsafe_allow_html=True)
        st.text(f"source: {e.data.get('source', '')}")  # source is untrusted-derived -> plain text


def render_guard_column() -> None:
    config = st.session_state.get("protected_config")
    st.markdown(theme.column_head("Protected", config or "no layers on", ok=True), unsafe_allow_html=True)
    session = st.session_state.get("guard_session")
    result = st.session_state.get("guard_result")
    if session is None:
        st.info("Enable the Action Guard and/or the Content Firewall in the sidebar.")
        return
    if result is None and session.pending is not None:  # paused on an ASK
        st.caption("paused · awaiting human approval")
        render_firewall_summary(session.events)
        render_decisions(session.events)
        render_approval_card(session)
        return
    st.caption(f"{config} · {result.run_id} · {result.status} · {result.duration_s:.1f}s")
    render_verdict(result)
    render_firewall_summary(result.events)
    render_decisions(result.events)
    render_outbox(result.sandbox, note=_outbox_note(result.events))
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


def render_inside_document_tab(spec) -> None:
    """Raw poisoned document -> revealed hidden/decoded views -> sanitised + spotlighted text."""
    from agentguard.firewall import scan, spotlight
    from agentguard.policy import load_policy
    from agentguard.text import text_views

    if not spec.overlay:
        st.info("This scenario has no injected document. Pick an attack scenario (e.g. plain-01, enc-01).")
        return
    policy = load_policy()
    for path, raw in spec.overlay.items():
        st.markdown(f"### {path}")
        st.markdown("**1. Raw document (as delivered to a naive agent)**")
        st.text(raw)
        tv = text_views(raw)
        if tv.hidden or tv.decoded:
            st.markdown("**2. Hidden / decoded channels the firewall reveals**")
            for v in tv.hidden + tv.decoded:
                st.text(f"[{v.kind}] {v.snippet(300)}")
        else:
            st.caption("No hidden or encoded channels in this document.")
        verdict = scan(raw, path, policy.firewall, set(policy.tools))
        st.markdown(f"**3. Firewall verdict: {verdict.action}**  ·  rules: {', '.join(verdict.rules) or '—'}")
        spotlighted = spotlight(verdict.sanitized_text, nonce="7f3a", source=path)
        st.markdown("**4. Sanitised + spotlighted text the agent actually sees**")
        st.text(spotlighted)
        st.divider()


def _headline_stats() -> list[str]:
    """Final numbers from the committed docs (not the latest scratch run)."""
    def row(path, config, split):
        df = pd.read_csv(ROOT / path)
        return df[(df["config"] == config) & (df["split"] == split)].iloc[0]

    def pct(x):
        return f"{float(x) * 100:.0f}%"

    cards = []
    try:
        base = row("docs/m6-classifier/summary-before-fix.csv", "baseline", "dev")
        full = row("docs/m6-classifier/summary.csv", "full", "dev")
        ben = row("docs/m6-classifier/summary.csv", "full", "benign")
        cards += [theme.stat(pct(base["asr_rate"]), "baseline attack success (dev)", "bad", "warning"),
                  theme.stat(pct(full["asr_rate"]), "AgentGuard attack success (dev)", "good", "verified_user"),
                  theme.stat(pct(full["catch_rate"]), "dev attacks caught", "accent", "radar"),
                  theme.stat(pct(full["completion_rate"]), "task completed on attacked tasks", "accent", "task_alt"),
                  theme.stat(pct(ben["completion_rate"]), "benign task completion", "good", "check_circle"),
                  theme.stat(pct(ben["fpr_rate"]), "false-positive rate", "good", "thumb_up")]
    except Exception:  # missing docs must never break the page
        pass
    try:
        un = row("docs/m7-unseen/summary-v2.csv", "full", "unseen")
        cards.append(theme.stat(pct(un["asr_rate"]), "attack success on held-out set (n=4)", "good", "science"))
    except Exception:
        pass
    try:
        lat = pd.read_csv(ROOT / "docs/m6-classifier/latency.csv")
        tot = lat[lat["layer"] == "TOTAL"].iloc[0]
        cards.append(theme.stat(f"{float(tot['p95_ms']):.0f} ms", "added latency p95 (target < 2 s)", "sun", "bolt"))
    except Exception:
        pass
    return cards


def render_results_tab() -> None:
    cards = _headline_stats()
    if cards:
        st.markdown(theme.section("Final results (gpt-oss-20b, dev + held-out)", "insights"), unsafe_allow_html=True)
        st.markdown(f'<div class="ag-stats">{"".join(cards)}</div>', unsafe_allow_html=True)
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


DEMO_PATH = [  # (button label, scenario, firewall on, guard on) -- see docs/DEMO.md
    ("1 · Hidden instruction", "enc-01-base64-comment", True, True),
    ("2 · Side by side", "plain-01", True, True),
    ("3 · Firewall off: guard holds", "plain-01", False, True),
    ("4 · Ask a human", "ambig-01-the-team", False, True),
]


def _apply_demo_beat(scenario_id: str, fw: bool, guard: bool) -> None:
    st.session_state.update(sid=scenario_id, fw_on=fw, guard_on=guard)
    _clear_run_state()


# ---- page -----------------------------------------------------------------------

scenarios = _scenarios()
settings = load_settings()

with st.sidebar:
    st.markdown(theme.brand(), unsafe_allow_html=True)
    st.header("Scenario")
    ids = sorted(scenarios, key=lambda i: (i != "plain-01", not scenarios[i].is_attack, i))
    sid = st.selectbox("Attack or task", ids, key="sid", format_func=lambda i: f"{i}: {scenarios[i].title}")
    spec = scenarios[sid]
    st.caption(f"split: {spec.split} · category: {spec.category}")
    if spec.description:
        st.caption(spec.description)
    request = st.text_area("User request (trusted)", value=spec.user_request.strip(), height=150, key=f"req-{sid}")
    st.caption("Protected column layers")
    st.session_state.setdefault("fw_on", True)
    st.session_state.setdefault("guard_on", True)
    firewall_on = st.toggle(":material/cleaning_services: Content Firewall (scan what it reads)", key="fw_on")
    guard_on = st.toggle(":material/verified_user: Action Guard (authorise what it does)", key="guard_on")
    mode = st.radio("LLM mode", list(MODES), index=list(MODES).index(settings.llm_mode), format_func=MODES.get)
    if st.button("Run", type="primary", width='stretch', icon=":material/play_arrow:"):
        with st.spinner("Running baseline and protected agents..."):
            start_run(spec, request, mode, guard_on, firewall_on)

    # One-click demo path (the 5-minute script): each beat sets the scenario and the layer toggles.
    st.divider()
    st.caption(f"Session monitor: session {_session_id()} (accumulates across runs)")
    st.button("New session", key="new-session", on_click=_new_session, width="stretch", icon=":material/refresh:")
    st.caption("Demo path")
    beat_icons = [":material/visibility_off:", ":material/compare_arrows:", ":material/shield:", ":material/how_to_reg:"]
    for n, (label, scenario_id, fw, guard) in enumerate(DEMO_PATH):
        if scenario_id in scenarios:
            st.button(label, key=f"demo-{label}", width="stretch", on_click=_apply_demo_beat,
                      args=(scenario_id, fw, guard), icon=beat_icons[n % len(beat_icons)])

st.markdown(theme.hero(), unsafe_allow_html=True)
if mode == "replay":
    st.caption("REPLAY mode — responses come from recorded runs (offline).")

live_tab, doc_tab, audit_tab, results_tab = st.tabs(
    [":material/bolt: Live attack", ":material/search: Inside the document", ":material/receipt_long: Audit log",
     ":material/insights: Evaluation results"])

with live_tab:
    if "baseline_result" not in st.session_state:
        st.info("Pick a scenario in the sidebar and press Run.")
    else:
        left, right = st.columns(2)
        with left:
            render_baseline_column(st.session_state["baseline_result"])
        with right:
            render_guard_column()

with doc_tab:
    render_inside_document_tab(spec)

with audit_tab:
    render_audit_tab()

with results_tab:
    render_results_tab()
