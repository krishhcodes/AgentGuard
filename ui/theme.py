"""AgentGuard UI theme: warm paper, ink outlines, sticker shadows, friendly serif headings, real icons.

Everything here is presentation. Only FIXED labels are ever rendered as HTML; any text that can be
influenced by an attacker (reasons, arguments, sources, snippets) stays plain text in app.py.
"""

from __future__ import annotations

import html

import streamlit as st

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500..700&family=DM+Sans:wght@400;500;600;700&display=swap');

:root{
  --paper:#FBF6EC; --card:#FFFFFF; --ink:#2A2521; --muted:#7B7167; --line:#E8DFCF; --dot:#E6DAC4;
  --coral:#F26B4F; --coral-soft:#FFE5DD; --sage:#3F9A6F; --sage-soft:#E2F3E9;
  --sun:#F2B33D; --sun-soft:#FFF0CC; --sky:#4C8FC4; --sky-soft:#E0EEF9; --brick:#D2433A; --brick-soft:#FCE3DF;
}
html, body, [class*="css"], .stApp, .stMarkdown, p, li, label, button, input, textarea{
  font-family:'DM Sans',system-ui,-apple-system,'Segoe UI',sans-serif !important; }
.stApp{
  color:var(--ink);
  background-color:var(--paper);
  background-image:radial-gradient(var(--dot) 1.2px, transparent 1.2px);
  background-size:26px 26px;
}
h1,h2,h3,.ag-serif{ font-family:'Fraunces',Georgia,'Times New Roman',serif !important; color:var(--ink); letter-spacing:-.01em; }
.ms{ font-family:'Material Symbols Rounded'; font-weight:normal; font-style:normal; font-size:1.3em; line-height:1;
  letter-spacing:normal; text-transform:none; display:inline-block; white-space:nowrap; direction:ltr;
  font-feature-settings:'liga'; -webkit-font-smoothing:antialiased; vertical-align:-0.22em; }

/* chrome */
#MainMenu, footer, [data-testid="stToolbar"], [data-testid="stDecoration"]{ display:none !important; }
header[data-testid="stHeader"]{ background:transparent; }
.block-container{ padding-top:2.2rem; padding-bottom:4rem; max-width:1240px; }
[data-testid="stVerticalBlock"]{ gap:1.15rem; }

/* sidebar */
section[data-testid="stSidebar"]{ background:#F5EEDF; border-right:2px solid var(--ink); }
section[data-testid="stSidebar"] [data-testid="stSidebarContent"]{ padding:1.6rem 1.3rem 2rem; }
section[data-testid="stSidebar"] h2{ font-family:'DM Sans',sans-serif !important; font-size:.76rem; letter-spacing:.16em; text-transform:uppercase; color:var(--muted); font-weight:700; margin-top:.4rem; }
section[data-testid="stSidebar"] [data-testid="stVerticalBlock"]{ gap:.9rem; }
.ag-brand{ display:flex; align-items:center; gap:.8rem; padding:.2rem 0 1.2rem; border-bottom:2px dashed #D9CDB6; margin-bottom:.4rem; }
.ag-logo{ width:46px; height:46px; border-radius:15px; display:grid; place-items:center; background:var(--coral); color:#fff;
  border:2px solid var(--ink); box-shadow:3px 3px 0 var(--ink); transform:rotate(-4deg); }
.ag-logo .ms{ font-size:1.7rem; }
.ag-brand b{ font-family:'Fraunces',serif; font-size:1.35rem; display:block; line-height:1.1; }
.ag-brand span.t{ font-size:.82rem; color:var(--muted); }

/* hero */
.ag-hero{ position:relative; padding:2rem 2.2rem 1.9rem; border-radius:26px; background:var(--card);
  border:2px solid var(--ink); box-shadow:7px 7px 0 var(--ink); margin:.3rem 0 1.7rem; }
.ag-tag{ display:inline-block; font-size:.8rem; font-weight:700; letter-spacing:.06em; padding:.3rem .8rem; border-radius:10px;
  background:var(--sun); border:2px solid var(--ink); transform:rotate(-2deg); margin-bottom:.9rem; }
.ag-hero h1{ margin:0 0 .5rem; font-size:3rem; font-weight:700; line-height:1.05; }
.ag-hero h1 em{ font-style:italic; color:var(--coral); }
.ag-hero p.lead{ font-size:1.12rem; line-height:1.6; max-width:60ch; color:#4A433C; margin:0 0 1.5rem; }
.ag-journey{ display:flex; align-items:flex-start; gap:0; flex-wrap:wrap; row-gap:1rem; }
.ag-step{ display:flex; flex-direction:column; align-items:center; gap:.45rem; width:96px; text-align:center; }
.ag-bubble{ width:54px; height:54px; border-radius:50%; display:grid; place-items:center; border:2px solid var(--ink); }
.ag-bubble .ms{ font-size:1.6rem; }
.ag-bubble.bad{ background:var(--brick-soft); color:var(--brick); } .ag-bubble.def{ background:var(--sage-soft); color:var(--sage); }
.ag-bubble.neu{ background:var(--sky-soft); color:var(--sky); } .ag-bubble.warn{ background:var(--sun-soft); color:#B07A10; }
.ag-step small{ font-size:.8rem; font-weight:600; line-height:1.25; color:#4A433C; }
.ag-link{ flex:1; min-width:18px; max-width:46px; height:0; border-top:2px dashed #BFB29A; margin-top:27px; }

/* tabs */
.stTabs [data-baseweb="tab-list"]{ gap:.3rem; border-bottom:2px solid var(--line); }
.stTabs [data-baseweb="tab"]{ height:auto; padding:.7rem 1.1rem; color:var(--muted); font-weight:600; border-radius:12px 12px 0 0; }
.stTabs [data-baseweb="tab"]:hover{ color:var(--ink); background:rgba(242,107,79,.08); }
.stTabs [aria-selected="true"]{ color:var(--ink) !important; background:var(--coral-soft); }
.stTabs [data-baseweb="tab-highlight"]{ background:var(--coral); height:3px; }
.stTabs [data-baseweb="tab-border"]{ display:none; }

/* run columns */
[data-testid="stHorizontalBlock"] > [data-testid="stColumn"], [data-testid="stHorizontalBlock"] > [data-testid="column"]{
  background:var(--card); border:2px solid var(--ink); border-radius:22px; padding:1.5rem 1.6rem 1.7rem; box-shadow:5px 5px 0 var(--ink); }
[data-testid="stHorizontalBlock"]{ gap:1.6rem; }
.ag-colhead{ display:flex; align-items:center; gap:.8rem; margin:.1rem 0 .5rem; }
.ag-badge{ width:44px; height:44px; border-radius:14px; display:grid; place-items:center; border:2px solid var(--ink); }
.ag-badge.bad{ background:var(--brick-soft); color:var(--brick); } .ag-badge.ok{ background:var(--sage-soft); color:var(--sage); }
.ag-colhead h3{ margin:0; font-size:1.5rem; line-height:1.1; }
.ag-colhead small{ display:block; color:var(--muted); font-size:.82rem; font-family:'DM Sans',sans-serif; margin-top:.15rem; }
.ag-sec{ margin:1.1rem 0 .5rem; font-size:.74rem; letter-spacing:.16em; text-transform:uppercase; color:var(--muted); font-weight:700; }
.ag-sec .ms{ font-size:1.15em; margin-right:.3rem; }

/* chips */
.ag-chip{ display:inline-flex; align-items:center; gap:.3rem; padding:.22rem .75rem .22rem .5rem; border-radius:999px; font-size:.78rem; font-weight:700;
  letter-spacing:.03em; margin:0 .45rem .2rem 0; border:1.5px solid var(--ink); color:var(--ink); }
.ag-chip .ms{ font-size:1.15em; }
.ag-chip.allow,.ag-chip.approved,.ag-chip.pass{ background:var(--sage-soft); }
.ag-chip.block,.ag-chip.denied,.ag-chip.quarantine{ background:var(--brick-soft); }
.ag-chip.ask,.ag-chip.flag{ background:var(--sun-soft); }
.ag-chip.sanitize{ background:var(--sky-soft); }
.ag-tool{ font-family:'JetBrains Mono',ui-monospace,monospace; font-size:.82rem; background:#F3ECDD; padding:.12rem .5rem; border-radius:8px; border:1px solid var(--line); }
.ag-rules{ color:var(--muted); font-size:.8rem; font-family:'JetBrains Mono',ui-monospace,monospace; margin-left:.4rem; }

/* alerts */
[data-testid="stAlert"]{ border-radius:16px; border:2px solid var(--ink); color:var(--ink); }
[data-testid="stAlert"] *{ color:var(--ink) !important; }
[data-testid="stAlert"][kind="error"], div[data-baseweb="notification"][kind="negative"]{ background:var(--brick-soft) !important; }
[data-testid="stAlert"][kind="success"], div[data-baseweb="notification"][kind="positive"]{ background:var(--sage-soft) !important; }
[data-testid="stAlert"][kind="warning"], div[data-baseweb="notification"][kind="warning"]{ background:var(--sun-soft) !important; }
[data-testid="stAlert"][kind="info"], div[data-baseweb="notification"][kind="info"]{ background:var(--sky-soft) !important; }

/* controls */
.stButton > button, .stFormSubmitButton > button{ border-radius:14px; font-weight:700; color:var(--ink); background:#fff; border:2px solid var(--ink);
  padding:.55rem 1.1rem; box-shadow:3px 3px 0 var(--ink); transition:transform .12s ease, box-shadow .12s ease; }
.stButton > button:hover, .stFormSubmitButton > button:hover{ transform:translate(-1px,-1px); box-shadow:4px 4px 0 var(--ink); border-color:var(--ink); color:var(--ink); }
.stButton > button:active{ transform:translate(2px,2px); box-shadow:1px 1px 0 var(--ink); }
.stButton > button[kind^="primary"], .stFormSubmitButton > button[kind^="primary"]{ background:var(--coral); color:#fff; }
.stButton > button[kind^="primary"] *, .stFormSubmitButton > button[kind^="primary"] *{ color:#fff !important; }
section[data-testid="stSidebar"] .stButton > button{ box-shadow:2px 2px 0 var(--ink); font-weight:600; justify-content:flex-start; }
[data-testid="stExpander"]{ border:2px solid var(--line); border-radius:16px; background:#FFFDF8; }
[data-testid="stCode"], pre{ border-radius:14px !important; border:1.5px solid var(--line); background:#FFFDF8 !important; }
[data-testid="stDataFrame"]{ border-radius:16px; overflow:hidden; border:2px solid var(--line); }
textarea, input, [data-baseweb="select"] > div{ border-radius:14px !important; background:#fff !important; border:1.5px solid #D9CDB6 !important; }
[data-testid="stCaptionContainer"], .stCaption{ color:var(--muted); }

/* results cards */
.ag-stats{ display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:1.3rem; margin:.6rem 0 1.3rem; }
.ag-stat{ position:relative; padding:1.3rem 1.4rem 1.2rem; border-radius:20px; border:2px solid var(--ink); box-shadow:5px 5px 0 var(--ink); }
.ag-stat .ico{ width:38px; height:38px; border-radius:12px; display:grid; place-items:center; background:#fff; border:2px solid var(--ink); margin-bottom:.8rem; }
.ag-stat .v{ font-family:'Fraunces',serif; font-size:2.7rem; font-weight:700; line-height:1; letter-spacing:-.02em; }
.ag-stat .l{ font-size:.92rem; color:#4A433C; margin-top:.5rem; line-height:1.4; }
.ag-stat.good{ background:var(--sage-soft); } .ag-stat.bad{ background:var(--brick-soft); } .ag-stat.accent{ background:var(--sky-soft); } .ag-stat.sun{ background:var(--sun-soft); }
"""

# (label, material icon, tone)
FLOW = [("Poisoned document", "description", "bad"), ("Content firewall", "cleaning_services", "def"),
        ("AI agent", "smart_toy", "neu"), ("Action guard", "verified_user", "def"),
        ("You approve", "how_to_reg", "warn"), ("Egress check", "outbox", "def"), ("Tools", "build", "neu")]

_CHIP = {"ALLOW": ("allow", "check_circle"), "APPROVED": ("approved", "how_to_reg"), "BLOCK": ("block", "block"),
         "DENIED": ("denied", "cancel"), "ASK": ("ask", "help"), "SANITIZE": ("sanitize", "cleaning_services"),
         "QUARANTINE": ("quarantine", "lock"), "FLAG": ("flag", "flag"), "PASS": ("pass", "check")}


def ms(name: str) -> str:
    return f'<span class="ms">{html.escape(name)}</span>'


def inject() -> None:
    st.markdown(f"<style>{CSS}</style>", unsafe_allow_html=True)


def brand() -> str:
    return (f'<div class="ag-brand"><div class="ag-logo">{ms("shield")}</div>'
            '<div><b>AgentGuard</b><span class="t">a bouncer for AI agents</span></div></div>')


def hero() -> str:
    steps = []
    for i, (label, icon, tone) in enumerate(FLOW):
        if i:
            steps.append('<div class="ag-link"></div>')
        steps.append(f'<div class="ag-step"><div class="ag-bubble {tone}">{ms(icon)}</div><small>{html.escape(label)}</small></div>')
    return ('<div class="ag-hero"><span class="ag-tag">prompt-injection shield</span>'
            '<h1>Your AI agent read a <em>poisoned</em> document.<br>Watch what happens next.</h1>'
            '<p class="lead">Run the same attack against an unprotected agent and a protected one, side by side. '
            'We check what the agent reads, approve what it does, and ask you before anything risky leaves.</p>'
            f'<div class="ag-journey">{"".join(steps)}</div></div>')


def chip(label: str, kind: str | None = None) -> str:
    """A pill for a FIXED label (decision / firewall action). Never pass attacker-influenced text."""
    key = (kind or label.split(" ")[0]).upper()
    cls, icon = _CHIP.get(key, ("pass", "check"))
    return f'<span class="ag-chip {cls}">{ms(icon)}{html.escape(label)}</span>'


def column_head(title: str, sub: str, ok: bool) -> str:
    icon = "verified_user" if ok else "warning"
    return (f'<div class="ag-colhead"><div class="ag-badge {"ok" if ok else "bad"}">{ms(icon)}</div>'
            f'<div><h3>{html.escape(title)}</h3><small>{html.escape(sub)}</small></div></div>')


def section(title: str, icon: str | None = None) -> str:
    return f'<div class="ag-sec">{ms(icon) if icon else ""}{html.escape(title)}</div>'


def stat(value: str, label: str, tone: str = "accent", icon: str = "insights") -> str:
    return (f'<div class="ag-stat {tone}"><div class="ico">{ms(icon)}</div>'
            f'<div class="v">{html.escape(value)}</div><div class="l">{html.escape(label)}</div></div>')
