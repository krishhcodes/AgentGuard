"""AgentGuard UI theme: tonal dark surfaces, indigo-violet accent, soft cards, pill controls (Stitch-style).

Everything here is presentation. Only FIXED labels are ever rendered as HTML; any text that can be
influenced by an attacker (reasons, arguments, sources, snippets) stays plain text in app.py.
"""

from __future__ import annotations

import html

import streamlit as st

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

:root{
  --bg:#0A0C16; --surface:#11142A; --surface2:#171B36; --line:rgba(140,150,255,.16);
  --text:#E8EAF8; --muted:#9AA1C7; --accent:#7C6CFF; --accent2:#4CC9F0;
  --ok:#3DDC97; --bad:#FF5D73; --warn:#FFB454; --violet:#B28DFF;
}
html, body, [class*="css"], .stApp{ font-family:'Inter',system-ui,-apple-system,'Segoe UI',sans-serif !important; }
.stApp{
  background:
    radial-gradient(900px 480px at 8% -8%, rgba(124,108,255,.20), transparent 60%),
    radial-gradient(760px 420px at 100% 0%, rgba(76,201,240,.12), transparent 55%),
    var(--bg);
  color:var(--text);
}
/* chrome */
#MainMenu, footer, [data-testid="stToolbar"], [data-testid="stDecoration"]{ display:none !important; }
header[data-testid="stHeader"]{ background:transparent; }
.block-container{ padding-top:1.4rem; max-width:1280px; }

/* sidebar */
section[data-testid="stSidebar"]{ background:linear-gradient(180deg,#0F1226,#0B0D1C); border-right:1px solid var(--line); }
section[data-testid="stSidebar"] h2, section[data-testid="stSidebar"] h3{ font-size:.78rem; letter-spacing:.14em; text-transform:uppercase; color:var(--muted); font-weight:600; }
.ag-brand{ display:flex; align-items:center; gap:.7rem; padding:.2rem 0 1rem; }
.ag-logo{ width:38px; height:38px; border-radius:12px; display:grid; place-items:center; font-size:1.2rem;
  background:linear-gradient(135deg,var(--accent),var(--accent2)); box-shadow:0 8px 24px rgba(124,108,255,.45); }
.ag-brand b{ font-size:1.05rem; letter-spacing:.01em; } .ag-brand span{ display:block; font-size:.72rem; color:var(--muted); }

/* hero */
.ag-hero{ padding:1.6rem 1.8rem; border-radius:24px; border:1px solid var(--line);
  background:linear-gradient(135deg, rgba(124,108,255,.18), rgba(76,201,240,.07) 55%, rgba(17,20,42,.6));
  box-shadow:0 20px 60px rgba(0,0,0,.35); margin-bottom:1.1rem; }
.ag-hero h1{ margin:0; font-size:2.35rem; font-weight:800; letter-spacing:-.02em;
  background:linear-gradient(90deg,#fff,#C9C2FF 55%,#8FE3FF); -webkit-background-clip:text; background-clip:text; color:transparent; }
.ag-hero p{ margin:.35rem 0 1rem; color:var(--muted); font-size:1.02rem; max-width:62ch; }
.ag-flow{ display:flex; flex-wrap:wrap; align-items:center; gap:.45rem; }
.ag-node{ padding:.38rem .8rem; border-radius:999px; font-size:.78rem; font-weight:600; border:1px solid var(--line); background:rgba(255,255,255,.04); }
.ag-node.untrusted{ border-color:rgba(255,93,115,.45); color:#FFB3BD; background:rgba(255,93,115,.10); }
.ag-node.defence{ border-color:rgba(124,108,255,.55); color:#CFC8FF; background:rgba(124,108,255,.16); }
.ag-node.neutral{ color:var(--text); }
.ag-arrow{ color:var(--muted); font-size:.8rem; }

/* tabs */
.stTabs [data-baseweb="tab-list"]{ gap:.4rem; background:var(--surface); padding:.3rem; border-radius:999px; border:1px solid var(--line); width:fit-content; }
.stTabs [data-baseweb="tab"]{ border-radius:999px; padding:.45rem 1.05rem; height:auto; color:var(--muted); font-weight:600; }
.stTabs [aria-selected="true"]{ background:linear-gradient(135deg,var(--accent),#5B8CFF); color:#fff !important; box-shadow:0 6px 18px rgba(124,108,255,.4); }
.stTabs [data-baseweb="tab-highlight"], .stTabs [data-baseweb="tab-border"]{ display:none; }

/* run columns as cards */
[data-testid="stHorizontalBlock"] > [data-testid="stColumn"], [data-testid="stHorizontalBlock"] > [data-testid="column"]{
  background:var(--surface); border:1px solid var(--line); border-radius:22px; padding:1.1rem 1.2rem;
  box-shadow:0 14px 40px rgba(0,0,0,.28); }
.ag-colhead{ display:flex; align-items:center; gap:.6rem; margin:.1rem 0 .5rem; }
.ag-dot{ width:12px; height:12px; border-radius:50%; } .ag-dot.bad{ background:var(--bad); box-shadow:0 0 14px var(--bad); } .ag-dot.ok{ background:var(--ok); box-shadow:0 0 14px var(--ok); }
.ag-colhead h3{ margin:0; font-size:1.25rem; font-weight:700; } .ag-colhead small{ color:var(--muted); font-family:'JetBrains Mono',monospace; }

/* chips */
.ag-chip{ display:inline-block; padding:.18rem .7rem; border-radius:999px; font-size:.74rem; font-weight:700; letter-spacing:.04em; margin-right:.35rem; border:1px solid transparent; }
.ag-chip.allow, .ag-chip.approved, .ag-chip.pass{ color:#8EF3C5; background:rgba(61,220,151,.13); border-color:rgba(61,220,151,.35); }
.ag-chip.block, .ag-chip.denied, .ag-chip.quarantine{ color:#FFB3BD; background:rgba(255,93,115,.14); border-color:rgba(255,93,115,.4); }
.ag-chip.ask, .ag-chip.flag{ color:#FFD9A0; background:rgba(255,180,84,.14); border-color:rgba(255,180,84,.4); }
.ag-chip.sanitize{ color:#D6C6FF; background:rgba(178,141,255,.16); border-color:rgba(178,141,255,.45); }
.ag-tool{ font-family:'JetBrains Mono',monospace; font-size:.82rem; color:#CFD3F3; background:rgba(255,255,255,.05); padding:.12rem .45rem; border-radius:8px; }
.ag-rules{ color:var(--muted); font-size:.78rem; font-family:'JetBrains Mono',monospace; }
.ag-sec{ margin:.9rem 0 .35rem; font-size:.72rem; letter-spacing:.14em; text-transform:uppercase; color:var(--muted); font-weight:700; }

/* alerts (verdict banners) */
[data-testid="stAlert"]{ border-radius:16px; border:1px solid var(--line); }
[data-testid="stAlert"][kind="error"], div[data-baseweb="notification"][kind="negative"]{ background:rgba(255,93,115,.12) !important; border-color:rgba(255,93,115,.45) !important; }
[data-testid="stAlert"][kind="success"], div[data-baseweb="notification"][kind="positive"]{ background:rgba(61,220,151,.10) !important; border-color:rgba(61,220,151,.4) !important; }
[data-testid="stAlert"][kind="warning"], div[data-baseweb="notification"][kind="warning"]{ background:rgba(255,180,84,.11) !important; border-color:rgba(255,180,84,.42) !important; }
[data-testid="stAlert"][kind="info"], div[data-baseweb="notification"][kind="info"]{ background:rgba(76,201,240,.09) !important; border-color:rgba(76,201,240,.35) !important; }

/* controls */
.stButton > button{ border-radius:999px; font-weight:600; border:1px solid var(--line); background:var(--surface2); color:var(--text); padding:.5rem 1.1rem; transition:all .15s ease; }
.stButton > button:hover{ border-color:var(--accent); transform:translateY(-1px); box-shadow:0 8px 22px rgba(124,108,255,.28); }
.stButton > button[kind="primary"]{ background:linear-gradient(135deg,var(--accent),#5B8CFF); border:none; color:#fff; box-shadow:0 10px 28px rgba(124,108,255,.5); }
[data-testid="stExpander"]{ border:1px solid var(--line); border-radius:16px; background:rgba(255,255,255,.02); }
[data-testid="stCode"], pre{ border-radius:14px !important; border:1px solid var(--line); }
[data-testid="stDataFrame"]{ border-radius:16px; overflow:hidden; border:1px solid var(--line); }
textarea, input, [data-baseweb="select"] > div{ border-radius:14px !important; }

/* results cards */
.ag-stats{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:.8rem; margin:.4rem 0 1rem; }
.ag-stat{ padding:1rem 1.1rem; border-radius:18px; border:1px solid var(--line); background:linear-gradient(160deg,var(--surface2),var(--surface)); }
.ag-stat .v{ font-size:1.9rem; font-weight:800; letter-spacing:-.02em; } .ag-stat .l{ font-size:.78rem; color:var(--muted); margin-top:.15rem; }
.ag-stat.good .v{ color:var(--ok); } .ag-stat.bad .v{ color:var(--bad); } .ag-stat.accent .v{ color:#C9C2FF; }
"""

FLOW = [("Untrusted content", "untrusted"), ("Content Firewall", "defence"), ("Agent", "neutral"),
        ("Action Guard", "defence"), ("Human approval", "neutral"), ("Egress Control", "defence"),
        ("Tools", "neutral"), ("Session Monitor", "defence")]

_CHIP_KIND = {"ALLOW": "allow", "APPROVED": "approved", "BLOCK": "block", "DENIED": "denied", "ASK": "ask",
              "SANITIZE": "sanitize", "QUARANTINE": "quarantine", "FLAG": "flag", "PASS": "pass"}


def inject() -> None:
    st.markdown(f"<style>{CSS}</style>", unsafe_allow_html=True)


def brand() -> str:
    return ('<div class="ag-brand"><div class="ag-logo">🛡️</div><div><b>AgentGuard</b>'
            '<span>prompt-injection shield</span></div></div>')


def hero() -> str:
    flow = '<span class="ag-arrow">→</span>'.join(f'<span class="ag-node {k}">{html.escape(n)}</span>' for n, k in FLOW)
    return ('<div class="ag-hero"><h1>AgentGuard</h1>'
            '<p>Unprotected vs protected agent, side by side. We scan what the agent reads, and we authorise '
            'what it does, with a human in the loop.</p>'
            f'<div class="ag-flow">{flow}</div></div>')


def chip(label: str, kind: str | None = None) -> str:
    """A pill for a FIXED label (decision / firewall action). Never pass attacker-influenced text."""
    k = kind or _CHIP_KIND.get(label.split(" ")[0].upper(), "pass")
    return f'<span class="ag-chip {k}">{html.escape(label)}</span>'


def column_head(title: str, sub: str, ok: bool) -> str:
    return (f'<div class="ag-colhead"><span class="ag-dot {"ok" if ok else "bad"}"></span>'
            f'<h3>{html.escape(title)}</h3><small>{html.escape(sub)}</small></div>')


def section(title: str) -> str:
    return f'<div class="ag-sec">{html.escape(title)}</div>'


def stat(value: str, label: str, tone: str = "accent") -> str:
    return f'<div class="ag-stat {tone}"><div class="v">{html.escape(value)}</div><div class="l">{html.escape(label)}</div></div>'
