"""Content-firewall pipeline (ARCHITECTURE 6.8): F0 normalise -> F1 decode -> F2 heuristics ->
F4 action (PASS / FLAG / SANITIZE / QUARANTINE). The LLM classifier (F3) arrives in M6.

Only the *visible* text is ever passed on; hidden and decoded channels are dropped by construction,
so an instruction in an HTML comment or a base64 blob never reaches the agent. SANITIZE additionally
removes the malicious *visible* sentences while preserving the quote fields around them. Fails closed:
any exception while scanning QUARANTINEs that segment.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field

from agentguard.firewall import heuristics
from agentguard.policy import FirewallPolicy
from agentguard.text import html_views, text_views

_BLANKLINE = re.compile(r"\n\s*\n")
_REMOVED_MARK = "[REMOVED BY FIREWALL: suspected instruction]"
_QUARANTINE_NOTE = "[QUARANTINED BY FIREWALL: this document was withheld as likely prompt injection; see the audit log]"

PASS, FLAG, SANITIZE, QUARANTINE = "PASS", "FLAG", "SANITIZE", "QUARANTINE"

_cache: dict[str, "FirewallVerdict"] = {}


@dataclass
class FirewallVerdict:
    action: str
    risk_score: float
    rules: list[str]
    hits: list[dict] = field(default_factory=list)
    sanitized_text: str = ""
    removed: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    latency_ms: float = 0.0


def _visible(normalized: str) -> str:
    return html_views(normalized)[0] if "<" in normalized else normalized


def _cache_key(text: str, tool_names: set[str], fw: FirewallPolicy) -> str:
    payload = f"{text}\x00{sorted(tool_names)}\x00{fw.weights}\x00{fw.t_low}\x00{fw.t_high}\x00{fw.quarantine_fraction}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def scan(text: str, source: str, fw: FirewallPolicy, tool_names: set[str]) -> FirewallVerdict:
    key = _cache_key(text, tool_names, fw)
    if key in _cache:
        return _cache[key]
    started = time.perf_counter()
    try:
        verdict = _scan(text, fw, tool_names)
    except Exception:  # fail closed: a scan error quarantines the segment (P6 for side effects)
        verdict = FirewallVerdict(action=QUARANTINE, risk_score=0.0, rules=["FW-SCAN-ERROR"],
                                  sanitized_text=_QUARANTINE_NOTE, anomalies=["FW-SCAN-ERROR"])
    verdict.latency_ms = round((time.perf_counter() - started) * 1000, 3)
    _cache[key] = verdict
    return verdict


def _scan(text: str, fw: FirewallPolicy, tool_names: set[str]) -> FirewallVerdict:
    tv = text_views(text)
    hits = heuristics.scan_views(tv, tool_names, fw)
    rules = sorted({r for h in hits for r in h.rules})
    max_score = max((h.score for h in hits), default=0.0)
    hit_dicts = [{"rules": h.rules, "view": h.view, "snippet": h.snippet, "score": h.score} for h in hits]

    # Remove malicious *visible* paragraphs (hidden/decoded channels are dropped regardless). HTML is
    # already one line per block element; plain text is split on blank lines. Scoring whole paragraphs
    # keeps a filename's "." from fragmenting an injection into sub-threshold pieces.
    visible = _visible(tv.normalized)
    parts = visible.split("\n") if "<" in text else _BLANKLINE.split(visible)
    kept, removed = [], []
    for part in parts:
        s = " ".join(part.split())
        if not s:
            continue
        score, _ = heuristics.score_sentence(s, tool_names, fw.weights)
        (removed if score >= fw.t_high else kept).append(s)
    sanitized_visible = "\n".join(kept).strip()
    removed_chars = sum(len(r) for r in removed)
    removed_fraction = removed_chars / max(len(visible.strip()), 1)

    hidden_malicious = any(h.score >= fw.t_high for h in hits if h.view != "normalized")
    decode_bomb = "DECODE_LIMIT" in tv.anomalies

    if decode_bomb or removed_fraction > fw.quarantine_fraction or (not sanitized_visible and (removed or hidden_malicious)):
        action, out = QUARANTINE, _QUARANTINE_NOTE
    elif removed or hidden_malicious:
        action = SANITIZE
        out = (sanitized_visible + (" " + _REMOVED_MARK if removed else "")).strip()
    elif max_score >= fw.t_low:
        action, out = FLAG, sanitized_visible or visible
    else:
        action, out = PASS, sanitized_visible or visible

    return FirewallVerdict(action=action, risk_score=max_score, rules=rules, hits=hit_dicts,
                           sanitized_text=out, removed=removed, anomalies=tv.anomalies)


def clear_cache() -> None:
    _cache.clear()
