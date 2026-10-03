"""Content-firewall pipeline (ARCHITECTURE 6.8): F0 normalise -> F1 decode -> F2 heuristics ->
F3 LLM classifier (ambiguous spans only, optional) -> F4 action (PASS / FLAG / SANITIZE / QUARANTINE).

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
from agentguard.firewall.classifier import ANOMALY as CLASSIFIER_ANOMALY
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
    classifier_ms: float = 0.0  # part of latency_ms spent in the F3 provider call
    classifier_called: bool = False


def _visible(normalized: str) -> str:
    return html_views(normalized)[0] if "<" in normalized else normalized


def _cache_key(text: str, tool_names: set[str], fw: FirewallPolicy, with_classifier: bool = False) -> str:
    payload = f"{with_classifier}\x00{text}\x00{sorted(tool_names)}\x00{fw.weights}\x00{fw.t_low}\x00{fw.t_high}\x00{fw.quarantine_fraction}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def scan(text: str, source: str, fw: FirewallPolicy, tool_names: set[str], classifier=None) -> FirewallVerdict:
    key = _cache_key(text, tool_names, fw, classifier is not None)
    if key in _cache:
        return _cache[key]
    started = time.perf_counter()
    try:
        verdict = _scan(text, fw, tool_names, classifier)
    except Exception:  # fail closed: a scan error quarantines the segment (P6 for side effects)
        verdict = FirewallVerdict(action=QUARANTINE, risk_score=0.0, rules=["FW-SCAN-ERROR"],
                                  sanitized_text=_QUARANTINE_NOTE, anomalies=["FW-SCAN-ERROR"])
    verdict.latency_ms = round((time.perf_counter() - started) * 1000, 3)
    _cache[key] = verdict
    return verdict


def _scan(text: str, fw: FirewallPolicy, tool_names: set[str], classifier=None) -> FirewallVerdict:
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
    kept, removed, ambiguous = [], [], []
    for part in parts:
        s = " ".join(part.split())
        if not s:
            continue
        score, _ = heuristics.score_sentence(s, tool_names, fw.weights)
        if score >= fw.t_high:
            removed.append(s)
        else:
            kept.append(s)
            if score >= fw.t_low:
                ambiguous.append(s)

    # F3: only the ambiguous middle band goes to the LLM classifier (one batched call).
    anomalies = list(tv.anomalies)
    classifier_ms, classifier_called, classifier_anomaly = 0.0, False, False
    if classifier is not None and ambiguous:
        res = classifier.classify(ambiguous)
        classifier_ms, classifier_called = res.latency_ms, res.called
        if res.anomaly:  # untrusted classifier output: keep the spans but FLAG them
            classifier_anomaly = True
            anomalies.append(f"{CLASSIFIER_ANOMALY}: {res.anomaly}")
            rules.append(CLASSIFIER_ANOMALY)
        else:
            for span, v in zip(ambiguous, res.verdicts):
                if classifier.is_instruction(v):
                    kept.remove(span)
                    removed.append(span)
                    hit_dicts.append({"rules": ["FW-CLASSIFIER"], "view": "classifier", "snippet": span[:160],
                                      "score": v.confidence, "category": v.category})
                    rules.append("FW-CLASSIFIER")
            rules = sorted(set(rules))
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
    elif classifier_anomaly or (classifier is None and max_score >= fw.t_low):
        action, out = FLAG, sanitized_visible or visible
    else:
        action, out = PASS, sanitized_visible or visible

    return FirewallVerdict(action=action, risk_score=max_score, rules=rules, hits=hit_dicts,
                           sanitized_text=out, removed=removed, anomalies=anomalies,
                           classifier_ms=classifier_ms, classifier_called=classifier_called)


def clear_cache() -> None:
    _cache.clear()
