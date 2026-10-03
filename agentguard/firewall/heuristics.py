"""Content-firewall heuristics (ARCHITECTURE 6.8, stage F2).

Sentence-level scoring by rule *families* (never by dev strings), across the normalized text and
every hidden/decoded view. The weights and thresholds live in policy.yaml so they can be tuned on
dev without code changes. Negatives are legitimate business imperatives ("please email your PO to
sales@vendor.example"), which must not score — see test_firewall.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from agentguard.policy import FirewallPolicy
from agentguard.text.views import TextViews, View

_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+|<[^>]+>")  # split on sentence ends, newlines, html tags

_OVERRIDE = re.compile(r"\b(ignore|disregard|forget|override|bypass)\b[^.]{0,40}\b"
                       r"(instruction|instructions|prompt|prompts|rule|rules|above|previous|prior|earlier)\b",
                       re.IGNORECASE)
_ROLE_MARKER = re.compile(r"\[/?\s*(system|assistant|user)\s*\]|<\|im_(start|end)\|>"
                          r"|^\s*#{2,}\s*system\b|^\s*(assistant|system|user)\s*:",
                          re.IGNORECASE | re.MULTILINE)
_ADDRESS_TERM = re.compile(r"\b(a\.?i\.?|assistant|agent|language model|llm|chat\s?bot|the model|any ai)\b",
                           re.IGNORECASE)
_IMPERATIVE = re.compile(r"\b(you|please|must|should|first|before|now|do this|use|call|invoke|read|send|"
                         r"forward|email|write|update|perform|proceed|confirm|verify)\b", re.IGNORECASE)
_SENSITIVE = re.compile(r"\b(bank|account|iban|routing|swift|password|credential|credentials|api[\s_-]?key|"
                        r"secret|secrets|token|confidential|salary|salaries|board minutes|private key)\b",
                        re.IGNORECASE)
_EXFIL_VERB = re.compile(r"\b(send|forward|upload|e-?mail|transmit|exfiltrate|post|leak|share|disclose|"
                         r"report|submit)\b", re.IGNORECASE)
_AUTHORITY = re.compile(r"\b(admin|administrator|it department|it team|compliance|security team|supervisor|"
                        r"management|head office)\b[^.]{0,40}\b(require|requires|required|must|mandatory|"
                        r"override|policy|programme|program|authori[sz]ed)\b", re.IGNORECASE)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_HIDDEN_KINDS = {"html-comment", "html-hidden", "html-attr"}
_ZW_KINDS = {"tag-chars"}
_DECODED_KINDS = {"base64", "hex", "url", "entity", "unicode-escape", "rot13"}


@dataclass
class Hit:
    rules: list[str]
    view: str
    snippet: str
    score: float


def _tool_directive(sentence: str, tool_names: set[str]) -> bool:
    low = sentence.lower()
    for name in tool_names:
        if name in low and (re.search(rf"\b{name}\s*\(", low) or _IMPERATIVE.search(sentence)):
            return True
    return False


def score_sentence(sentence: str, tool_names: set[str], weights: dict) -> tuple[float, list[str]]:
    """Base families that apply to any view. Returns (score, matched_rule_ids)."""
    rules: list[str] = []
    if _OVERRIDE.search(sentence):
        rules.append("FW-OVERRIDE")
    if _ROLE_MARKER.search(sentence):
        rules.append("FW-ROLE-MARKER")
    if _ADDRESS_TERM.search(sentence) and _IMPERATIVE.search(sentence):
        rules.append("FW-AGENT-ADDRESS")
    if _tool_directive(sentence, tool_names):
        rules.append("FW-TOOL-DIRECTIVE")
    if _EXFIL_VERB.search(sentence) and _SENSITIVE.search(sentence):
        # Exfil verb near a *sensitive noun*. Requiring the sensitive noun (not just an address)
        # keeps legitimate "please email your PO to sales@vendor.example" from scoring at all.
        rules.append("FW-EXFIL-INTENT")
    if _AUTHORITY.search(sentence):
        rules.append("FW-AUTHORITY")
    return sum(weights.get(r, 0) for r in rules), rules


def _view_modifier(view_kind: str) -> str | None:
    if view_kind in _ZW_KINDS:
        return "FW-ZW"
    if view_kind in _HIDDEN_KINDS:
        return "FW-HIDDEN-HTML"
    if view_kind in _DECODED_KINDS:
        return "FW-DECODED"
    return None


def scan_view(view: View, tool_names: set[str], fw: FirewallPolicy) -> list[Hit]:
    weights = fw.weights
    modifier = _view_modifier(view.kind)  # FW-ZW | FW-HIDDEN-HTML | FW-DECODED | None
    hits: list[Hit] = []
    for sentence in _SENT_SPLIT.split(view.text):
        s = sentence.strip()
        if not s:
            continue
        score, rules = score_sentence(s, tool_names, weights)
        if modifier == "FW-ZW":
            # Zero-width / tag-char hidden text is a risk on its own, instruction or not.
            rules = ["FW-ZW", *rules]
            score += weights.get("FW-ZW", 0)
        elif modifier in ("FW-HIDDEN-HTML", "FW-DECODED") and rules:
            # Other hidden/decoded channels flag only when the content already looks like an
            # instruction, so benign comments and alt-text do not trigger.
            rules = [*rules, modifier]
            score += weights.get(modifier, 0)
        if rules:
            hits.append(Hit(rules=rules, view=view.kind, snippet=s[:160], score=score))
    return hits


def scan_views(tv: TextViews, tool_names: set[str], fw: FirewallPolicy) -> list[Hit]:
    hits: list[Hit] = []
    for view in tv.all_views():
        hits.extend(scan_view(view, tool_names, fw))
    if "DECODE_LIMIT" in tv.anomalies:
        hits.append(Hit(rules=["FW-DECODED"], view="decoded", snippet="decode budget exceeded",
                        score=fw.weights.get("FW-DECODED", 0)))
    return hits
