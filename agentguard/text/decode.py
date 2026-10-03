"""Decoding views (ARCHITECTURE 6.7, stage F1).

Reveals instructions or secrets hidden behind an encoding: base64, hex, URL-percent, HTML entities,
\\uXXXX escapes and ROT13. Recursive (depth <= 3) with a total output budget, so a decode bomb is
bounded and reported as the DECODE_LIMIT anomaly instead of hanging. Never raises. False-positive
guarded: a base64/hex candidate is only accepted if it decodes to mostly-printable text, so SKUs and
binary blobs don't produce noise.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
from urllib.parse import unquote

from agentguard.text.views import View

MAX_DEPTH = 3
OUTPUT_BUDGET = 64 * 1024

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]?){8,}")
_UNICODE_ESC_RE = re.compile(r"\\u[0-9a-fA-F]{4}")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return ok / len(s)


def _try_base64(token: str) -> str | None:
    if len(token) % 4 or len(token) < 16:
        return None
    try:
        raw = base64.b64decode(token, validate=True)
        text = raw.decode("utf-8", errors="strict")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return text if _printable_ratio(text) >= 0.80 and text.strip() else None


def _try_hex(token: str) -> str | None:
    cleaned = re.sub(r"[\s:]", "", token)
    if len(cleaned) % 2 or len(cleaned) < 16:
        return None
    try:
        text = bytes.fromhex(cleaned).decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if _printable_ratio(text) >= 0.80 and text.strip() else None


def _whole_text_decoders(text: str) -> list[tuple[str, str]]:
    """Decoders applied to the whole string. Each returns (kind, decoded) when it changes the text."""
    out: list[tuple[str, str]] = []
    if "%" in text:
        u = unquote(text)
        if u != text:
            out.append(("url", u))
    if "&" in text and ";" in text:
        h = html.unescape(text)
        if h != text:
            out.append(("entity", h))
    if _UNICODE_ESC_RE.search(text):
        try:
            u = codecs.decode(text, "unicode_escape")
            if u != text:
                out.append(("unicode-escape", u))
        except Exception:
            pass
    rot = codecs.encode(text, "rot_13")
    if rot != text and re.search(r"[A-Za-z]", text):
        out.append(("rot13", rot))  # low confidence; useful to the firewall in M5
    return out


def _decode_once(text: str) -> list[View]:
    views: list[View] = []
    for m in _B64_RE.finditer(text):
        decoded = _try_base64(m.group())
        if decoded:
            views.append(View("base64", decoded, m.start()))
    for m in _HEX_RE.finditer(text):
        decoded = _try_hex(m.group())
        if decoded:
            views.append(View("hex", decoded, m.start()))
    for kind, decoded in _whole_text_decoders(text):
        views.append(View(kind, decoded, 0))
    return views


def decode_views(text: str) -> tuple[list[View], list[str]]:
    """Return (decoded_views, anomalies). Recursive up to MAX_DEPTH within OUTPUT_BUDGET."""
    results: list[View] = []
    anomalies: list[str] = []
    seen: set[str] = set()
    budget = OUTPUT_BUDGET
    frontier = [(text, 0)]
    while frontier:
        current, depth = frontier.pop(0)
        if depth >= MAX_DEPTH:
            continue
        for view in _decode_once(current):
            key = (view.kind, view.text)
            if view.text in seen or view.text == text:
                continue
            seen.add(view.text)
            budget -= len(view.text)
            if budget < 0:
                anomalies.append("DECODE_LIMIT")
                return results, anomalies
            results.append(view)
            # rot13 is noisy and self-inverse; don't recurse on it.
            if view.kind != "rot13":
                frontier.append((view.text, depth + 1))
    return results, anomalies
