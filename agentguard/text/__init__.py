"""Text normalisation and decoding library (ARCHITECTURE 6.7).

A shared library (not a layer) used by the Taint Ledger (M4, to see the same views the agent can
decode) and the Content Firewall (M5). Pure stdlib: no bs4, no network.
"""

from __future__ import annotations

from agentguard.text.decode import decode_views
from agentguard.text.html_views import html_views
from agentguard.text.normalize import normalize
from agentguard.text.views import TextViews, View

__all__ = ["text_views", "normalize", "html_views", "decode_views", "TextViews", "View"]


def text_views(raw: str) -> TextViews:
    """Full pipeline: normalize -> HTML hidden channel -> recursive decode, over all surfaced text."""
    normalized, hidden = normalize(raw)
    visible, html_hidden = html_views(normalized)
    hidden = html_hidden + hidden
    # Decode the normalized text and every hidden channel, so a base64 blob inside an HTML comment is
    # still revealed.
    decoded: list[View] = []
    anomalies: list[str] = []
    for source in [normalized, *(v.text for v in hidden)]:
        views, anom = decode_views(source)
        decoded += views
        anomalies += anom
    # De-duplicate decoded views by text, preserving order.
    seen: set[str] = set()
    unique: list[View] = []
    for v in decoded:
        if v.text not in seen:
            seen.add(v.text)
            unique.append(v)
    return TextViews(raw=raw, normalized=normalized, hidden=hidden, decoded=unique,
                     anomalies=sorted(set(anomalies)))
