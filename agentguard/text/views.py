"""Shared view types for the text library (ARCHITECTURE 6.7).

A View is one way of reading a piece of untrusted text: the visible/normalized form, a hidden
channel (zero-width-spelled text, HTML comments, display:none spans, tag characters), or a decoded
form (base64, hex, ...). Every view carries its kind and an offset into the original, so a guard or
firewall decision can point at exactly what triggered it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class View:
    kind: str  # normalized | zero-width | tag-chars | html-comment | html-hidden | html-attr |
    #            base64 | hex | url | entity | unicode-escape | rot13
    text: str
    offset: int = 0

    def snippet(self, limit: int = 160) -> str:
        t = " ".join(self.text.split())
        return t if len(t) <= limit else t[:limit] + "..."


@dataclass
class TextViews:
    raw: str
    normalized: str
    hidden: list[View] = field(default_factory=list)
    decoded: list[View] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)

    def all_views(self) -> list[View]:
        """Every readable view, starting with the normalized text."""
        return [View("normalized", self.normalized, 0), *self.hidden, *self.decoded]

    def all_texts(self) -> list[str]:
        return [v.text for v in self.all_views()]
