"""HTML hidden-channel extraction (ARCHITECTURE 6.7), stdlib html.parser only (no bs4).

Returns the visible text plus a hidden channel: HTML comments, text inside display:none /
visibility:hidden / hidden elements, and carrier attributes (alt, title, aria-label, meta content).
A poisoned quotation often hides its instruction in exactly these places.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

from agentguard.text.views import View

_HIDDEN_STYLE_RE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.IGNORECASE)
_CARRIER_ATTRS = {"alt", "title", "aria-label"}


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible: list[str] = []
        self.comments: list[str] = []
        self.hidden_text: list[str] = []
        self.attrs: list[str] = []
        self._hidden_depth = 0
        self._skip_depth = 0  # inside <script>/<style>

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        style, has_hidden = d.get("style", ""), ("hidden" in d)
        if tag in ("script", "style"):
            self._skip_depth += 1
        if _HIDDEN_STYLE_RE.search(style or "") or has_hidden:
            self._hidden_depth += 1
        for name, value in attrs:
            if value and (name in _CARRIER_ATTRS or (tag == "meta" and name == "content")):
                self.attrs.append(value)

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        # We can't perfectly match which end tag closed a hidden element with the stdlib parser, so
        # a hidden region ends at the next close tag. Good enough for surfacing the hidden text.
        if self._hidden_depth:
            self._hidden_depth -= 1

    def handle_startendtag(self, tag, attrs):
        for name, value in attrs:
            if value and (name in _CARRIER_ATTRS or (tag == "meta" and name == "content")):
                self.attrs.append(value)

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._hidden_depth:
            self.hidden_text.append(data)
        elif data.strip():
            self.visible.append(data)

    def handle_comment(self, data):
        if data.strip():
            self.comments.append(data)


def html_views(text: str) -> tuple[str, list[View]]:
    """Return (visible_text, hidden_views). If the text isn't HTML, visible == text and hidden==[]."""
    if "<" not in text:
        return text, []
    parser = _Extractor()
    try:
        parser.feed(text)
        parser.close()
    except Exception:  # never raise on malformed HTML
        return text, []
    hidden: list[View] = []
    hidden += [View("html-comment", c) for c in parser.comments if c.strip()]
    joined_hidden = " ".join(t for t in parser.hidden_text if t.strip())
    if joined_hidden.strip():
        hidden.append(View("html-hidden", joined_hidden))
    hidden += [View("html-attr", a) for a in parser.attrs if a.strip()]
    visible = " ".join(t.strip() for t in parser.visible if t.strip())
    return (visible or text), hidden
