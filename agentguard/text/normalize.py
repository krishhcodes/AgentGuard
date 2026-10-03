"""Unicode normalisation and hidden-channel surfacing (ARCHITECTURE 6.7, stage F0).

normalize() returns the cleaned text plus hidden views for anything an attacker tried to hide in
the character stream: zero-width-spelled words (revealed once the zero-width chars are removed),
Unicode *tag* characters (U+E0000-U+E007F) decoded back to ASCII, and a small homoglyph fold so a
Cyrillic lookalike can't disguise a keyword. It never raises.
"""

from __future__ import annotations

import unicodedata

from agentguard.text.views import View

# Zero-width and bidirectional controls used to hide or reorder text.
_ZERO_WIDTH = {
    *range(0x200B, 0x2010),  # ZWSP..RLM (includes bidi LRM/RLM and marks)
    *range(0x202A, 0x202F),  # bidi embeddings/overrides
    *range(0x2060, 0x2065),  # word joiner, invisible operators
    0xFEFF,                  # BOM / zero-width no-break space
}
_TAG_BASE, _TAG_LAST = 0xE0000, 0xE007F  # Unicode tag characters
# A deliberately small homoglyph fold (Cyrillic/Greek -> Latin lookalikes).
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "Α": "A", "Ο": "O",
})


def _strip_and_collect_tags(text: str) -> tuple[str, str]:
    kept: list[str] = []
    tag_chars: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in _ZERO_WIDTH:
            continue  # drop: a zero-width-spelled word becomes readable once these are gone
        if _TAG_BASE <= cp <= _TAG_LAST:
            tag_chars.append(chr(cp - _TAG_BASE))  # tag char -> the ASCII it mirrors
            continue
        kept.append(ch)
    return "".join(kept), "".join(tag_chars)


def normalize(text: str) -> tuple[str, list[View]]:
    """Return (normalized_text, hidden_views)."""
    hidden: list[View] = []
    stripped, tag_text = _strip_and_collect_tags(text)
    normalized = unicodedata.normalize("NFKC", stripped).translate(_HOMOGLYPHS)
    if tag_text.strip():
        hidden.append(View("tag-chars", tag_text))
    # If removing zero-width chars changed the text, the cleaned form may reveal a hidden word;
    # it is already the normalized text, so no separate view is needed. We only flag tag chars and
    # (below) leave the normalized text as the primary view.
    return normalized, hidden
