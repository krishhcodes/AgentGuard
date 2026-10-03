"""BM25 retrieval over the vendor-quotation corpus.

Documents are indexed as raw text (HTML included): the baseline agent sees exactly what
an attacker wrote, hidden comments and all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from rank_bm25 import BM25Okapi

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_TAG_RE = re.compile(r"<[^>]+>")
CHUNK_CHARS = 800


@dataclass(frozen=True)
class Chunk:
    source: str  # e.g. quotes/nimbus_laptops_quote.html#0
    path: str
    text: str


def _stem(token: str) -> str:
    # Plural folding only ("laptops" -> "laptop"); enough for a small English corpus.
    if len(token) > 3 and token.endswith("s") and not token.endswith("ss"):
        return token[:-1]
    return token


def tokenize(text: str) -> list[str]:
    return [_stem(t) for t in _TOKEN_RE.findall(text.lower())]


def chunk_document(path: str, text: str, max_chars: int = CHUNK_CHARS) -> list[Chunk]:
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text.replace("\r\n", "\n")) if p.strip()]
    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        if current and len(current) + len(para) + 2 > max_chars:
            chunks.append(current)
            current = para
        else:
            current = f"{current}\n\n{para}" if current else para
    if current:
        chunks.append(current)
    return [Chunk(f"{path}#{i}", path, c) for i, c in enumerate(chunks)]


class Retriever:
    def __init__(self, documents: dict[str, str]):
        self.chunks = [c for path in sorted(documents) for c in chunk_document(path, documents[path])]
        # Rank on text with markup removed (tags inflate length); the chunk delivered to the
        # agent stays raw, hidden HTML included.
        corpus = [tokenize(f"{c.path} {_TAG_RE.sub(' ', c.text)}") for c in self.chunks]
        self._bm25 = BM25Okapi(corpus) if corpus else None

    def search(self, query: str, k: int) -> list[Chunk]:
        if self._bm25 is None:
            return []
        scores = self._bm25.get_scores(tokenize(query))
        ranked = sorted(range(len(self.chunks)), key=lambda i: (-scores[i], i))
        return [self.chunks[i] for i in ranked[:k] if scores[i] > 0]
