"""Taint Ledger (ARCHITECTURE 6.9): session-scoped provenance + data-flow memory.

It answers two questions for the Action Guard:
  origin_of(value)        -> where did this recipient/path/table first appear? (user / directory /
                             untrusted:<source> / unknown)
  confidential_overlap(t) -> does this outbound text carry confidential data read earlier, by canary,
                             exact/normalised containment, 5-word shingle, or a cumulative (chunked)
                             match across everything already sent to the same sink?

It is a pydantic model so it serialises into the LangGraph checkpoint. Matching uses the shared text
library, so a secret hidden behind base64/hex in an outbound argument is still caught. Paraphrased
leaks are a documented limitation (see tests); the session-level confidential-read signal is the
backstop (CONFIDENTIAL_EGRESS fires on any egress once a confidential read has happened).
"""

from __future__ import annotations

import difflib
import re

from pydantic import BaseModel, ConfigDict

from agentguard.text import text_views

CANARY_RE = re.compile(r"CANARY-[A-Z]+-[0-9a-f]{6}")
_WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@/-]*")
_SHINGLE = 5
_ENTRY_TEXT_CAP = 4000
_FUZZY_RATIO = 0.90


class FlowResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    matched: bool = False
    method: str = ""  # canary | exact | shingle | fuzzy | session
    source: str = ""  # confidential path, or "session" for the read-happened signal
    snippet: str = ""


class ProvenanceResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    origin: str = "unknown"  # user | directory | untrusted:<source> | unknown
    evidence: list[dict] = []


class LedgerEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    channel: str
    confidential: bool
    texts: list[str]  # normalized + hidden + decoded views (trimmed)


class ConfidentialBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    text: str


def _views_texts(raw: str) -> list[str]:
    tv = text_views(raw)
    out, seen = [], set()
    for t in tv.all_texts():
        t = t[:_ENTRY_TEXT_CAP]
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _words(text: str) -> list[str]:
    return _WORD_RE.findall(text.lower())


def _shingles(text: str, n: int = _SHINGLE) -> set[str]:
    w = _words(text)
    return {" ".join(w[i:i + n]) for i in range(len(w) - n + 1)} if len(w) >= n else set()


class TaintLedger(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_norm: str = ""
    directory: list[str] = []
    entries: list[LedgerEntry] = []
    confidential_bodies: list[ConfidentialBody] = []
    confidential_canaries: list[str] = []
    egress_by_sink: dict[str, list[str]] = {}

    # ---- recording -------------------------------------------------------------

    def record_segment(self, *, text: str, source: str, channel: str, confidential: bool) -> None:
        texts = _views_texts(text)
        self.entries.append(LedgerEntry(source=source, channel=channel,
                                        confidential=confidential, texts=texts))
        if confidential:
            for t in texts:
                self.confidential_bodies.append(ConfidentialBody(source=source, text=t))
                self.confidential_canaries.extend(CANARY_RE.findall(t))

    def record_egress(self, sink: str, text: str) -> None:
        self.egress_by_sink.setdefault(sink, []).append(text)

    @property
    def has_confidential_read(self) -> bool:
        return bool(self.confidential_bodies)

    # ---- queries ---------------------------------------------------------------

    def origin_of(self, value: str) -> ProvenanceResult:
        v = (value or "").strip().lower()
        if not v:
            return ProvenanceResult(origin="unknown")
        if v in self.user_norm.lower():
            return ProvenanceResult(origin="user", evidence=[{"source": "user", "snippet": value}])
        if any(v == d.lower() for d in self.directory):
            return ProvenanceResult(origin="directory", evidence=[{"source": "directory", "snippet": value}])
        for e in self.entries:
            for t in e.texts:
                if v in t.lower():
                    return ProvenanceResult(origin=f"untrusted:{e.source}",
                                            evidence=[{"source": e.source, "snippet": value}])
        return ProvenanceResult(origin="unknown")

    def confidential_overlap(self, text: str, *, sink: str | None = None) -> FlowResult:
        candidates = _views_texts(text)
        hay = "\n".join(candidates).lower()
        # 1) canary tokens (strongest, exact).
        for c in self.confidential_canaries:
            if c.lower() in hay:
                return FlowResult(matched=True, method="canary",
                                  source=self._source_of_canary(c), snippet=c)
        # 2) 5-word shingle containment of a confidential body.
        cand_shingles = set()
        for t in candidates:
            cand_shingles |= _shingles(t)
        for cb in self.confidential_bodies:
            for sh in _shingles(cb.text):
                if sh in cand_shingles:
                    return FlowResult(matched=True, method="shingle", source=cb.source, snippet=sh)
        # 3) fuzzy match for short secrets (difflib stands in for rapidfuzz.partial_ratio).
        fuzzy = self._fuzzy_secret(candidates)
        if fuzzy.matched:
            return fuzzy
        # 4) cumulative (chunked) check: everything sent to this sink, concatenated.
        if sink is not None:
            prior = self.egress_by_sink.get(sink, [])
            if prior:
                # Concatenate WITHOUT separators: a canary split across several messages to one sink
                # only reassembles if the pieces are joined directly.
                combined = "".join(prior) + text
                combo_hay = "".join(_views_texts(combined)).lower()
                for c in self.confidential_canaries:
                    if c.lower() in combo_hay:
                        return FlowResult(matched=True, method="chunked",
                                          source=self._source_of_canary(c), snippet=c)
        return FlowResult(matched=False)

    def _fuzzy_secret(self, candidates: list[str]) -> FlowResult:
        secrets = [(cb.source, line.strip()) for cb in self.confidential_bodies
                   for line in cb.text.splitlines()
                   if 8 <= len(line.strip()) <= 64 and " " not in line.strip()]
        for cand in candidates:
            for token in set(_WORD_RE.findall(cand)):
                if len(token) < 8:
                    continue
                for src, secret in secrets:
                    if difflib.SequenceMatcher(None, token.lower(), secret.lower()).ratio() >= _FUZZY_RATIO:
                        return FlowResult(matched=True, method="fuzzy", source=src, snippet=secret[:40])
        return FlowResult(matched=False)

    def _source_of_canary(self, canary: str) -> str:
        for cb in self.confidential_bodies:
            if canary in cb.text:
                return cb.source
        return self.confidential_bodies[0].source if self.confidential_bodies else "confidential"
