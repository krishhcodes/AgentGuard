"""The mock environment: virtual file store, outbox, records DB and canned web.

Every run gets a fresh Sandbox. Fixture files are read once from data/ (read-only) and
held in memory; nothing here writes to disk or opens a socket. Scenario overlays
(poisoned documents or web pages) apply to this instance only.
"""

from __future__ import annotations

import posixpath
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from agentguard.config import DATA_DIR
from agentguard.policy import Policy

FILE_ROOTS = ("quotes", "confidential")
WEB_PREFIX = "web/"
CANARY_RE = re.compile(r"CANARY-[A-Z]+-[0-9a-f]{6}")
_FRONT_MATTER_RE = re.compile(r"\A---\n(.*?)\n---\n(.*)\Z", re.DOTALL)
_WORD_RE = re.compile(r"[a-z0-9]+")


@dataclass
class WebPage:
    url: str
    title: str
    keywords: list[str]
    text: str
    source: str  # virtual path, e.g. web/acme_reviews.md


@dataclass
class Email:
    to: str
    subject: str
    body: str


@dataclass
class DbMutation:
    table: str
    record_id: str
    fields: dict[str, str]
    action: str  # insert | update


@dataclass
class FileRead:
    requested: str
    resolved: str | None
    ok: bool
    confidential: bool
    escape_attempt: bool = False


@dataclass
class SandboxState:
    outbox: list[Email] = field(default_factory=list)
    db_mutations: list[DbMutation] = field(default_factory=list)
    read_log: list[FileRead] = field(default_factory=list)
    web_queries: list[str] = field(default_factory=list)
    executed_calls: dict[str, str] = field(default_factory=dict)  # dedup key -> prior result


def resolve_vpath(path: str) -> tuple[str | None, bool]:
    """Normalise a requested path inside the virtual root. Returns (resolved, escape_attempt).

    Shared by the sandbox (for reads) and the Action Guard (PATH_ESCAPES_SANDBOX), so both judge
    traversal identically.
    """
    p = path.strip().replace("\\", "/")
    if not p or p.startswith("/") or re.match(r"^[A-Za-z]:", p) or "://" in p:
        return None, True
    norm = posixpath.normpath(p)
    if norm == ".." or norm.startswith("../"):
        return None, True
    return norm, False


def parse_web_page(source: str, raw: str) -> WebPage:
    match = _FRONT_MATTER_RE.match(raw.replace("\r\n", "\n"))
    if not match:
        raise ValueError(f"web page {source} is missing YAML front matter")
    meta = yaml.safe_load(match.group(1))
    return WebPage(
        url=meta["url"],
        title=meta["title"],
        keywords=[str(k).lower() for k in meta.get("keywords", [])],
        text=match.group(2).strip(),
        source=source,
    )


def _load_fixture_files(data_dir: Path) -> tuple[dict[str, str], dict[str, str]]:
    files: dict[str, str] = {}
    for root in FILE_ROOTS:
        for path in sorted((data_dir / root).rglob("*")):
            if path.is_file():
                files[path.relative_to(data_dir).as_posix()] = path.read_text(encoding="utf-8")
    web: dict[str, str] = {}
    for path in sorted((data_dir / "web").glob("*.md")):
        web[f"{WEB_PREFIX}{path.name}"] = path.read_text(encoding="utf-8")
    return files, web


class Sandbox:
    def __init__(self, policy: Policy, overlay: dict[str, str] | None = None, data_dir: Path = DATA_DIR):
        self.policy = policy
        files, web_raw = _load_fixture_files(data_dir)
        for vpath, content in (overlay or {}).items():
            vpath = vpath.replace("\\", "/")
            if vpath.startswith(WEB_PREFIX):
                web_raw[vpath] = content
            elif vpath.split("/", 1)[0] in FILE_ROOTS:
                files[vpath] = content
            else:
                raise ValueError(f"overlay path {vpath!r} must start with quotes/, confidential/ or web/")
        self.files = files
        self.web_pages = [parse_web_page(src, raw) for src, raw in sorted(web_raw.items())]
        self.db = sqlite3.connect(":memory:")
        self.db.executescript((data_dir / "db_seed.sql").read_text(encoding="utf-8"))
        self.state = SandboxState()

    # ---- helpers -----------------------------------------------------------------

    def resolve_path(self, path: str) -> tuple[str | None, bool]:
        """Normalise a requested path inside the virtual root. Returns (resolved, escape_attempt)."""
        return resolve_vpath(path)

    def is_confidential(self, vpath: str) -> bool:
        return self.policy.is_confidential(vpath)

    def corpus_documents(self) -> dict[str, str]:
        """The RAG corpus: vendor quotations only (never confidential files)."""
        return {p: t for p, t in self.files.items() if p.startswith("quotes/")}

    def canaries(self, vpath: str | None = None) -> set[str]:
        paths = [vpath] if vpath else [p for p in self.files if self.is_confidential(p)]
        return {c for p in paths for c in CANARY_RE.findall(self.files.get(p, ""))}

    # ---- tools (no authorisation here: the baseline is deliberately permissive) ---

    def read_file(self, path: str) -> str:
        resolved, escape = self.resolve_path(path)
        if resolved is None or resolved not in self.files:
            self.state.read_log.append(FileRead(path, resolved, False, False, escape))
            if escape:
                return f"Error: path {path!r} is outside the document store."
            return f"Error: file {path!r} not found."
        confidential = self.is_confidential(resolved)
        self.state.read_log.append(FileRead(path, resolved, True, confidential))
        return self.files[resolved]

    def search_web(self, query: str) -> str:
        self.state.web_queries.append(query)
        terms = set(_WORD_RE.findall(query.lower()))
        scored = []
        for i, page in enumerate(self.web_pages):
            haystack = set(page.keywords) | set(_WORD_RE.findall(f"{page.title} {page.text}".lower()))
            score = len(terms & set(page.keywords)) * 2 + len(terms & haystack)
            if score:
                scored.append((-score, i, page))
        if not scored:
            return "No results found."
        results = [p for _, _, p in sorted(scored)[:3]]
        return "\n\n".join(f"[{n}] {p.title}\nURL: {p.url}\n{p.text}" for n, p in enumerate(results, 1))

    def send_email(self, to: str, subject: str, body: str) -> str:
        self.state.outbox.append(Email(to=to, subject=subject, body=body))
        return f"Email queued (id=msg-{len(self.state.outbox):03d}) to {to}."

    def write_record(self, table: str, record_id: str, fields: dict[str, str]) -> str:
        tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if table not in tables:
            return f"Error: unknown table {table!r}. Known tables: {', '.join(sorted(tables))}."
        columns = [r[1] for r in self.db.execute(f"PRAGMA table_info({table})")]
        unknown = [k for k in fields if k not in columns or k == "id"]
        if unknown:
            return f"Error: unknown or read-only fields {unknown} for table {table!r}. Columns: {columns}."
        values = {k: str(v) for k, v in fields.items()}
        exists = self.db.execute(f"SELECT 1 FROM {table} WHERE id = ?", (record_id,)).fetchone()
        if exists:
            if values:
                assignments = ", ".join(f"{k} = ?" for k in values)
                self.db.execute(f"UPDATE {table} SET {assignments} WHERE id = ?", (*values.values(), record_id))
            action = "update"
        else:
            cols = ["id", *values]
            self.db.execute(
                f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
                (record_id, *values.values()),
            )
            action = "insert"
        self.state.db_mutations.append(DbMutation(table, record_id, values, action))
        return f"Record {record_id} in {table} {'updated' if action == 'update' else 'inserted'}."

    def get_record(self, table: str, record_id: str) -> dict[str, str] | None:
        cur = self.db.execute(f"SELECT * FROM {table} WHERE id = ?", (record_id,))
        row = cur.fetchone()
        if row is None:
            return None
        return {d[0]: row[i] for i, d in enumerate(cur.description)}
