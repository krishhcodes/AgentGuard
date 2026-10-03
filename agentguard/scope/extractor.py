"""Scope Extractor (ARCHITECTURE 6.6).

Algorithm:
  1. Deterministic pre-pass over the user text: literal emails, file paths, record targets,
     stated field names, directory aliases.
  2. One LLM call (role `scope`) that *proposes* the task's intent as strict JSON.
  3. Deterministic post-validation, which is the authority: drop any recipient not literally
     present or alias-resolved, drop confidential paths not literally named, drop unknown tools,
     add implied read-only defaults, and send unresolved references to `ambiguities`.

Invariant P1: the LLM sees ONLY the user request and policy tool names / directory aliases.
No untrusted content (documents, tool output) ever reaches this module.
"""

from __future__ import annotations

import json
import re
import time

from langchain_core.messages import HumanMessage, SystemMessage

from agentguard.llm import LLMUnavailable
from agentguard.policy import Policy
from agentguard.scope.models import Ambiguity, EgressFlow, Scope, ScopeMeta, WriteTarget

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PATH_RE = re.compile(r"\b(?:quotes|confidential|web)/[A-Za-z0-9_./-]+")
RECORD_RE = re.compile(r"\b(V-\d+|PO-\d+)\b", re.IGNORECASE)
DOMAIN_PHRASE_RE = re.compile(r"(?:anyone|everyone|anybody|somebody)\s+at\s+([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE)
_TABLE_OF = {"V": "vendors", "PO": "purchase_orders"}


def _columns(policy: Policy) -> set[str]:
    # Stated-field detection uses the DB columns; kept here as a small static set so the extractor
    # has no sandbox dependency. Mirrors data/db_seed.sql.
    return {"name", "contact_email", "bank_account", "status", "vendor_id", "item",
            "quantity", "unit_price", "notes", "payment_status"}


class Prepass:
    def __init__(self, text: str, policy: Policy):
        low = text.lower()
        self.emails = sorted({m.lower() for m in EMAIL_RE.findall(text)})
        self.paths = sorted(set(PATH_RE.findall(text)))
        self.confidential_paths = sorted(p for p in self.paths if policy.is_confidential(p))
        self.aliases = sorted({addr for phrase, addr in policy.directory.items() if phrase in low})
        self.domains = sorted({d.lower() for d in DOMAIN_PHRASE_RE.findall(text)})
        self.stated_fields = sorted(c for c in _columns(policy) if re.search(rf"\b{re.escape(c)}\b", low))
        targets: dict[tuple[str, str], None] = {}
        for rid in RECORD_RE.findall(text):
            rid = rid.upper()
            targets[(_TABLE_OF[rid.split("-")[0]], rid)] = None
        self.record_targets = list(targets)

    @property
    def recipients(self) -> list[str]:
        return sorted(set(self.emails) | set(self.aliases))


def build_scope_prompt(user_request: str, policy: Policy) -> list:
    """The exact messages sent to the scope model. Trusted inputs only (P1)."""
    tools = "\n".join(f"- {name} ({p.risk}): {p.description}" for name, p in policy.tools.items())
    aliases = "\n".join(f"- {phrase!r} -> {addr}" for phrase, addr in policy.directory.items()) or "(none)"
    system = (
        "You extract the AUTHORISED SCOPE of a procurement assistant's task from the user's request. "
        "You see only the user's request and the tool catalogue below; you never see documents or tool "
        "output. Decide which tools the task legitimately needs and which recipients, files and records "
        "the user explicitly refers to. Do NOT invent recipients, paths or records that the user did not "
        "mention. If the user wants to send something but names no resolvable recipient, still include "
        "send_email in allowed_tools and leave recipients empty.\n\n"
        f"Tools:\n{tools}\n\nDirectory aliases (resolve only if the user names them):\n{aliases}\n\n"
        "Respond with ONLY a JSON object, no prose, with keys: "
        '{"task_summary": str, "allowed_tools": [tool names], "recipients": [emails], '
        '"confidential_paths": [paths], "write_targets": [{"table": str, "record_id": str, '
        '"fields": [str]}], "needs_web_search": bool}.'
    )
    return [SystemMessage(system), HumanMessage(user_request.strip())]


def _parse_json(content: str) -> dict:
    if isinstance(content, list):  # some providers return content blocks
        content = "".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in content)
    text = content.strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in scope model output")
    return json.loads(text[start:end + 1])


def _llm_propose(user_request: str, policy: Policy, llm) -> dict:
    reply = llm.invoke(build_scope_prompt(user_request, policy))
    return _parse_json(reply.content)


def _validate(
    user_request: str, pre: Prepass, proposal: dict | None, policy: Policy,
    scope_id: str, model_name: str, latency_ms: float, fallback_used: bool,
) -> Scope:
    low = user_request.lower()
    dropped: list[str] = []
    proposal = proposal or {}
    proposed_tools = {t for t in proposal.get("allowed_tools", []) if isinstance(t, str)}
    for t in proposed_tools - set(policy.tools):
        dropped.append(f"unknown tool {t!r}")

    recipients = pre.recipients
    for r in proposal.get("recipients", []):
        if isinstance(r, str) and r.lower() not in recipients:
            dropped.append(f"recipient {r!r} not present in the user request")
    for p in proposal.get("confidential_paths", []):
        if isinstance(p, str) and p not in pre.confidential_paths:
            dropped.append(f"confidential path {p!r} not named by the user")

    # Tools: read_file is always implied; egress/write tools need literal evidence OR an LLM signal.
    allowed = {"read_file"}
    wants_email = bool(recipients) or "send_email" in proposed_tools or bool(re.search(r"\b(email|e-mail|send|forward)\b", low))
    wants_search = proposal.get("needs_web_search") is True or "search_web" in proposed_tools or "search the web" in low
    wants_write = bool(pre.record_targets) or "write_record" in proposed_tools
    if wants_email:
        allowed.add("send_email")
    if wants_search:
        allowed.add("search_web")
    if wants_write:
        allowed.add("write_record")

    write_targets = [
        WriteTarget(table=t, record_id=rid, fields=pre.stated_fields) for t, rid in pre.record_targets
    ]

    ambiguities: list[Ambiguity] = []
    if fallback_used:
        # Degraded path: reads keep working; every egress/write tool becomes ASK, not a silent allow.
        for t in ("send_email", "search_web", "write_record"):
            if t in allowed:
                ambiguities.append(Ambiguity(field="tool", text=t,
                                             reason="scope model unavailable; confirm this action manually"))
    elif "send_email" in allowed and not recipients and not pre.domains:
        ambiguities.append(Ambiguity(
            field="recipient", text="unresolved recipient",
            reason="the user asked to send something but named no address or known alias"))

    # Explicitly requested confidential -> recipient flows: only when the user named BOTH the
    # confidential file and a recipient (plus a send verb). These are the ONLY confidential egresses
    # the guard allows without asking (CONFIDENTIAL_EGRESS, M4).
    egress_flows = (
        [EgressFlow(source=src, recipient=rcpt) for src in pre.confidential_paths for rcpt in recipients]
        if (pre.confidential_paths and recipients and "send_email" in allowed) else []
    )

    return Scope(
        scope_id=scope_id,
        task_summary=str(proposal.get("task_summary") or "procurement task")[:300],
        allowed_tools=sorted(allowed),
        read_resources=["quotes/**"],
        confidential_resources=pre.confidential_paths,
        recipients=recipients,
        recipient_domains=pre.domains,
        write_targets=write_targets,
        egress_flows=egress_flows,
        ambiguities=ambiguities,
        meta=ScopeMeta(model=model_name, latency_ms=round(latency_ms, 1),
                       fallback_used=fallback_used, dropped_items=dropped),
    )


def extract_scope(user_request: str, policy: Policy, llm, *, scope_id: str, model_name: str = "scope") -> Scope:
    pre = Prepass(user_request, policy)
    started = time.perf_counter()
    proposal: dict | None = None
    fallback_used = False
    try:
        proposal = _llm_propose(user_request, policy, llm)
    except (LLMUnavailable, ValueError, json.JSONDecodeError):
        fallback_used = True  # read-only defaults + egress/write -> ASK (fail soft for reads, P6)
    latency_ms = (time.perf_counter() - started) * 1000
    return _validate(user_request, pre, proposal, policy, scope_id, model_name, latency_ms, fallback_used)
