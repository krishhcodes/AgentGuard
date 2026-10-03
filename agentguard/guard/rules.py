"""Action Guard rule catalogue (ARCHITECTURE 6.10).

Every rule is deterministic and returns human-readable evidence. M2 implements the core
scope/policy rules; the taint/data-flow rules (ARG_FROM_UNTRUSTED_SOURCE, CONFIDENTIAL_EGRESS,
SECRET_PATTERN_EGRESS) arrive in M4 with the Taint Ledger.

Decision lattice: BLOCK > ASK > ALLOW (the most restrictive hit wins). SCHEMA_INVALID
short-circuits, because the other rules cannot parse invalid arguments. An ALLOW decision still
records which scope entries matched, so allows are explainable too.
"""

from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from agentguard.audit.events import truncate
from agentguard.guard.taint import TaintLedger
from agentguard.policy import Policy
from agentguard.sandbox.env import resolve_vpath
from agentguard.sandbox.tools import TOOL_ARG_MODELS
from agentguard.scope.models import Scope
from agentguard.text import text_views

ALLOW, ASK, BLOCK = "ALLOW", "ASK", "BLOCK"
_RANK = {ALLOW: 0, ASK: 1, BLOCK: 2}


class RuleHit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    decision: str  # ALLOW (positive evidence) | ASK | BLOCK
    severity: str  # info | warn | high
    reason: str
    evidence: list[dict[str, Any]] = []


class GuardDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    call_id: str
    tool: str
    args_redacted: dict[str, Any]
    decision: str  # ALLOW | ASK | BLOCK | APPROVED | DENIED (last two after human_gate)
    rule_hits: list[RuleHit] = []
    scope_ref: str = ""
    latency_ms: float = 0.0

    @property
    def rule_ids(self) -> list[str]:
        return [h.rule_id for h in self.rule_hits if h.decision != ALLOW]

    @property
    def reason(self) -> str:
        shown = [h for h in self.rule_hits if h.decision != ALLOW] or self.rule_hits
        return "; ".join(h.reason for h in shown)

    @property
    def evidence(self) -> list[dict[str, Any]]:
        return [e for h in self.rule_hits for e in h.evidence]


def _redact(args: dict[str, Any]) -> dict[str, Any]:
    return {k: truncate(v, 200) if isinstance(v, str) else v for k, v in args.items()}


def _recipient_ok(to: str, scope: Scope) -> bool:
    to = to.strip().lower()
    if to in {r.lower() for r in scope.recipients}:
        return True
    domain = to.rsplit("@", 1)[-1] if "@" in to else ""
    return bool(domain) and domain in {d.lower() for d in scope.recipient_domains}


def _check_read(args: dict, scope: Scope, policy: Policy) -> list[RuleHit]:
    path = args.get("path")
    if not isinstance(path, str):
        return []  # SCHEMA_INVALID already handled this
    resolved, escape = resolve_vpath(path)
    if escape or resolved is None:
        return [RuleHit(rule_id="PATH_ESCAPES_SANDBOX", decision=BLOCK, severity="high",
                        reason=f"Path {path!r} escapes the document store.",
                        evidence=[{"arg": "path", "value": truncate(path, 120)}])]
    if policy.is_confidential(resolved):
        if resolved in scope.confidential_resources:
            return [RuleHit(rule_id="CONFIDENTIAL_AUTHORIZED", decision=ALLOW, severity="info",
                            reason=f"Confidential file {resolved} was explicitly named by the user.",
                            evidence=[{"matched": "scope.confidential_resources", "value": resolved}])]
        return [RuleHit(rule_id="CONFIDENTIAL_NOT_AUTHORIZED", decision=BLOCK, severity="high",
                        reason=f"{resolved} is confidential and the user did not ask to read it.",
                        evidence=[{"arg": "path", "value": resolved}])]
    if any(fnmatch(resolved, g) for g in scope.read_resources):
        return [RuleHit(rule_id="RESOURCE_IN_SCOPE", decision=ALLOW, severity="info",
                        reason=f"{resolved} is inside the task's read scope.",
                        evidence=[{"matched": "scope.read_resources", "value": resolved}])]
    return [RuleHit(rule_id="RESOURCE_NOT_IN_SCOPE", decision=ASK, severity="warn",
                    reason=f"{resolved} is outside the task's read scope; confirm before reading.",
                    evidence=[{"arg": "path", "value": resolved}])]


def _check_email(args: dict, scope: Scope, policy: Policy) -> list[RuleHit]:
    to = args.get("to")
    if not isinstance(to, str):
        return []
    if _recipient_ok(to, scope):
        return [RuleHit(rule_id="RECIPIENT_APPROVED", decision=ALLOW, severity="info",
                        reason=f"Recipient {to} was named by the user.",
                        evidence=[{"matched": "scope.recipients", "value": to}])]
    if scope.ambiguity_for("recipient") is not None:
        amb = scope.ambiguity_for("recipient")
        return [RuleHit(rule_id="RECIPIENT_AMBIGUOUS", decision=ASK, severity="warn",
                        reason=f"The user asked to send a message but the recipient is unresolved ({amb.text}); confirm {to}.",
                        evidence=[{"arg": "to", "value": to}, {"ambiguity": amb.text}])]
    return [RuleHit(rule_id="RECIPIENT_NOT_APPROVED", decision=BLOCK, severity="high",
                    reason=f"Recipient {to} was not named by the user.",
                    evidence=[{"arg": "to", "value": to}])]


def _check_search(args: dict, scope: Scope, policy: Policy) -> list[RuleHit]:
    # search_web is `egress`; TOOL_NOT_IN_SCOPE already blocks it when the task did not request a
    # web search. If it is in scope, the query itself is checked by the flow rules in M4.
    return [RuleHit(rule_id="SEARCH_IN_SCOPE", decision=ALLOW, severity="info",
                    reason="Web search is part of the requested task.",
                    evidence=[{"matched": "scope.allowed_tools", "value": "search_web"}])]


def _check_write(args: dict, scope: Scope, policy: Policy) -> list[RuleHit]:
    table, record_id = args.get("table"), args.get("record_id")
    fields = args.get("fields") or {}
    if not isinstance(table, str) or not isinstance(record_id, str):
        return []
    match = next((w for w in scope.write_targets
                  if w.table == table and (w.record_id is None or w.record_id == record_id)), None)
    if match is None:
        return [RuleHit(rule_id="WRITE_TARGET_NOT_IN_SCOPE", decision=BLOCK, severity="high",
                        reason=f"The user did not ask to modify {table}/{record_id}.",
                        evidence=[{"arg": "table", "value": table}, {"arg": "record_id", "value": record_id}])]
    hits = [RuleHit(rule_id="WRITE_TARGET_IN_SCOPE", decision=ALLOW, severity="info",
                    reason=f"{table}/{record_id} is the record the user named.",
                    evidence=[{"matched": "scope.write_targets", "value": f"{table}/{record_id}"}])]
    risky = [f for f in (fields if isinstance(fields, dict) else {})
             if f in policy.high_risk_fields and f not in match.fields]
    if risky:
        hits.append(RuleHit(rule_id="HIGH_RISK_FIELD", decision=ASK, severity="warn",
                            reason=f"Write sets high-risk field(s) {risky} the user did not state; confirm.",
                            evidence=[{"fields": risky}]))
    return hits


_CHECKS = {"read_file": _check_read, "send_email": _check_email,
           "search_web": _check_search, "write_record": _check_write}


def _egress_view(tool: str, args: dict, scope: Scope) -> dict | None:
    """Per-tool egress descriptor: the text leaving, the sink key (for cumulative checks), the
    identifying argument (for provenance), and whether the sink is authorised."""
    if tool == "send_email":
        to = str(args.get("to", ""))
        return {"text": f"{to}\n{args.get('subject', '')}\n{args.get('body', '')}",
                "sink": to.lower(), "value": to, "recipient": to, "authorised": _recipient_ok(to, scope)}
    if tool == "search_web":
        return {"text": str(args.get("query", "")), "sink": "web", "value": "",
                "recipient": None, "authorised": False}  # the web is always an external sink
    if tool == "write_record":
        table, rid = args.get("table"), args.get("record_id")
        fields = args.get("fields") or {}
        in_scope = any(w.table == table and (w.record_id is None or w.record_id == rid)
                       for w in scope.write_targets)
        return {"text": " ".join(str(v) for v in fields.values()), "sink": f"{table}/{rid}",
                "value": str(rid or ""), "recipient": None, "authorised": in_scope}
    return None


def _check_flow(tool: str, args: dict, scope: Scope, policy: Policy, ledger: TaintLedger) -> list[RuleHit]:
    """M4 data-flow rules for egress/write tools: SECRET_PATTERN_EGRESS, CONFIDENTIAL_EGRESS,
    ARG_FROM_UNTRUSTED_SOURCE."""
    eg = _egress_view(tool, args, scope)
    if eg is None:
        return []
    hits: list[RuleHit] = []
    all_text = "\n".join(text_views(eg["text"]).all_texts())

    secrets = policy.matched_secrets(all_text)
    if secrets:
        hits.append(RuleHit(rule_id="SECRET_PATTERN_EGRESS", decision=BLOCK, severity="high",
                            reason=f"Outbound {tool} argument contains secret-shaped data: {secrets[:3]}.",
                            evidence=[{"secrets": secrets[:3]}]))

    flow = ledger.confidential_overlap(eg["text"], sink=eg["sink"])
    if flow.matched or ledger.has_confidential_read:
        flow_authorised = eg["recipient"] is not None and any(
            f.recipient.lower() == eg["recipient"].lower() for f in scope.egress_flows)
        src = flow.source or (ledger.confidential_bodies[0].source if ledger.confidential_bodies else "confidential")
        ev = [{"source": src, "method": flow.method or "session-read", "snippet": truncate(flow.snippet, 120)}]
        if not eg["authorised"]:
            hits.append(RuleHit(rule_id="CONFIDENTIAL_EGRESS", decision=BLOCK, severity="high",
                                reason=f"This {tool} would send confidential data ({src}) to an unauthorised sink.",
                                evidence=ev))
        elif not flow_authorised:
            hits.append(RuleHit(rule_id="CONFIDENTIAL_EGRESS", decision=ASK, severity="warn",
                                reason=f"This {tool} sends confidential data ({src}); the user did not authorise this flow.",
                                evidence=ev))

    if eg["value"]:
        prov = ledger.origin_of(eg["value"])
        if prov.origin.startswith("untrusted:"):
            hits.append(RuleHit(rule_id="ARG_FROM_UNTRUSTED_SOURCE", decision=ASK, severity="warn",
                                reason=f"The {tool} target {eg['value']!r} came from untrusted content, "
                                       f"not the user ({prov.origin}).",
                                evidence=prov.evidence))
    return hits


def evaluate_call(call: dict, scope: Scope, policy: Policy, ledger: TaintLedger | None = None) -> list[RuleHit]:
    """Run the rule catalogue for one proposed call and return every hit (lattice applied later)."""
    tool, args = call["name"], call.get("args") or {}
    model = TOOL_ARG_MODELS.get(tool)
    if model is None:
        return [RuleHit(rule_id="SCHEMA_INVALID", decision=BLOCK, severity="high",
                        reason=f"Unknown tool {tool!r}.", evidence=[{"tool": tool}])]
    try:
        model.model_validate(args)
    except ValidationError as e:
        return [RuleHit(rule_id="SCHEMA_INVALID", decision=BLOCK, severity="high",
                        reason=f"Arguments do not match the {tool} schema.",
                        evidence=[{"errors": truncate(str(e.errors(include_url=False)), 200)}])]

    hits: list[RuleHit] = []
    if tool not in scope.allowed_tools:
        risk = policy.tools[tool].risk
        decision = ASK if risk == "read" else BLOCK
        hits.append(RuleHit(rule_id="TOOL_NOT_IN_SCOPE", decision=decision, severity="high",
                            reason=f"Tool {tool} ({risk}) is not part of the authorised task.",
                            evidence=[{"tool": tool, "risk": risk}]))
    if scope.ambiguous_tool(tool) is not None:
        hits.append(RuleHit(rule_id="TOOL_SCOPE_AMBIGUOUS", decision=ASK, severity="warn",
                            reason=f"Use of {tool} is ambiguous for this task; confirm.",
                            evidence=[{"tool": tool}]))
    hits.extend(_CHECKS[tool](args, scope, policy))
    if ledger is not None and policy.tools[tool].risk in ("egress", "write"):
        hits.extend(_check_flow(tool, args, scope, policy, ledger))
    return hits


def decide(call: dict, scope: Scope, policy: Policy, ledger: TaintLedger | None = None) -> GuardDecision:
    hits = evaluate_call(call, scope, policy, ledger)
    decision = ALLOW
    for h in hits:
        if _RANK[h.decision] > _RANK[decision]:
            decision = h.decision
    return GuardDecision(
        call_id=call.get("id") or "",
        tool=call["name"],
        args_redacted=_redact(call.get("args") or {}),
        decision=decision,
        rule_hits=hits,
        scope_ref=scope.scope_id,
    )
