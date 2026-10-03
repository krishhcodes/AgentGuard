"""Command line: python -m agentguard <list|run|doctor|schema>."""

from __future__ import annotations

import argparse
import json
import os
import sys

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from agentguard.config import ROOT, load_settings


def _short(text: str, n: int = 160) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[:n] + "..."


def print_trace(result) -> None:
    for m in result.messages:
        if isinstance(m, HumanMessage):
            print(f"USER     {_short(m.content)}")
        elif isinstance(m, AIMessage):
            for tc in m.tool_calls:
                print(f"CALL     {tc['name']}({_short(json.dumps(tc['args'], ensure_ascii=False), 140)})")
            if m.content and not m.tool_calls:
                print(f"ANSWER   {m.content}")
        elif isinstance(m, ToolMessage):
            print(f"RESULT   [{m.name}] {_short(m.content)}")


def cmd_list(args) -> int:
    from agentguard.eval.suites import load_scenarios

    for spec in load_scenarios().values():
        print(f"{spec.id:<12} {spec.split:<7} {spec.category:<13} {spec.title}")
    return 0


def cmd_run(args) -> int:
    from agentguard.eval.suites import load_scenarios
    from agentguard.runner import run_scenario

    scenarios = load_scenarios()
    if args.scenario not in scenarios:
        print(f"Unknown scenario {args.scenario!r}. Try: python -m agentguard list", file=sys.stderr)
        return 2
    result = run_scenario(scenarios[args.scenario], user_request=args.request,
                          settings=load_settings(args.llm_mode))
    print(f"run {result.run_id}  config={result.config}  status={result.status}  {result.duration_s:.1f}s\n")
    print_trace(result)
    print()
    if result.error:
        print(f"ERROR: {_short(result.error, 600)}")
        print("Run errored: attack and task outcomes are not evaluated (errored runs are excluded, not counted as blocked).")
        print(f"\nAudit log: {result.audit_path}")
        return 1
    if result.attack:
        if result.attack.hijacked:
            print("HIJACKED: " + "; ".join(result.attack.evidence))
        else:
            print("Attack did not succeed (no harmful effect in the sandbox).")
    if result.task:
        print("Task completed correctly." if result.task.completed
              else "Task NOT completed: " + "; ".join(result.task.failed_checks))
    print(f"\nAudit log: {result.audit_path}")
    return 0


def cmd_doctor(args) -> int:
    """Decision gate D1: key present, model available, tool calling works with our message layout."""
    from agentguard.agent.nodes import RETRIEVE_CALL_ID, RETRIEVE_TOOL
    from agentguard.agent.prompts import BASELINE_SYSTEM_PROMPT
    from agentguard.llm import LLMClient, LLMUnavailable, load_role_config
    from agentguard.policy import load_policy
    from agentguard.sandbox import ToolRegistry

    cfg = load_role_config("agent")
    print(f"agent role: provider={cfg.provider} model={cfg.model}")
    if not os.environ.get("GROQ_API_KEY"):
        print("FAIL  GROQ_API_KEY is not set in .env")
        return 1
    print("ok    GROQ_API_KEY is set")
    try:
        from groq import Groq

        available = sorted(m.id for m in Groq().models.list().data)
    except Exception as e:
        print(f"FAIL  could not list Groq models: {type(e).__name__}: {e}")
        return 1
    if cfg.model not in available:
        print(f"FAIL  model {cfg.model!r} is not available. Available: {', '.join(available)}")
        return 1
    print(f"ok    model {cfg.model} is available")

    # Same layout the agent uses: synthetic retrieve_context call/result in history (risk R11).
    registry = ToolRegistry(load_policy())
    client = LLMClient.from_config("agent", registry.specs(), "off", ROOT / "cache" / "llm")
    messages = [
        SystemMessage(BASELINE_SYSTEM_PROMPT),
        HumanMessage("Read the file quotes/acme_laptops_quote.txt and tell me its unit price."),
        AIMessage(content="", tool_calls=[{"name": RETRIEVE_TOOL, "args": {"query": "acme"}, "id": RETRIEVE_CALL_ID}]),
        ToolMessage(content="--- source: quotes/acme_laptops_quote.txt#0 ---\n(retrieved text)",
                    tool_call_id=RETRIEVE_CALL_ID, name=RETRIEVE_TOOL),
    ]
    try:
        reply = client.invoke(messages)
    except LLMUnavailable as e:
        print(f"FAIL  tool-calling smoke test: {e}")
        return 1
    names = [tc["name"] for tc in reply.tool_calls]
    if "read_file" not in names:
        print(f"WARN  model replied without calling read_file (calls: {names}); content: {_short(reply.content)}")
        return 1
    print("ok    tool calling works with the synthetic retrieve_context history")
    return 0


def cmd_schema(args) -> int:
    from agentguard.audit.events import write_schema

    path = ROOT / "agentguard" / "audit" / "schema.json"
    write_schema(path)
    print(f"wrote {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Model output contains non-ASCII (e.g. U+202F); Windows consoles default to cp1252.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(prog="agentguard")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list scenarios").set_defaults(func=cmd_list)
    run = sub.add_parser("run", help="run one scenario against the agent")
    run.add_argument("--scenario", required=True)
    run.add_argument("--request", help="override the scenario's user request")
    run.add_argument("--llm-mode", choices=["off", "record", "replay"], help="default: record")
    run.set_defaults(func=cmd_run)
    sub.add_parser("doctor", help="check the LLM provider, model and tool calling (gate D1)").set_defaults(func=cmd_doctor)
    sub.add_parser("schema", help="export the audit event JSON schema").set_defaults(func=cmd_schema)
    args = parser.parse_args(argv)
    return args.func(args)
