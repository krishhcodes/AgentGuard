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


def _stdin_human(payload) -> dict:
    """CLI approve/deny prompt for ASK decisions. Default (empty input) denies (fail closed)."""
    answers = {}
    for ask in payload.get("asks", []):
        print(f"\nASK  {ask['tool']}({json.dumps(ask['args'], ensure_ascii=False)})")
        print(f"     rules: {', '.join(ask['rules'])}")
        print(f"     {ask['reason']}")
        choice = input("     approve this call? [y/N] ").strip().lower()
        answers[ask["call_id"]] = "approve" if choice in ("y", "yes") else "deny"
    return answers


def cmd_run(args) -> int:
    from agentguard.agent.graph import CONFIGS
    from agentguard.eval.suites import load_scenarios
    from agentguard.runner import run_scenario

    scenarios = load_scenarios()
    if args.scenario not in scenarios:
        print(f"Unknown scenario {args.scenario!r}. Try: python -m agentguard list", file=sys.stderr)
        return 2
    if args.config not in CONFIGS:
        print(f"Unknown config {args.config!r}. Available: {', '.join(CONFIGS)}", file=sys.stderr)
        return 2
    result = run_scenario(scenarios[args.scenario], config=args.config, user_request=args.request,
                          human=_stdin_human, settings=load_settings(args.llm_mode))
    print(f"run {result.run_id}  config={result.config}  status={result.status}  {result.duration_s:.1f}s\n")
    print_trace(result)
    if result.decisions:
        print("\nGuard decisions:")
        for d in result.decisions:
            rules = f" [{', '.join(d['rules'])}]" if d["rules"] else ""
            print(f"  {d['decision']:<9} {d['tool']}{rules}")
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

    from agentguard.llm import load_groq_keys

    cfg = load_role_config("agent")
    print(f"agent role: provider={cfg.provider} model={cfg.model}")
    keys = load_groq_keys()
    if not keys:
        print("FAIL  no Groq key set (add GROQ_API_KEY or GROQ_API_KEYS to .env)")
        return 1
    print(f"ok    {len(keys)} Groq key(s) configured"
          + (f" (~{len(keys) * 200}k tokens/day across the free tier)" if len(keys) > 1 else ""))
    os.environ["GROQ_API_KEY"] = keys[0]  # the groq sdk reads this; keys may be set only via GROQ_API_KEYS
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


def _freeze_ok(args) -> bool:
    """Freeze protocol: unseen results only count from a clean, committed tree with an intact manifest."""
    import subprocess
    from datetime import datetime

    from agentguard.eval.freeze import verify_manifest

    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    if dirty:
        print("freeze refused: the git tree is dirty. Commit first.\n" + dirty)
        return False
    problems = verify_manifest()
    if problems:
        print("freeze refused: unseen manifest mismatch: " + "; ".join(problems))
        return False
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    log = ROOT / "results" / "UNSEEN_RUNS.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat(timespec='seconds')} commit={commit} configs={args.configs} splits={args.splits}\n")
    print(f"freeze ok at {commit[:10]} (logged to {log})")
    return True


def cmd_eval(args) -> int:
    from datetime import datetime

    from agentguard.eval.harness import run_suite
    from agentguard.eval.report import render_markdown, write_latency_csv, write_misses_csv, write_summary_csv

    if args.patient:
        os.environ["AGENTGUARD_PATIENT_S"] = str(6 * 3600)
    if args.freeze and not _freeze_ok(args):
        return 1
    configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    splits = [s.strip() for s in args.splits.split(",") if s.strip()]
    out_dir = ROOT / "results" / datetime.now().strftime("%Y%m%d-%H%M%S")
    print(f"configs={configs} splits={splits} repeats={args.repeats} mode={args.llm_mode or 'record'}")
    print(f"writing to {out_dir}\n")
    records = run_suite(
        configs=configs, splits=splits, repeats=args.repeats,
        settings=load_settings(args.llm_mode),
        only=[s.strip() for s in args.only.split(",")] if args.only else None,
        out_csv=out_dir / "runs.csv", delay_s=args.delay,
        progress=lambda line: print(line, flush=True),
    )
    write_summary_csv(records, out_dir / "summary.csv")
    write_latency_csv(records, out_dir / "latency.csv")
    write_misses_csv(records, out_dir / "misses.csv")
    guarded = any(c in configs for c in ("guard_only", "full", "compromised_agent"))
    title = ("AgentGuard evaluation (M6: full pipeline)" if "full" in configs
             else "AgentGuard evaluation (M2: guard)" if guarded else "Baseline evaluation (M1)")
    markdown = render_markdown(records, title=title)
    (out_dir / "RESULTS.md").write_text(markdown, encoding="utf-8")
    print("\n" + markdown)
    print(f"Artifacts: {out_dir}")
    return 0


def cmd_freeze_manifest(args) -> int:
    from agentguard.eval.freeze import verify_manifest, write_manifest

    if args.verify:
        problems = verify_manifest()
        if problems:
            print("Unseen manifest MISMATCH:")
            for p in problems:
                print(f"  - {p}")
            return 1
        print("ok    unseen set matches MANIFEST.sha256")
        return 0
    path = write_manifest()
    print(f"wrote {path}")
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
    run.add_argument("--config", default="baseline",
                     help="baseline | guard_only | compromised_agent")
    run.add_argument("--request", help="override the scenario's user request")
    run.add_argument("--llm-mode", choices=["off", "record", "replay", "auto"], help="default: auto")
    run.set_defaults(func=cmd_run)
    ev = sub.add_parser("eval", help="run suites x configs x repeats and write metrics")
    ev.add_argument("--configs", default="baseline", help="comma-separated (M1: baseline only)")
    ev.add_argument("--splits", default="dev,benign", help="comma-separated: dev, unseen, benign")
    ev.add_argument("--repeats", type=int, default=3)
    ev.add_argument("--llm-mode", choices=["off", "record", "replay", "auto"],
                    help="auto = reuse recorded runs, call Groq only for new/changed scenarios")
    ev.add_argument("--freeze", action="store_true",
                    help="refuse on a dirty git tree; log the commit hash to results/UNSEEN_RUNS.log")
    ev.add_argument("--patient", action="store_true",
                    help="when every Groq key hits its daily cap, wait for the window to free up (unattended runs)")
    ev.add_argument("--only", help="comma-separated scenario ids to run (a quick sample, e.g. for latency)")
    ev.add_argument("--delay", type=float, default=0.0, help="seconds between runs (free-tier pacing)")
    ev.set_defaults(func=cmd_eval)
    fm = sub.add_parser("freeze-manifest", help="write or verify the unseen-set SHA-256 manifest")
    fm.add_argument("--verify", action="store_true")
    fm.set_defaults(func=cmd_freeze_manifest)
    sub.add_parser("doctor", help="check the LLM provider, model and tool calling (gate D1)").set_defaults(func=cmd_doctor)
    sub.add_parser("schema", help="export the audit event JSON schema").set_defaults(func=cmd_schema)
    args = parser.parse_args(argv)
    return args.func(args)
