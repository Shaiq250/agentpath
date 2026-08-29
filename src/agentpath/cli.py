"""Command line interface.

Two commands, deliberately separate:

  collect   reads config files and, unless told not to, starts each configured
            server to ask what tools it offers. This is the only command that
            executes anything.
  analyze   reads a manifest and reports attack paths. Offline, always.

Keeping them apart means analysis is reproducible from a file, tests never need
a live system, and the risky half of the tool is one command the user chooses to
run rather than something that happens implicitly.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agents import AgentUnavailable, ModelAgent, ScriptedAgent
from .baseline import BaselineError, apply_baseline, build_baseline, load_baseline
from .classify import classify_agent
from .confirm import (
    apply_confirmations,
    apply_issue_confirmations,
    confirm_all,
    confirm_poisoning,
)
from .crossserver import find_issues
from .collect import collect as run_collect
from .discovery import ServerSpec, config_locations, discover
from .findings import analyze as run_analysis
from .importers import IMPORTERS, ImportError_, to_manifest
from .labels import SEVERITIES, at_least
from .model import ManifestError, load_manifest, manifest_to_dict
from .policy import PolicyError, apply_policy, find_policy, load_policy
from .report import to_json, to_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentpath",
        description="Find attack paths in the tools available to an AI agent.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser(
        "collect",
        help="discover configured MCP servers and record their tools",
        description=(
            "Reads agent config files and starts each configured server to ask which "
            "tools it offers. Starting a server means running the command in the config "
            "file, so the commands are printed before anything runs. Use --no-launch to "
            "read the configs without executing anything."
        ),
    )
    collect.add_argument("-o", "--out", default="manifest.json",
                         help="where to write the manifest (default: manifest.json)")
    collect.add_argument("--no-launch", action="store_true",
                         help="read config files only; do not start any server")
    collect.add_argument("--name", default="", help="name for the collected agent")
    collect.add_argument("--timeout", type=float, default=15.0,
                         help="seconds to wait for each server to reply (default: 15)")
    collect.add_argument("--no-cache", action="store_true",
                         help="ignore cached tool lists and re-enumerate everything")

    confirm = sub.add_parser(
        "confirm",
        help="test whether an agent actually walks the candidate paths",
        description=(
            "For each candidate path, stands up a stand in source tool that returns "
            "content with a planted instruction, and a stand in sink tool that records "
            "calls and does nothing else. The real tools are never called: nothing is "
            "sent, refunded or executed. A path is confirmed only when the sink is "
            "called with a marker that existed nowhere but inside the planted content."
        ),
    )
    confirm.add_argument("manifest", help="path to an agent manifest JSON file")
    confirm.add_argument("-o", "--out", default="confirmations.json",
                         help="where to write the results (default: confirmations.json)")
    confirm.add_argument("--agent", choices=("model", "scripted"), default="model",
                         help="model uses a real language model and needs an API key; "
                              "scripted uses an offline stand in that only proves the "
                              "harness works (default: model)")
    confirm.add_argument("--model", default="claude-sonnet-5",
                         help="model id to test, when --agent model")
    confirm.add_argument("--attempts", type=int, default=3,
                         help="payload variations to try per path (default: 3)")
    confirm.add_argument("--policy", help="path to an .agentpath.yml file")
    confirm.add_argument(
        "--what", choices=("paths", "poisoning", "all"), default="all",
        help="paths tests whether an agent walks a source to sink path. poisoning "
             "puts a flagged tool description in front of a model and watches whether "
             "it follows the instructions inside it (default: all)",
    )

    scan = sub.add_parser(
        "scan",
        help="collect and analyse this machine in one step",
        description=(
            "The short way in. Reads the agent configuration on this machine, asks each "
            "server what it offers, and prints a report. Equivalent to collect followed "
            "by analyze, and it keeps the manifest so the report can be reproduced or "
            "re-analysed later without touching anything again."
        ),
    )
    scan.add_argument("--no-launch", action="store_true",
                      help="read config files only; do not start any server")
    scan.add_argument("--manifest", default="manifest.json",
                      help="where to keep the collected manifest (default: manifest.json)")
    scan.add_argument("-o", "--out", help="write the report to a file instead of stdout")
    scan.add_argument("--format", choices=("md", "json", "html", "sarif"), default="md")
    scan.add_argument("--fail-on", choices=SEVERITIES, default="low")
    scan.add_argument("--policy", help="path to an .agentpath.yml file")
    scan.add_argument("--no-policy", action="store_true")
    scan.add_argument("--baseline", help="a baseline file of findings that already existed")
    scan.add_argument("--ignore-declared", action="store_true")
    scan.add_argument("--allow-incomplete", action="store_true")
    scan.add_argument("--timeout", type=float, default=15.0)
    scan.add_argument("--no-cache", action="store_true")
    scan.add_argument("--name", default="")

    importer = sub.add_parser(
        "import",
        help="build a manifest from tools that did not come from MCP",
        description=(
            "Converts tool definitions from somewhere else into a manifest, which "
            "analyze and confirm then treat like any other. Reads a file and writes a "
            "file: nothing is executed and nothing is fetched."
        ),
    )
    importer.add_argument("path", help="a JSON file of tool definitions or an OpenAPI document")
    importer.add_argument("-o", "--out", default="manifest.json")
    importer.add_argument("--format", choices=("auto", *sorted(IMPORTERS)), default="auto")
    importer.add_argument("--server", default="",
                          help="name to give the group of tools in the manifest")
    importer.add_argument("--name", default="", help="name to give the agent")

    analyze = sub.add_parser("analyze", help="analyse an agent manifest, offline")
    analyze.add_argument("manifest", help="path to an agent manifest JSON file")
    analyze.add_argument("-o", "--out", help="write the report to a file instead of stdout")
    analyze.add_argument("--format", choices=("md", "json", "html", "sarif"),
                         default="md")
    analyze.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="low",
        help="exit non zero when a finding at this severity or above exists (default: low)",
    )
    analyze.add_argument(
        "--policy",
        help="path to an .agentpath.yml file (default: one in the current directory)",
    )
    analyze.add_argument(
        "--no-policy", action="store_true",
        help="ignore any policy file, so nothing is overridden or suppressed",
    )
    analyze.add_argument(
        "--confirmations",
        help="a confirmations.json from `agentpath confirm`, to fold into the report",
    )
    analyze.add_argument(
        "--baseline",
        help="a baseline file of findings that already existed; they are reported but "
             "do not fail the build",
    )
    analyze.add_argument(
        "--write-baseline",
        metavar="PATH",
        help="write the current findings to a baseline file and exit 0",
    )
    analyze.add_argument(
        "--ignore-declared",
        action="store_true",
        help="for the exit code only, ignore severity reductions that came from claims "
             "in the policy file, such as a sink declared as gated behind human approval",
    )
    analyze.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="do not exit non zero merely because some servers were not enumerated",
    )
    return parser


# ---------------------------------------------------------------- collect

def _warn_about_launching(specs: list[ServerSpec]) -> None:
    """Show exactly what is about to run, before it runs.

    A README warning is not much use to someone who has already typed the
    command. Printing the commands costs nothing and means nobody can say they
    were not told.
    """
    local = [spec for spec in specs if spec.transport == "stdio"]
    remote = [spec for spec in specs if spec.transport != "stdio"]
    if not local and not remote:
        return

    if local:
        print("agentpath is about to start the following servers to ask for their tools.",
              file=sys.stderr)
        print("This runs the commands exactly as your config files define them:",
              file=sys.stderr)
        for spec in local:
            print(f"  {spec.name}: {spec.command_line}", file=sys.stderr)
    if remote:
        print("It will also contact these remote servers over the network:", file=sys.stderr)
        for spec in remote:
            print(f"  {spec.name}: {spec.url}", file=sys.stderr)
    print("If you did not write these config files, stop and run with --no-launch, "
          "or scan inside a container.", file=sys.stderr)
    print("", file=sys.stderr)


def _narrate(event: str, spec: ServerSpec, detail: str) -> None:
    labels = {
        "launching": "starting",
        "enumerated": "ok",
        "cached": "cached",
        "skipped": "skipped",
        "failed": "FAILED",
    }
    print(f"  [{labels.get(event, event)}] {spec.name}: {detail}", file=sys.stderr)


def cmd_collect(args: argparse.Namespace) -> int:
    specs = discover()
    if not specs:
        print("No MCP server configurations found. Looked in:", file=sys.stderr)
        for _harness, path in config_locations():
            print(f"  {path}", file=sys.stderr)
        return 2

    print(f"Found {len(specs)} configured servers.", file=sys.stderr)
    if not args.no_launch:
        _warn_about_launching(specs)

    result = run_collect(
        specs,
        launch=not args.no_launch,
        agent_name=args.name,
        timeout=args.timeout,
        use_cache=not args.no_cache,
        on_event=_narrate,
    )

    Path(args.out).write_text(
        json.dumps(manifest_to_dict(result.agent, result.collection), indent=2),
        encoding="utf-8",
    )

    tools = sum(1 for _ in result.agent.tools())
    print(f"\nWrote {args.out}: {len(result.agent.servers)} servers, {tools} tools.",
          file=sys.stderr)

    missing = result.agent.unenumerated()
    if missing:
        names = ", ".join(server.name for server in missing)
        print(f"Incomplete: {len(missing)} of {len(result.agent.servers)} servers were not "
              f"enumerated ({names}).", file=sys.stderr)
        print("Their tools are unknown, so any attack path through them will be missing "
              "from the analysis.", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- scan

def cmd_scan(args: argparse.Namespace) -> int:
    """collect then analyze, so the first thing anyone runs produces a report.

    Deliberately still writes the manifest. Keeping it means the report can be
    reproduced, re-analysed with a different policy, or confirmed against a
    model later, without going back and touching the machine a second time.
    """
    collect_args = argparse.Namespace(
        out=args.manifest, no_launch=args.no_launch, name=args.name,
        timeout=args.timeout, no_cache=args.no_cache)
    code = cmd_collect(collect_args)
    if code:
        return code

    print("", file=sys.stderr)
    analyze_args = argparse.Namespace(
        manifest=args.manifest, out=args.out, format=args.format,
        fail_on=args.fail_on, policy=args.policy, no_policy=args.no_policy,
        baseline=args.baseline, write_baseline=None, confirmations=None,
        ignore_declared=args.ignore_declared, allow_incomplete=args.allow_incomplete)
    return cmd_analyze(analyze_args)


# ---------------------------------------------------------------- import

def cmd_import(args: argparse.Namespace) -> int:
    try:
        data = json.loads(Path(args.path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not read {args.path}: {exc}", file=sys.stderr)
        return 2

    try:
        manifest = to_manifest(data, args.format, args.server, args.name, args.path)
    except ImportError_ as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    Path(args.out).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    tools = len(manifest["servers"][0]["tools"])
    print(f"Wrote {args.out}: {tools} tools from {manifest['agent']['harness']}.",
          file=sys.stderr)
    print("These tools were listed in the file rather than obtained from a running "
          "server, so the manifest is complete by construction.", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- confirm

def _load_policy_for(args) -> tuple[object, int]:
    """Shared policy loading. Returns (policy, error_code)."""
    if getattr(args, "no_policy", False):
        return None, 0
    policy_path = Path(args.policy) if args.policy else find_policy()
    if args.policy and not Path(args.policy).is_file():
        print(f"error: no policy file at {args.policy}", file=sys.stderr)
        return None, 2
    if not policy_path:
        return None, 0
    try:
        policy = load_policy(policy_path)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None, 2
    print(f"using policy {policy_path}", file=sys.stderr)
    return policy, 0


def cmd_confirm(args: argparse.Namespace) -> int:
    try:
        agent_model = load_manifest(args.manifest)
    except (ManifestError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    policy, code = _load_policy_for(args)
    if code:
        return code

    classify_agent(agent_model)
    apply_policy(agent_model, policy)
    findings = run_analysis(agent_model, policy)
    issues = find_issues(agent_model, policy)
    candidates = [f for f in findings if not f.suppressed] if args.what != "poisoning" else []
    flagged = [i for i in issues
               if i.status == "open"
               and i.kind in ("tool_description_injection", "concealed_text_in_description")
               ] if args.what != "paths" else []

    if not candidates and not flagged:
        print("Nothing to confirm.", file=sys.stderr)
        return 0

    if args.agent == "scripted":
        agent = ScriptedAgent("follows")
        print("Using the scripted stand in. This tests the harness, not a real agent.",
              file=sys.stderr)
    else:
        try:
            agent = ModelAgent(model=args.model)
        except AgentUnavailable as exc:
            print(f"error: {exc}", file=sys.stderr)
            print("Set ANTHROPIC_API_KEY, or use --agent scripted to test the harness "
                  "without a model.", file=sys.stderr)
            return 2

    plan = []
    if candidates:
        plan.append(f"{len(candidates)} candidate paths")
    if flagged:
        plan.append(f"{len(flagged)} flagged descriptions")
    print(f"Confirming {' and '.join(plan)} against {agent.name}.", file=sys.stderr)
    print("Stand in tools only: nothing is sent, refunded or executed.", file=sys.stderr)

    def narrate(event, payload):
        if event == "start":
            print(f"  testing {payload.id}: {payload.source.tool} -> {payload.sink.tool}",
                  file=sys.stderr)
        else:
            mark = {"confirmed": "CONFIRMED", "not_confirmed": "not confirmed",
                    "not_delivered": "NOT TESTED (payload never reached the agent)",
                    "untestable": "untestable"}[payload.verdict]
            detail = (f"{payload.succeeded}/{payload.attempts}"
                      if payload.verdict == "confirmed"
                      else f"delivered {payload.delivered}/{payload.attempts}")
            print(f"    {mark} ({detail})", file=sys.stderr)

    results = confirm_all(candidates, agent, args.attempts, on_event=narrate) if candidates else []

    def narrate_issue(event, payload):
        if event == "start":
            print(f"  testing {payload.id}: {', '.join(payload.tools) or 'server level'}",
                  file=sys.stderr)
        else:
            mark = {"confirmed": "CONFIRMED", "not_confirmed": "not confirmed",
                    "not_delivered": "NOT TESTED (the tool was never called)",
                    "untestable": "untestable"}[payload.verdict]
            print(f"    {mark} ({payload.succeeded}/{payload.attempts})", file=sys.stderr)

    poisoning = (confirm_poisoning(flagged, agent, args.attempts, on_event=narrate_issue)
                 if flagged else [])

    Path(args.out).write_text(
        json.dumps({
            "schema": "agentpath-confirmations/v2",
            "agent": {"kind": agent.kind, "name": agent.name,
                      "trustworthy": agent.trustworthy},
            "results": [result.to_dict() for result in results],
            "poisoning": [result.to_dict() for result in poisoning],
        }, indent=2),
        encoding="utf-8",
    )
    confirmed = sum(1 for result in results if result.verdict == "confirmed")
    undelivered = sum(1 for result in results if result.verdict == "not_delivered")
    lines = []
    if results:
        lines.append(f"{confirmed} of {len(results)} paths confirmed")
    if poisoning:
        walked = sum(1 for r in poisoning if r.verdict == "confirmed")
        lines.append(f"{walked} of {len(poisoning)} descriptions followed by the agent")
    print(f"\nWrote {args.out}: {'; '.join(lines)}.", file=sys.stderr)
    if undelivered:
        print(f"{undelivered} paths were never exercised: the agent did not read the "
              f"planted content, so those are not negative results.", file=sys.stderr)
    if not agent.trustworthy:
        print("Reminder: these results came from a scripted stand in and say nothing "
              "about real agent behaviour.", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- analyze

def cmd_analyze(args: argparse.Namespace) -> int:
    try:
        agent = load_manifest(args.manifest)
    except (ManifestError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    policy, code = _load_policy_for(args)
    if code:
        return code

    classify_agent(agent)
    apply_policy(agent, policy)
    findings = run_analysis(agent, policy)

    issues = find_issues(agent, policy)

    baseline = None
    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
        except BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    marked = apply_baseline(findings, baseline, issues)
    if marked:
        print(f"{marked} findings are in the baseline and will not fail this run",
              file=sys.stderr)

    if args.write_baseline:
        snapshot = build_baseline(findings, issues)
        Path(args.write_baseline).write_text(
            json.dumps(snapshot.to_dict(), indent=2), encoding="utf-8")
        print(f"wrote {len(snapshot.entries)} findings to {args.write_baseline}. "
              f"These will no longer fail a build. They are still real findings.",
              file=sys.stderr)
        return 0

    if args.confirmations:
        try:
            payload = json.loads(Path(args.confirmations).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: could not read confirmations: {exc}", file=sys.stderr)
            return 2
        apply_confirmations(findings, payload.get("results", []))
        apply_issue_confirmations(issues, payload.get("poisoning", []))

    if args.format == "json":
        text = to_json(agent, findings, issues)
    elif args.format == "html":
        from .report_html import to_html
        text = to_html(agent, findings)
    elif args.format == "sarif":
        from .sarif import to_sarif
        text = to_sarif(agent, findings, issues=issues)
    else:
        text = to_markdown(agent, findings, issues)

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {len(findings)} findings to {args.out}", file=sys.stderr)
    else:
        try:
            print(text)
        except BrokenPipeError:  # output piped into head, less and friends
            pass

    from .mitigation import undeclared_severity

    def severity_for_exit(finding):
        return (undeclared_severity(finding) if args.ignore_declared
                else finding.severity)

    triggered = any(
        at_least(severity_for_exit(finding), args.fail_on)
        for finding in findings
        if finding.counts_against_you
    ) or any(at_least(issue.severity, args.fail_on)
             for issue in issues if issue.counts_against_you)
    # An incomplete scan also exits non zero. In CI, a scan that quietly covered
    # half the servers should not pass as green.
    incomplete = not agent.complete and not args.allow_incomplete
    return 1 if (triggered or incomplete) else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        return cmd_analyze(args)
    if args.command == "collect":
        return cmd_collect(args)
    if args.command == "confirm":
        return cmd_confirm(args)
    if args.command == "import":
        return cmd_import(args)
    if args.command == "scan":
        return cmd_scan(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
