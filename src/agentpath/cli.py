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

from .classify import classify_agent
from .collect import collect as run_collect
from .discovery import ServerSpec, config_locations, discover
from .findings import analyze as run_analysis
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

    analyze = sub.add_parser("analyze", help="analyse an agent manifest, offline")
    analyze.add_argument("manifest", help="path to an agent manifest JSON file")
    analyze.add_argument("-o", "--out", help="write the report to a file instead of stdout")
    analyze.add_argument("--format", choices=("md", "json"), default="md")
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
    launchable = [spec for spec in specs if spec.transport == "stdio"]
    if not launchable:
        return
    print("agentpath is about to start the following servers to ask for their tools.",
          file=sys.stderr)
    print("This runs the commands exactly as your config files define them:", file=sys.stderr)
    for spec in launchable:
        print(f"  {spec.name}: {spec.command_line}", file=sys.stderr)
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


# ---------------------------------------------------------------- analyze

def cmd_analyze(args: argparse.Namespace) -> int:
    try:
        agent = load_manifest(args.manifest)
    except (ManifestError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    policy = None
    if not args.no_policy:
        policy_path = Path(args.policy) if args.policy else find_policy()
        if args.policy and not Path(args.policy).is_file():
            print(f"error: no policy file at {args.policy}", file=sys.stderr)
            return 2
        if policy_path:
            try:
                policy = load_policy(policy_path)
            except PolicyError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            print(f"using policy {policy_path}", file=sys.stderr)

    classify_agent(agent)
    apply_policy(agent, policy)
    findings = run_analysis(agent, policy)

    render = to_json if args.format == "json" else to_markdown
    text = render(agent, findings)

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {len(findings)} findings to {args.out}", file=sys.stderr)
    else:
        try:
            print(text)
        except BrokenPipeError:  # output piped into head, less and friends
            pass

    triggered = any(
        at_least(finding.severity, args.fail_on)
        for finding in findings
        if not finding.suppressed
    )
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
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
