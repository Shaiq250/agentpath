"""Command line interface.

`analyze` is offline and reads a manifest. `collect`, which enumerates a live
agent's servers and writes that manifest, arrives in M1 and stays a separate
command so that analysis never needs a live system.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .classify import classify_agent
from .findings import analyze as run_analysis
from .labels import SEVERITIES, at_least
from .model import ManifestError, load_manifest
from .report import to_json, to_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentpath",
        description="Find attack paths in the tools available to an AI agent.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

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
    return parser


def cmd_analyze(args: argparse.Namespace) -> int:
    try:
        agent = load_manifest(args.manifest)
    except (ManifestError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    classify_agent(agent)
    findings = run_analysis(agent)

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

    return 1 if any(at_least(f.severity, args.fail_on) for f in findings) else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        return cmd_analyze(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
