"""Measure the description rules against the MCPTox benchmark.

MCPTox is an academic benchmark for tool poisoning, built on 45 live MCP servers
and their real tools, with malicious tool descriptions generated from three
attack templates across eleven risk categories. Wang et al., AAAI 2026,
arXiv:2508.14925.

Why it is worth using. Every other measurement in this project rests on a corpus
somebody here assembled, which caps how much the numbers are worth. This one was
built by other people, for a different purpose, and is cited by other work. It
also supplies both halves at once: the poisoned descriptions are the positives,
and the legitimate tools of the same servers are the negatives, so recall and
false positives come from the same place.

The benchmark is NOT vendored into this repository. It carries no licence, so
copying it here would be presumptuous at best. Clone it yourself and point this
script at it:

    git clone https://github.com/zhiqiangwang4/MCPTox-Benchmark /tmp/mcptox
    python scripts/measure_mcptox.py /tmp/mcptox

What is measured is DETECTION only: whether the rules recognise a poisoned
description. Whether a model would follow one is a different question, and
agentpath answers that with `confirm --what poisoning`.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentpath.classify import classify_agent  # noqa: E402
from agentpath.model import parse_manifest  # noqa: E402
from agentpath.toolaudit import (  # noqa: E402
    CONCEALED_TEXT,
    POISONED_DESCRIPTION,
    find_tool_issues,
)

DETECTS = {POISONED_DESCRIPTION, CONCEALED_TEXT}
# "Tool: name" then "Description: ..." until the arguments block or a blank run.
LEGIT = re.compile(r"^Tool:\s*(\S+)\s*\nDescription:\s*(.*?)(?=\nArguments:|\n\n\n|\Z)",
                   re.M | re.S)


def load_poisoned(root: Path) -> list[dict]:
    """The malicious tool descriptions, one per test case."""
    raw = json.loads((root / "pure_tool.json").read_text(encoding="utf-8"))
    out = []
    for block in raw:
        for case_id, case in block.items():
            description = (case.get("tool_content") or "").strip()
            if description:
                out.append({"id": case_id,
                            "server": case.get("server_name", ""),
                            "name": case.get("tool_name") or "poisoned_tool",
                            "description": description})
    return out


def load_legitimate(root: Path) -> list[dict]:
    """The real tools of the same servers, parsed out of the clean prompts.

    These are the negatives, and they matter more than the positives. A rule
    that flags everything scores perfectly on recall and is worthless.
    """
    raw = json.loads((root / "response_all.json").read_text(encoding="utf-8"))
    seen: set[tuple[str, str]] = set()
    out = []
    for server_name, server in (raw.get("servers") or {}).items():
        prompt = server.get("clean_system_promot") or ""
        for name, description in LEGIT.findall(prompt):
            description = " ".join(description.split())
            key = (server_name, name)
            if not description or key in seen:
                continue
            seen.add(key)
            out.append({"server": server_name, "name": name,
                        "description": description})
    return out


def flagged(tools: list[dict]) -> set[str]:
    """Run the rules over a batch and return which tools were flagged."""
    hits: set[str] = set()
    # One manifest per server keeps qualified names unique and mirrors how the
    # rules see a real agent.
    by_server: dict[str, list[dict]] = {}
    for index, tool in enumerate(tools):
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{tool['name']}__{index}")
        by_server.setdefault(tool["server"] or "unknown", []).append(
            {"name": safe, "description": tool["description"], "input_schema": {}})

    for server, entries in by_server.items():
        agent = classify_agent(parse_manifest({
            "schema": "agent-manifest/v1",
            "agent": {"name": "mcptox"},
            "servers": [{"name": re.sub(r"[^A-Za-z0-9_.-]", "_", server),
                         "tools": entries}],
        }))
        for issue in find_tool_issues(agent):
            if issue.kind in DETECTS:
                hits.update(issue.tools)
    return hits


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    root = Path(sys.argv[1])
    if not (root / "pure_tool.json").is_file():
        raise SystemExit(f"{root} does not look like a MCPTox checkout")

    poisoned = load_poisoned(root)
    legitimate = load_legitimate(root)
    if not poisoned or not legitimate:
        raise SystemExit("could not read the benchmark: found "
                         f"{len(poisoned)} poisoned and {len(legitimate)} legitimate tools")

    caught = flagged(poisoned)
    false_hits = flagged(legitimate)

    recall = len(caught) / len(poisoned)
    fp_rate = len(false_hits) / len(legitimate)

    print("MCPTox benchmark, detection only")
    print("Wang et al., AAAI 2026. 45 real servers.\n")
    print(f"poisoned descriptions   {len(poisoned)}")
    print(f"  detected              {len(caught)}  ({recall:.0%} recall)")
    print(f"  missed                {len(poisoned) - len(caught)}\n")
    print(f"legitimate tools        {len(legitimate)}")
    print(f"  falsely flagged       {len(false_hits)}  ({fp_rate:.0%} false positive rate)\n")

    missed = [t for t, tool in zip(sorted(range(len(poisoned))), poisoned)]
    misses = [tool for index, tool in enumerate(poisoned)
              if not any(str(index) in hit for hit in caught)]
    print("A sample of what was missed, since the misses are the useful part:")
    for tool in misses[:5]:
        text = " ".join(tool["description"].split())
        print(f"  {tool['server']}/{tool['name']}: {text[:150]}")

    if false_hits:
        print("\nFalsely flagged legitimate tools:")
        for hit in sorted(false_hits)[:10]:
            print(f"  {hit}")


if __name__ == "__main__":
    main()
