"""Measure false positives against InjecAgent's legitimate tools.

InjecAgent (Zhan et al.) tests something different from this project's
description rules: it injects attacker instructions into tool RESPONSES, the
content an agent reads back, rather than into tool descriptions. So it cannot
measure whether these rules catch a poisoned description.

What it can measure, and what no corpus here had measured before, is the other
half. Its toolkit definitions are hundreds of ordinary tool descriptions written
by people with no connection to this project and no interest in its rules. Every
finding on them is a false positive.

Precision is the half these rules claim to be strongest at, and it is the half
that decides whether anyone keeps a scanner installed. This is the first fully
independent test of it.

    git clone https://github.com/uiuc-kang-lab/InjecAgent /tmp/injecagent
    python scripts/measure_injecagent.py /tmp/injecagent
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentpath.classify import classify_agent  # noqa: E402
from agentpath.model import parse_manifest  # noqa: E402
from agentpath.toolaudit import find_tool_issues  # noqa: E402


def load_tools(root: Path) -> list[dict]:
    raw = json.loads((root / "data" / "tools.json").read_text(encoding="utf-8"))
    out = []
    for toolkit in raw:
        kit = toolkit.get("name_for_model") or toolkit.get("toolkit") or "kit"
        for tool in toolkit.get("tools", []) or []:
            name = tool.get("name")
            description = tool.get("summary") or tool.get("description") or ""
            if not name or not description:
                continue
            params = {p.get("name", f"p{i}"): "string"
                      for i, p in enumerate(tool.get("parameters", []) or [])
                      if isinstance(p, dict)}
            out.append({"kit": str(kit), "name": str(name),
                        "description": str(description), "params": params})
    return out


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    root = Path(sys.argv[1])
    tools = load_tools(root)
    if not tools:
        raise SystemExit(f"no tools found under {root}")

    by_kit: dict[str, list[dict]] = {}
    for index, tool in enumerate(tools):
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{tool['name']}__{index}")
        by_kit.setdefault(tool["kit"], []).append(
            {"name": safe, "description": tool["description"],
             "input_schema": tool["params"]})

    flagged = []
    for kit, entries in by_kit.items():
        agent = classify_agent(parse_manifest({
            "schema": "agent-manifest/v1",
            "agent": {"name": "injecagent"},
            "servers": [{"name": re.sub(r"[^A-Za-z0-9_.-]", "_", kit), "tools": entries}],
        }))
        for issue in find_tool_issues(agent):
            flagged.append((issue.kind, issue.tools, issue.evidence.get("matched")))

    print("InjecAgent legitimate toolkits, false positives only")
    print("Zhan et al. Their tool definitions, none of them poisoned.\n")
    print(f"toolkits            {len(by_kit)}")
    print(f"tool descriptions   {len(tools)}")
    print(f"falsely flagged     {len(flagged)}  "
          f"({len(flagged) / len(tools):.1%})\n")
    for kind, names, matched in flagged:
        print(f"  {kind}  {names}")
        print(f"    matched: {matched}")


if __name__ == "__main__":
    main()
