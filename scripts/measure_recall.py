"""Do the description rules CATCH poisoning they have never seen?

The false positive anchor asks whether the rules stay quiet on ordinary tools.
This asks the opposite and harder question, using deliberately vulnerable
servers published by other people: Invariant Labs' original tool poisoning and
shadowing demonstrations, and the Damn Vulnerable MCP challenge servers.

The labels come from those repositories' own documentation. DVMCP names which
challenge is the tool poisoning one and which is the shadowing one, so the answer
key was written by the people who built the samples rather than by anyone here.

Recall is the number that matters for a detector, and it is allowed to be bad.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentpath.classify import classify_agent  # noqa: E402
from agentpath.model import load_manifest  # noqa: E402
from agentpath.toolaudit import CONCEALED_TEXT, POISONED_DESCRIPTION, find_tool_issues  # noqa: E402

CORPUS = Path(__file__).resolve().parents[1] / "examples" / "recall"
DETECTS = {POISONED_DESCRIPTION, CONCEALED_TEXT}


def main() -> None:
    truth = json.loads((CORPUS / "ground-truth.json").read_text())["poisoned"]

    flagged: set[str] = set()
    seen: set[str] = set()
    for path in sorted(CORPUS.glob("*-server.json")):
        agent = classify_agent(load_manifest(path))
        for tool in agent.tools():
            seen.add(tool.qualified)
        for issue in find_tool_issues(agent):
            if issue.kind in DETECTS:
                flagged.update(issue.tools)

    caught = sorted(t for t, poisoned in truth.items() if poisoned and t in flagged)
    missed = sorted(t for t, poisoned in truth.items() if poisoned and t not in flagged)
    false_pos = sorted(t for t, poisoned in truth.items() if not poisoned and t in flagged)
    positives = len(caught) + len(missed)
    negatives = sum(1 for p in truth.values() if not p)

    print(f"Recall corpus: {len(truth)} tools, {positives} documented as poisoned "
          f"by their own repositories\n")
    print(f"caught          {len(caught)} of {positives} "
          f"({len(caught) / positives:.0%})")
    print(f"missed          {len(missed)}")
    print(f"false positives {len(false_pos)} of {negatives} benign tools\n")

    for name in missed:
        print(f"  MISSED {name}")
    for name in false_pos:
        print(f"  FALSE POSITIVE {name}")


if __name__ == "__main__":
    main()
