"""Check the rules against an answer key neither of us wrote.

The problem with measuring a classifier is finding ground truth that did not
come from the same head as the rules. Hand labelling by the person who wrote the
rules only proves they are internally consistent.

MCP tool annotations are a way out. Server authors declare, in their own source,
what their tools do: readOnlyHint says a tool does not modify its environment,
openWorldHint says it reaches out to external entities. Those declarations were
written by people who had never heard of this tool, which makes them independent
in exactly the way a corpus we wrote ourselves is not.

So: switch the annotations off, work out what each tool does from its name,
description and schema alone, and see whether that agrees with what its author
declared.

Two mappings, both taken straight from the MCP specification:

  readOnlyHint true   the tool does not modify its environment,
                      so it should NOT be labelled state-change
  readOnlyHint false  the tool does modify something,
                      so it SHOULD be labelled state-change
  openWorldHint true  the tool interacts with external entities,
                      so untrusted-read is expected
  openWorldHint false it does not, so untrusted-read is not expected

Limits worth stating plainly. This only covers the two labels annotations speak
to, only for tools whose authors bothered to write them, and an annotation can
itself be wrong or lazily copied. It is a narrower check than full labelling. It
is also the only measurement here whose answer key is genuinely external.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentpath.classify import classify_tool  # noqa: E402
from agentpath.labels import STATE_CHANGE, UNTRUSTED_READ  # noqa: E402
from agentpath.model import load_manifest  # noqa: E402

CORPUS = Path(__file__).resolve().parents[1] / "examples" / "heldout"


def collect() -> list[tuple[str, dict, set[str]]]:
    rows = []
    for path in sorted(CORPUS.glob("*-server.json")):
        agent = load_manifest(path)
        for tool in agent.tools():
            if not tool.annotations:
                continue  # nothing declared, so nothing to check against
            blind = {hit.label for hit in classify_tool(tool, use_annotations=False)}
            rows.append((tool.qualified, tool.annotations, blind))
    return rows


def check(rows, key: str, label: str, expect_when_true: bool):
    """Compare our blind reading against one declared annotation."""
    agree, disagree = 0, []
    for name, annotations, blind in rows:
        if key not in annotations:
            continue
        declared = annotations[key]
        expected = declared if expect_when_true else not declared
        got = label in blind
        if got == expected:
            agree += 1
        else:
            disagree.append((name, declared, got))
    return agree, disagree


def main() -> None:
    rows = collect()
    if not rows:
        raise SystemExit("no annotated tools found in the held out corpus")

    print(f"Agreement with server author annotations")
    print(f"{len(rows)} annotated tools, classified without reading their annotations.\n")

    total_agree = total_seen = 0

    for key, label, expect_when_true, blurb in [
        ("readOnlyHint", STATE_CHANGE, False,
         "readOnlyHint false means the tool modifies something, so we expect state-change"),
        ("openWorldHint", UNTRUSTED_READ, True,
         "openWorldHint true means the tool reaches outside, so we expect untrusted-read"),
    ]:
        agree, disagree = check(rows, key, label, expect_when_true)
        seen = agree + len(disagree)
        if not seen:
            continue
        total_agree += agree
        total_seen += seen
        print(f"{key} vs {label}")
        print(f"  {blurb}")
        print(f"  agreed on {agree} of {seen} ({agree / seen:.0%})")
        for name, declared, got in disagree:
            said = "we said yes" if got else "we said no"
            print(f"    disagreed: {name}, author said {key}={str(declared).lower()}, {said}")
        print()

    print(f"Overall agreement: {total_agree} of {total_seen} "
          f"({total_agree / total_seen:.0%})" if total_seen else "nothing to compare")
    print("\nEvery disagreement above is either a rule that needs work or an annotation")
    print("that does not match its own description. Both are worth looking at, and the")
    print("second is itself a finding worth reporting.")


if __name__ == "__main__":
    main()
