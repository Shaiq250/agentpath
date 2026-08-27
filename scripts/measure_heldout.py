"""Measure the classifier against servers it was never tuned on.

The difference between this and measure_labels.py is not the code, it is the
order things happened in. The tuned corpus was labelled, measured, and then the
rules were changed until they matched, so its score says how well the tool agrees
with tools it has already seen. This corpus was labelled before the tool was ever
run against it, and the rules must not be touched between the labelling and the
result.

That makes this the number that means something, and it is allowed to be bad.
A held out score that comes out lower is the tool telling you the truth, which is
the entire point of holding a corpus out.

Once you have read the result, this batch is spent. Every future measurement
needs servers nobody has looked at yet.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentpath.classify import classify_agent  # noqa: E402
from agentpath.labels import ALL_LABELS  # noqa: E402
from agentpath.model import load_manifest  # noqa: E402

CORPUS = Path(__file__).resolve().parents[1] / "examples" / "heldout"


def load_truth() -> dict[str, list[str]]:
    raw = json.loads((CORPUS / "ground-truth.json").read_text())["tools"]
    unlabelled = sorted(name for name, labels in raw.items() if labels is None)
    if unlabelled:
        raise SystemExit(
            "This corpus is not labelled yet, so there is nothing to measure.\n"
            f"{len(unlabelled)} tools still have null in ground-truth.json, starting with:\n"
            + "\n".join(f"  {name}" for name in unlabelled[:5])
            + "\n\nRead examples/heldout/WORKSHEET.md, decide the labels yourself, and fill\n"
              "them in before running this. Labelling after seeing the result would make\n"
              "the number worthless."
        )
    return raw


def measure() -> dict:
    truth = load_truth()

    predicted: dict[str, set[str]] = {}
    for path in sorted(CORPUS.glob("*-server.json")):
        if path.name == "ground-truth.json":
            continue
        agent = classify_agent(load_manifest(path))
        for tool in agent.tools():
            predicted[tool.qualified] = tool.label_set()

    missing = sorted(set(truth) - set(predicted))
    extra = sorted(set(predicted) - set(truth))
    if missing or extra:
        raise SystemExit(f"corpus and ground truth disagree.\nmissing: {missing}\nextra: {extra}")

    stats = {label: {"tp": 0, "fp": 0, "fn": 0} for label in ALL_LABELS}
    mistakes: list[str] = []
    for tool, expected in truth.items():
        got, want = predicted[tool], set(expected)
        for label in ALL_LABELS:
            if label in got and label in want:
                stats[label]["tp"] += 1
            elif label in got and label not in want:
                stats[label]["fp"] += 1
                mistakes.append(f"  false positive  {tool}: {label}")
            elif label not in got and label in want:
                stats[label]["fn"] += 1
                mistakes.append(f"  false negative  {tool}: {label}")
    return {"stats": stats, "mistakes": mistakes, "tools": len(truth)}


def rate(num: int, den: int) -> float:
    return num / den if den else 1.0


def main() -> None:
    result = measure()
    stats = result["stats"]
    servers = len(list(CORPUS.glob("*-server.json")))

    print(f"Held out corpus: {result['tools']} tools across {servers} servers")
    print("Labelled before the tool was run against them. Rules unchanged since.\n")
    print(f"{'label':<16}{'precision':>11}{'recall':>9}{'tp':>5}{'fp':>5}{'fn':>5}")
    print("-" * 51)

    totals = {"tp": 0, "fp": 0, "fn": 0}
    for label in ALL_LABELS:
        s = stats[label]
        for key in totals:
            totals[key] += s[key]
        print(f"{label:<16}{rate(s['tp'], s['tp'] + s['fp']):>11.2f}"
              f"{rate(s['tp'], s['tp'] + s['fn']):>9.2f}{s['tp']:>5}{s['fp']:>5}{s['fn']:>5}")

    print("-" * 51)
    print(f"{'overall':<16}{rate(totals['tp'], totals['tp'] + totals['fp']):>11.2f}"
          f"{rate(totals['tp'], totals['tp'] + totals['fn']):>9.2f}"
          f"{totals['tp']:>5}{totals['fp']:>5}{totals['fn']:>5}")

    if result["mistakes"]:
        print("\nEvery mistake, so none of them hide behind the averages:")
        for line in result["mistakes"]:
            print(line)
        print("\nThis is the honest number. Put it in the README before you fix anything.")


if __name__ == "__main__":
    main()
