"""Measure the classifier against hand assigned labels.

Run: python scripts/measure_labels.py

Precision is what fraction of the labels we assign are correct, so it is the
false positive number. Recall is what fraction of the correct labels we find, so
it is the false negative number. Both matter, and they trade against each other:
the entry point label is tuned for precision on purpose, because every wrong
entry point multiplies across every sink in the agent.

The ground truth is our own judgement, written down in ground-truth.json with the
reasoning for the debatable calls. It is not an independent benchmark and the
README should not pretend otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentpath.classify import classify_agent  # noqa: E402
from agentpath.labels import ALL_LABELS  # noqa: E402
from agentpath.model import load_manifest  # noqa: E402

CORPUS = Path(__file__).resolve().parents[1] / "examples" / "corpus"


def measure() -> dict:
    truth = json.loads((CORPUS / "ground-truth.json").read_text())["tools"]

    predicted: dict[str, set[str]] = {}
    for path in sorted(CORPUS.glob("*.json")):
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
        got = predicted[tool]
        want = set(expected)
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


def rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 1.0


def main() -> None:
    result = measure()
    stats = result["stats"]

    print(f"Corpus: {result['tools']} tools across 6 servers\n")
    print(f"{'label':<16}{'precision':>11}{'recall':>9}{'tp':>5}{'fp':>5}{'fn':>5}")
    print("-" * 51)

    totals = {"tp": 0, "fp": 0, "fn": 0}
    for label in ALL_LABELS:
        s = stats[label]
        for key in totals:
            totals[key] += s[key]
        precision = rate(s["tp"], s["tp"] + s["fp"])
        recall = rate(s["tp"], s["tp"] + s["fn"])
        print(f"{label:<16}{precision:>11.2f}{recall:>9.2f}"
              f"{s['tp']:>5}{s['fp']:>5}{s['fn']:>5}")

    print("-" * 51)
    precision = rate(totals["tp"], totals["tp"] + totals["fp"])
    recall = rate(totals["tp"], totals["tp"] + totals["fn"])
    print(f"{'overall':<16}{precision:>11.2f}{recall:>9.2f}"
          f"{totals['tp']:>5}{totals['fp']:>5}{totals['fn']:>5}")

    if result["mistakes"]:
        print("\nEvery mistake, so none of them hide behind the averages:")
        for line in result["mistakes"]:
            print(line)


if __name__ == "__main__":
    main()
