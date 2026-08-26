"""Lock the classifier against the hand labelled corpus.

Read the honest caveat before trusting the numbers: the classifier was tuned
until it matched this corpus, so a perfect score here measures agreement with
our own labels, not accuracy on servers we have never seen. What the test is
genuinely good for is catching regressions. Change a rule, and any tool this
corpus covers that starts being labelled differently shows up immediately, by
name.

Adding servers to the corpus BEFORE touching the rules is how this becomes a
real measurement over time.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from measure_labels import measure  # noqa: E402


def test_corpus_and_ground_truth_cover_the_same_tools():
    measure()  # raises if a tool is in one and not the other


def test_no_regression_against_the_hand_labelled_corpus():
    result = measure()
    assert result["mistakes"] == [], "\n".join(["classifier changed:"] + result["mistakes"])


def test_the_corpus_is_big_enough_to_be_worth_running():
    assert measure()["tools"] >= 30


def test_entry_point_precision_is_never_traded_away():
    """One wrong entry point multiplies across every sink, so this label is the
    one place a false positive is more expensive than a false negative."""
    stats = measure()["stats"]["untrusted-read"]
    assert stats["fp"] == 0
