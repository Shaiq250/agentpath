"""Guards on the held out corpus.

Nothing here measures accuracy. These tests exist to protect the conditions that
make the eventual number meaningful, because the corpus is only worth anything
while those conditions hold.
"""

import json
from pathlib import Path

import pytest

from agentpath.model import load_manifest

CORPUS = Path(__file__).resolve().parents[1] / "examples" / "heldout"


def truth():
    return json.loads((CORPUS / "ground-truth.json").read_text())


def test_every_manifest_parses():
    for path in sorted(CORPUS.glob("*-server.json")):
        agent = load_manifest(path)
        assert list(agent.tools())


def test_ground_truth_covers_exactly_the_corpus():
    listed = set(truth()["tools"])
    actual = set()
    for path in sorted(CORPUS.glob("*-server.json")):
        for tool in load_manifest(path).tools():
            actual.add(tool.qualified)
    assert listed == actual


def test_manifests_record_where_they_came_from():
    """A held out corpus is only credible if the data is traceable to a real server."""
    for path in sorted(CORPUS.glob("*-server.json")):
        raw = json.loads(path.read_text())
        assert raw.get("_source"), f"{path.name} does not say where its tools came from"


def test_labels_used_are_real_labels():
    from agentpath.labels import ALL_LABELS

    for tool, labels in truth()["tools"].items():
        if labels is None:
            continue
        for label in labels:
            assert label in ALL_LABELS, f"{tool} uses an unknown label {label!r}"


def test_the_measurement_refuses_to_run_while_unlabelled():
    """Measuring a half labelled corpus would produce a number that means nothing."""
    import subprocess
    import sys

    script = Path(__file__).resolve().parents[1] / "scripts" / "measure_heldout.py"
    if all(v is not None for v in truth()["tools"].values()):
        pytest.skip("corpus is labelled, so the guard no longer applies")
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
    assert result.returncode != 0
    assert "not labelled yet" in result.stdout + result.stderr


def test_the_recorded_result_is_kept():
    """The pre-fix number stays in the repo so it cannot be quietly improved."""
    recorded = CORPUS / "RESULT-2026-08-27.txt"
    assert recorded.is_file()
    text = recorded.read_text()
    assert "before any rule was changed" in text
    assert "39 of 42" in text


def test_annotation_blind_mode_really_ignores_annotations():
    """The whole measurement rests on this, so it gets its own test."""
    from agentpath.classify import classify_tool
    from agentpath.labels import STATE_CHANGE, UNTRUSTED_READ
    from agentpath.model import Tool

    tool = Tool(name="opaque_thing", server="s", description="Does a thing.",
                annotations={"destructiveHint": True, "openWorldHint": True})
    blind = {hit.label for hit in classify_tool(tool, use_annotations=False)}
    seeing = {hit.label for hit in classify_tool(tool, use_annotations=True)}
    assert STATE_CHANGE not in blind and UNTRUSTED_READ not in blind
    assert STATE_CHANGE in seeing and UNTRUSTED_READ in seeing


def test_the_verbs_the_measurement_found_are_covered_now():
    """Regression guard for the three misses recorded in RESULT-2026-08-27.txt."""
    from agentpath.classify import classify_tool
    from agentpath.labels import STATE_CHANGE
    from agentpath.model import Tool

    for name, desc in [("git_commit", "Records changes to the repository"),
                       ("git_reset", "Unstages all staged changes"),
                       ("git_checkout", "Switches branches")]:
        labels = {h.label for h in classify_tool(Tool(name=name, server="git",
                                                      description=desc),
                                                 use_annotations=False)}
        assert STATE_CHANGE in labels, f"{name} lost its state-change label again"


def test_read_only_false_is_treated_as_a_state_change_declaration():
    """An author writing readOnlyHint=false is saying the tool changes something.

    destructiveHint only separates destructive changes from additive ones, so
    acting on it alone discards the plainer statement: creating a project is not
    destructive and is still a change.
    """
    from agentpath.classify import classify_tool
    from agentpath.labels import STATE_CHANGE
    from agentpath.model import Tool

    tool = Tool(name="create_team", server="s", description="Create a new team.",
                annotations={"readOnlyHint": False, "destructiveHint": False})
    assert STATE_CHANGE in {h.label for h in classify_tool(tool)}


def test_the_second_batch_result_is_kept():
    recorded = Path(__file__).resolve().parents[1] / "examples" / "heldout-2" / "RESULT-2026-08-27.txt"
    assert recorded.is_file()
    assert "before any rule or mapping was changed" in recorded.read_text()


def test_the_open_world_mapping_stays_retired():
    """It was retired for a reason. Putting it back needs an argument, not a diff."""
    script = (Path(__file__).resolve().parents[1] / "scripts"
              / "measure_annotations.py").read_text()
    assert "openWorldHint" in script, "the reasoning should stay documented"
    assert '("openWorldHint", UNTRUSTED_READ' not in script, "the comparison must not return"
