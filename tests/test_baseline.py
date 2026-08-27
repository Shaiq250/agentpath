"""Baseline behaviour.

The risk this file guards against is a baseline quietly turning into approval.
A baseline is a snapshot with no judgement in it, and the report has to keep
saying so, otherwise a team ends up believing forty findings were reviewed when
nobody looked at any of them.
"""

import json

import pytest

from agentpath.baseline import BaselineError, apply_baseline, build_baseline, load_baseline
from agentpath.cli import main
from agentpath.findings import active, analyze
from agentpath.fingerprint import fingerprint, fingerprint_of
from agentpath.policy import parse_policy
from agentpath.report import to_markdown

from conftest import EXAMPLES


def test_fingerprint_is_stable_across_renumbering():
    """Ids are positional and shift when findings are added. Fingerprints do not."""
    a = fingerprint("rule_x", "s/source", "s/sink")
    b = fingerprint("rule_x", "s/source", "s/sink")
    assert a == b
    assert a != fingerprint("rule_y", "s/source", "s/sink")
    assert a != fingerprint("rule_x", "s/other", "s/sink")


def test_baseline_round_trip_marks_the_same_findings(support_agent):
    findings = analyze(support_agent)
    baseline = build_baseline(findings)
    assert len(baseline.entries) == len(findings)

    again = analyze(support_agent)
    assert apply_baseline(again, baseline) == len(again)
    assert all(f.baselined for f in again)
    assert active(again) == []


def test_a_new_finding_is_not_baselined(support_agent, coding_agent):
    """The whole point: old findings pass, new ones do not."""
    baseline = build_baseline(analyze(support_agent))
    other = analyze(coding_agent)
    assert apply_baseline(other, baseline) == 0
    assert all(not f.baselined for f in other)


def test_baselined_findings_do_not_fail_the_build(tmp_path):
    manifest = str(EXAMPLES / "support-agent.json")
    path = tmp_path / "bl.json"
    assert main(["analyze", manifest, "--write-baseline", str(path)]) == 0
    assert main(["analyze", manifest]) == 1
    assert main(["analyze", manifest, "--baseline", str(path)]) == 0


def test_the_report_says_a_baseline_is_not_approval(support_agent):
    findings = analyze(support_agent)
    apply_baseline(findings, build_baseline(analyze(support_agent)))
    text = to_markdown(support_agent, findings)
    assert "## Already in the baseline" in text
    assert "not a decision that any of it is acceptable" in text
    assert "No attack paths found." not in text


def test_an_all_baselined_result_does_not_claim_nothing_was_found(support_agent):
    findings = analyze(support_agent)
    apply_baseline(findings, build_baseline(analyze(support_agent)))
    text = to_markdown(support_agent, findings)
    assert "No new attack paths." in text
    assert "not the same as nothing being found" in text


def test_accepted_findings_are_not_written_into_a_baseline(research_agent):
    """Acceptance and baselining are different records and must not merge."""
    policy = parse_policy({"accept": [{"rule": "*", "reason": "reviewed"}]})
    findings = analyze(research_agent, policy)
    assert build_baseline(findings).entries == {}


def test_a_malformed_baseline_is_an_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{}")
    with pytest.raises(BaselineError):
        load_baseline(path)
