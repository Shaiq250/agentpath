import json

import pytest
import yaml

from agentpath.classify import classify_agent
from agentpath.cli import main
from agentpath.findings import analyze
from agentpath.labels import CODE_EXEC, UNTRUSTED_READ
from agentpath.policy import PolicyError, apply_policy, find_policy, load_policy, parse_policy
from agentpath.report import to_markdown

from conftest import EXAMPLES, has_path


def write(tmp_path, data):
    path = tmp_path / ".agentpath.yml"
    path.write_text(yaml.safe_dump(data))
    return path


# -- parsing ---------------------------------------------------------------

def test_bare_list_replaces_the_labels():
    policy = parse_policy({"labels": {"s/t": ["code-exec"]}})
    assert policy.label_sets["s/t"] == ["code-exec"]


def test_add_and_remove_are_separate_from_set():
    policy = parse_policy({"labels": {"s/t": {"add": ["egress"], "remove": ["secret-read"]}}})
    assert policy.label_adds["s/t"] == ["egress"]
    assert policy.label_removes["s/t"] == ["secret-read"]


def test_an_unknown_label_is_rejected_with_the_valid_ones():
    with pytest.raises(PolicyError) as exc:
        parse_policy({"labels": {"s/t": ["not-a-label"]}})
    assert "untrusted-read" in str(exc.value)


def test_an_acceptance_without_a_reason_is_rejected():
    """A decision nobody can review later is not a decision worth recording."""
    with pytest.raises(PolicyError):
        parse_policy({"accept": [{"rule": "untrusted_read_to_egress"}]})


def test_bad_yaml_is_reported_with_the_path(tmp_path):
    path = tmp_path / ".agentpath.yml"
    path.write_text("labels: [unclosed")
    with pytest.raises(PolicyError) as exc:
        load_policy(path)
    assert str(path) in str(exc.value)


def test_find_policy_does_not_walk_up_the_tree(tmp_path):
    """Silently inheriting suppressions from a parent directory would be nasty."""
    (tmp_path / ".agentpath.yml").write_text("{}")
    child = tmp_path / "child"
    child.mkdir()
    assert find_policy(child) is None
    assert find_policy(tmp_path) is not None


# -- label overrides -------------------------------------------------------

def test_clearing_labels_removes_the_findings(coding_agent):
    """The false positive escape hatch: this tool is not an entry point here."""
    before = analyze(coding_agent)
    assert has_path(before, "github/read_pull_request", "workspace/run_shell")

    policy = parse_policy({"labels": {"github/read_pull_request": []}})
    apply_policy(coding_agent, policy)
    after = analyze(coding_agent)
    assert not has_path(after, "github/read_pull_request", "workspace/run_shell")


def test_adding_a_label_creates_the_finding(coding_agent):
    """The false negative escape hatch: read_file IS an entry point here."""
    policy = parse_policy({"labels": {"workspace/read_file": {"add": ["untrusted-read"]}}})
    apply_policy(coding_agent, policy)
    findings = analyze(coding_agent)
    assert has_path(findings, "workspace/read_file", "workspace/run_shell",
                    rule="untrusted_read_to_code_exec")


def test_an_override_says_so_in_the_evidence(coding_agent):
    policy = parse_policy({"labels": {"workspace/read_file": {"add": ["untrusted-read"]}}})
    apply_policy(coding_agent, policy)
    tool = coding_agent.tool("workspace/read_file")
    assert tool.reason_for(UNTRUSTED_READ) == "set by .agentpath.yml"


def test_trust_overrides_change_boundary_crossing(research_agent):
    policy = parse_policy({"trust": {"web": "internal", "slack": "internal"}})
    apply_policy(research_agent, policy)
    findings = analyze(research_agent)
    assert all(not f.crosses_trust_boundary for f in findings)


# -- acceptance ------------------------------------------------------------

def test_an_accepted_path_is_suppressed_not_deleted(research_agent):
    policy = parse_policy({"accept": [{
        "rule": "untrusted_read_to_egress",
        "source": "web/fetch_url", "sink": "slack/post_message",
        "reason": "Reviewed, Slack channel is internal only", "date": "2026-09-01",
    }]})
    findings = analyze(research_agent, policy)
    assert [f.status for f in findings] == ["suppressed"]

    text = to_markdown(research_agent, findings)
    assert "## Accepted" in text
    assert "Slack channel is internal only" in text


def test_wildcards_match_a_whole_rule(support_agent):
    policy = parse_policy({"accept": [
        {"rule": "*", "reason": "whole agent accepted for now"},
    ]})
    findings = analyze(support_agent, policy)
    assert all(f.suppressed for f in findings)


def test_suppressed_findings_do_not_trigger_the_exit_code(tmp_path, capsys):
    write(tmp_path, {"accept": [{"rule": "*", "reason": "accepted"}]})
    manifest = EXAMPLES / "research-assistant.json"
    assert main(["analyze", str(manifest), "--policy", str(tmp_path / ".agentpath.yml")]) == 0
    assert main(["analyze", str(manifest), "--no-policy"]) == 1


def test_accepted_count_is_in_the_json(research_agent):
    from agentpath.report import to_json
    policy = parse_policy({"accept": [{"rule": "*", "reason": "accepted"}]})
    payload = json.loads(to_json(research_agent, analyze(research_agent, policy)))
    assert payload["counts"]["findings"] == 0
    assert payload["counts"]["accepted"] == 1


def test_a_missing_explicit_policy_path_is_an_error(capsys):
    code = main(["analyze", str(EXAMPLES / "support-agent.json"), "--policy", "/nope.yml"])
    assert code == 2


def test_an_all_accepted_result_does_not_claim_nothing_was_found(research_agent):
    """Same failure mode as the false all clear: findings existed, they were
    waved through, and the report must not imply the agent came up clean."""
    policy = parse_policy({"accept": [{"rule": "*", "reason": "accepted"}]})
    text = to_markdown(research_agent, analyze(research_agent, policy))
    assert "No attack paths found." not in text
    assert "No outstanding attack paths." in text
    assert "not the same as nothing being found" in text
