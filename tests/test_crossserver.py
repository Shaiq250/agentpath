"""Cross server issues: shadowing, confusable names, and drift.

These are the findings that only exist because several servers share one agent,
so none of them can be seen by looking at a tool on its own.
"""

import json

from agentpath.classify import classify_agent
from agentpath.crossserver import (
    ADDED,
    CONFUSABLE,
    DRIFT,
    REMOVED,
    SHADOWING,
    find_issues,
    no_baseline_servers,
)
from agentpath.findings import analyze
from agentpath.model import load_manifest, parse_manifest
from agentpath.report import to_json, to_markdown

from conftest import EXAMPLES


def shadowed():
    return classify_agent(load_manifest(EXAMPLES / "shadowed-agent.json"))


def kinds(issues):
    return [issue.kind for issue in issues]


# -- shadowing -------------------------------------------------------------

def test_two_servers_claiming_one_name_is_reported():
    issues = find_issues(shadowed())
    shadowing = [i for i in issues if i.kind == SHADOWING]
    assert len(shadowing) == 1
    assert shadowing[0].tools == ["community-plugin/read_file", "workspace/read_file"]


def test_a_trust_asymmetry_raises_the_severity():
    """A third party server standing in for a privileged one is the attack."""
    issue = next(i for i in find_issues(shadowed()) if i.kind == SHADOWING)
    assert issue.severity in ("critical", "high")
    assert "not equally trusted" in issue.detail


def test_equally_trusted_shadowing_is_still_reported_but_lower():
    agent = classify_agent(parse_manifest({
        "schema": "agent-manifest/v1",
        "agent": {"name": "a"},
        "servers": [
            {"name": "one", "trust": "internal",
             "tools": [{"name": "lookup", "description": "Look something up."}]},
            {"name": "two", "trust": "internal",
             "tools": [{"name": "lookup", "description": "Look something up."}]},
        ],
    }))
    issue = next(i for i in find_issues(agent) if i.kind == SHADOWING)
    assert issue.severity in ("medium", "high")
    assert "not equally trusted" not in issue.detail


# -- confusable ------------------------------------------------------------

def test_names_differing_only_by_case_or_version_are_flagged():
    issues = [i for i in find_issues(shadowed()) if i.kind == CONFUSABLE]
    assert issues
    assert set(issues[0].tools) == {"workspace/send_report", "community-plugin/sendReport2"}


def test_identical_names_are_not_reported_twice():
    """An exact clash is shadowing. It must not also appear as confusable."""
    issues = find_issues(shadowed())
    confusable_tools = [set(i.tools) for i in issues if i.kind == CONFUSABLE]
    assert {"workspace/read_file", "community-plugin/read_file"} not in confusable_tools


def test_similar_names_on_one_server_are_left_alone():
    """One author naming their own tools is their business, not a finding."""
    agent = classify_agent(parse_manifest({
        "schema": "agent-manifest/v1",
        "agent": {"name": "a"},
        "servers": [{"name": "one", "tools": [
            {"name": "get_item", "description": "Get an item."},
            {"name": "getItem2", "description": "Get an item, newer."},
        ]}],
    }))
    assert not [i for i in find_issues(agent) if i.kind == CONFUSABLE]


# -- drift -----------------------------------------------------------------

def test_a_changed_definition_becomes_a_high_severity_issue():
    issue = next(i for i in find_issues(shadowed()) if i.kind == DRIFT)
    assert issue.severity == "high"
    assert "telemetry endpoint" in issue.detail


def test_added_and_removed_tools_are_distinguished():
    agent = classify_agent(parse_manifest({
        "schema": "agent-manifest/v2",
        "agent": {"name": "a"},
        "servers": [{"name": "s", "seen_before": True, "drift": [
            {"tool": "new_thing", "change": "added", "detail": "appeared"},
            {"tool": "old_thing", "change": "removed", "detail": "gone"},
        ], "tools": [{"name": "new_thing", "description": "x"}]}],
    }))
    found = kinds(find_issues(agent))
    assert ADDED in found and REMOVED in found


# -- the first scan problem ------------------------------------------------

def test_a_server_never_seen_before_cannot_have_been_checked_for_drift(support_agent):
    """Silence on a first scan would be the false all clear again."""
    assert no_baseline_servers(support_agent) == [s.name for s in support_agent.servers]


def test_the_report_says_drift_was_not_checked(support_agent):
    text = to_markdown(support_agent, analyze(support_agent), find_issues(support_agent))
    assert "Drift was not checked for every server" in text
    assert "no conclusion about whether" in text


def test_a_previously_seen_server_does_not_trigger_the_note():
    agent = shadowed()
    assert no_baseline_servers(agent) == []
    text = to_markdown(agent, analyze(agent), find_issues(agent))
    assert "Drift was not checked" not in text


# -- output ----------------------------------------------------------------

def test_issues_appear_in_the_markdown_report():
    agent = shadowed()
    text = to_markdown(agent, analyze(agent), find_issues(agent))
    assert "## Between servers" in text
    assert "APX-0001" in text


def test_issues_appear_in_json():
    agent = shadowed()
    payload = json.loads(to_json(agent, analyze(agent), find_issues(agent)))
    assert payload["cross_server_issues"]
    assert payload["drift_not_checked"] == []


def test_issues_appear_in_sarif():
    from agentpath.sarif import to_sarif

    agent = shadowed()
    doc = json.loads(to_sarif(agent, analyze(agent), issues=find_issues(agent)))
    rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert SHADOWING in rule_ids
    declared = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids <= declared


def test_a_shadowing_issue_can_fail_the_build():
    from agentpath.cli import main
    assert main(["analyze", str(EXAMPLES / "shadowed-agent.json"),
                 "--fail-on", "high"]) == 1
