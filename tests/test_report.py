import json

from agentpath.findings import analyze
from agentpath.report import to_json, to_markdown


def test_markdown_contains_scenario_fix_and_reason(support_agent):
    text = to_markdown(support_agent, analyze(support_agent))
    assert "**Scenario.**" in text
    assert "**Fix.**" in text
    assert "Why these tools were labelled this way" in text


def test_markdown_says_candidates_are_not_confirmed(support_agent):
    text = to_markdown(support_agent, analyze(support_agent))
    assert "candidate" in text.lower()


def test_empty_report_does_not_claim_safety(docs_agent):
    text = to_markdown(docs_agent, analyze(docs_agent))
    assert "No attack paths found." in text
    assert "not a guarantee" in text


def test_json_is_valid_and_carries_every_finding(support_agent):
    findings = analyze(support_agent)
    payload = json.loads(to_json(support_agent, findings))
    assert payload["schema"] == "agentpath-report/v1"
    assert len(payload["findings"]) == len(findings)
    first = payload["findings"][0]
    for key in ("id", "rule", "severity", "status", "source", "sink", "scenario", "fix"):
        assert key in first
