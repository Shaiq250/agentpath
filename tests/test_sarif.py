"""SARIF output, checked for shape and for honesty."""

import json

from agentpath.agents import ScriptedAgent
from agentpath.baseline import apply_baseline, build_baseline
from agentpath.confirm import apply_confirmations, confirm_all
from agentpath.findings import analyze
from agentpath.policy import parse_policy
from agentpath.sarif import to_sarif


def parse(agent, findings):
    return json.loads(to_sarif(agent, findings))


def test_sarif_has_the_required_shape(support_agent):
    doc = parse(support_agent, analyze(support_agent))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "agentpath"
    assert doc["runs"][0]["results"]


def test_every_rule_that_can_fire_is_declared(support_agent):
    doc = parse(support_agent, analyze(support_agent))
    declared = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    used = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert used <= declared


def test_results_carry_a_stable_fingerprint(support_agent):
    doc = parse(support_agent, analyze(support_agent))
    for result in doc["runs"][0]["results"]:
        assert result["partialFingerprints"]["agentpathPath/v1"]


def test_critical_maps_to_error(support_agent):
    doc = parse(support_agent, analyze(support_agent))
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["exfiltration_chain"] == "error"


def test_accepted_findings_appear_as_suppressions_not_omissions(research_agent):
    """Leaving them out would hide that the finding exists at all."""
    policy = parse_policy({"accept": [{"rule": "*", "reason": "internal channel only"}]})
    doc = parse(research_agent, analyze(research_agent, policy))
    result = doc["runs"][0]["results"][0]
    assert result["suppressions"][0]["justification"] == "internal channel only"


def test_baselined_findings_appear_as_suppressions(support_agent):
    findings = analyze(support_agent)
    apply_baseline(findings, build_baseline(analyze(support_agent)))
    doc = parse(support_agent, findings)
    assert all("suppressions" in r for r in doc["runs"][0]["results"])


def test_a_confirmed_finding_says_who_walked_it(support_agent):
    findings = analyze(support_agent)
    apply_confirmations(findings, confirm_all(findings, ScriptedAgent("follows"), 1))
    doc = parse(support_agent, findings)
    text = doc["runs"][0]["results"][0]["message"]["text"]
    assert "scripted stand in walked this path" in text


def test_an_incomplete_scan_is_reported_in_the_run(support_agent):
    from agentpath.model import EnumerationStatus, FAILED
    support_agent.servers[0].status = EnumerationStatus(FAILED, "boom")
    doc = parse(support_agent, analyze(support_agent))
    note = doc["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]
    assert "Scan incomplete" in note["message"]["text"]
