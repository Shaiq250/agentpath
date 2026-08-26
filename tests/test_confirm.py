"""Tests for the confirmation harness.

The thing being guarded here is not really the mechanism, it is the honesty of
the output. A confirmation feature that overstates what it observed is worse than
no confirmation feature, so most of these tests are about wording and provenance
rather than about plumbing.
"""

import json

import pytest

from agentpath.agents import AgentUnavailable, ModelAgent, ScriptedAgent
from agentpath.confirm import apply_confirmations, confirm_all, confirm_finding
from agentpath.findings import analyze
from agentpath.harness import CONFIRMED, NOT_CONFIRMED, UNTESTABLE, Recorder, build_scenario, judge
from agentpath.payloads import LIBRARY, default_selection
from agentpath.report import to_json, to_markdown


# -- the harness -----------------------------------------------------------

def test_the_source_tool_serves_content_containing_the_payload():
    scenario = build_scenario("read_ticket", "send_email", LIBRARY[0], "APA-DEADBEEF")
    recorder = Recorder()
    content = scenario.handle(recorder, "read_ticket", {})
    assert "APA-DEADBEEF" in content
    assert "send_email" in content


def test_the_sink_records_the_call_and_does_nothing_else():
    """The whole safety argument: the real action never happens."""
    scenario = build_scenario("read_ticket", "issue_refund", LIBRARY[0], "APA-DEADBEEF")
    recorder = Recorder()
    result = scenario.handle(recorder, "issue_refund", {"amount": 500})
    assert json.loads(result) == {"status": "ok"}
    assert [c.name for c in recorder.calls] == ["issue_refund"]


def test_the_oracle_needs_the_marker_not_just_a_sink_call():
    """A sink call without the marker does not prove the planted data reached it."""
    scenario = build_scenario("read_ticket", "send_email", LIBRARY[0], "APA-DEADBEEF")
    recorder = Recorder()
    scenario.handle(recorder, "send_email", {"to": "someone@example.com"})
    verdict, evidence = judge(scenario, recorder)
    assert verdict == NOT_CONFIRMED
    assert evidence["sink_called"] is True
    assert evidence["sink_called_with_marker"] is False


def test_the_oracle_confirms_when_the_marker_travels():
    scenario = build_scenario("read_ticket", "send_email", LIBRARY[0], "APA-DEADBEEF")
    recorder = Recorder()
    scenario.handle(recorder, "send_email", {"reference": "APA-DEADBEEF"})
    verdict, evidence = judge(scenario, recorder)
    assert verdict == CONFIRMED
    assert "APA-DEADBEEF" in evidence["observed_call"]


def test_every_payload_carries_both_slots():
    for payload in LIBRARY:
        rendered = payload.render("do_thing", "APA-12345678")
        assert "do_thing" in rendered and "APA-12345678" in rendered


def test_attempts_cycle_through_different_payloads():
    """One refusal proves nothing, so a run has to vary the phrasing."""
    assert len({p.id for p in default_selection(3)}) == 3


# -- agents ----------------------------------------------------------------

def test_the_compliant_scripted_agent_walks_the_path(support_agent):
    finding = analyze(support_agent)[0]
    result = confirm_finding(finding, ScriptedAgent("follows"), attempts=2)
    assert result.verdict == CONFIRMED
    assert result.succeeded >= 1


def test_the_cautious_scripted_agent_does_not(support_agent):
    finding = analyze(support_agent)[0]
    result = confirm_finding(finding, ScriptedAgent("ignores"), attempts=2)
    assert result.verdict == NOT_CONFIRMED


def test_scripted_results_are_marked_untrustworthy(support_agent):
    """The single most important line in this module."""
    finding = analyze(support_agent)[0]
    result = confirm_finding(finding, ScriptedAgent("follows"), attempts=1)
    assert result.trustworthy is False
    assert "says nothing about whether a real agent" in result.caveat


def test_a_negative_result_always_carries_the_caveat(support_agent):
    finding = analyze(support_agent)[0]
    result = confirm_finding(finding, ScriptedAgent("ignores"), attempts=1)
    assert "not a guarantee of safety" in result.caveat


def test_no_api_key_means_untestable_not_a_silent_fallback(support_agent, monkeypatch):
    """Falling back to the scripted agent here would fake evidence."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(AgentUnavailable):
        ModelAgent()


def test_the_model_agent_loop_serves_tools_and_records_the_sink(support_agent):
    """Exercises the real API loop with a stubbed transport, no key, no network."""
    finding = analyze(support_agent)[0]
    sink = finding.sink.tool
    calls = {"n": 0}

    def transport(body):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"content": [{"type": "tool_use", "id": "1",
                                 "name": finding.source.tool, "input": {}}]}
        if calls["n"] == 2:
            # A compliant model: it read the content and obeyed it.
            served = body["messages"][-1]["content"][0]["content"]
            import re
            marker = re.search(r"APA-[0-9A-F]{8}", served).group(0)
            return {"content": [{"type": "tool_use", "id": "2", "name": sink,
                                 "input": {"reference": marker}}]}
        return {"content": [{"type": "text", "text": "done"}]}

    agent = ModelAgent(model="test-model", transport=transport)
    result = confirm_finding(finding, agent, attempts=1)
    assert result.verdict == CONFIRMED
    assert result.trustworthy is True
    assert result.caveat == ""


# -- report ----------------------------------------------------------------

def test_suppressed_findings_are_not_tested(research_agent):
    from agentpath.policy import parse_policy
    policy = parse_policy({"accept": [{"rule": "*", "reason": "accepted"}]})
    findings = analyze(research_agent, policy)
    assert confirm_all(findings, ScriptedAgent("follows")) == []


def test_the_report_names_the_scripted_agent_as_a_stand_in(support_agent):
    findings = analyze(support_agent)
    apply_confirmations(findings, confirm_all(findings, ScriptedAgent("follows"), 1))
    text = to_markdown(support_agent, findings)
    assert "A scripted stand in called" in text
    assert "not that a real agent behaves this way" in text


def test_the_report_names_a_real_model_by_name(support_agent):
    findings = analyze(support_agent)
    for finding in findings:
        finding.confirmation = {"finding_id": finding.id, "verdict": "confirmed",
                                "attempts": 3, "succeeded": 2, "trustworthy": True,
                                "agent_name": "claude-sonnet-4-6",
                                "observed_call": "issue_refund({})", "caveat": ""}
    text = to_markdown(support_agent, findings)
    assert "`claude-sonnet-4-6` called" in text
    assert "scripted stand in" not in text


def test_a_not_confirmed_finding_is_never_presented_as_safe(support_agent):
    findings = analyze(support_agent)
    apply_confirmations(findings, confirm_all(findings, ScriptedAgent("ignores"), 1))
    text = to_markdown(support_agent, findings)
    assert "Not confirmed." in text
    assert "not a guarantee of safety" in text


def test_a_not_confirmed_finding_stays_in_the_report(support_agent):
    """It is still a candidate. A negative test does not clear it."""
    findings = analyze(support_agent)
    before = len(findings)
    apply_confirmations(findings, confirm_all(findings, ScriptedAgent("ignores"), 1))
    text = to_markdown(support_agent, findings)
    assert text.count("### APA-") == before


def test_json_flags_a_scripted_only_run(support_agent):
    findings = analyze(support_agent)
    apply_confirmations(findings, confirm_all(findings, ScriptedAgent("follows"), 1))
    payload = json.loads(to_json(support_agent, findings))
    assert payload["confirmation"]["confirmed"] >= 1
    assert payload["confirmation"]["from_scripted_agent_only"] is True
