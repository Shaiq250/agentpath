"""Severity adjustment for what is already true about an environment.

The two properties worth protecting: a mitigation never removes a finding, and
anything the user merely asserted is labelled as asserted. agentpath cannot see
whether a sink is really gated behind human approval, only that someone wrote it
down, and a report that blurs those two is worse than one that ignores policy
altogether.
"""

from agentpath.classify import classify_agent
from agentpath.findings import analyze
from agentpath.mitigation import _shift, adjustments_for, apply_mitigations
from agentpath.model import parse_manifest
from agentpath.policy import PolicyError, apply_policy, parse_policy
from agentpath.report import to_markdown
import pytest


def two_server_agent(source_trust="third-party", sink_trust="privileged"):
    return classify_agent(parse_manifest({
        "schema": "agent-manifest/v1",
        "agent": {"name": "a"},
        "servers": [
            {"name": "inbox", "trust": source_trust, "tools": [
                {"name": "read_ticket", "description": "Read a support ticket.",
                 "annotations": {"openWorldHint": True}}]},
            {"name": "core", "trust": sink_trust, "tools": [
                {"name": "run_shell", "description": "Execute a shell command.",
                 "input_schema": {"command": "string"}}]},
        ],
    }))


# -- the ladder -------------------------------------------------------------

def test_severity_never_falls_off_either_end():
    assert _shift("low", -5) == "low"
    assert _shift("critical", 5) == "critical"
    assert _shift("high", -1) == "medium"
    assert _shift("medium", 1) == "high"


def test_a_mitigation_never_removes_a_finding():
    """The whole point. Lowering is not hiding, and only an accept entry hides."""
    agent = two_server_agent()
    policy = parse_policy({"gated": ["core/run_shell"],
                           "approved_flows": [{"from": "*", "to": "*",
                                               "reason": "all reviewed"}]})
    findings = analyze(agent, policy)
    assert len(findings) == 1
    finding = findings[0]
    # Adjustments are a net sum, so this is critical raised once for the boundary
    # then lowered twice. The property being guarded is that it is still here.
    assert finding.severity == "high"
    assert finding.original_severity == "critical"
    assert not finding.suppressed


# -- direction --------------------------------------------------------------

def test_reaching_a_more_trusted_domain_raises_severity():
    agent = two_server_agent("third-party", "privileged")
    finding = analyze(agent)[0]
    apply_mitigations([finding], agent, parse_policy({}))
    assert finding.severity == "critical"
    assert any(a["direction"] == "up" for a in finding.adjustments)


def test_the_other_direction_is_explained_but_not_raised():
    agent = two_server_agent("privileged", "third-party")
    finding = analyze(agent)[0]
    before = finding.severity
    apply_mitigations([finding], agent, parse_policy({}))
    assert finding.severity == before
    assert [a["direction"] for a in finding.adjustments] == ["note"]


def test_staying_inside_one_domain_lowers_severity():
    agent = two_server_agent("internal", "internal")
    finding = analyze(agent)[0]
    apply_mitigations([finding], agent, parse_policy({}))
    assert finding.severity == "high"
    assert finding.original_severity == "critical"


# -- declared versus observed -----------------------------------------------

def test_a_gate_is_recorded_as_declared_not_observed():
    """agentpath cannot see a human approval step. It can only be told about one."""
    agent = two_server_agent()
    policy = parse_policy({"gated": ["core/run_shell"]})
    adjustments = adjustments_for(analyze(agent)[0], agent, policy)
    gate = next(a for a in adjustments if "human approval" in a.reason)
    assert gate.declared is True


def test_boundary_reasoning_comes_from_the_data_not_the_user():
    adjustments = adjustments_for(analyze(two_server_agent())[0], two_server_agent(),
                                  parse_policy({}))
    assert all(not a.declared for a in adjustments)


def test_the_report_says_which_adjustments_were_merely_declared():
    agent = two_server_agent()
    policy = parse_policy({"gated": ["core/run_shell"]})
    text = to_markdown(agent, analyze(agent, policy))
    assert "declared in your policy file, not verified by this tool" in text
    assert "from the configuration itself" in text


# -- policy shapes ----------------------------------------------------------

def test_domains_group_servers_without_repeating_trust_per_server():
    agent = two_server_agent("unknown", "unknown")
    apply_policy(agent, parse_policy({"domains": {"privileged": ["core"],
                                                  "third-party": ["inbox"]}}))
    assert {s.name: s.trust for s in agent.servers} == {
        "inbox": "third-party", "core": "privileged"}


def test_an_explicit_trust_beats_a_domain_grouping():
    """The more specific statement should win."""
    agent = two_server_agent("unknown", "unknown")
    apply_policy(agent, parse_policy({"domains": {"privileged": ["core", "inbox"]},
                                      "trust": {"inbox": "third-party"}}))
    assert {s.name: s.trust for s in agent.servers}["inbox"] == "third-party"


def test_an_approved_flow_without_a_reason_is_rejected():
    """It lowers findings, so it has to record who thought about it."""
    with pytest.raises(PolicyError):
        parse_policy({"approved_flows": [{"from": "internal", "to": "internal"}]})


def test_an_approved_flow_offsets_a_boundary_crossing():
    """internal to privileged raises by one, and a reviewed flow gives that back."""
    agent = two_server_agent("internal", "privileged")
    raised = analyze(agent, parse_policy({}))[0]
    assert raised.severity == "critical"

    with_flow = analyze(two_server_agent("internal", "privileged"), parse_policy({
        "approved_flows": [{"from": "internal", "to": "privileged",
                            "reason": "same estate, reviewed"}]}))[0]
    assert with_flow.severity == "critical"  # already at the ceiling
    assert [a["direction"] for a in with_flow.adjustments] == ["up", "down"]
    assert any("reviewed" in a["reason"] for a in with_flow.adjustments)


def test_an_approved_flow_lowers_a_path_that_has_room_to_move():
    agent = two_server_agent("internal", "internal")
    plain = analyze(agent, parse_policy({}))[0]
    flowed = analyze(two_server_agent("internal", "internal"), parse_policy({
        "approved_flows": [{"from": "internal", "to": "internal",
                            "reason": "same estate, reviewed"}]}))[0]
    assert flowed.severity != plain.severity


def test_ignore_declared_uses_the_severity_before_any_claim():
    """A gated: line for a tool nobody gates should not be able to turn CI green."""
    from agentpath.mitigation import undeclared_severity

    agent = two_server_agent("internal", "internal")
    policy = parse_policy({"gated": ["core/run_shell"]})
    finding = analyze(agent, policy)[0]

    assert finding.original_severity == "critical"
    assert finding.severity == "medium"        # lowered by the domain and the claim
    assert undeclared_severity(finding) == "high"   # only the checkable part counts


def test_the_flag_changes_the_exit_code(tmp_path):
    import json
    from agentpath.cli import main
    from agentpath.model import manifest_to_dict

    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps(manifest_to_dict(two_server_agent("internal",
                                                                    "internal"))))
    policy = tmp_path / ".agentpath.yml"
    policy.write_text("gated:\n  - \"core/run_shell\"\n")

    assert main(["analyze", str(manifest), "--policy", str(policy),
                 "--fail-on", "high"]) == 0
    assert main(["analyze", str(manifest), "--policy", str(policy),
                 "--fail-on", "high", "--ignore-declared"]) == 1
