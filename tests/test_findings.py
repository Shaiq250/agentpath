from agentpath.findings import analyze
from agentpath.labels import severity_rank

from conftest import has_path


def test_support_agent_finds_the_refund_path(support_agent):
    findings = analyze(support_agent)
    assert has_path(findings, "zendesk/read_ticket", "zendesk/issue_refund",
                    rule="untrusted_read_to_state_change")


def test_support_agent_finds_the_exfiltration_chain(support_agent):
    """A ticket can be read, customer records can be read, email goes out."""
    findings = analyze(support_agent)
    assert has_path(findings, "zendesk/read_ticket", "zendesk/send_email",
                    rule="exfiltration_chain")


def test_coding_assistant_finds_code_execution(coding_agent):
    findings = analyze(coding_agent)
    assert has_path(findings, "github/read_pull_request", "workspace/run_shell",
                    rule="untrusted_read_to_code_exec")
    critical = [f for f in findings if f.severity == "critical"]
    assert critical, "reading a PR into a shell tool is the critical case"


def test_research_assistant_finds_the_egress_path(research_agent):
    findings = analyze(research_agent)
    assert has_path(findings, "web/fetch_url", "slack/post_message")


def test_read_only_docs_agent_reports_nothing(docs_agent):
    """The negative fixture. If this ever fails we have started over reporting."""
    assert analyze(docs_agent) == []


def test_findings_are_ranked_most_severe_first(support_agent):
    findings = analyze(support_agent)
    ranks = [severity_rank(f.severity) for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_ids_are_assigned_in_report_order(support_agent):
    findings = analyze(support_agent)
    assert [f.id for f in findings] == [f"APA-{i:04d}" for i in range(1, len(findings) + 1)]


def test_one_finding_per_tool_pair(support_agent):
    """Two rules can match the same pair. Only the more severe one is reported."""
    findings = analyze(support_agent)
    pairs = [(f.source.tool, f.sink.tool) for f in findings]
    assert len(pairs) == len(set(pairs))


def test_trust_boundary_crossing_is_flagged(coding_agent):
    findings = analyze(coding_agent)
    crossing = [f for f in findings if f.crosses_trust_boundary]
    assert crossing, "third-party github into privileged workspace crosses a boundary"


def test_a_tool_is_never_a_path_to_itself():
    from agentpath.classify import classify_agent
    from agentpath.model import parse_manifest

    agent = parse_manifest({
        "schema": "agent-manifest/v1",
        "agent": {"name": "one"},
        "servers": [{"name": "s", "tools": [
            {"name": "fetch_and_send", "description": "Fetch a url and post it to a webhook.",
             "input_schema": {"url": "string", "webhook_url": "string"}},
        ]}],
    })
    classify_agent(agent)
    assert analyze(agent) == []
