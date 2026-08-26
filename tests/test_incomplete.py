"""The false all clear is the worst thing this tool could produce.

A server that was never enumerated contributes zero tools, and zero tools looks
exactly like a harmless server unless the report says otherwise. These tests
exist to make sure it always says otherwise.
"""

import json

from agentpath.classify import classify_agent
from agentpath.cli import main
from agentpath.findings import analyze
from agentpath.model import manifest_to_dict, parse_manifest
from agentpath.report import to_json, to_markdown


def build(state="failed", reason="server exited before replying"):
    return parse_manifest({
        "schema": "agent-manifest/v2",
        "agent": {"name": "partial"},
        "servers": [
            {"name": "unknown-server", "command": "npx thing",
             "status": {"state": state, "reason": reason}, "tools": []},
        ],
    })


def test_v1_manifests_are_still_complete_by_construction():
    """Hand written manifests list their tools, so nothing is missing."""
    agent = parse_manifest({
        "schema": "agent-manifest/v1",
        "agent": {"name": "handmade"},
        "servers": [{"name": "s", "tools": [{"name": "t"}]}],
    })
    assert agent.complete is True


def test_report_never_says_no_attack_paths_found_when_incomplete():
    agent = classify_agent(build())
    text = to_markdown(agent, analyze(agent))
    assert "No attack paths found.\n" not in text
    assert "Scan incomplete." in text
    assert "not a clean result" in text


def test_report_names_the_missing_servers_and_the_reason():
    agent = classify_agent(build())
    text = to_markdown(agent, analyze(agent))
    assert "unknown-server" in text
    assert "server exited before replying" in text


def test_a_complete_empty_scan_still_reads_as_clean(docs_agent):
    text = to_markdown(docs_agent, analyze(docs_agent))
    assert "No attack paths found." in text
    assert "Scan incomplete." not in text


def test_json_carries_the_completeness_flag():
    agent = classify_agent(build())
    payload = json.loads(to_json(agent, analyze(agent)))
    assert payload["complete"] is False
    assert payload["unenumerated"][0]["server"] == "unknown-server"


def test_incomplete_scan_exits_non_zero_even_with_no_findings(tmp_path, capsys):
    """In CI, a scan that quietly covered half the servers must not pass green."""
    path = tmp_path / "m.json"
    path.write_text(json.dumps(manifest_to_dict(build(), {})))
    assert main(["analyze", str(path)]) == 1
    assert main(["analyze", str(path), "--allow-incomplete"]) == 0


def test_no_launch_mode_produces_an_incomplete_report(tmp_path):
    from agentpath.collect import collect
    from agentpath.discovery import ServerSpec

    result = collect(
        [ServerSpec(name="s", harness="test", source_path="/tmp/c.json", command="true")],
        launch=False, cache_file=tmp_path / "c.json")
    agent = classify_agent(result.agent)
    text = to_markdown(agent, analyze(agent))
    assert "Scan incomplete." in text
