import json

import pytest

from agentpath.model import ManifestError, parse_manifest

GOOD = {
    "schema": "agent-manifest/v1",
    "agent": {"name": "a"},
    "servers": [{"name": "s", "tools": [{"name": "t", "description": "d"}]}],
}


def test_parses_a_minimal_manifest():
    agent = parse_manifest(GOOD)
    assert agent.name == "a"
    assert [t.qualified for t in agent.tools()] == ["s/t"]


def test_rejects_wrong_schema():
    bad = dict(GOOD, schema="agent-manifest/v99")
    with pytest.raises(ManifestError):
        parse_manifest(bad)


def test_rejects_missing_agent_name():
    bad = dict(GOOD, agent={})
    with pytest.raises(ManifestError):
        parse_manifest(bad)


def test_rejects_duplicate_tool_names_on_one_server():
    bad = json.loads(json.dumps(GOOD))
    bad["servers"][0]["tools"].append({"name": "t"})
    with pytest.raises(ManifestError):
        parse_manifest(bad)


def test_trust_defaults_to_unknown(support_agent):
    tool = support_agent.tool("zendesk/read_ticket")
    assert support_agent.trust_of(tool) == "third-party"
