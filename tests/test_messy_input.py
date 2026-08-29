"""What happens when the input is what a real machine actually contains.

Every manifest in the other tests was written carefully. Config files on a real
machine are written by hand and by other tools, so fields arrive in the wrong
shape regularly. A scanner that throws on one malformed entry has stopped
scanning the whole machine, which is a worse outcome than reading that entry
generously.
"""

from agentpath.classify import classify_agent
from agentpath.crossserver import find_issues
from agentpath.discovery import parse_config
from agentpath.findings import analyze
from agentpath.model import parse_manifest
from agentpath.report import to_markdown
from agentpath.report_html import to_html
from agentpath.sarif import to_sarif


def analyse(manifest):
    agent = classify_agent(parse_manifest(manifest))
    findings = analyze(agent)
    issues = find_issues(agent)
    # Every output path has to survive it, not just the analysis.
    to_markdown(agent, findings, issues)
    to_html(agent, findings)
    to_sarif(agent, findings, issues=issues)
    return agent, findings


MESSY = {
    "schema": "agent-manifest/v1",
    "agent": {"name": "messy"},
    "servers": [{"name": "s", "tools": [
        {"name": "no_description"},
        {"name": "unicode_tool", "description": "Emoji \U0001f527 and unicode accents"},
        {"name": "very_long", "description": "x" * 20000},
        {"name": "weird chars/in name", "description": "Has a slash and a space."},
        {"name": "null_fields", "description": None, "input_schema": None,
         "annotations": None},
        {"name": "list_schema", "description": "Schema is a list",
         "input_schema": ["not", "a", "dict"]},
        {"name": "numeric_description", "description": 12345},
        {"name": "list_description", "description": ["a", "list", "of", "lines"]},
        {"name": "nested_annotations", "annotations": {"readOnlyHint": "yes please"}},
    ]}],
}


def test_a_manifest_full_of_wrong_types_still_analyses():
    agent, _ = analyse(MESSY)
    assert len(list(agent.tools())) == 9


def test_a_description_that_is_not_a_string_is_read_anyway():
    agent, _ = analyse(MESSY)
    assert agent.tool("s/numeric_description").description == "12345"
    assert "list of lines" in agent.tool("s/list_description").description


def test_a_schema_that_is_a_list_becomes_parameters():
    agent, _ = analyse(MESSY)
    assert set(agent.tool("s/list_schema").input_schema) == {"not", "a", "dict"}


def test_an_annotation_with_the_wrong_type_does_not_clear_a_tool():
    """readOnlyHint: "yes please" is not true, and must not be read as true."""
    agent, _ = analyse(MESSY)
    tool = agent.tool("s/nested_annotations")
    assert tool.annotations["readOnlyHint"] == "yes please"


def test_a_very_long_description_does_not_break_a_report():
    agent, findings = analyse(MESSY)
    assert len(to_markdown(agent, findings)) < 200_000


# -- config files -----------------------------------------------------------

def test_a_command_written_as_a_list():
    """Some tools serialise argv rather than a command string."""
    specs = parse_config({"mcpServers": {"a": {"command": ["npx", "thing"]}}}, "h", "/c")
    assert specs[0].command_line == "npx thing"


def test_args_written_as_a_single_string():
    """One string is one argument, not a string to iterate character by character."""
    specs = parse_config({"mcpServers": {"a": {"command": "npx", "args": "thing"}}},
                         "h", "/c")
    assert specs[0].args == ["thing"]


def test_a_numeric_server_name_becomes_a_string():
    specs = parse_config({"mcpServers": {5: {"command": "x"}}}, "h", "/c")
    assert specs[0].name == "5"


def test_env_values_that_are_not_strings():
    specs = parse_config({"mcpServers": {"a": {"command": "x", "env": {"K": ["a", "b"]}}}},
                         "h", "/c")
    assert specs[0].env == {"K": "a b"}


def test_entries_that_are_not_objects_are_skipped_not_fatal():
    raw = {"mcpServers": {"a": None, "b": "just a string",
                          "c": {"command": "real"}}}
    assert [s.name for s in parse_config(raw, "h", "/c")] == ["c"]
