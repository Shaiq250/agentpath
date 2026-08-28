"""Bringing in tools that did not come from MCP.

The analysis never cared where a tool came from, and these tests exist to keep it
that way: an imported manifest goes through the same classifier, the same rules
and the same report as a collected one.
"""

import json

import pytest

from agentpath.classify import classify_agent
from agentpath.findings import analyze
from agentpath.importers import ImportError_, detect, from_openapi, from_tool_definitions, to_manifest
from agentpath.labels import CODE_EXEC, STATE_CHANGE, UNTRUSTED_READ
from agentpath.model import parse_manifest

OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "Support API"},
    "servers": [{"url": "https://api.support.example.com"}],
    "paths": {
        "/tickets/{id}": {
            "get": {"operationId": "get_ticket",
                    "summary": "Retrieve a support ticket including customer comments",
                    "parameters": [{"name": "id", "in": "path",
                                    "schema": {"type": "string"}}]},
            "delete": {"operationId": "delete_ticket", "summary": "Delete a ticket"},
        },
        "/messages": {
            "post": {"operationId": "send_message",
                     "summary": "Send an email to a recipient",
                     "requestBody": {"content": {"application/json": {"schema": {
                         "properties": {"to": {"type": "string"}}}}}}},
        },
    },
}


# -- tool definition arrays -------------------------------------------------

def test_a_plain_list_of_tools_is_understood():
    block = from_tool_definitions([
        {"name": "read_ticket", "description": "Read a ticket.",
         "input_schema": {"properties": {"id": {"type": "string"}}}},
    ])
    assert block["tools"][0]["name"] == "read_ticket"
    assert block["tools"][0]["input_schema"] == {"id": "string"}


def test_the_openai_function_wrapper_is_unwrapped():
    """Different vendors, same definitions. Neither spelling should need a flag."""
    block = from_tool_definitions([
        {"type": "function", "function": {"name": "send_email",
                                          "description": "Send an email.",
                                          "parameters": {"properties": {"to": {}}}}},
    ])
    assert block["tools"][0]["name"] == "send_email"
    assert "to" in block["tools"][0]["input_schema"]


def test_camel_case_input_schema_is_accepted():
    block = from_tool_definitions({"tools": [
        {"name": "x", "inputSchema": {"properties": {"q": {"type": "string"}}}}]})
    assert block["tools"][0]["input_schema"] == {"q": "string"}


def test_a_file_with_no_named_tools_is_an_error():
    with pytest.raises(ImportError_):
        from_tool_definitions([{"description": "no name here"}])


# -- openapi ----------------------------------------------------------------

def test_each_operation_becomes_a_tool():
    block = from_openapi(OPENAPI)
    assert {t["name"] for t in block["tools"]} == {"get_ticket", "delete_ticket",
                                                   "send_message"}


def test_the_http_method_supplies_the_annotations():
    """A GET is a read whatever it is called, and a DELETE changes something even
    when its summary is a cheerful sentence about tidying up."""
    tools = {t["name"]: t for t in from_openapi(OPENAPI)["tools"]}
    assert tools["get_ticket"]["annotations"]["readOnlyHint"] is True
    assert tools["delete_ticket"]["annotations"]["destructiveHint"] is True
    assert tools["send_message"]["annotations"]["readOnlyHint"] is False


def test_a_public_base_url_makes_the_server_third_party():
    assert from_openapi(OPENAPI)["trust"] == "third-party"


def test_a_local_api_is_not_marked_third_party():
    spec = dict(OPENAPI, servers=[{"url": "http://localhost:8000"}])
    assert from_openapi(spec)["trust"] != "third-party"


def test_request_body_properties_become_parameters():
    tools = {t["name"]: t for t in from_openapi(OPENAPI)["tools"]}
    assert "to" in tools["send_message"]["input_schema"]


def test_something_that_is_not_openapi_is_rejected():
    with pytest.raises(ImportError_):
        from_openapi({"info": {"title": "no paths"}})


# -- detection and the manifest --------------------------------------------

def test_the_format_is_detected_without_a_flag():
    assert detect(OPENAPI) == "openapi"
    assert detect([{"name": "x"}]) == "tools"
    assert detect({"tools": [{"name": "x"}]}) == "tools"


def test_an_unrecognisable_file_says_which_flag_to_pass():
    with pytest.raises(ImportError_) as exc:
        detect({"something": "else"})
    assert "--format" in str(exc.value)


def test_an_imported_manifest_parses_and_is_complete():
    """Imported tools were listed in a file, so nothing was skipped."""
    agent = parse_manifest(to_manifest(OPENAPI))
    assert agent.complete is True
    assert len(list(agent.tools())) == 3


def test_imported_tools_go_through_the_same_analysis():
    agent = classify_agent(parse_manifest(to_manifest(OPENAPI)))
    labels = {t.name: t.label_set() for t in agent.tools()}
    assert UNTRUSTED_READ in labels["get_ticket"]
    assert STATE_CHANGE in labels["delete_ticket"]

    findings = analyze(agent)
    pairs = {(f.source.tool, f.sink.tool) for f in findings}
    assert ("get_ticket", "delete_ticket") in pairs


def test_a_python_style_tool_list_reaches_a_finding():
    manifest = to_manifest([
        {"name": "fetch_page", "description": "Fetch a web page and return its text.",
         "input_schema": {"properties": {"url": {"type": "string"}}}},
        {"name": "run_python", "description": "Execute a Python snippet.",
         "input_schema": {"properties": {"code": {"type": "string"}}}},
    ], server="local")
    agent = classify_agent(parse_manifest(manifest))
    assert CODE_EXEC in {h.label for h in agent.tool("local/run_python").labels}
    assert analyze(agent), "an untrusted read reaching code execution should be reported"
