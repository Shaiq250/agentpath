from agentpath.classify import classify_tool
from agentpath.labels import CODE_EXEC, EGRESS, SECRET_READ, STATE_CHANGE, UNTRUSTED_READ
from agentpath.model import Tool


def test_open_world_annotation_marks_untrusted_read():
    tool = Tool(name="read_ticket", server="s", annotations={"openWorldHint": True})
    labels = {hit.label for hit in classify_tool(tool)}
    assert UNTRUSTED_READ in labels


def test_destructive_annotation_marks_state_change():
    tool = Tool(name="do_thing", server="s", annotations={"destructiveHint": True})
    labels = {hit.label for hit in classify_tool(tool)}
    assert STATE_CHANGE in labels


def test_command_parameter_marks_code_exec():
    tool = Tool(name="anything", server="s", input_schema={"command": "string"})
    labels = {hit.label for hit in classify_tool(tool)}
    assert CODE_EXEC in labels


def test_name_pattern_marks_egress():
    tool = Tool(name="send_email", server="s")
    labels = {hit.label for hit in classify_tool(tool)}
    assert EGRESS in labels


def test_read_only_annotation_does_not_clear_a_dangerous_tool():
    """A server author can annotate anything. The dangerous reading has to win."""
    tool = Tool(name="delete_repo", server="s", annotations={"readOnlyHint": True})
    hits = classify_tool(tool)
    assert STATE_CHANGE in {hit.label for hit in hits}
    conflicts = [h for h in hits if "conflicts" in h.reason]
    assert conflicts, "the conflict should be recorded in the evidence"


def test_every_label_carries_a_reason(support_agent):
    for tool in support_agent.tools():
        for hit in tool.labels:
            assert hit.reason
            assert 0.0 < hit.confidence <= 1.0


def test_secret_read_on_credential_reader():
    tool = Tool(name="get_env", server="s", description="Return an environment variable.")
    labels = {hit.label for hit in classify_tool(tool)}
    assert SECRET_READ in labels


def test_a_privileged_lookup_is_not_an_entry_point(support_agent):
    """Regression: 'get' plus 'customer' used to make this an untrusted source.

    Every wrongly labelled entry point multiplies across every sink, so this is
    the single most expensive kind of false positive the tool can make.
    """
    tool = support_agent.tool("billing-db/get_customer_record")
    assert not tool.has(UNTRUSTED_READ)
    assert tool.has(SECRET_READ)


def test_an_action_tool_is_not_an_entry_point(support_agent):
    tool = support_agent.tool("zendesk/issue_refund")
    assert not tool.has(UNTRUSTED_READ)
    assert tool.has(STATE_CHANGE)


def test_an_outbound_tool_is_not_an_entry_point(research_agent):
    tool = research_agent.tool("slack/post_message")
    assert not tool.has(UNTRUSTED_READ)
    assert tool.has(EGRESS)


def test_entry_point_needs_a_read_verb_and_an_external_noun():
    reads_external = Tool(name="read_ticket", server="s",
                          description="Read a support ticket.")
    reads_internal = Tool(name="read_row", server="s",
                          description="Read a row from the internal table.")
    assert UNTRUSTED_READ in {h.label for h in classify_tool(reads_external)}
    assert UNTRUSTED_READ not in {h.label for h in classify_tool(reads_internal)}
