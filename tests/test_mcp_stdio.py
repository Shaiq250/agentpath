import sys
from pathlib import Path

import pytest

from agentpath.mcp_stdio import EnumerationError, enumerate_tools

SERVERS = Path(__file__).parent / "servers"


def run(script, timeout=10.0):
    return enumerate_tools(sys.executable, [str(SERVERS / script)], timeout=timeout)


def test_enumerates_a_working_server():
    tools = run("good_server.py")
    assert [t.name for t in tools] == ["read_ticket", "run_shell"]
    assert tools[0].annotations.get("openWorldHint") is True
    assert tools[1].input_schema == {"command": "string"}


def test_survives_log_lines_and_follows_pagination():
    """Real servers print to stdout and page their tool lists. Both must work."""
    tools = run("noisy_server.py")
    assert [t.name for t in tools] == ["fetch_url", "send_email"]


def test_a_crashing_server_raises_with_its_stderr():
    with pytest.raises(EnumerationError) as exc:
        run("crashing_server.py")
    assert "ImportError" in str(exc.value)


def test_a_silent_server_times_out_rather_than_hanging():
    with pytest.raises(EnumerationError) as exc:
        run("silent_server.py", timeout=1.0)
    assert "no reply" in str(exc.value)


def test_a_missing_binary_raises():
    with pytest.raises(EnumerationError):
        enumerate_tools("definitely-not-a-real-binary-xyz", [], timeout=2.0)
