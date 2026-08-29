"""The HTTP transport.

Tested against a real server on localhost rather than a mock, for the same
reason the stdio client is: the interesting failures are in what real servers
do, and this one answers as an event stream rather than a plain body.
"""

import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agentpath.mcp_http import HttpClient, enumerate_everything
from agentpath.mcp_stdio import EnumerationError

SERVERS = Path(__file__).parent / "servers"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def remote():
    port = free_port()
    process = subprocess.Popen([sys.executable, str(SERVERS / "http_server.py"), str(port)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}/mcp"
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.05)
    yield url
    process.terminate()
    process.wait(timeout=5)


def test_tools_are_enumerated_from_a_remote_server(remote):
    tools, prompts, resources = enumerate_everything(remote, timeout=5)
    assert [t.name for t in tools] == ["fetch_page", "run_query"]
    assert tools[0].annotations.get("openWorldHint") is True
    assert prompts == [] and resources == []


def test_an_event_stream_reply_is_parsed():
    """Servers may answer with a stream or a plain body. Both mean the same."""
    stream = ('event: message\n'
              'data: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n\n')
    assert HttpClient("http://x")._parse(stream) == {
        "jsonrpc": "2.0", "id": 1, "result": {"tools": []}}


def test_a_plain_json_reply_is_parsed():
    assert HttpClient("http://x")._parse('{"jsonrpc":"2.0","id":1,"result":{}}')["id"] == 1


def test_notifications_in_the_stream_are_skipped():
    """Log events share the channel, so the reply is not always the first line."""
    stream = ('data: {"jsonrpc":"2.0","method":"notifications/message"}\n\n'
              'data: {"jsonrpc":"2.0","id":2,"result":{"ok":true}}\n\n')
    assert HttpClient("http://x")._parse(stream)["result"] == {"ok": True}


def test_the_session_id_is_returned_on_later_requests(remote):
    client = HttpClient(remote, timeout=5)
    client.handshake()
    assert client.session_id == "test-session"


def test_a_server_that_does_not_implement_prompts_is_not_a_failure(remote):
    """Plenty of servers offer tools and nothing else."""
    client = HttpClient(remote, timeout=5)
    client.handshake()
    assert client._paged("prompts/list", "prompts") == []


def test_an_unreachable_server_raises_rather_than_hanging():
    with pytest.raises(EnumerationError):
        enumerate_everything("http://127.0.0.1:9/mcp", timeout=2)


def test_an_analysis_runs_on_remotely_collected_tools(remote, tmp_path):
    from agentpath.classify import classify_agent
    from agentpath.collect import collect
    from agentpath.discovery import HTTP, ServerSpec
    from agentpath.findings import analyze

    result = collect([ServerSpec(name="remote", harness="test", source_path="/tmp/c.json",
                                 transport=HTTP, url=remote)],
                     timeout=5, cache_file=tmp_path / "c.json")
    agent = classify_agent(result.agent)
    assert result.agent.complete is True
    findings = analyze(agent)
    assert any(f.source.tool == "fetch_page" and f.sink.tool == "run_query"
               for f in findings)
