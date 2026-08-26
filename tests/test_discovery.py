import json

from agentpath.discovery import HTTP, STDIO, discover, parse_config


def test_parses_the_mcpservers_shape():
    specs = parse_config(
        {"mcpServers": {"zendesk": {"command": "npx", "args": ["zendesk-mcp"],
                                    "env": {"TOKEN": "x"}}}},
        "claude-desktop", "/tmp/cfg.json")
    assert len(specs) == 1
    assert specs[0].name == "zendesk"
    assert specs[0].transport == STDIO
    assert specs[0].command_line == "npx zendesk-mcp"
    assert specs[0].env == {"TOKEN": "x"}


def test_parses_the_vscode_servers_shape():
    specs = parse_config({"servers": {"local": {"command": "python", "args": ["s.py"]}}},
                         "vscode", "/tmp/cfg.json")
    assert [s.name for s in specs] == ["local"]


def test_recognises_http_servers():
    specs = parse_config({"mcpServers": {"remote": {"url": "https://example.com/mcp"}}},
                         "cursor", "/tmp/cfg.json")
    assert specs[0].transport == HTTP


def test_discover_skips_malformed_files(tmp_path):
    """One broken config should not stop the rest of the machine being scanned."""
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"mcpServers": {"a": {"command": "true"}}}))
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json")
    specs = discover([("h", bad), ("h", good)])
    assert [s.name for s in specs] == ["a"]


def test_discover_ignores_missing_files(tmp_path):
    assert discover([("h", tmp_path / "nope.json")]) == []
