import json

from agentpath.cli import main

from conftest import EXAMPLES


def test_analyze_exits_one_when_findings_exist(capsys):
    code = main(["analyze", str(EXAMPLES / "support-agent.json")])
    assert code == 1
    assert "Attack paths in agent" in capsys.readouterr().out


def test_analyze_exits_zero_on_a_clean_agent(capsys):
    code = main(["analyze", str(EXAMPLES / "readonly-docs-agent.json")])
    assert code == 0


def test_fail_on_threshold_is_respected():
    """The research assistant has high findings but nothing critical."""
    assert main(["analyze", str(EXAMPLES / "research-assistant.json"), "--fail-on", "critical"]) == 0
    assert main(["analyze", str(EXAMPLES / "research-assistant.json"), "--fail-on", "high"]) == 1


def test_json_format_is_parseable(capsys):
    main(["analyze", str(EXAMPLES / "coding-assistant.json"), "--format", "json"])
    json.loads(capsys.readouterr().out)


def test_bad_manifest_exits_two(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main(["analyze", str(bad)]) == 2
    assert "error:" in capsys.readouterr().err


def test_scan_runs_collect_then_analyze(tmp_path, monkeypatch, capsys):
    """The short way in. A first run should produce a report, not a manifest and
    a second command to look up."""
    config = tmp_path / ".cursor"
    config.mkdir()
    import json
    import sys
    from pathlib import Path

    server = Path(__file__).parent / "servers" / "good_server.py"
    (config / "mcp.json").write_text(json.dumps({"mcpServers": {
        "good": {"command": sys.executable, "args": [str(server)]}}}))

    monkeypatch.chdir(tmp_path)
    code = main(["scan", "--manifest", "m.json"])
    out = capsys.readouterr().out

    assert (tmp_path / "m.json").is_file(), "the manifest is kept so the report is reproducible"
    assert "Attack paths in agent" in out
    assert code == 1, "the demo server has a read to shell path"


def test_scan_with_no_configuration_says_so(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert main(["scan", "--manifest", "m.json"]) == 2
    assert "No MCP server configurations found" in capsys.readouterr().err
