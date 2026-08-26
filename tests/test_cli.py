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
