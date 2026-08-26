from pathlib import Path

import pytest

from agentpath.classify import classify_agent
from agentpath.findings import analyze
from agentpath.model import load_manifest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def load(name):
    agent = load_manifest(EXAMPLES / name)
    classify_agent(agent)
    return agent


@pytest.fixture
def support_agent():
    return load("support-agent.json")


@pytest.fixture
def coding_agent():
    return load("coding-assistant.json")


@pytest.fixture
def research_agent():
    return load("research-assistant.json")


@pytest.fixture
def docs_agent():
    return load("readonly-docs-agent.json")


def findings_for(agent):
    return analyze(agent)


def has_path(findings, source, sink, rule=None):
    for finding in findings:
        pair = (f"{finding.source.server}/{finding.source.tool}",
                f"{finding.sink.server}/{finding.sink.tool}")
        if pair == (source, sink) and (rule is None or finding.rule == rule):
            return True
    return False
