"""Report writers. Markdown for people, JSON for tooling."""

from __future__ import annotations

import json
from typing import Any

from .findings import Finding
from .model import Agent

SEVERITY_ORDER = ("critical", "high", "medium", "low")

DISCLAIMER = (
    "Every finding below is a candidate produced by static analysis. A candidate means the "
    "combination of tools makes the path possible, not that this agent has been observed "
    "walking it. Confirmation mode, which watches whether the agent really calls the sink, "
    "arrives in a later version."
)


def to_markdown(agent: Agent, findings: list[Finding]) -> str:
    lines: list[str] = []
    lines.append(f"# Attack paths in agent `{agent.name}`")
    lines.append("")
    if agent.harness:
        lines.append(f"Harness: `{agent.harness}`")
    if agent.source_path:
        lines.append(f"Configuration: `{agent.source_path}`")
    server_count = len(agent.servers)
    tool_count = sum(1 for _ in agent.tools())
    lines.append(f"Servers: {server_count}. Tools: {tool_count}. Findings: {len(findings)}.")
    lines.append("")

    if not findings:
        lines.append("No attack paths found.")
        lines.append("")
        lines.append(
            "This means no dangerous label combination was detected in the tools available to "
            "this agent. It is not a guarantee that the agent is safe."
        )
        lines.append("")
        return "\n".join(lines)

    counts = {level: sum(1 for f in findings if f.severity == level) for level in SEVERITY_ORDER}
    summary = ", ".join(f"{counts[level]} {level}" for level in SEVERITY_ORDER if counts[level])
    lines.append(f"**Summary: {summary}.**")
    lines.append("")
    lines.append(DISCLAIMER)
    lines.append("")

    for level in SEVERITY_ORDER:
        group = [f for f in findings if f.severity == level]
        if not group:
            continue
        lines.append(f"## {level.capitalize()}")
        lines.append("")
        for finding in group:
            lines.append(f"### {finding.id}: {finding.name}")
            lines.append("")
            lines.append(f"`{finding.source.server}/{finding.source.tool}` "
                         f"-> agent -> `{finding.sink.server}/{finding.sink.tool}`")
            lines.append("")
            if finding.crosses_trust_boundary:
                lines.append(f"This path crosses a trust boundary: the source sits in the "
                             f"`{finding.source.trust}` domain and the sink in "
                             f"`{finding.sink.trust}`.")
                lines.append("")
            lines.append(f"**Scenario.** {finding.scenario}")
            lines.append("")
            lines.append(f"**Fix.** {finding.fix}")
            lines.append("")
            lines.append(f"**Why these tools were labelled this way.** "
                         f"Source: {finding.evidence['source_reason']}. "
                         f"Sink: {finding.evidence['sink_reason']}. "
                         f"Confidence: {finding.evidence['confidence']}.")
            lines.append("")

    return "\n".join(lines)


def to_json(agent: Agent, findings: list[Finding]) -> str:
    payload: dict[str, Any] = {
        "schema": "agentpath-report/v1",
        "agent": {
            "name": agent.name,
            "harness": agent.harness,
            "source_path": agent.source_path,
        },
        "counts": {
            "servers": len(agent.servers),
            "tools": sum(1 for _ in agent.tools()),
            "findings": len(findings),
        },
        "note": DISCLAIMER,
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2)
