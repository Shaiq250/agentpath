"""SARIF 2.1.0 output, so findings can live in GitHub code scanning.

Two decisions here are worth knowing about.

Results carry a partial fingerprint derived from the rule and the two tools it
connects, rather than the positional APA id. GitHub uses that to recognise the
same finding across runs, so a path that has been there for weeks does not keep
reappearing as new.

Accepted and baselined findings are emitted as SARIF suppressions rather than
being left out. A consumer then knows the finding exists and why it is not being
raised, which is the same principle the Markdown report follows: a suppression
nobody can see is indistinguishable from a bug.
"""

from __future__ import annotations

import json
from typing import Any

from .findings import Finding
from .fingerprint import fingerprint, fingerprint_of
from .model import Agent
from .rules import all_rules

SARIF_VERSION = "2.1.0"
SCHEMA_URI = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
              "Schemata/sarif-schema-2.1.0.json")
INFO_URI = "https://github.com/Shaiq250/agentpath"

# SARIF has three useful levels. Critical and high both map to error because
# code scanning treats error as the thing that blocks, and a path to code
# execution should block.
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _driver_rules() -> list[dict[str, Any]]:
    descriptors = [
        {"id": kind, "name": kind,
         "shortDescription": {"text": title},
         "defaultConfiguration": {"level": level},
         "properties": {"tags": ["security", "ai-agent", "cross-server"]}}
        for kind, title, level in [
            ("tool_shadowing", "Two servers offer a tool with the same name", "error"),
            ("confusable_tool_names", "Tool names are easy to confuse", "note"),
            ("tool_definition_changed", "A tool definition changed since the last scan",
             "error"),
            ("tool_added_since_last_scan", "A server added a tool", "warning"),
            ("tool_removed_since_last_scan", "A server removed a tool", "note"),
        ]
    ]
    for rule in all_rules():
        descriptors.append({
            "id": rule.id,
            "name": rule.id,
            "shortDescription": {"text": rule.name},
            "fullDescription": {
                "text": (f"Reports an agent where a tool carrying the "
                         f"{rule.source_label} capability can reach a tool carrying "
                         f"{rule.sink_label}.")
            },
            "defaultConfiguration": {"level": LEVELS.get(rule.severity, "warning")},
            "properties": {
                "tags": ["security", "ai-agent", "prompt-injection"],
                "problem.severity": rule.severity,
            },
        })
    return sorted(descriptors, key=lambda d: d["id"])


def _message(finding: Finding) -> str:
    verdict = finding.confirmation.get("verdict") if finding.confirmation else ""
    prefix = ""
    if verdict == "confirmed":
        agent = finding.confirmation.get("agent_name", "an agent")
        trust = finding.confirmation.get("trustworthy")
        who = agent if trust else "a scripted stand in"
        prefix = f"Observed: {who} walked this path. "
    elif verdict == "not_confirmed":
        prefix = "Tested and not walked, which is not the same as safe. "
    elif verdict == "not_delivered":
        prefix = "Not tested: the agent never read the planted content. "
    return (f"{prefix}{finding.source.server}/{finding.source.tool} can reach "
            f"{finding.sink.server}/{finding.sink.tool} through this agent. "
            f"{finding.scenario} Fix: {finding.fix}")


def _suppression(finding: Finding) -> list[dict[str, Any]] | None:
    if finding.suppressed:
        return [{
            "kind": "external",
            "justification": finding.suppression.get("reason", "accepted by policy"),
        }]
    if finding.baselined:
        return [{
            "kind": "external",
            "justification": "present in the baseline, so not treated as new",
        }]
    return None


def to_sarif(agent: Agent, findings: list[Finding], version: str = "0.1.0",
             issues=None) -> str:
    from . import __version__

    location = agent.source_path or "agent-manifest.json"
    results = []
    for finding in findings:
        result: dict[str, Any] = {
            "ruleId": finding.rule,
            "level": LEVELS.get(finding.severity, "warning"),
            "message": {"text": _message(finding)},
            "partialFingerprints": {"agentpathPath/v1": fingerprint_of(finding)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": location},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "severity": finding.severity,
                "status": finding.status,
                "crossesTrustBoundary": finding.crosses_trust_boundary,
                "sourceTool": f"{finding.source.server}/{finding.source.tool}",
                "sinkTool": f"{finding.sink.server}/{finding.sink.tool}",
            },
        }
        suppression = _suppression(finding)
        if suppression:
            result["suppressions"] = suppression
        results.append(result)

    for issue in (issues or []):
        results.append({
            "ruleId": issue.kind,
            "level": LEVELS.get(issue.severity, "warning"),
            "message": {"text": f"{issue.detail} Fix: {issue.fix}"},
            "partialFingerprints": {
                "agentpathIssue/v1": fingerprint(issue.kind, ",".join(issue.tools), "")
            },
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": location},
                "region": {"startLine": 1},
            }}],
            "properties": {"severity": issue.severity, "tools": issue.tools,
                           "crossServer": True},
        })

    notifications = []
    from .crossserver import no_baseline_servers
    fresh = no_baseline_servers(agent)
    if fresh:
        notifications.append({
            "level": "note",
            "message": {"text": (f"Drift was not checked for {', '.join(sorted(fresh))}: "
                                 f"these servers were seen for the first time, so there is "
                                 f"nothing to compare against yet.")},
        })

    if not agent.complete:
        missing = ", ".join(server.name for server in agent.unenumerated())
        notifications.append({
            "level": "warning",
            "message": {"text": (f"Scan incomplete. These servers were not enumerated, so "
                                 f"paths through them are missing: {missing}.")},
        })

    run: dict[str, Any] = {
        "tool": {"driver": {
            "name": "agentpath",
            "version": __version__,
            "informationUri": INFO_URI,
            "rules": _driver_rules(),
        }},
        "results": results,
    }
    if notifications:
        run["invocations"] = [{
            "executionSuccessful": True,
            "toolExecutionNotifications": notifications,
        }]

    return json.dumps({
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }, indent=2)
