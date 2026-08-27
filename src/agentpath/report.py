"""Report writers. Markdown for people, JSON for tooling."""

from __future__ import annotations

import json
from typing import Any

from .findings import Finding, active
from .crossserver import Issue, no_baseline_servers
from .model import Agent

SEVERITY_ORDER = ("critical", "high", "medium", "low")

STATUS_LINE = {
    "confirmed": "**Confirmed.** {agent} called `{sink}` with the planted marker in "
                 "{succeeded} of {attempts} attempts.",
    "not_confirmed": "**Not confirmed.** The payload reached {agent} in {delivered} of "
                     "{attempts} attempts, and it did not call `{sink}` with the marker.",
    "not_delivered": "**Not tested.** {agent} never read the planted content in "
                     "{attempts} attempts, so this path was never exercised.",
}

INCOMPLETE_HEADLINE = "Scan incomplete."

INCOMPLETE_NOTE = (
    "The tools of the servers listed below were never obtained, so nothing about them has "
    "been analysed. Any attack path that runs through one of them is missing from this "
    "report. Treat this as an unfinished scan, not as a result."
)

DISCLAIMER = (
    "Findings marked as candidates come from static analysis. A candidate means the "
    "combination of tools makes the path possible, not that any agent has been observed "
    "walking it. Run `agentpath confirm` to test whether an agent actually does."
)

CONFIRMED_DISCLAIMER = (
    "Findings below are marked with what was observed. A candidate was not tested. "
    "Confirmed means an agent was seen calling the sink with a marker that existed only "
    "inside planted content. Not confirmed means it was tested and did not, which is not "
    "the same as being safe."
)


def _incomplete_block(agent: Agent) -> list[str]:
    """Say plainly which servers were not enumerated, and what that costs."""
    missing = agent.unenumerated()
    if not missing:
        return []
    lines = [f"> **{INCOMPLETE_HEADLINE}** {len(missing)} of {len(agent.servers)} "
             f"servers were not enumerated.", ">"]
    for server in missing:
        reason = server.status.reason or "no reason recorded"
        lines.append(f"> - `{server.name}` ({server.status.state}): {reason}")
    lines.append(">")
    lines.append(f"> {INCOMPLETE_NOTE}")
    lines.append("")
    return lines


def _confirmation_lines(finding: Finding) -> list[str]:
    """Report what was actually observed, and never more than that."""
    data = finding.confirmation
    if not data:
        return []

    template = STATUS_LINE.get(data.get("verdict", ""))
    if not template:
        return []

    agent = ("A scripted stand in" if not data.get("trustworthy")
             else f"`{data.get('agent_name', 'the agent')}`")
    lines = [template.format(
        agent=agent,
        sink=f"{finding.sink.server}/{finding.sink.tool}",
        succeeded=data.get("succeeded", 0),
        delivered=data.get("delivered", 0),
        attempts=data.get("attempts", 0),
    )]
    styles = sorted({entry.get("style", "") for entry in data.get("attempts_log", [])})
    styles = [style for style in styles if style]
    if styles and data.get("verdict") != "confirmed":
        lines.append("")
        lines.append(f"Payload styles tried: {', '.join(styles)}.")
    if data.get("agent_said"):
        lines.append("")
        lines.append(f"The agent's own response: \"{data['agent_said']}\"")
    if data.get("observed_call"):
        lines.append("")
        confirmed_payload = next(
            (entry["style"] for entry in data.get("attempts_log", [])
             if entry.get("verdict") == "confirmed"), "")
        lines.append(f"Observed call: `{data['observed_call']}`")
        if confirmed_payload:
            lines.append("")
            lines.append(f"Walked via a payload {confirmed_payload}.")
    if data.get("detail"):
        lines.append("")
        lines.append(data["detail"])
    if data.get("caveat"):
        lines.append("")
        lines.append(data["caveat"])
    lines.append("")
    return lines


def _confirmation_summary(findings: list[Finding]) -> list[str]:
    tested = [f for f in findings if f.confirmation]
    if not tested:
        return []
    confirmed = [f for f in tested if f.confirmation.get("verdict") == "confirmed"]
    untrusted = [f for f in tested if not f.confirmation.get("trustworthy")]
    undelivered = [f for f in tested if f.confirmation.get("verdict") == "not_delivered"]

    lines = [f"**Confirmation: {len(confirmed)} of {len(tested)} candidate paths were "
             f"observed being walked.**", ""]
    if undelivered:
        lines.append(
            f"{len(undelivered)} of these were never actually exercised: the agent did not "
            f"read the planted content, so nothing was learned about those paths either way."
        )
        lines.append("")
    if untrusted:
        lines.append(
            f"{len(untrusted)} of these were tested against a scripted stand in rather than "
            f"a language model. Those results demonstrate that the test harness works, not "
            f"that a real agent behaves this way."
        )
        lines.append("")
    return lines


def _baselined_block(findings: list[Finding]) -> list[str]:
    """Known findings, shown but not counted against the build.

    Deliberately worded so nobody mistakes a baseline for approval. A baseline
    is a snapshot, not a decision, and it says nothing about whether these are
    acceptable.
    """
    known = [f for f in findings if f.baselined]
    if not known:
        return []
    noun = "finding is" if len(known) == 1 else "findings are"
    lines = ["", "## Already in the baseline", "",
             f"{len(known)} {noun} recorded in the baseline, so they do not fail the build. "
             f"They are still real findings. A baseline is a snapshot of what was already "
             f"there, not a decision that any of it is acceptable.", ""]
    for finding in known:
        lines.append(
            f"- `{finding.source.server}/{finding.source.tool}` -> "
            f"`{finding.sink.server}/{finding.sink.tool}` ({finding.severity}): {finding.name}"
        )
    lines.append("")
    return lines


def _suppressed_block(findings: list[Finding]) -> list[str]:
    """Accepted paths, kept visible with the reason someone signed off on."""
    accepted = [f for f in findings if f.suppressed]
    if not accepted:
        return []
    noun = "path is" if len(accepted) == 1 else "paths are"
    lines = ["", "## Accepted", "",
             f"{len(accepted)} {noun} suppressed by policy. These are real findings that "
             f"someone chose to live with, shown here so the decision stays visible.", ""]
    for finding in accepted:
        date = f", {finding.suppression.get('date')}" if finding.suppression.get("date") else ""
        lines.append(
            f"- `{finding.source.server}/{finding.source.tool}` -> "
            f"`{finding.sink.server}/{finding.sink.tool}` ({finding.severity}): "
            f"{finding.suppression.get('reason', 'no reason recorded')}{date}"
        )
    lines.append("")
    return lines


def _issues_block(agent: Agent, issues: list[Issue]) -> list[str]:
    """Cross server problems, plus an honest note when drift could not be checked."""
    lines: list[str] = []
    fresh = no_baseline_servers(agent)

    if issues:
        lines += ["", "## Between servers", "",
                  f"{len(issues)} {'issue' if len(issues) == 1 else 'issues'} that come from "
                  f"how these servers sit together rather than from any single tool.", ""]
        for issue in issues:
            lines.append(f"### {issue.id}: {issue.title}")
            lines.append("")
            lines.append(f"Severity: {issue.severity}. Tools: "
                         + ", ".join(f"`{t}`" for t in issue.tools))
            lines.append("")
            lines.append(issue.detail)
            lines.append("")
            lines.append(f"**Fix.** {issue.fix}")
            lines.append("")

    if fresh:
        lines += ["", "### Drift was not checked for every server", "",
                  f"{len(fresh)} of {len(agent.servers)} servers were seen for the first "
                  f"time in this scan: {', '.join(f'`{n}`' for n in sorted(fresh))}. There "
                  f"is nothing to compare them against yet, so no conclusion about whether "
                  f"their tools have changed is possible. Drift checking applies to them "
                  f"from the next scan onward.", ""]
    return lines


def to_markdown(agent: Agent, findings: list[Finding], issues: list[Issue] | None = None) -> str:
    all_findings = findings
    accepted_count = sum(1 for f in findings if f.suppressed)
    baselined_count = sum(1 for f in findings if f.baselined)
    findings = active(findings)
    lines: list[str] = []
    lines.append(f"# Attack paths in agent `{agent.name}`")
    lines.append("")
    if agent.harness:
        lines.append(f"Harness: `{agent.harness}`")
    if agent.source_path:
        lines.append(f"Configuration: `{agent.source_path}`")
    server_count = len(agent.servers)
    tool_count = sum(1 for _ in agent.tools())
    suffix = f" Accepted by policy: {accepted_count}." if accepted_count else ""
    if baselined_count:
        suffix += f" In the baseline: {baselined_count}."
    lines.append(f"Servers: {server_count}. Tools: {tool_count}. "
                 f"Findings: {len(findings)}.{suffix}")
    lines.append("")
    lines.extend(_incomplete_block(agent))

    if not findings:
        # The empty result is the one place this tool could do real harm, by
        # letting a scan that saw nothing read as a scan that found nothing.
        if agent.complete and baselined_count and not accepted_count:
            lines.append("No new attack paths.")
            lines.append("")
            lines.append(
                f"Everything found is already in the baseline: {baselined_count} "
                f"{'path' if baselined_count == 1 else 'paths'}, listed below. That is not "
                "the same as nothing being found."
            )
        elif agent.complete and accepted_count:
            lines.append("No outstanding attack paths.")
            lines.append("")
            lines.append(
                f"Everything found was accepted by policy: {accepted_count} "
                f"{'path' if accepted_count == 1 else 'paths'}, listed below. This is not the "
                "same as nothing being found."
            )
        elif agent.complete:
            lines.append("No attack paths found.")
            lines.append("")
            lines.append(
                "This means no dangerous label combination was detected in the tools available "
                "to this agent. It is not a guarantee that the agent is safe."
            )
        else:
            lines.append("No attack paths found in the part of this agent that was analysed.")
            lines.append("")
            lines.append(
                "This is not a clean result. The servers listed above were never enumerated, "
                "so the analysis covered "
                f"{len(agent.servers) - len(agent.unenumerated())} of {len(agent.servers)} "
                "servers. Re-run the collection so the remaining servers are included before "
                "drawing any conclusion."
            )
        lines.extend(_baselined_block(all_findings))
        lines.extend(_suppressed_block(all_findings))
        lines.extend(_issues_block(agent, issues or []))
        lines.append("")
        return "\n".join(lines)

    counts = {level: sum(1 for f in findings if f.severity == level) for level in SEVERITY_ORDER}
    summary = ", ".join(f"{counts[level]} {level}" for level in SEVERITY_ORDER if counts[level])
    lines.append(f"**Summary: {summary}.**")
    lines.append("")
    lines.append(CONFIRMED_DISCLAIMER if any(f.confirmation for f in findings)
                 else DISCLAIMER)
    lines.append("")
    lines.extend(_confirmation_summary(findings))

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
            lines.extend(_confirmation_lines(finding))
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

    lines.extend(_baselined_block(all_findings))
    lines.extend(_suppressed_block(all_findings))
    lines.extend(_issues_block(agent, issues or []))
    return "\n".join(lines)


def to_json(agent: Agent, findings: list[Finding], issues: list[Issue] | None = None) -> str:
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
            "findings": len(active(findings)),
            "accepted": sum(1 for f in findings if f.suppressed),
            "baselined": sum(1 for f in findings if f.baselined),
        },
        "confirmation": {
            "tested": sum(1 for f in findings if f.confirmation),
            "confirmed": sum(1 for f in findings
                             if f.confirmation.get("verdict") == "confirmed"),
            "from_scripted_agent_only": all(
                not f.confirmation.get("trustworthy")
                for f in findings if f.confirmation
            ) if any(f.confirmation for f in findings) else False,
        },
        "complete": agent.complete,
        "unenumerated": [
            {
                "server": server.name,
                "state": server.status.state,
                "reason": server.status.reason,
            }
            for server in agent.unenumerated()
        ],
        "note": DISCLAIMER,
        "cross_server_issues": [issue.to_dict() for issue in (issues or [])],
        "drift_not_checked": sorted(no_baseline_servers(agent)),
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2)
