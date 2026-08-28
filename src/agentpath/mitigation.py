"""Adjust a finding's severity for what is already true about the environment.

A tool that reports every path at full severity is describing a theoretical
system rather than the one in front of it. A path that stays inside one trusted
server is not the same as one that carries data from a third party plugin into a
privileged one, and a sink that a human has to approve before it fires is not the
same as one that does not.

Two rules hold this honest.

Severity moves, findings do not disappear. A mitigation is a reason to look at
something second rather than a reason not to look at it. Nothing here can reduce
a finding below low, and nothing here removes one. Suppressing is what the accept
list is for, and that is a decision a person makes explicitly.

Everything here is a claim, not an observation. agentpath cannot see whether a
sink really is gated behind human approval. It only knows the user said so in
their policy file. So every adjustment is reported with its reason and with the
word declared, and the original severity stays visible. If the gate does not
exist, the report should let someone notice that rather than quietly bake it in.
"""

from __future__ import annotations

from dataclasses import dataclass

from .labels import SEVERITIES
from .crossserver import TRUST_ORDER


@dataclass
class Adjustment:
    direction: str   # "up", "down", or "note" for reasoning that changes nothing
    reason: str
    declared: bool   # whether this came from the user's policy rather than the data


def _shift(severity: str, steps: int) -> str:
    """Move along the severity ladder without falling off either end."""
    order = list(SEVERITIES)  # low, medium, high, critical
    try:
        index = order.index(severity)
    except ValueError:
        return severity
    return order[max(0, min(len(order) - 1, index + steps))]


def _trust(value: str) -> int:
    return TRUST_ORDER.get(value, 1)


def adjustments_for(finding, agent, policy) -> list[Adjustment]:
    source_trust = finding.source.trust
    sink_trust = finding.sink.trust
    out: list[Adjustment] = []

    if finding.crosses_trust_boundary:
        # Direction matters. Untrusted content arriving at a more privileged tool
        # is the case worth waking someone for. The reverse is data leaving a
        # trusted place, which is serious but already what the rule describes.
        if _trust(source_trust) < _trust(sink_trust):
            out.append(Adjustment(
                "up",
                f"content from the {source_trust} domain reaches a tool in the more "
                f"trusted {sink_trust} domain",
                declared=False,
            ))
        else:
            # Data leaving a trusted place for a less trusted one is serious, and
            # it is already what the rule describes, so this is recorded as
            # reasoning rather than as a change. Saying nothing here would leave a
            # reader wondering whether the boundary was considered at all.
            out.append(Adjustment(
                "note",
                f"the path runs from the {source_trust} domain out to {sink_trust}, which "
                f"is the direction this rule already accounts for",
                declared=False,
            ))
    else:
        out.append(Adjustment(
            "down",
            f"both ends sit in the {source_trust} domain, so nothing crosses a boundary",
            declared=False,
        ))

    if policy is not None:
        sink = f"{finding.sink.server}/{finding.sink.tool}"
        if policy.is_gated(sink):
            out.append(Adjustment(
                "down",
                f"{sink} is declared as requiring human approval before it runs",
                declared=True,
            ))

        flow = policy.approved_flow_for(source_trust, sink_trust)
        if flow:
            out.append(Adjustment(
                "down",
                f"the flow from {source_trust} to {sink_trust} is declared as reviewed: "
                f"{flow.reason}",
                declared=True,
            ))

    return out


def apply_mitigations(findings, agent, policy) -> None:
    """Adjust severities in place, keeping the original and the reasoning."""
    for finding in findings:
        if finding.suppressed:
            continue
        adjustments = adjustments_for(finding, agent, policy)
        if not adjustments:
            continue

        steps = sum({"up": 1, "down": -1}.get(a.direction, 0) for a in adjustments)
        finding.original_severity = finding.severity
        finding.severity = _shift(finding.severity, steps)
        finding.adjustments = [
            {"direction": a.direction, "reason": a.reason, "declared": a.declared}
            for a in adjustments
        ]
