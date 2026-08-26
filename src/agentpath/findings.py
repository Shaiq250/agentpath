"""Findings, and the engine that produces them."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .graph import candidate_pairs
from .labels import severity_rank
from .model import Agent, Tool
from .rules import all_rules


@dataclass
class Endpoint:
    server: str
    tool: str
    labels: list[str]
    trust: str = "unknown"


@dataclass
class Finding:
    id: str
    rule: str
    name: str
    severity: str
    status: str
    source: Endpoint
    sink: Endpoint
    crosses_trust_boundary: bool
    scenario: str
    fix: str
    evidence: dict[str, Any] = field(default_factory=dict)
    suppression: dict[str, str] = field(default_factory=dict)
    confirmation: dict[str, Any] = field(default_factory=dict)

    @property
    def suppressed(self) -> bool:
        return self.status == "suppressed"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _endpoint(tool: Tool, agent: Agent) -> Endpoint:
    return Endpoint(
        server=tool.server,
        tool=tool.name,
        labels=sorted(tool.label_set()),
        trust=agent.trust_of(tool),
    )


def analyze(agent: Agent, policy=None) -> list[Finding]:
    """Run every rule over the agent and return deduplicated, ranked findings.

    When two rules fire on the same pair of tools, the more severe one wins and
    the other is dropped. Without that, an agent matching both the plain egress
    rule and the full exfiltration chain would report the same pair twice.
    """
    best: dict[tuple[str, str], Finding] = {}

    for rule in all_rules():
        if not rule.applies(agent):
            continue
        for source, sink in candidate_pairs(agent, rule.source_label, rule.sink_label):
            if not rule.matches(source, sink, agent):
                continue
            key = (source.qualified, sink.qualified)
            existing = best.get(key)
            if existing and severity_rank(existing.severity) >= severity_rank(rule.severity):
                continue
            confidence = min(
                source.confidence_for(rule.source_label),
                sink.confidence_for(rule.sink_label),
            )
            best[key] = Finding(
                id="",
                rule=rule.id,
                name=rule.name,
                severity=rule.severity,
                status="candidate",
                source=_endpoint(source, agent),
                sink=_endpoint(sink, agent),
                crosses_trust_boundary=agent.trust_of(source) != agent.trust_of(sink),
                scenario=rule.scenario(source, sink, agent),
                fix=rule.fix(source, sink, agent),
                evidence={
                    "source_reason": source.reason_for(rule.source_label),
                    "sink_reason": sink.reason_for(rule.sink_label),
                    "confidence": round(confidence, 2),
                },
            )

    # Accepted paths are marked, never dropped. A suppression nobody can see is
    # indistinguishable from a bug in the analyser.
    if policy is not None:
        for finding in best.values():
            source = f"{finding.source.server}/{finding.source.tool}"
            sink = f"{finding.sink.server}/{finding.sink.tool}"
            acceptance = policy.acceptance_for(finding.rule, source, sink)
            if acceptance:
                finding.status = "suppressed"
                finding.suppression = {
                    "reason": acceptance.reason,
                    "date": acceptance.date,
                    "policy": policy.source_path,
                }

    findings = sorted(
        best.values(),
        key=lambda f: (-severity_rank(f.severity), f.source.server, f.source.tool,
                       f.sink.server, f.sink.tool),
    )
    for index, finding in enumerate(findings, start=1):
        finding.id = f"APA-{index:04d}"
    return findings


def active(findings: list[Finding]) -> list[Finding]:
    """Findings that still stand, ignoring the ones a user has accepted."""
    return [finding for finding in findings if not finding.suppressed]
