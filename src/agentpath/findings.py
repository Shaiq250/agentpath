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
    baseline: dict[str, str] = field(default_factory=dict)
    # Other server pairings that produce the same path, collapsed into this one.
    also_matches: list[str] = field(default_factory=list)

    @property
    def suppressed(self) -> bool:
        return self.status == "suppressed"

    @property
    def baselined(self) -> bool:
        return self.status == "baselined"

    @property
    def counts_against_you(self) -> bool:
        """Whether this finding should fail a build.

        Accepted and baselined findings are still real and still shown. They
        just are not what breaks CI today.
        """
        return not (self.suppressed or self.baselined)

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

    findings = _collapse_shadowed(list(best.values()), agent)
    findings = sorted(
        findings,
        key=lambda f: (-severity_rank(f.severity), f.source.server, f.source.tool,
                       f.sink.server, f.sink.tool),
    )
    for index, finding in enumerate(findings, start=1):
        finding.id = f"APA-{index:04d}"
    return findings


def _collapse_shadowed(findings: list[Finding], agent: Agent) -> list[Finding]:
    """Report one path once, even when shadowed tools offer several routes to it.

    When two servers both offer read_file and both offer send_report, the naive
    result is four findings describing one situation. That is the cross product
    problem arriving through a side door: shadowing multiplies findings.

    So paths that differ only in which server provides an identically named tool
    are folded into a single finding. The one kept is the most alarming, and the
    others are listed on it, because which server actually answers the call is
    the shadowing issue's business and is reported there.
    """
    shadowed = {
        name for name in {tool.name for tool in agent.tools()}
        if len({tool.server for tool in agent.tools() if tool.name == name}) > 1
    }
    if not shadowed:
        return findings

    groups: dict[tuple[str, str, str], list[Finding]] = {}
    for finding in findings:
        if finding.source.tool in shadowed or finding.sink.tool in shadowed:
            groups.setdefault(
                (finding.rule, finding.source.tool, finding.sink.tool), []).append(finding)

    collapsed: list[Finding] = []
    dropped: set[int] = set()
    for group in groups.values():
        if len(group) < 2:
            continue
        # Keep the worst: a path that crosses a trust boundary is the one a
        # reader needs to see, since that is where shadowing actually hurts.
        keep = max(group, key=lambda f: (severity_rank(f.severity),
                                         f.crosses_trust_boundary))
        keep.also_matches = sorted(
            f"{f.source.server}/{f.source.tool} to {f.sink.server}/{f.sink.tool}"
            for f in group if f is not keep
        )
        collapsed.append(keep)
        for finding in group:
            if finding is not keep:
                dropped.add(id(finding))

    return [f for f in findings if id(f) not in dropped]


def active(findings: list[Finding]) -> list[Finding]:
    """Findings that still stand, ignoring accepted and baselined ones."""
    return [finding for finding in findings
            if not finding.suppressed and not finding.baselined]
