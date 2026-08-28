"""The .agentpath.yml file: corrections and accepted risk.

Two problems this solves, both of which decide whether anyone keeps the tool
installed past the first run.

The classifier guesses from names, descriptions and annotations. It will be
wrong about tools specific to your environment, in both directions: a curated
internal search that it thinks is an untrusted entry point, a file reader that
really is one because attackers can write to that directory. Without a way to
correct it, the only options are to accept noise or to uninstall.

And a real finding is not always a finding you are going to act on. A team that
has reviewed a path and decided to live with it needs to record that decision
with a reason, so the next scan does not re-raise it, and so the acceptance is
visible rather than remembered.

Accepted findings are suppressed, never deleted. They stay in the report under
their own heading with the reason attached, because a suppression nobody can see
is indistinguishable from a bug.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .labels import ALL_LABELS
from .model import Agent, LabelHit

POLICY_FILENAMES = (".agentpath.yml", ".agentpath.yaml")
OVERRIDE_CONFIDENCE = 1.0
OVERRIDE_REASON = "set by .agentpath.yml"


class PolicyError(ValueError):
    """Raised when a policy file cannot be understood."""


@dataclass
class Acceptance:
    """One path a user has reviewed and chosen to live with."""

    rule: str = "*"
    source: str = "*"
    sink: str = "*"
    reason: str = ""
    date: str = ""

    def matches(self, rule: str, source: str, sink: str) -> bool:
        return (
            fnmatch.fnmatch(rule, self.rule)
            and fnmatch.fnmatch(source, self.source)
            and fnmatch.fnmatch(sink, self.sink)
        )


@dataclass
class ApprovedFlow:
    """A path between two trust domains that someone has reviewed and accepted.

    Deliberately weaker than an acceptance. An acceptance says "this exact path
    is fine and I do not want to see it". An approved flow says "traffic in this
    direction has been thought about", which lowers a finding without hiding it,
    because the reviewer approved a shape rather than this particular pair.
    """

    source: str = "*"
    sink: str = "*"
    reason: str = ""

    def matches(self, source_domain: str, sink_domain: str) -> bool:
        return (fnmatch.fnmatch(source_domain, self.source)
                and fnmatch.fnmatch(sink_domain, self.sink))


@dataclass
class Policy:
    label_sets: dict[str, list[str]] = field(default_factory=dict)
    domains: dict[str, str] = field(default_factory=dict)
    approved_flows: list[ApprovedFlow] = field(default_factory=list)
    gated: list[str] = field(default_factory=list)
    label_adds: dict[str, list[str]] = field(default_factory=dict)
    label_removes: dict[str, list[str]] = field(default_factory=dict)
    trust: dict[str, str] = field(default_factory=dict)
    acceptances: list[Acceptance] = field(default_factory=list)
    source_path: str = ""

    @property
    def empty(self) -> bool:
        return not (self.label_sets or self.label_adds or self.label_removes
                    or self.trust or self.acceptances or self.domains
                    or self.approved_flows or self.gated)

    def is_gated(self, qualified: str) -> bool:
        """Whether the user says this tool needs a human to approve each call."""
        return any(fnmatch.fnmatch(qualified, pattern) for pattern in self.gated)

    def approved_flow_for(self, source_domain: str, sink_domain: str) -> ApprovedFlow | None:
        for flow in self.approved_flows:
            if flow.matches(source_domain, sink_domain):
                return flow
        return None

    def acceptance_for(self, rule: str, source: str, sink: str) -> Acceptance | None:
        for acceptance in self.acceptances:
            if acceptance.matches(rule, source, sink):
                return acceptance
        return None


def _validate_labels(labels: Any, where: str) -> list[str]:
    if labels is None:
        return []
    if isinstance(labels, str):
        labels = [labels]
    if not isinstance(labels, list):
        raise PolicyError(f"{where}: expected a list of labels")
    for label in labels:
        if label not in ALL_LABELS:
            raise PolicyError(
                f"{where}: {label!r} is not a label. Valid labels: {', '.join(ALL_LABELS)}"
            )
    return list(labels)


def parse_policy(raw: dict[str, Any], source_path: str = "") -> Policy:
    if raw is None:
        return Policy(source_path=source_path)
    if not isinstance(raw, dict):
        raise PolicyError(f"{source_path}: the policy file must be a mapping")

    policy = Policy(source_path=source_path)

    for tool, spec in (raw.get("labels") or {}).items():
        where = f"labels.{tool}"
        # Shorthand: a bare list replaces the labels entirely.
        if isinstance(spec, (list, str)) or spec is None:
            policy.label_sets[tool] = _validate_labels(spec, where)
            continue
        if not isinstance(spec, dict):
            raise PolicyError(f"{where}: expected a list, or a mapping with set/add/remove")
        if "set" in spec:
            policy.label_sets[tool] = _validate_labels(spec["set"], where + ".set")
        if "add" in spec:
            policy.label_adds[tool] = _validate_labels(spec["add"], where + ".add")
        if "remove" in spec:
            policy.label_removes[tool] = _validate_labels(spec["remove"], where + ".remove")

    # domains is the readable form: one line per domain listing its servers.
    # trust is the original per server form. Both end up in the same map.
    domains = raw.get("domains") or {}
    if not isinstance(domains, dict):
        raise PolicyError(f"{source_path}: domains must be a mapping of domain to servers")
    for domain, servers in domains.items():
        if isinstance(servers, str):
            servers = [servers]
        if not isinstance(servers, list):
            raise PolicyError(f"{source_path}: domains.{domain} must be a list of servers")
        for server in servers:
            policy.domains[str(server)] = str(domain)

    gated = raw.get("gated") or []
    if isinstance(gated, str):
        gated = [gated]
    if not isinstance(gated, list):
        raise PolicyError(f"{source_path}: gated must be a list of tools")
    policy.gated = [str(entry) for entry in gated]

    for index, entry in enumerate(raw.get("approved_flows") or []):
        if not isinstance(entry, dict):
            raise PolicyError(f"{source_path}: approved_flows[{index}] must be a mapping")
        if not entry.get("reason"):
            raise PolicyError(
                f"{source_path}: approved_flows[{index}] needs a reason. An approved flow "
                f"lowers findings, so it has to record who thought about it and why"
            )
        policy.approved_flows.append(ApprovedFlow(
            source=str(entry.get("from", "*")),
            sink=str(entry.get("to", "*")),
            reason=str(entry["reason"]),
        ))

    trust = raw.get("trust") or {}
    if not isinstance(trust, dict):
        raise PolicyError(f"{source_path}: trust must be a mapping of server to domain")
    policy.trust = {str(k): str(v) for k, v in trust.items()}

    for index, entry in enumerate(raw.get("accept") or []):
        if not isinstance(entry, dict):
            raise PolicyError(f"{source_path}: accept[{index}] must be a mapping")
        if not entry.get("reason"):
            # An acceptance without a reason is a decision nobody can review later.
            raise PolicyError(
                f"{source_path}: accept[{index}] needs a reason explaining why this "
                f"path is acceptable"
            )
        policy.acceptances.append(Acceptance(
            rule=str(entry.get("rule", "*")),
            source=str(entry.get("source", "*")),
            sink=str(entry.get("sink", "*")),
            reason=str(entry["reason"]),
            date=str(entry.get("date", "")),
        ))

    return policy


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"{path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: not valid YAML: {exc}") from exc
    return parse_policy(raw, str(path))


def find_policy(start: Path | None = None) -> Path | None:
    """Look for a policy file in this directory. No walking up the tree.

    Picking up a file from a parent directory the user forgot about would be a
    surprising way to have findings silently suppressed.
    """
    start = start or Path.cwd()
    for name in POLICY_FILENAMES:
        candidate = start / name
        if candidate.is_file():
            return candidate
    return None


def apply_policy(agent: Agent, policy: Policy | None) -> Agent:
    """Apply label and trust overrides. Call after classify_agent."""
    if not policy:
        return agent

    for server in agent.servers:
        # An explicit per server trust wins over a domain grouping, since it is
        # the more specific statement.
        if server.name in policy.domains:
            server.trust = policy.domains[server.name]
        if server.name in policy.trust:
            server.trust = policy.trust[server.name]

    for tool in agent.tools():
        key = tool.qualified

        if key in policy.label_sets:
            tool.labels = [
                LabelHit(label, OVERRIDE_CONFIDENCE, OVERRIDE_REASON)
                for label in policy.label_sets[key]
            ]

        for label in policy.label_removes.get(key, []):
            tool.labels = [hit for hit in tool.labels if hit.label != label]

        for label in policy.label_adds.get(key, []):
            if not tool.has(label):
                tool.labels.append(LabelHit(label, OVERRIDE_CONFIDENCE, OVERRIDE_REASON))

    return agent
