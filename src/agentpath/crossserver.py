"""Findings that exist between servers rather than inside one tool.

Everything up to here has asked what a single tool can do and which tools can
reach which. These three ask a different question: what happens when several
servers share one agent.

  shadowing   two servers offer a tool with the same name, so the agent may
              call the one you did not mean
  confusable  two names differ only cosmetically, which is the same failure
              with a thinner disguise
  drift       a server's tool is not the tool it was last time you looked

None of these is visible from one tool in isolation, which is why the graph is
worth having.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .fingerprint import fingerprint
from .labels import SINK_LABELS, severity_rank
from .model import Agent

SHADOWING = "tool_shadowing"
CONFUSABLE = "confusable_tool_names"
DRIFT = "tool_definition_changed"
ADDED = "tool_added_since_last_scan"
REMOVED = "tool_removed_since_last_scan"

# How much we trust a domain, so an asymmetry can be described rather than just
# noticed. Unknown sits in the middle: we cannot claim it is safe or dangerous.
TRUST_ORDER = {"third-party": 0, "unknown": 1, "internal": 2, "privileged": 3}


@dataclass
class Issue:
    id: str
    kind: str
    severity: str
    title: str
    detail: str
    fix: str
    tools: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalise(name: str) -> str:
    """Reduce a tool name to what a hurried reader would see.

    Case, separators and a trailing version number all disappear, because none
    of them is what a person uses to tell two tools apart at a glance.
    """
    lowered = re.sub(r"[_\-\s]+", "", name.lower())
    return re.sub(r"(v?\d+)$", "", lowered)


def _trust(value: str) -> int:
    return TRUST_ORDER.get(value, 1)


def find_shadowing(agent: Agent) -> list[Issue]:
    """Two servers, one tool name."""
    by_name: dict[str, list] = {}
    for tool in agent.tools():
        by_name.setdefault(tool.name, []).append(tool)

    issues: list[Issue] = []
    for name, tools in sorted(by_name.items()):
        servers = {tool.server for tool in tools}
        if len(servers) < 2:
            continue

        trusts = {tool.server: agent.trust_of(tool) for tool in tools}
        least = min(trusts.values(), key=_trust)
        most = max(trusts.values(), key=_trust)
        dangerous = any(
            any(tool.has(label) for label in SINK_LABELS) for tool in tools
        )

        # An ambiguity between two equally trusted servers is a correctness
        # problem. One that lets a less trusted server stand in for a more
        # trusted one is an attack.
        if _trust(least) < _trust(most):
            severity = "critical" if dangerous else "high"
            detail = (
                f"{len(tools)} servers offer a tool called {name!r}: "
                f"{', '.join(sorted(servers))}. They are not equally trusted: "
                f"{least} and {most} both claim this name. Which one the agent calls "
                f"depends on its client's resolution order, so a server in the {least} "
                f"domain may end up standing in for one you trust more."
            )
        else:
            severity = "high" if dangerous else "medium"
            detail = (
                f"{len(tools)} servers offer a tool called {name!r}: "
                f"{', '.join(sorted(servers))}. Which one the agent calls depends on its "
                f"client's resolution order, so it may not be the one you intended."
            )

        issues.append(Issue(
            id="",
            kind=SHADOWING,
            severity=severity,
            title=f"Tool name {name!r} is offered by more than one server",
            detail=detail,
            fix=(f"Remove {name!r} from all but one server, rename it on the others, or "
                 f"if your client supports it, pin {name!r} to a specific server."),
            tools=sorted(tool.qualified for tool in tools),
            evidence={"trust": trusts, "reaches_a_sink": dangerous},
        ))
    return issues


def find_confusable(agent: Agent) -> list[Issue]:
    """Names that are not identical but are hard to tell apart."""
    by_shape: dict[str, list] = {}
    for tool in agent.tools():
        by_shape.setdefault(_normalise(tool.name), []).append(tool)

    issues: list[Issue] = []
    for shape, tools in sorted(by_shape.items()):
        names = {tool.name for tool in tools}
        servers = {tool.server for tool in tools}
        # Identical names are shadowing and already reported. Same server is the
        # author's own business. Only cross server near misses land here.
        if len(names) < 2 or len(servers) < 2:
            continue

        issues.append(Issue(
            id="",
            kind=CONFUSABLE,
            severity="low",
            title="Tool names on different servers are easy to confuse",
            detail=(
                f"{', '.join(sorted(tool.qualified for tool in tools))} differ only by "
                f"case, punctuation or a version number. Nothing here is necessarily "
                f"wrong, but a person reviewing an agent's tool list, or approving one "
                f"call out of several, can reasonably mistake one for the other."
            ),
            fix="Rename one of them to something that reads differently at a glance.",
            tools=sorted(tool.qualified for tool in tools),
            evidence={"normalised": shape},
        ))
    return issues


def find_drift(agent: Agent) -> list[Issue]:
    """Tools that are not what they were at the last scan."""
    kinds = {
        "modified": (DRIFT, "high",
                     "A tool definition changed since the last scan"),
        "added": (ADDED, "medium",
                  "A server started offering a tool it did not offer before"),
        "removed": (REMOVED, "low",
                    "A server stopped offering a tool it used to offer"),
    }

    issues: list[Issue] = []
    for server in agent.servers:
        for change in server.drift:
            kind, severity, title = kinds.get(
                change.get("change", ""), (DRIFT, "medium", "A tool changed"))
            qualified = f"{server.name}/{change.get('tool', '?')}"

            if kind == DRIFT:
                fix = (f"Read the new definition before using this agent again. If you did "
                       f"not expect {qualified} to change, treat the server as untrusted "
                       f"until you know why it did.")
            elif kind == ADDED:
                fix = (f"Confirm you meant to give this agent {qualified}. A server can add "
                       f"capability at any time, and nothing asks you to approve it.")
            else:
                fix = f"Confirm the removal was intended and nothing depends on {qualified}."

            issues.append(Issue(
                id="",
                kind=kind,
                severity=severity,
                title=title,
                detail=f"{qualified}: {change.get('detail', 'changed')}",
                fix=fix,
                tools=[qualified],
                evidence={"change": change.get("change", "")},
            ))
    return issues


def no_baseline_servers(agent: Agent) -> list[str]:
    """Servers we have never seen before, so drift cannot have been checked.

    Silence here would be the false all clear again: a first scan finds no drift
    for the same reason an unplugged smoke alarm finds no fire.
    """
    return [server.name for server in agent.servers
            if server.status.known and not server.seen_before]


def find_issues(agent: Agent) -> list[Issue]:
    issues = find_shadowing(agent) + find_confusable(agent) + find_drift(agent)
    issues.sort(key=lambda i: (-severity_rank(i.severity), i.kind, i.tools))
    for index, issue in enumerate(issues, start=1):
        issue.id = f"APX-{index:04d}"
    return issues
