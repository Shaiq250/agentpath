"""Rule base class and registry.

One file per attack pattern under rules/, auto discovered at import time. Rules
are pure functions over the model: no I/O, no network, so each is trivially
testable and adding a pattern means adding one file.
"""

from __future__ import annotations

from typing import Iterable

from ..model import Agent, Tool

REGISTRY: list[type["Rule"]] = []


def register(cls: type["Rule"]) -> type["Rule"]:
    REGISTRY.append(cls)
    return cls


class Rule:
    """A dangerous combination of capability labels.

    A rule fires when a tool carrying ``source_label`` and a tool carrying
    ``sink_label`` are reachable from the same agent. ``requires_present`` is an
    extra label that must exist somewhere on the agent for the rule to apply, so
    a full exfiltration chain can be told apart from plain egress.
    """

    id: str = ""
    name: str = ""
    severity: str = "medium"
    source_label: str = ""
    sink_label: str = ""
    requires_present: str | None = None

    def applies(self, agent: Agent) -> bool:
        if self.requires_present is None:
            return True
        return self.requires_present in agent.labels_present()

    def matches(self, source: Tool, sink: Tool, agent: Agent) -> bool:
        """Optional per pair check, for rules whose condition depends on the pair.

        Default is that any pair carrying the right labels matches.
        """
        return True

    def scenario(self, source: Tool, sink: Tool, agent: Agent) -> str:
        raise NotImplementedError

    def fix(self, source: Tool, sink: Tool, agent: Agent) -> str:
        raise NotImplementedError


def all_rules() -> Iterable[Rule]:
    from . import load_all

    load_all()
    return [cls() for cls in REGISTRY]
