from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ..harness import Recorder, Scenario


class AgentUnavailable(RuntimeError):
    """The agent cannot run: no key, no network, unsupported configuration."""


@dataclass
class AgentResult:
    recorder: Recorder
    transcript: list[dict[str, Any]] = field(default_factory=list)


class ConfirmationAgent(Protocol):
    kind: str          # "scripted" or "model"
    name: str          # something identifying, e.g. the model id
    trustworthy: bool  # whether results say anything about real agent behaviour

    def run(self, scenario: Scenario) -> AgentResult:
        ...
