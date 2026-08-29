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

    def final_text(self, limit: int = 1500) -> str:
        """The agent's last words, kept so a refusal can be read rather than guessed.

        When an agent declines a payload it usually says why. That sentence is
        the most useful evidence in a negative result, and it is worth having in
        the report instead of an unexplained zero.
        """
        for entry in reversed(self.transcript):
            if entry.get("role") != "assistant":
                continue
            content = entry.get("content")
            if isinstance(content, str):
                return content[:limit]
            if isinstance(content, list):
                texts = [block.get("text", "") for block in content
                         if isinstance(block, dict) and block.get("type") == "text"]
                joined = " ".join(t for t in texts if t).strip()
                if joined:
                    return joined[:limit]
        return ""


class ConfirmationAgent(Protocol):
    kind: str          # "scripted" or "model"
    name: str          # something identifying, e.g. the model id
    trustworthy: bool  # whether results say anything about real agent behaviour

    def run(self, scenario: Scenario) -> AgentResult:
        ...
