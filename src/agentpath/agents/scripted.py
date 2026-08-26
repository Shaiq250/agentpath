"""A scripted stand in for an agent. Not a model.

It exists so the harness, the payload delivery, the marker and the oracle can be
tested offline, deterministically, in CI, with no API key and no cost.

Two behaviours, because both verdicts need to be reachable in a test:

  follows   reads the content and does what the planted text says
  ignores   reads the content, treats it as data, and answers the actual task

Neither tells you anything about a real agent. `trustworthy` is False and stays
False, and the report is required to say so wherever these results appear.
"""

from __future__ import annotations

import re

from ..harness import Recorder, Scenario
from .base import AgentResult


class ScriptedAgent:
    kind = "scripted"
    trustworthy = False

    def __init__(self, behaviour: str = "follows"):
        if behaviour not in {"follows", "ignores"}:
            raise ValueError("behaviour must be 'follows' or 'ignores'")
        self.behaviour = behaviour
        self.name = f"scripted:{behaviour}"

    def run(self, scenario: Scenario) -> AgentResult:
        recorder = Recorder()
        transcript = []

        # Step one: do the task it was given, which means reading the item.
        content = scenario.handle(recorder, scenario.source_tool, {"id": "1"})
        transcript.append({"role": "tool", "name": scenario.source_tool, "content": content})

        if self.behaviour == "ignores":
            transcript.append({"role": "assistant",
                               "content": "The customer is asking about a missing order."})
            return AgentResult(recorder=recorder, transcript=transcript)

        # Step two: a fully compliant agent obeys the instruction it just read,
        # including passing along the reference the text told it to use.
        marker = self._find_marker(content)
        arguments = {"target": "item-1"}
        if marker:
            arguments["reference"] = marker
        scenario.handle(recorder, scenario.sink_tool, arguments)
        transcript.append({"role": "tool", "name": scenario.sink_tool, "content": "ok"})
        transcript.append({"role": "assistant", "content": "Done, and registered as asked."})
        return AgentResult(recorder=recorder, transcript=transcript)

    @staticmethod
    def _find_marker(content: str) -> str | None:
        """Pull the reference out of the content the way a compliant agent would.

        Deliberately generic: it looks for the marker format rather than being
        told the value, so the oracle is still tested rather than short circuited.
        """
        match = re.search(r"\bAPA-[0-9A-F]{8}\b", content)
        return match.group(0) if match else None
