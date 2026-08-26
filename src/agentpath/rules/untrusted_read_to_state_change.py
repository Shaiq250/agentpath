from ..labels import STATE_CHANGE, UNTRUSTED_READ
from ..model import Agent, Tool
from .base import Rule, register


@register
class UntrustedReadToStateChange(Rule):
    id = "untrusted_read_to_state_change"
    name = "Untrusted input can drive a state changing action"
    severity = "high"
    source_label = UNTRUSTED_READ
    sink_label = STATE_CHANGE

    def scenario(self, source: Tool, sink: Tool, agent: Agent) -> str:
        return (
            f"An attacker supplies content that {source.qualified} will read, containing an "
            f"instruction addressed to the agent. The agent acts on it and calls "
            f"{sink.qualified}, so the attacker chooses an action that changes real state."
        )

    def fix(self, source: Tool, sink: Tool, agent: Agent) -> str:
        return (
            f"Put {sink.qualified} behind human confirmation, restrict what it can act on, or "
            f"stop this agent from reading {source.qualified} in the same session."
        )
