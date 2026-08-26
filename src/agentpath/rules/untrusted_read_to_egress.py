from ..labels import EGRESS, UNTRUSTED_READ
from ..model import Agent, Tool
from .base import Rule, register


@register
class UntrustedReadToEgress(Rule):
    id = "untrusted_read_to_egress"
    name = "Untrusted input can reach an outbound channel"
    severity = "high"
    source_label = UNTRUSTED_READ
    sink_label = EGRESS

    def scenario(self, source: Tool, sink: Tool, agent: Agent) -> str:
        return (
            f"An attacker plants an instruction in content read by {source.qualified} telling the "
            f"agent to forward what it knows. The agent calls {sink.qualified}, sending whatever "
            f"is in its context to a destination the attacker chose."
        )

    def fix(self, source: Tool, sink: Tool, agent: Agent) -> str:
        return (
            f"Restrict {sink.qualified} to a fixed allow list of destinations, or require "
            f"approval before it sends, or separate reading and sending into different agents."
        )
