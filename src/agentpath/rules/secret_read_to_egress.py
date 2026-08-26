from ..labels import EGRESS, SECRET_READ
from ..model import Agent, Tool
from .base import Rule, register


@register
class SecretReadToEgress(Rule):
    """No known untrusted entry point, but the exit half of a chain is present."""

    id = "secret_read_to_egress"
    name = "Sensitive data and an outbound channel in the same agent"
    severity = "medium"
    source_label = SECRET_READ
    sink_label = EGRESS

    def scenario(self, source: Tool, sink: Tool, agent: Agent) -> str:
        return (
            f"{source.qualified} can read sensitive data and {sink.qualified} can send data out "
            f"of this environment. Any entry point for attacker controlled content, including "
            f"one this analysis has not identified, completes an exfiltration chain."
        )

    def fix(self, source: Tool, sink: Tool, agent: Agent) -> str:
        return (
            f"Narrow what {source.qualified} can read, or restrict {sink.qualified} to approved "
            f"destinations, so that no future entry point completes the chain."
        )
