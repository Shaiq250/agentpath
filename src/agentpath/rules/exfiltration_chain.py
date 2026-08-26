from ..labels import EGRESS, SECRET_READ, UNTRUSTED_READ
from ..model import Agent, Tool
from .base import Rule, register


@register
class ExfiltrationChain(Rule):
    """Untrusted entry, sensitive data in reach, and a way out. The full chain."""

    id = "exfiltration_chain"
    name = "Full exfiltration chain: untrusted input, sensitive data, outbound channel"
    severity = "critical"
    source_label = UNTRUSTED_READ
    sink_label = EGRESS
    requires_present = SECRET_READ

    @staticmethod
    def _holders(sink: Tool, agent: Agent) -> list[str]:
        """Sensitive readers other than the sink itself.

        A tool that both holds the data and sends it is one tool, not a chain,
        and belongs to a different finding.
        """
        return sorted(
            tool.qualified
            for tool in agent.tools()
            if tool.has(SECRET_READ) and tool.qualified != sink.qualified
        )

    def matches(self, source: Tool, sink: Tool, agent: Agent) -> bool:
        return bool(self._holders(sink, agent))

    def scenario(self, source: Tool, sink: Tool, agent: Agent) -> str:
        holders = self._holders(sink, agent)
        others = [name for name in holders if name != source.qualified]
        if source.qualified in holders and others:
            reach = f"{source.qualified} itself and {', '.join(others[:2])}"
        elif source.qualified in holders:
            reach = f"{source.qualified} itself"
        else:
            reach = ", ".join(holders[:3])
        return (
            f"An attacker plants an instruction in content read by {source.qualified}. The agent "
            f"can reach sensitive data through {reach}, and can send data out through "
            f"{sink.qualified}. The instruction asks it to collect that data and forward it, "
            f"which the agent does in one uninterrupted turn."
        )

    def fix(self, source: Tool, sink: Tool, agent: Agent) -> str:
        return (
            f"Break the chain at one point: keep {source.qualified} out of any session that can "
            f"also reach sensitive data, or pin {sink.qualified} to approved destinations, or "
            f"require approval before sensitive data leaves."
        )
