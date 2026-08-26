from ..labels import CODE_EXEC, UNTRUSTED_READ
from ..model import Agent, Tool
from .base import Rule, register


@register
class UntrustedReadToCodeExec(Rule):
    id = "untrusted_read_to_code_exec"
    name = "Untrusted input can reach code execution"
    severity = "critical"
    source_label = UNTRUSTED_READ
    sink_label = CODE_EXEC

    def scenario(self, source: Tool, sink: Tool, agent: Agent) -> str:
        return (
            f"An attacker plants instructions inside content returned by {source.qualified}. "
            f"The agent has no way to separate that content from its own instructions, follows "
            f"it, and calls {sink.qualified}, running attacker chosen code on the host that runs "
            f"the agent."
        )

    def fix(self, source: Tool, sink: Tool, agent: Agent) -> str:
        return (
            f"Remove {sink.qualified} from this agent, or require human approval before it runs, "
            f"or move {source.qualified} into a separate agent that has no execution tool."
        )
