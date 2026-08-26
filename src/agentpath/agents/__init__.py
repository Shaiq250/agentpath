"""Agents that can be put through the harness.

Two kinds, and the difference between them is the most important thing in this
whole feature.

A SCRIPTED agent is a small program, not a language model. It always follows the
instructions it reads, because it is written to. Running the harness against it
proves the plumbing works: the payload was delivered, the marker travelled, the
oracle noticed. It proves nothing whatsoever about whether any real agent is
vulnerable, and a result from it must never be presented as if it did.

A MODEL agent is a real language model with these tools. Its decision to call the
sink is a real decision. Only these results are evidence about agent behaviour.

Everything downstream carries `trustworthy` so the report can keep the two
apart. If they ever look the same in the output, this feature is worse than not
having it at all.
"""

from .base import AgentResult, AgentUnavailable, ConfirmationAgent  # noqa: F401
from .scripted import ScriptedAgent  # noqa: F401
from .model_agent import ModelAgent  # noqa: F401
