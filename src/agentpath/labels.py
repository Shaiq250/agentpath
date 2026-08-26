"""The five capability labels a tool can carry, and severity ordering."""

UNTRUSTED_READ = "untrusted-read"
SECRET_READ = "secret-read"
EGRESS = "egress"
STATE_CHANGE = "state-change"
CODE_EXEC = "code-exec"

ALL_LABELS = (UNTRUSTED_READ, SECRET_READ, EGRESS, STATE_CHANGE, CODE_EXEC)

# Labels that make a tool a plausible entry point for attacker controlled content.
SOURCE_LABELS = (UNTRUSTED_READ,)

# Labels that make a tool worth reaching.
SINK_LABELS = (EGRESS, STATE_CHANGE, CODE_EXEC)

SEVERITIES = ("low", "medium", "high", "critical")


def severity_rank(name: str) -> int:
    """Higher is worse. Unknown severities sort lowest."""
    try:
        return SEVERITIES.index(name)
    except ValueError:
        return -1


def at_least(severity: str, threshold: str) -> bool:
    return severity_rank(severity) >= severity_rank(threshold)
