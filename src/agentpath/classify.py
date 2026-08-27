"""Turn a tool definition into capability labels, with a reason for each.

Signal types, in descending order of how much we trust them:

  1. MCP annotations supplied in the tool definition
  2. Input schema parameter names
  3. Tool name patterns
  4. Description keywords

Signal five, an explicit user override file, arrives in M2.

Every label carries the signal that produced it, so the report can always answer
"why did you flag this". When we are unsure we label anyway: a false positive
costs the reader half a minute, a false negative is a missed attack path.

The one place that bias is deliberately reversed is the untrusted-read label.
See below for why.
"""

from __future__ import annotations

import re

from .labels import CODE_EXEC, EGRESS, SECRET_READ, STATE_CHANGE, UNTRUSTED_READ
from .model import Agent, LabelHit, Tool

# --------------------------------------------------------------------------
# untrusted-read: the entry point label
#
# This one is treated more strictly than the others, on purpose. Every entry
# point multiplies: one wrongly labelled source produces a finding against every
# sink in the agent. Loose matching here does not over report by a little, it
# floods the output and buries the real paths.
#
# So untrusted-read needs two things to agree: a verb that means the tool reads
# something, and a noun that means the thing it reads comes from outside. A
# server annotation of openWorldHint is accepted on its own, because that is the
# server author explicitly saying this tool reaches into the open world.
#
# Cost of the strictness: a tool like read_file is not treated as an entry point
# today, even though an attacker who can write a file could use it as one. That
# is a known limitation, listed in the README, and the override file in M2 is how
# a user adds the label for their own environment.
# --------------------------------------------------------------------------

READ_VERBS = r"\b(read|fetch|get|list|search|browse|crawl|receive|load|view|scan)\b"

EXTERNAL_CONTENT = (
    "email", "inbox", "mail", "ticket", "issue", "pull request", "pull_request",
    "comment", "review", "url", "uri", "web page", "webpage", "website", "web",
    "attachment", "feed", "rss", "customer message", "user message", "chat",
    "thread", "external", "untrusted", "third party", "search result", "document upload",
)


def _external_noun(tool: Tool) -> str | None:
    haystacks = [
        tool.name.lower().replace("_", " ").replace("-", " "),
        (tool.description or "").lower(),
        " ".join(str(param).lower() for param in tool.input_schema),
    ]
    for noun in EXTERNAL_CONTENT:
        for haystack in haystacks:
            if noun in haystack:
                return noun
    return None


NAME_PATTERNS: list[tuple[str, str, float]] = [
    (SECRET_READ, r"\b(secret|credential|token|password|key|env|config|record)\b", 0.7),
    (EGRESS, r"\b(send|post|publish|upload|share|notify|email|webhook|export)\b", 0.7),
    (STATE_CHANGE, r"\b(create|update|delete|remove|write|merge|refund|transfer|approve|close|assign|cancel|move|rename|add|insert|post|upload|publish|send|share|click|fill|submit|comment|react|commit|reset|checkout|revert|restore|stage|apply|install|deploy|rollback)\b", 0.7),
    (CODE_EXEC, r"\b(exec|eval|shell|bash|subprocess|terminal)\b", 0.8),
    (CODE_EXEC, r"\b(run|execute|invoke)[ _](shell|bash|command|script|code|python|node|program)\b", 0.9),
]

DESCRIPTION_KEYWORDS: list[tuple[str, tuple[str, ...], float]] = [
    (SECRET_READ, ("secret", "credential", "api key", "password", "token",
                   "private", "environment variable", "customer record",
                   "payment token", "any file", "profile field", "database"), 0.5),
    (EGRESS, ("send an email", "send a", "post a", "post to", "publish", "upload",
              "outbound", "webhook", "recipient", "forward", "transmit", "telemetry",
              "exfiltrat", "send the contents", "report to", "relay"), 0.5),
    (STATE_CHANGE, ("refund", "delete", "modify", "update", "write to", "merge",
                    "charge", "transfer", "cancel"), 0.5),
    (CODE_EXEC, ("shell", "arbitrary code", "subprocess", "interpreter",
                 "shell command", "execute a command", "run a command"), 0.6),
]

SCHEMA_PARAMS: list[tuple[str, tuple[str, ...], float]] = [
    (EGRESS, ("recipient", "to", "webhook_url", "channel"), 0.5),
    (CODE_EXEC, ("command", "cmd", "code", "script", "shell"), 0.8),
]

# secret-read from a file path only when the tool actually returns the contents.
CONTENT_READ_VERBS = r"\b(read|get|fetch|load|cat|download|contents)\b"
PATH_PARAMS = ("path", "file_path", "filename")
METADATA_WORDS = ("info", "stat", "metadata", "exists", "size", "permissions",
                  "list", "search", "directory", "dir", "tree")


def _add(hits: list[LabelHit], label: str, confidence: float, reason: str) -> None:
    hits.append(LabelHit(label=label, confidence=confidence, reason=reason))


def _untrusted_read_hits(tool: Tool, use_annotations: bool = True) -> list[LabelHit]:
    hits: list[LabelHit] = []

    if use_annotations and tool.annotations.get("openWorldHint") is True:
        _add(hits, UNTRUSTED_READ, 0.8, "annotation openWorldHint=true")

    words = tool.name.lower().replace("_", " ").replace("-", " ")
    verb = re.search(READ_VERBS, words) or re.search(READ_VERBS, (tool.description or "").lower())
    noun = _external_noun(tool)
    if verb and noun:
        _add(
            hits,
            UNTRUSTED_READ,
            0.6,
            f"reads ({verb.group(0)!r}) content that comes from outside ({noun!r})",
        )

    return hits


def classify_tool(tool: Tool, use_annotations: bool = True) -> list[LabelHit]:
    """Return the labels for one tool. Pure function, no I/O.

    use_annotations=False ignores everything the server author declared and
    reasons only from the name, the description and the schema. That is not a
    mode anyone should scan with, since throwing away a real signal makes the
    results worse. It exists so the rules can be checked against the
    annotations as an independent answer key: if the classifier can work out
    what a tool does without being told, and its conclusion matches what the
    server author declared, that agreement means something. Leaving the
    annotations switched on would just be checking that we can read them.
    """
    hits: list[LabelHit] = list(_untrusted_read_hits(tool, use_annotations))
    words = tool.name.lower().replace("-", " ").replace("_", " ")
    description = (tool.description or "").lower()

    if use_annotations and tool.annotations.get("destructiveHint") is True:
        _add(hits, STATE_CHANGE, 0.9, "annotation destructiveHint=true")

    for label, params, confidence in SCHEMA_PARAMS:
        for param in tool.input_schema:
            if str(param).lower() in params:
                _add(hits, label, confidence, f"input schema has parameter {param!r}")
                break

    path_param = next(
        (p for p in tool.input_schema if str(p).lower() in PATH_PARAMS), None
    )
    if path_param and re.search(CONTENT_READ_VERBS, words + " " + description):
        if not any(word in words for word in METADATA_WORDS):
            _add(hits, SECRET_READ, 0.5,
                 f"returns the contents of a file named by {path_param!r}")

    for label, pattern, confidence in NAME_PATTERNS:
        match = re.search(pattern, words)
        if match:
            _add(hits, label, confidence, f"name contains {match.group(0)!r}")

    for label, keywords, confidence in DESCRIPTION_KEYWORDS:
        for keyword in keywords:
            if keyword in description:
                _add(hits, label, confidence, f"description mentions {keyword!r}")
                break

    if not use_annotations:
        return _dedupe(hits)
    return _resolve_conflicts(tool, _dedupe(hits))


def _dedupe(hits: list[LabelHit]) -> list[LabelHit]:
    seen: set[tuple[str, str]] = set()
    out: list[LabelHit] = []
    for hit in hits:
        key = (hit.label, hit.reason)
        if key not in seen:
            seen.add(key)
            out.append(hit)
    return out


def _resolve_conflicts(tool: Tool, hits: list[LabelHit]) -> list[LabelHit]:
    """readOnlyHint says a tool is harmless. Our own signals may disagree.

    When they do, the dangerous reading wins and we keep a note of the conflict.
    A tool annotated read only whose name says delete is a finding in itself, not
    a resolution, and a malicious server can annotate whatever it likes.
    """
    if tool.annotations.get("readOnlyHint") is not True:
        return hits

    dangerous = {STATE_CHANGE, CODE_EXEC, EGRESS}
    conflicting = sorted({hit.label for hit in hits} & dangerous)
    if not conflicting:
        return hits

    out = list(hits)
    for label in conflicting:
        out.append(
            LabelHit(
                label=label,
                confidence=0.5,
                reason=(
                    "annotation readOnlyHint=true conflicts with other signals; "
                    "annotations are supplied by the server author and are not "
                    "trusted to clear a tool"
                ),
            )
        )
    return out


def classify_agent(agent: Agent, use_annotations: bool = True) -> Agent:
    """Label every tool on the agent in place, then return it."""
    for tool in agent.tools():
        tool.labels = classify_tool(tool, use_annotations)
    return agent
