"""Checks on a tool or a server itself, rather than on paths between tools.

The path analysis asks what an agent could be made to do. These ask whether a
tool or the config that starts it is already suspicious on its own.

The classes covered here are the publicly documented MCP attack patterns, and
each rule names the one it implements so a reader can go and check the source
material rather than take our word for it:

  tool poisoning        instructions to the model hidden in a tool description,
                        which the model reads and the user usually does not
  concealed payloads    the same, made invisible in an approval dialog using
                        Unicode tag blocks, zero width or bidi characters
  supply chain          a server started from an unpinned package, so the code
                        that runs tomorrow need not be the code approved today
  transport exposure    a remote server reached over plain http, where anyone on
                        the path can rewrite the tool list

Rug pulls and tool shadowing are the other named classes and they live in
crossserver.py, because both need more than one snapshot or more than one
server to see.

What is deliberately NOT here, because a tool manifest cannot support it, is
recorded in docs/coverage.md rather than guessed at.
"""

from __future__ import annotations

import re
from typing import Any

from .crossserver import Issue
from .model import Agent, Tool

POISONED_DESCRIPTION = "tool_description_injection"
CONCEALED_TEXT = "concealed_text_in_description"
UNPINNED_SERVER = "unpinned_server_package"
INSECURE_TRANSPORT = "insecure_remote_transport"
CONFIG_SECRET = "credential_in_server_config"

# Phrases that address the model rather than describing the tool. Kept narrow on
# purpose: "you must provide an organization slug" is ordinary documentation, so
# a rule that fires on any second person imperative would be useless. These are
# the ones with no innocent reading.
CONCEALMENT = [
    (r"\bdo(?: not|n't) (?:tell|inform|mention|reveal|show|notify)\b", "asks the model to hide something from the user"),
    (r"\bwithout (?:telling|informing|notifying|alerting) (?:the )?(?:user|human)\b", "asks the model to act without telling the user"),
    (r"\b(?:secretly|silently|covertly|discreetly)\b(?=.{0,60}\b(?:call|send|read|forward|include)\b)", "asks the model to act covertly"),
    (r"\bkeep (?:this|it) (?:secret|hidden|to yourself|between us)\b", "asks the model to keep something from the user"),
]

OVERRIDE = [
    (r"\bignore (?:all |any )?(?:previous|prior|earlier|above)\b", "tries to override earlier instructions"),
    (r"\bdisregard (?:all |any )?(?:previous|prior|earlier|above)\b", "tries to override earlier instructions"),
    (r"\b(?:new|updated) (?:instructions|system prompt)\b", "claims to supply new instructions"),
    (r"<\s*/?\s*[A-Za-z][A-Za-z _-]{2,20}\s*>(?=[^<]{20,})", "wraps text in a pseudo tag, which is how an instruction block is marked out for the model"),
]

CHAINING = [
    (r"\bbefore (?:using|calling|invoking|running) (?:this|any) tool,? (?:you (?:must|should)|always)\b", "requires another call before this one"),
    (r"\balways (?:call|invoke|run|use) (?:the )?[\w_]+ (?:tool )?(?:first|before)\b", "requires another tool be called first"),
    (r"\byou (?:must|should) (?:first |also )?(?:call|invoke|forward|send|include)\b.{0,80}\b(?:every|each|all) (?:time|call|request)\b", "instructs the model to call something on every request"),
]

# Characters that carry text a person will not see in an approval dialog. The
# tag block is the interesting one: it encodes readable ASCII invisibly.
INVISIBLE = {
    "Unicode tag block": (0xE0000, 0xE007F),
    "zero width character": (0x200B, 0x200F),
    "word joiner or invisible operator": (0x2060, 0x2064),
    "bidirectional override": (0x202A, 0x202E),
    "bidirectional isolate": (0x2066, 0x2069),
}

PINNED = re.compile(r"@[\w.\-]+$|@[\w.\-]+\s|==[\w.\-]+|:[\w.\-]+$")
UNPINNED_RUNNERS = ("npx", "uvx", "pipx", "bunx")
SECRET_NAME = re.compile(r"(token|secret|password|passwd|api[_-]?key|credential|private[_-]?key)", re.I)
REFERENCE = re.compile(r"^\$\{?[\w.]+\}?$|^\$\(.*\)$")


def _scan(text: str, patterns) -> list[tuple[str, str]]:
    found = []
    lowered = text.lower()
    for pattern, why in patterns:
        match = re.search(pattern, lowered)
        if match:
            found.append((match.group(0), why))
    return found


def find_poisoned_descriptions(agent: Agent) -> list[Issue]:
    """Tool poisoning: instructions aimed at the model inside a tool description.

    A description is not documentation as far as the model is concerned. It is
    context, and it is read every time the tool list is loaded. The user sees it
    once, at approval, if at all.
    """
    issues: list[Issue] = []
    for tool in agent.tools():
        text = f"{tool.description} {' '.join(str(k) for k in tool.input_schema)}"
        if not text.strip():
            continue

        hits = (_scan(text, CONCEALMENT) + _scan(text, OVERRIDE) + _scan(text, CHAINING))
        if not hits:
            continue

        # Concealment is the one with no legitimate reading at all, so it decides
        # severity on its own.
        concealing = bool(_scan(text, CONCEALMENT))
        reasons = "; ".join(sorted({why for _, why in hits}))
        quoted = ", ".join(sorted({repr(phrase) for phrase, _ in hits}))

        issues.append(Issue(
            id="",
            kind=POISONED_DESCRIPTION,
            severity="critical" if concealing else "high",
            title="A tool description contains instructions aimed at the model",
            detail=(
                f"{tool.qualified} has a description that {reasons}. The phrase or phrases "
                f"matched were {quoted}. A tool description is loaded into the model's "
                f"context every time the tool list is read, so text like this is acted on "
                f"rather than merely displayed, and the user typically sees it once at "
                f"approval if at all."
            ),
            fix=(
                f"Read the full description of {tool.qualified} as it is sent to the model, "
                f"not as your client summarises it. If the wording was not put there by "
                f"someone you trust, treat the whole server as hostile: a description that "
                f"steers the model is the tool poisoning pattern."
            ),
            tools=[tool.qualified],
            evidence={"matched": [phrase for phrase, _ in hits], "conceals": concealing},
        ))
    return issues


def find_concealed_text(agent: Agent) -> list[Issue]:
    """Payloads a person cannot see in an approval dialog.

    Unicode tag characters encode ordinary ASCII in a range that renders as
    nothing. A description can therefore read as harmless while carrying
    instructions the model still receives in full.
    """
    issues: list[Issue] = []
    for tool in agent.tools():
        text = tool.description or ""
        found: dict[str, int] = {}
        for char in text:
            point = ord(char)
            for label, (low, high) in INVISIBLE.items():
                if low <= point <= high:
                    found[label] = found.get(label, 0) + 1

        if not found:
            continue

        decoded = "".join(
            chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E
        )
        summary = ", ".join(f"{n} x {label}" for label, n in sorted(found.items()))
        issues.append(Issue(
            id="",
            kind=CONCEALED_TEXT,
            severity="critical",
            title="A tool description contains characters that do not render",
            detail=(
                f"{tool.qualified} carries {summary} inside its description. These do not "
                f"appear when the description is displayed, so what a person approves and "
                f"what the model receives are not the same text."
                + (f" The hidden characters decode to: {decoded!r}." if decoded else "")
            ),
            fix=(
                f"Treat {tool.qualified} as hostile until its author explains the hidden "
                f"characters. There is no benign reason for a tool description to contain "
                f"text that renders as nothing."
            ),
            tools=[tool.qualified],
            evidence={"kinds": found, "decoded": decoded},
        ))
    return issues


def find_unpinned_servers(agent: Agent) -> list[Issue]:
    """Supply chain: a server whose code can change without you doing anything.

    Approval is a moment, not a state. If the command fetches whatever version
    is current, the thing you approved is not necessarily the thing that runs
    next time.
    """
    issues: list[Issue] = []
    for server in agent.servers:
        command = (server.command or "").strip()
        if not command:
            continue
        parts = command.split()
        runner = next((p for p in parts if p.split("/")[-1] in UNPINNED_RUNNERS), None)
        if not runner:
            continue

        after = parts[parts.index(runner) + 1:]
        package = next((p for p in after if not p.startswith("-")), "")
        if not package:
            continue
        pinned = bool(PINNED.search(package)) and not package.endswith("@latest")
        if pinned:
            continue

        issues.append(Issue(
            id="",
            kind=UNPINNED_SERVER,
            severity="medium",
            title="A server is started from an unpinned package",
            detail=(
                f"Server {server.name!r} runs `{command}`, which resolves {package!r} at "
                f"launch rather than to a fixed version. The tools you reviewed can be "
                f"replaced by whatever the registry serves next time, without anything "
                f"changing on this machine and without a new approval."
            ),
            fix=(f"Pin the version, for example {package}@1.2.3, and update it deliberately. "
                 f"agentpath will tell you when a pinned server's tool definitions change."),
            tools=[],
            evidence={"server": server.name, "package": package, "command": command},
        ))
    return issues


def find_insecure_transport(agent: Agent) -> list[Issue]:
    """A remote server reached over plain http controls its own tool list.

    Anyone able to see or rewrite that traffic can rewrite the descriptions the
    model reads, which makes every other check here moot.
    """
    issues: list[Issue] = []
    for server in agent.servers:
        command = server.command or ""
        if not command.startswith("http://"):
            continue
        host = command.split("//", 1)[-1].split("/")[0].split(":")[0]
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            continue

        issues.append(Issue(
            id="",
            kind=INSECURE_TRANSPORT,
            severity="high",
            title="A remote server is reached over plain http",
            detail=(
                f"Server {server.name!r} is configured at {command}. The tool list, the "
                f"descriptions the model reads, and every argument sent to it travel "
                f"unencrypted, so anyone on the network path can read them or replace them."
            ),
            fix=f"Use https for {server.name!r}, or run it locally.",
            tools=[],
            evidence={"server": server.name, "url": command},
        ))
    return issues


def find_config_secrets(agent: Agent) -> list[Issue]:
    """Credentials written into an agent config rather than referenced.

    Only the variable NAME is ever recorded or printed. The value is what we are
    warning about, so repeating it in a report or a manifest would be its own
    small version of the same mistake.
    """
    issues: list[Issue] = []
    for server in agent.servers:
        names = [name for name in getattr(server, "literal_secrets", []) or []]
        if not names:
            continue
        issues.append(Issue(
            id="",
            kind=CONFIG_SECRET,
            severity="high",
            title="A credential appears to be written into the agent config",
            detail=(
                f"Server {server.name!r} sets {', '.join(sorted(names))} to a literal value "
                f"rather than a reference to a secret store or an environment variable. "
                f"Agent configs are routinely committed, synced and shared, and a token in "
                f"one is a token in all of those places. The value itself is not repeated "
                f"here or stored in the manifest."
            ),
            fix=(f"Move the value out of the config and reference it, for example "
                 f"\"${{MY_TOKEN}}\", then rotate it, because it has been sitting in a file "
                 f"that was probably not treated as a secret."),
            tools=[],
            evidence={"server": server.name, "variables": sorted(names)},
        ))
    return issues


def find_tool_issues(agent: Agent) -> list[Issue]:
    return (find_poisoned_descriptions(agent)
            + find_concealed_text(agent)
            + find_unpinned_servers(agent)
            + find_insecure_transport(agent)
            + find_config_secrets(agent))
