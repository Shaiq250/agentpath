"""Find MCP server configurations on this machine.

Reading a config file tells you which servers an agent is set up to use, and the
command that starts each one. It does not tell you which tools those servers
offer: that only comes from asking the server itself, which is what
mcp_stdio.py does.

Nothing in this module executes anything.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

STDIO = "stdio"
HTTP = "http"


@dataclass
class ServerSpec:
    """One configured server, as the config file describes it."""

    name: str
    harness: str
    source_path: str
    transport: str = STDIO
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""

    @property
    def command_line(self) -> str:
        """Exactly what would be run, for showing the user before we run it."""
        if self.transport != STDIO:
            return self.url
        return " ".join([self.command, *self.args]).strip()


def _flatten(value: Any) -> str:
    """A config value as a string, however it was written.

    A command arrives as a list often enough to matter, because some tools
    serialise argv that way.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(_flatten(item) for item in value)
    return str(value)


def _home() -> Path:
    return Path(os.path.expanduser("~"))


def config_locations(cwd: Path | None = None) -> list[tuple[str, Path]]:
    """Known config paths, as (harness, path) pairs. Paths may not exist."""
    home = _home()
    cwd = cwd or Path.cwd()
    appdata = os.environ.get("APPDATA", "")

    candidates: list[tuple[str, Path]] = [
        ("claude-desktop", home / "Library/Application Support/Claude/claude_desktop_config.json"),
        ("claude-desktop", home / ".config/Claude/claude_desktop_config.json"),
        ("claude-code", home / ".claude.json"),
        ("claude-code", cwd / ".mcp.json"),
        ("cursor", home / ".cursor/mcp.json"),
        ("cursor", cwd / ".cursor/mcp.json"),
        ("vscode", cwd / ".vscode/mcp.json"),
        ("windsurf", home / ".codeium/windsurf/mcp_config.json"),
    ]
    if appdata:
        candidates.append(
            ("claude-desktop", Path(appdata) / "Claude/claude_desktop_config.json")
        )
    return candidates


def parse_config(raw: dict[str, Any], harness: str, source_path: str) -> list[ServerSpec]:
    """Pull server definitions out of one config file.

    Harnesses disagree on the top level key: most use mcpServers, VS Code uses
    servers. Both shapes appear in the wild, so accept either.
    """
    block = raw.get("mcpServers") or raw.get("servers") or {}
    if not isinstance(block, dict):
        return []

    specs: list[ServerSpec] = []
    for name, entry in block.items():
        if not isinstance(entry, dict):
            continue

        # These files are written by hand and by other tools, so every field
        # arrives in the wrong shape sooner or later. A scanner that throws on
        # one odd entry has stopped scanning the whole machine, which is a worse
        # outcome than reading that entry generously.
        url = _flatten(entry.get("url"))
        declared = entry.get("type") or entry.get("transport")
        transport = HTTP if (url or declared in {"http", "sse", "streamable-http"}) else STDIO

        raw_args = entry.get("args") or []
        if isinstance(raw_args, str):
            # A single string is one argument, not a string to iterate over.
            raw_args = [raw_args]
        elif not isinstance(raw_args, (list, tuple)):
            raw_args = []

        raw_env = entry.get("env")
        env = ({str(k): _flatten(v) for k, v in raw_env.items()}
               if isinstance(raw_env, dict) else {})

        specs.append(
            ServerSpec(
                name=str(name),
                harness=harness,
                source_path=source_path,
                transport=transport,
                command=_flatten(entry.get("command")),
                args=[_flatten(a) for a in raw_args],
                env=env,
                url=url,
            )
        )
    return specs


def discover(paths: list[tuple[str, Path]] | None = None) -> list[ServerSpec]:
    """Read every config file that exists and return the servers it declares.

    A config file that is unreadable or malformed is skipped rather than fatal:
    one broken file should not stop the rest of the machine being scanned.
    """
    specs: list[ServerSpec] = []
    for harness, path in (paths if paths is not None else config_locations()):
        if not path.is_file():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(raw, dict):
            specs.extend(parse_config(raw, harness, str(path)))
    return specs
