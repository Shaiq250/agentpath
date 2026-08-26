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
        url = entry.get("url", "")
        declared = entry.get("type") or entry.get("transport")
        transport = HTTP if (url or declared in {"http", "sse", "streamable-http"}) else STDIO
        specs.append(
            ServerSpec(
                name=name,
                harness=harness,
                source_path=source_path,
                transport=transport,
                command=entry.get("command", "") or "",
                args=[str(a) for a in entry.get("args", []) or []],
                env={str(k): str(v) for k, v in (entry.get("env") or {}).items()},
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
