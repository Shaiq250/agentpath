"""The data model: an agent, its servers, and their tools.

The analyser never touches a live system. It reads a manifest file, which is the
offline analog of an IAM dump. Live collection writes that file; analysis only
ever reads it. That split is what keeps every test hermetic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

SCHEMA = "agent-manifest/v1"


class ManifestError(ValueError):
    """Raised when a manifest file is malformed."""


@dataclass(frozen=True)
class LabelHit:
    """One capability label, plus why the classifier assigned it."""

    label: str
    confidence: float
    reason: str


@dataclass
class Tool:
    name: str
    server: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)
    labels: list[LabelHit] = field(default_factory=list)

    @property
    def qualified(self) -> str:
        return f"{self.server}/{self.name}"

    def label_set(self) -> set[str]:
        return {hit.label for hit in self.labels}

    def has(self, label: str) -> bool:
        return any(hit.label == label for hit in self.labels)

    def confidence_for(self, label: str) -> float:
        hits = [h.confidence for h in self.labels if h.label == label]
        return max(hits) if hits else 0.0

    def reason_for(self, label: str) -> str:
        reasons = [h.reason for h in self.labels if h.label == label]
        return "; ".join(reasons)


@dataclass
class Server:
    name: str
    transport: str = "stdio"
    command: str = ""
    trust: str = "unknown"
    tools: list[Tool] = field(default_factory=list)


@dataclass
class Agent:
    name: str
    harness: str = ""
    source_path: str = ""
    servers: list[Server] = field(default_factory=list)

    def tools(self) -> Iterator[Tool]:
        for server in self.servers:
            yield from server.tools

    def tool(self, qualified: str) -> Tool | None:
        for tool in self.tools():
            if tool.qualified == qualified:
                return tool
        return None

    def server(self, name: str) -> Server | None:
        for server in self.servers:
            if server.name == name:
                return server
        return None

    def trust_of(self, tool: Tool) -> str:
        server = self.server(tool.server)
        return server.trust if server else "unknown"

    def labels_present(self) -> set[str]:
        found: set[str] = set()
        for tool in self.tools():
            found |= tool.label_set()
        return found


def load_manifest(path: str | Path) -> Agent:
    """Read and validate an agent manifest from disk."""
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{path}: not valid JSON: {exc}") from exc
    return parse_manifest(raw, source=str(path))


def parse_manifest(raw: dict[str, Any], source: str = "<memory>") -> Agent:
    if not isinstance(raw, dict):
        raise ManifestError(f"{source}: manifest must be a JSON object")

    schema = raw.get("schema")
    if schema != SCHEMA:
        raise ManifestError(f"{source}: expected schema {SCHEMA!r}, found {schema!r}")

    agent_block = raw.get("agent") or {}
    if not agent_block.get("name"):
        raise ManifestError(f"{source}: agent.name is required")

    servers: list[Server] = []
    for entry in raw.get("servers", []):
        server_name = entry.get("name")
        if not server_name:
            raise ManifestError(f"{source}: every server needs a name")
        server = Server(
            name=server_name,
            transport=entry.get("transport", "stdio"),
            command=entry.get("command", ""),
            trust=entry.get("trust", "unknown"),
        )
        seen: set[str] = set()
        for tool_entry in entry.get("tools", []):
            tool_name = tool_entry.get("name")
            if not tool_name:
                raise ManifestError(f"{source}: a tool on server {server_name!r} has no name")
            if tool_name in seen:
                raise ManifestError(
                    f"{source}: server {server_name!r} defines {tool_name!r} twice"
                )
            seen.add(tool_name)
            server.tools.append(
                Tool(
                    name=tool_name,
                    server=server_name,
                    description=tool_entry.get("description", ""),
                    input_schema=tool_entry.get("input_schema", {}) or {},
                    annotations=tool_entry.get("annotations", {}) or {},
                )
            )
        servers.append(server)

    return Agent(
        name=agent_block["name"],
        harness=agent_block.get("harness", ""),
        source_path=agent_block.get("source_path", ""),
        servers=servers,
    )
