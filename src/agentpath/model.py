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

SCHEMA = "agent-manifest/v2"
ACCEPTED_SCHEMAS = ("agent-manifest/v1", "agent-manifest/v2")

# A server's tools are only known if we actually asked it. Anything else has to
# be visible in the report, because a server we failed to enumerate contributes
# zero tools, and zero tools silently looks exactly like a safe server.
ENUMERATED = "enumerated"
SKIPPED = "skipped"
FAILED = "failed"


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
class EnumerationStatus:
    """Whether this server's tool list was actually obtained, and if not, why."""

    state: str = ENUMERATED
    reason: str = ""

    @property
    def known(self) -> bool:
        return self.state == ENUMERATED

    def to_dict(self) -> dict[str, str]:
        out = {"state": self.state}
        if self.reason:
            out["reason"] = self.reason
        return out


@dataclass
class Server:
    name: str
    transport: str = "stdio"
    command: str = ""
    trust: str = "unknown"
    tools: list[Tool] = field(default_factory=list)
    status: EnumerationStatus = field(default_factory=EnumerationStatus)
    # What changed about this server since the last scan, recorded at collection
    # time because that is the only moment both versions are available.
    drift: list[dict[str, Any]] = field(default_factory=list)
    seen_before: bool = False
    # Names only, never values. The value is the thing being warned about, so
    # copying it into a manifest would repeat the mistake being reported.
    literal_secrets: list[str] = field(default_factory=list)
    # A server exposes more than tools. Prompts and resources are also loaded
    # into the model's context, and text that steers a model does not care which
    # of the three it arrived in.
    prompts: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)


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

    def unenumerated(self) -> list[Server]:
        """Servers whose tools we do not actually know."""
        return [server for server in self.servers if not server.status.known]

    @property
    def complete(self) -> bool:
        return not self.unenumerated()

    def labels_present(self) -> set[str]:
        found: set[str] = set()
        for tool in self.tools():
            found |= tool.label_set()
        return found


def _text(value: Any) -> str:
    """Whatever the file contained, as a string.

    Real config files are written by hand and by other tools, so a description
    arrives as a number, a list of strings, or null often enough to matter. A
    security scanner that crashes on one malformed entry has failed at the exact
    moment it was needed, so everything is coerced rather than rejected.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(_text(item) for item in value.values())
    return str(value)


def _mapping(value: Any) -> dict[str, Any]:
    """A schema or annotation block, whatever shape it arrived in."""
    if isinstance(value, dict):
        return {str(k): v for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        # Some generators emit a list of parameter names rather than a mapping.
        return {str(item): "string" for item in value if isinstance(item, (str, int))}
    return {}


def _build_tool(entry: dict[str, Any], name: str, server: str) -> Tool:
    return Tool(
        name=str(name),
        server=server,
        description=_text(entry.get("description")),
        input_schema=_mapping(entry.get("input_schema") or entry.get("inputSchema")),
        annotations=_mapping(entry.get("annotations")),
    )


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
    if schema not in ACCEPTED_SCHEMAS:
        raise ManifestError(
            f"{source}: expected one of {ACCEPTED_SCHEMAS}, found {schema!r}"
        )

    agent_block = raw.get("agent") or {}
    if not agent_block.get("name"):
        raise ManifestError(f"{source}: agent.name is required")

    servers: list[Server] = []
    for entry in raw.get("servers", []):
        server_name = entry.get("name")
        if not server_name:
            raise ManifestError(f"{source}: every server needs a name")
        # A v1 manifest is hand written, so its tool list is complete by
        # construction. Only v2 records a status, because only v2 can be the
        # output of a collection that partly failed.
        status_entry = entry.get("status") or {}
        server = Server(
            name=server_name,
            transport=entry.get("transport", "stdio"),
            command=entry.get("command", ""),
            trust=entry.get("trust", "unknown"),
            status=EnumerationStatus(
                state=status_entry.get("state", ENUMERATED),
                reason=status_entry.get("reason", ""),
            ),
            drift=entry.get("drift", []) or [],
            seen_before=bool(entry.get("seen_before", False)),
            literal_secrets=entry.get("literal_secrets", []) or [],
            prompts=entry.get("prompts", []) or [],
            resources=entry.get("resources", []) or [],
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
            server.tools.append(_build_tool(tool_entry, tool_name, server_name))
        servers.append(server)

    return Agent(
        name=agent_block["name"],
        harness=agent_block.get("harness", ""),
        source_path=agent_block.get("source_path", ""),
        servers=servers,
    )


def manifest_to_dict(agent: Agent, collection: dict[str, Any] | None = None) -> dict[str, Any]:
    """Serialise an agent back to a manifest, for the collector to write."""
    return {
        "schema": SCHEMA,
        "agent": {
            "name": agent.name,
            "harness": agent.harness,
            "source_path": agent.source_path,
        },
        "collection": collection or {},
        "servers": [
            {
                "name": server.name,
                "transport": server.transport,
                "command": server.command,
                "trust": server.trust,
                "status": server.status.to_dict(),
                "drift": server.drift,
                "seen_before": server.seen_before,
                "literal_secrets": server.literal_secrets,
                "prompts": server.prompts,
                "resources": server.resources,
                "tools": [
                    {
                        "name": tool.name,
                        "description": tool.description,
                        "input_schema": tool.input_schema,
                        "annotations": tool.annotations,
                    }
                    for tool in server.tools
                ],
            }
            for server in agent.servers
        ],
    }
