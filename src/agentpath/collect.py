"""Turn configured servers into a manifest.

Two modes, and the difference between them is whether anything runs:

  launch     read the configs, start each server, ask it for its tools
  no-launch  read the configs only, and record every server as skipped

Launching is the default, because the normal case is scanning your own machine
where those servers already run. That does mean the tool executes the commands
found in the config file, so the caller is shown exactly what is about to run
before it runs.

Whatever the mode, a server whose tools we did not obtain is recorded as such.
That status travels with the manifest into the report. A server we could not
enumerate contributes zero tools, and zero tools is indistinguishable from a
harmless server unless we say so.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .discovery import STDIO, ServerSpec, discover
from .mcp_stdio import DEFAULT_TIMEOUT, EnumerationError, RawTool, enumerate_tools
from .model import (
    ENUMERATED,
    FAILED,
    SKIPPED,
    Agent,
    EnumerationStatus,
    Server,
    Tool,
)

CACHE_VERSION = 1


def cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(base) / "agentpath" / "enumeration.json"


def tool_fingerprint(tool: Tool) -> str:
    """A hash of everything about a tool that a rug pull would change.

    Description and schema are included deliberately: a server that quietly
    rewrites a tool's description after you approved it has changed what the
    agent will do with it, even though the name is the same.
    """
    payload = json.dumps(
        {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
            "annotations": tool.annotations,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _cache_key(spec: ServerSpec) -> str:
    material = f"{spec.name}\x00{spec.transport}\x00{spec.command_line}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def load_cache(path: Path | None = None) -> dict:
    path = path or cache_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": CACHE_VERSION, "servers": {}}
    if raw.get("version") != CACHE_VERSION:
        return {"version": CACHE_VERSION, "servers": {}}
    return raw


def save_cache(cache: dict, path: Path | None = None) -> None:
    path = path or cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except OSError:
        pass  # a cache that cannot be written is not a reason to fail a scan


def _to_tools(server_name: str, raw_tools: Iterable[RawTool]) -> list[Tool]:
    return [
        Tool(
            name=raw.name,
            server=server_name,
            description=raw.description,
            input_schema=raw.input_schema or {},
            annotations=raw.annotations or {},
        )
        for raw in raw_tools
    ]


@dataclass
class CollectionResult:
    agent: Agent
    collection: dict


def collect(
    specs: list[ServerSpec] | None = None,
    launch: bool = True,
    agent_name: str = "",
    timeout: float = DEFAULT_TIMEOUT,
    use_cache: bool = True,
    cache_file: Path | None = None,
    on_event: Callable[[str, ServerSpec, str], None] | None = None,
) -> CollectionResult:
    """Build an Agent from configured servers.

    on_event is called as (event, spec, detail) so the CLI can narrate without
    this module knowing anything about printing.
    """
    specs = discover() if specs is None else specs
    cache = load_cache(cache_file) if use_cache else {"version": CACHE_VERSION, "servers": {}}
    cache.setdefault("servers", {})

    servers: list[Server] = []
    for spec in specs:
        server = Server(
            name=spec.name,
            transport=spec.transport,
            command=spec.command_line,
            trust="unknown",
        )

        if not launch:
            server.status = EnumerationStatus(
                SKIPPED, "no-launch mode: the server was not started, so its tools are unknown"
            )
            _emit(on_event, "skipped", spec, server.status.reason)
            servers.append(server)
            continue

        if spec.transport != STDIO:
            server.status = EnumerationStatus(
                SKIPPED,
                f"{spec.transport} transport is not enumerated yet, so its tools are unknown",
            )
            _emit(on_event, "skipped", spec, server.status.reason)
            servers.append(server)
            continue

        key = _cache_key(spec)
        cached = cache["servers"].get(key) if use_cache else None
        if cached:
            server.tools = _to_tools(spec.name, [RawTool(**entry) for entry in cached["tools"]])
            server.status = EnumerationStatus(ENUMERATED)
            _emit(on_event, "cached", spec, f"{len(server.tools)} tools")
            servers.append(server)
            continue

        _emit(on_event, "launching", spec, spec.command_line)
        try:
            raw_tools = enumerate_tools(spec.command, spec.args, spec.env, timeout)
        except EnumerationError as exc:
            server.status = EnumerationStatus(FAILED, str(exc))
            _emit(on_event, "failed", spec, str(exc))
            servers.append(server)
            continue

        server.tools = _to_tools(spec.name, raw_tools)
        server.status = EnumerationStatus(ENUMERATED)
        cache["servers"][key] = {
            "name": spec.name,
            "command": spec.command_line,
            "collected_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "tools": [
                {
                    "name": raw.name,
                    "description": raw.description,
                    "input_schema": raw.input_schema,
                    "annotations": raw.annotations,
                }
                for raw in raw_tools
            ],
            "fingerprints": {
                tool.name: tool_fingerprint(tool) for tool in server.tools
            },
        }
        _emit(on_event, "enumerated", spec, f"{len(server.tools)} tools")
        servers.append(server)

    if use_cache:
        save_cache(cache, cache_file)

    harnesses = sorted({spec.harness for spec in specs})
    sources = sorted({spec.source_path for spec in specs})
    agent = Agent(
        name=agent_name or (harnesses[0] if len(harnesses) == 1 else "local-machine"),
        harness=", ".join(harnesses),
        source_path=", ".join(sources),
        servers=servers,
    )
    collection = {
        "mode": "launch" if launch else "no-launch",
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "complete": agent.complete,
        "unenumerated": [server.name for server in agent.unenumerated()],
    }
    return CollectionResult(agent=agent, collection=collection)


def _emit(on_event, event: str, spec: ServerSpec, detail: str) -> None:
    if on_event:
        on_event(event, spec, detail)
