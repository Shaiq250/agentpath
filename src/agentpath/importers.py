"""Bring tools in from somewhere that is not MCP.

MCP is not the only way an agent gets tools, and the analysis never cared. It
works on a manifest, and a manifest is just a list of tools with names,
descriptions and schemas. So the useful thing here is not a plugin system, it is
turning that observation into two concrete converters and a documented format
anyone can target without asking.

  tool definitions   the plain array of {name, description, input_schema} that
                     an agent built against a model API already has, in either
                     the snake_case or camelCase spelling
  openapi            an API description, where each operation becomes a tool.
                     Agents wrap OpenAPI constantly, and the HTTP method says
                     something the tool name often does not: GET is a read, POST
                     and DELETE change something

Neither importer executes anything or reaches the network. They read a file and
write a manifest, and everything downstream is unchanged.
"""

from __future__ import annotations

import json
from typing import Any

from .model import SCHEMA

# What an HTTP method says about a tool, in the same vocabulary the MCP
# annotations use, so the classifier treats both sources identically.
METHOD_ANNOTATIONS = {
    "get": {"readOnlyHint": True},
    "head": {"readOnlyHint": True},
    "options": {"readOnlyHint": True},
    "post": {"readOnlyHint": False},
    "put": {"readOnlyHint": False},
    "patch": {"readOnlyHint": False},
    "delete": {"readOnlyHint": False, "destructiveHint": True},
}


class ImportError_(ValueError):
    """Raised when a file cannot be understood as tools."""


def _schema_properties(schema: dict[str, Any]) -> dict[str, str]:
    """Flatten a JSON Schema to the parameter map a manifest uses."""
    if not isinstance(schema, dict):
        return {}
    properties = schema.get("properties")
    if isinstance(properties, dict):
        return {str(name): str((spec or {}).get("type", "string"))
                if isinstance(spec, dict) else "string"
                for name, spec in properties.items()}
    # Already flat, as a hand written manifest would be.
    return {str(k): str(v) for k, v in schema.items() if not str(k).startswith("$")}


def from_tool_definitions(data: Any, server: str = "tools") -> dict[str, Any]:
    """A list of tool definitions as sent to a model API."""
    if isinstance(data, dict):
        data = data.get("tools") or data.get("functions") or []
    if not isinstance(data, list):
        raise ImportError_("expected a list of tools, or an object with a tools key")

    tools = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        # OpenAI wraps the real definition in {"type": "function", "function": {...}}
        entry = entry.get("function", entry)
        name = entry.get("name")
        if not name:
            continue
        schema = (entry.get("input_schema") or entry.get("inputSchema")
                  or entry.get("parameters") or {})
        tools.append({
            "name": str(name),
            "description": str(entry.get("description", "")),
            "input_schema": _schema_properties(schema),
            "annotations": entry.get("annotations") or {},
        })

    if not tools:
        raise ImportError_("no tools found: every entry was missing a name")
    return {"name": server, "transport": "other", "command": "",
            "trust": "unknown", "tools": tools}


def from_openapi(spec: Any, server: str = "") -> dict[str, Any]:
    """An OpenAPI description, one tool per operation.

    The HTTP method carries information the tool name often loses. A GET is a
    read whatever it is called, and a DELETE changes something even when its
    summary is a cheerful sentence about tidying up. Those become the same
    annotations MCP servers declare, so the classifier does not need to know
    where a tool came from.
    """
    if not isinstance(spec, dict) or "paths" not in spec:
        raise ImportError_("not an OpenAPI document: no paths section")

    info = spec.get("info") or {}
    name = server or str(info.get("title") or "openapi").strip().lower().replace(" ", "-")

    servers = spec.get("servers") or []
    base = ""
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        base = str(servers[0].get("url", ""))

    tools = []
    for path, operations in (spec.get("paths") or {}).items():
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if method.lower() not in METHOD_ANNOTATIONS or not isinstance(operation, dict):
                continue

            operation_id = operation.get("operationId")
            slug = str(operation_id) if operation_id else (
                f"{method.lower()}_{path.strip('/').replace('/', '_').replace('{', '').replace('}', '')}"
            )

            parameters = {}
            for parameter in operation.get("parameters") or []:
                if isinstance(parameter, dict) and parameter.get("name"):
                    schema = parameter.get("schema") or {}
                    parameters[str(parameter["name"])] = str(schema.get("type", "string"))
            body = (((operation.get("requestBody") or {}).get("content") or {})
                    .get("application/json") or {}).get("schema") or {}
            parameters.update(_schema_properties(body))

            description = " ".join(str(
                operation.get("description") or operation.get("summary") or "").split())
            tools.append({
                "name": slug,
                "description": f"{description} ({method.upper()} {path})".strip(),
                "input_schema": parameters,
                "annotations": dict(METHOD_ANNOTATIONS[method.lower()]),
            })

    if not tools:
        raise ImportError_("no operations found in the paths section")

    # An API reached over the public internet is not the same trust domain as
    # something on this machine, and saying unknown when the document tells us
    # otherwise would waste information.
    trust = "third-party" if base.startswith("http") and "localhost" not in base else "unknown"
    return {"name": name, "transport": "http", "command": base, "trust": trust,
            "tools": tools}


def detect(data: Any) -> str:
    if isinstance(data, dict) and "paths" in data and ("openapi" in data or "swagger" in data):
        return "openapi"
    if isinstance(data, list):
        return "tools"
    if isinstance(data, dict) and (data.get("tools") or data.get("functions")):
        return "tools"
    raise ImportError_(
        "could not tell what this file is. Pass --format openapi or --format tools")


IMPORTERS = {"openapi": from_openapi, "tools": from_tool_definitions}


def to_manifest(data: Any, fmt: str = "auto", server: str = "",
                agent_name: str = "", source_path: str = "") -> dict[str, Any]:
    fmt = detect(data) if fmt == "auto" else fmt
    if fmt not in IMPORTERS:
        raise ImportError_(f"unknown format {fmt!r}. Valid: {', '.join(sorted(IMPORTERS))}")

    block = IMPORTERS[fmt](data, server) if server else IMPORTERS[fmt](data)
    return {
        "schema": SCHEMA,
        "agent": {"name": agent_name or f"{block['name']}-agent",
                  "harness": f"imported/{fmt}", "source_path": source_path},
        "collection": {"mode": "import", "format": fmt, "complete": True,
                       "unenumerated": []},
        # Imported tools are known in full, because the file listed them. Nothing
        # was skipped, so the incomplete scan machinery has nothing to report.
        "servers": [dict(block, status={"state": "enumerated"}, seen_before=False,
                         drift=[], literal_secrets=[])],
    }
