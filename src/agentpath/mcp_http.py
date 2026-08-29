"""Ask a remote MCP server what it offers, over streamable HTTP.

The counterpart to mcp_stdio.py, and a much smaller risk. Enumerating a stdio
server means running a command from a config file. Enumerating an HTTP server
means sending a JSON-RPC request to a URL in that file, which is closer to
opening a link than to executing a program.

It is still a request to somewhere a config file chose, so it happens under the
same rules: only when launching is enabled, and never under --no-launch.

Two shapes of reply have to be handled, because the transport allows either. A
plain JSON body, or an event stream where the payload arrives on data lines. The
same request can get either answer from different servers, so both are parsed.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .mcp_stdio import CLIENT_INFO, PROTOCOL_VERSION, EnumerationError, RawTool

DEFAULT_TIMEOUT = 15.0
ACCEPT = "application/json, text/event-stream"


class HttpClient:
    """A short lived session with one remote MCP server."""

    def __init__(self, url: str, timeout: float = DEFAULT_TIMEOUT, opener=None):
        self.url = url
        self.timeout = timeout
        self.session_id = ""
        self._next_id = 0
        # Injectable so the request loop can be tested without a network.
        self._opener = opener or self._urlopen

    def _urlopen(self, request):
        return urllib.request.urlopen(request, timeout=self.timeout)

    # -- transport ---------------------------------------------------------

    @staticmethod
    def _parse(body: str) -> dict[str, Any]:
        """Accept a JSON body or an event stream carrying the same JSON."""
        text = body.strip()
        if not text:
            return {}
        if text.startswith("{"):
            return json.loads(text)

        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if not payload or payload == "[DONE]":
                continue
            try:
                message = json.loads(payload)
            except json.JSONDecodeError:
                continue
            # Notifications and log events share the stream, so keep looking
            # until something with a result or an error turns up.
            if "result" in message or "error" in message or "id" in message:
                return message
        return {}

    def _send(self, payload: dict[str, Any], expect_reply: bool = True) -> dict[str, Any]:
        headers = {"content-type": "application/json", "accept": ACCEPT,
                   "mcp-protocol-version": PROTOCOL_VERSION}
        if self.session_id:
            headers["mcp-session-id"] = self.session_id

        request = urllib.request.Request(
            self.url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        try:
            with self._opener(request) as response:
                # The server assigns a session on initialize and expects it back.
                session = response.headers.get("mcp-session-id")
                if session:
                    self.session_id = session
                if not expect_reply:
                    return {}
                body = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            raise EnumerationError(f"server returned {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise EnumerationError(f"could not reach {self.url}: {exc}") from exc

        message = self._parse(body)
        if "error" in message:
            raise EnumerationError(f"server returned an error: {message['error']}")
        return message.get("result", {})

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next_id += 1
        return self._send({"jsonrpc": "2.0", "id": self._next_id,
                           "method": method, "params": params or {}})

    # -- protocol ----------------------------------------------------------

    def handshake(self) -> dict[str, Any]:
        result = self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        })
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"},
                   expect_reply=False)
        return result

    def _paged(self, method: str, key: str) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(50):
            try:
                result = self._request(method, {"cursor": cursor} if cursor else {})
            except EnumerationError as exc:
                # Not every server implements prompts or resources, which is
                # ordinary rather than a failure.
                if "-32601" in str(exc) or "not found" in str(exc).lower():
                    return []
                raise
            for entry in result.get(key, []) or []:
                if isinstance(entry, dict) and (entry.get("name") or entry.get("uri")):
                    found.append(entry)
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return found

    def list_tools(self) -> list[RawTool]:
        return [
            RawTool(name=entry["name"],
                    description=entry.get("description", "") or "",
                    input_schema=(entry.get("inputSchema")
                                  or entry.get("input_schema") or {}),
                    annotations=entry.get("annotations") or {})
            for entry in self._paged("tools/list", "tools") if entry.get("name")
        ]


def enumerate_everything(url: str, timeout: float = DEFAULT_TIMEOUT, opener=None):
    """Tools, prompts and resources from a remote server."""
    client = HttpClient(url, timeout, opener)
    client.handshake()
    return (client.list_tools(),
            client._paged("prompts/list", "prompts"),
            client._paged("resources/list", "resources"))
