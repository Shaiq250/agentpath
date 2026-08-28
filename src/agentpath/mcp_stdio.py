"""Ask a stdio MCP server what tools it offers.

This is the only module in the project that executes anything. Everything else
reads files and reasons about them.

The protocol is small enough to speak directly rather than pulling in the SDK:
newline delimited JSON-RPC over the server's stdin and stdout. Send initialize,
send the initialized notification, send tools/list, read the reply, shut the
process down. Doing it by hand keeps the codebase synchronous and makes the
process lifecycle, the timeouts and the kill path ours to control, which matters
more here than protocol coverage does.
"""

from __future__ import annotations

import json
import os
import queue
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "agentpath", "version": "0.2.0"}
DEFAULT_TIMEOUT = 15.0


class EnumerationError(RuntimeError):
    """Raised when a server could not be asked for its tools."""


@dataclass
class RawTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    annotations: dict[str, Any]


def _reader(stream, sink: queue.Queue) -> None:
    try:
        for line in stream:
            sink.put(line)
    except (ValueError, OSError):
        pass
    finally:
        sink.put(None)


class StdioClient:
    """A short lived connection to one stdio MCP server."""

    def __init__(self, command: str, args: list[str], env: dict[str, str] | None = None,
                 timeout: float = DEFAULT_TIMEOUT):
        self.command = command
        self.args = args
        self.env = env or {}
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None
        self._lines: queue.Queue = queue.Queue()
        self._errors: queue.Queue = queue.Queue()
        self._next_id = 0

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> "StdioClient":
        argv = ([self.command, *self.args] if self.args
                else shlex.split(self.command))
        if not argv:
            raise EnumerationError("no command to run")

        environment = dict(os.environ)
        environment.update(self.env)

        try:
            self.proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=environment,
            )
        except (OSError, ValueError) as exc:
            raise EnumerationError(f"could not start server: {exc}") from exc

        threading.Thread(target=_reader, args=(self.proc.stdout, self._lines),
                         daemon=True).start()
        threading.Thread(target=_reader, args=(self.proc.stderr, self._errors),
                         daemon=True).start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        """Shut the server down, and do not let a hung process outlive us."""
        if not self.proc:
            return
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    # -- protocol ----------------------------------------------------------

    def _stderr_tail(self, limit: int = 200) -> str:
        chunks: list[str] = []
        while not self._errors.empty():
            item = self._errors.get_nowait()
            if item:
                chunks.append(item.strip())
        return " ".join(chunks)[-limit:]

    def _send(self, payload: dict[str, Any]) -> None:
        assert self.proc and self.proc.stdin
        try:
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()
        except (OSError, ValueError) as exc:
            raise EnumerationError(f"server closed its input: {exc}") from exc

    def _await(self, request_id: int) -> dict[str, Any]:
        """Read until the reply with this id arrives, ignoring anything else.

        Servers emit notifications and log lines on the same channel, so a reply
        is not necessarily the next line.
        """
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty:
                break
            if line is None:
                tail = self._stderr_tail()
                raise EnumerationError(
                    f"server exited before replying{': ' + tail if tail else ''}"
                )
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue  # not every line a server prints is protocol traffic
            if message.get("id") == request_id:
                if "error" in message:
                    raise EnumerationError(f"server returned an error: {message['error']}")
                return message.get("result", {})
        raise EnumerationError(f"no reply within {self.timeout:g}s")

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next_id += 1
        self._send({
            "jsonrpc": "2.0",
            "id": self._next_id,
            "method": method,
            "params": params or {},
        })
        return self._await(self._next_id)

    def handshake(self) -> dict[str, Any]:
        result = self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        })
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result

    def list_tools(self) -> list[RawTool]:
        """Page through tools/list and return everything the server declares."""
        tools: list[RawTool] = []
        cursor: str | None = None
        for _ in range(50):  # a server that never stops paging is a broken server
            params = {"cursor": cursor} if cursor else {}
            result = self._request("tools/list", params)
            for entry in result.get("tools", []) or []:
                if not isinstance(entry, dict) or not entry.get("name"):
                    continue
                tools.append(RawTool(
                    name=entry["name"],
                    description=entry.get("description", "") or "",
                    input_schema=(entry.get("inputSchema")
                                  or entry.get("input_schema") or {}),
                    annotations=entry.get("annotations") or {},
                ))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools


    def list_named(self, method: str, key: str) -> list[dict[str, Any]]:
        """Page through prompts/list or resources/list.

        A server that does not implement these answers with a method not found
        error, which is ordinary rather than a failure: plenty of servers offer
        tools and nothing else. Anything else is left to raise, because a server
        that breaks when asked a standard question is worth knowing about.
        """
        found: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(50):
            try:
                result = self._request(method, {"cursor": cursor} if cursor else {})
            except EnumerationError as exc:
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


def enumerate_everything(command: str, args: list[str], env: dict[str, str] | None = None,
                         timeout: float = DEFAULT_TIMEOUT):
    """Tools, prompts and resources in one connection."""
    with StdioClient(command, args, env, timeout) as client:
        client.handshake()
        return (client.list_tools(),
                client.list_named("prompts/list", "prompts"),
                client.list_named("resources/list", "resources"))


def enumerate_tools(command: str, args: list[str], env: dict[str, str] | None = None,
                    timeout: float = DEFAULT_TIMEOUT) -> list[RawTool]:
    """Start a server, ask for its tools, stop it. Raises EnumerationError."""
    with StdioClient(command, args, env, timeout) as client:
        client.handshake()
        return client.list_tools()
