"""A minimal, honest MCP server. Used to test enumeration for real."""
import json
import sys

TOOLS = [
    {"name": "read_ticket", "description": "Read a support ticket and its comments.",
     "inputSchema": {"ticket_id": "string"},
     "annotations": {"readOnlyHint": True, "openWorldHint": True}},
    {"name": "run_shell", "description": "Execute a shell command.",
     "inputSchema": {"command": "string"}},
]


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        method, msg_id = msg.get("method"), msg.get("id")
        if msg_id is None:
            continue  # a notification
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "good", "version": "1.0"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": msg_id,
                              "error": {"code": -32601, "message": "no such method"}}),
                  flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}), flush=True)


main()
