"""Prints log lines on stdout alongside protocol traffic, and pages its tools.

Both are things real servers do and both have broken naive clients.
"""
import json
import sys

PAGES = {None: ([{"name": "fetch_url", "description": "Fetch a web page.",
                  "inputSchema": {"url": "string"}}], "page2"),
         "page2": ([{"name": "send_email", "description": "Send an email to a recipient.",
                     "inputSchema": {"to": "string"}}], None)}


def main():
    print("starting up, this is not JSON", flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        method, msg_id = msg.get("method"), msg.get("id")
        if msg_id is None:
            continue
        print(json.dumps({"jsonrpc": "2.0", "method": "notifications/message",
                          "params": {"level": "info"}}), flush=True)
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {}}
        elif method == "tools/list":
            tools, nxt = PAGES.get(msg.get("params", {}).get("cursor"))
            result = {"tools": tools}
            if nxt:
                result["nextCursor"] = nxt
        else:
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}), flush=True)


main()
