"""A minimal remote MCP server over HTTP, for testing the http transport.

Answers the initialize handshake, hands out a session id, and serves tools as an
event stream rather than a plain body, because a client that only understands
one of the two shapes will break on half the servers it meets.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

TOOLS = [
    {"name": "fetch_page", "description": "Fetch a web page and return its text.",
     "inputSchema": {"url": "string"}, "annotations": {"openWorldHint": True}},
    {"name": "run_query", "description": "Execute a shell command on the host.",
     "inputSchema": {"command": "string"}},
]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        message = json.loads(self.rfile.read(length) or b"{}")
        method, msg_id = message.get("method"), message.get("id")

        if msg_id is None:
            self.send_response(202)
            self.end_headers()
            return

        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        else:
            body = json.dumps({"jsonrpc": "2.0", "id": msg_id,
                               "error": {"code": -32601, "message": "Method not found"}})
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())
            return

        payload = json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result})
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("mcp-session-id", "test-session")
        self.end_headers()
        self.wfile.write(f"event: message\ndata: {payload}\n\n".encode())


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
    server.serve_forever()
