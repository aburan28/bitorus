"""HTTP front end for a decoy node.

`DecoyServer.handle` is transport-agnostic dicts, so this is a thin
adapter: accept JSON-RPC over POST, hand it to the core, return the result.

Streamable HTTP with JSON responses. SSE streaming is not implemented --
a discovery-only server has nothing to stream -- but a client that requests
it is recorded, because capability negotiation is part of the scaffold
fingerprint.

    python3 -m bitorus.decoy.http --node us-east --port 8080

DEPLOYMENT: this is attacker-facing infrastructure by design. Read
prototype/README.md#deploying-a-decoy before exposing it. In particular it
must run with default-deny egress, on infrastructure that holds nothing
else, on a domain not associated with anything real.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .payloads import Encoding
from .server import DecoyServer, Depth

MAX_REQUEST_BYTES = 1024 * 1024


class _Handler(BaseHTTPRequestHandler):
    server_version = "nginx"          # a decoy should not advertise itself
    sys_version = ""
    decoy: DecoyServer = None         # injected by serve()
    sessions: dict = {}               # Mcp-Session-Id -> Session

    def log_message(self, fmt, *args):
        """Silence the default access log; sessions are the real record."""

    def _send(self, status: int, body: bytes = b"", content_type="application/json",
              extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        # A bare GET is a scanner or a browser, not an MCP client. Recorded
        # as a connection, nothing more.
        if self.path == "/healthz":
            return self._send(200, b'{"ok":true}')
        self._send(404, b"Not Found", "text/plain")

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._send(400, b'{"error":"bad length"}')
        if length > MAX_REQUEST_BYTES:
            return self._send(413, b'{"error":"too large"}')

        raw = self.rfile.read(length)
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            return self._send(400, json.dumps({
                "jsonrpc": "2.0", "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }).encode())

        session_id = self.headers.get("Mcp-Session-Id")
        session = self.sessions.get(session_id) if session_id else None
        if session is None:
            session = self.decoy.open_session()
            self.sessions[session.session_id] = session

        # Transport metadata is recorded once, as a server-side annotation.
        # It must not enter the method sequence: a per-request event would
        # double every entry and make the fingerprint depend on how many
        # HTTP round-trips a client chose to use.
        if not session.transport:
            session.transport = {
                "accept": self.headers.get("Accept", ""),
                "user_agent": self.headers.get("User-Agent", ""),
            }

        response = self.decoy.handle(session, message)

        if response is None:
            return self._send(202, b"", extra={"Mcp-Session-Id": session.session_id})

        self._send(
            200,
            json.dumps(response).encode(),
            extra={"Mcp-Session-Id": session.session_id},
        )

        is_agent, reasons = session.is_agent_candidate()
        if is_agent and session.depth >= Depth.TRIPPED_CANARY:
            print(
                f"\n\033[91mAGENT CANDIDATE\033[0m  node={self.decoy.node_id} "
                f"encoding={self.decoy.encoding.value}\n"
                f"  session      {session.session_id}\n"
                f"  client       {session.client_name} {session.client_version or ''}\n"
                f"  fingerprint  {session.scaffold_fingerprint()}\n"
                f"  depth        {session.depth.label}\n"
                f"  tools called {', '.join(session.tools_called)}\n"
                + "".join(f"  - {r}\n" for r in reasons),
                flush=True,
            )


def serve(node_id: str, port: int, encoding: Encoding | None = None,
          host: str = "127.0.0.1") -> None:
    """Run one decoy node.

    Binds loopback by default. Exposing it is a deliberate act requiring
    --host 0.0.0.0, so a demo cannot become an exposure by accident.
    """
    decoy = DecoyServer(node_id=node_id, encoding=encoding)
    handler = type("Handler", (_Handler,), {"decoy": decoy, "sessions": {}})
    httpd = ThreadingHTTPServer((host, port), handler)

    print(f"decoy node '{node_id}' on http://{host}:{port}  "
          f"encoding={decoy.encoding.value}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("\033[93mexposed beyond loopback -- confirm egress is default-deny\033[0m")
    print("waiting for clients; agent candidates print here\n", flush=True)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        _summarize(decoy)


def _summarize(decoy: DecoyServer) -> None:
    sessions = list(decoy.sessions.values())
    if not sessions:
        return print("no sessions")
    print(f"\n{len(sessions)} session(s) on node '{decoy.node_id}':\n")
    for s in sessions:
        is_agent, reasons = s.is_agent_candidate()
        mark = "\033[91mAGENT\033[0m" if is_agent else "     "
        print(f"  {mark} {s.session_id}  {s.depth.label:<32} {s.client_name or '?'}")
        for r in reasons:
            print(f"          - {r}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bitorus.decoy.http")
    parser.add_argument("--node", default="local", help="node id, used in honeytokens")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address; anything but loopback is an exposure")
    parser.add_argument("--encoding", choices=[e.value for e in Encoding],
                        help="injection encoding (default: assigned by node index)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    serve(
        node_id=args.node,
        port=args.port,
        host=args.host,
        encoding=Encoding(args.encoding) if args.encoding else None,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
