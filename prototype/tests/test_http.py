"""HTTP front-end tests.

Runs a real server on an ephemeral loopback port and drives it with a real
HTTP client, so the adapter is exercised end to end rather than mocked.

The bind-address test is a safety test: a demo must not become an exposure
by accident.
"""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from bitorus.decoy.http import _Handler
from bitorus.decoy.payloads import CANARY_TOOL, Encoding
from bitorus.decoy.server import DecoyServer, Depth
from bitorus.decoy.simulated_clients import SimulatedAgent


class _Node:
    """A decoy node on an ephemeral loopback port, for the duration of a test."""

    def __init__(self, encoding=Encoding.HTML_COMMENT):
        self.decoy = DecoyServer(node_id="test", encoding=encoding)
        handler = type("H", (_Handler,), {"decoy": self.decoy, "sessions": {}})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def post(self, payload: dict, session_id: str | None = None):
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        request = urllib.request.Request(
            self.url, data=json.dumps(payload).encode(), headers=headers, method="POST"
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            body = response.read()
            return response.status, dict(response.headers), (json.loads(body) if body else None)


class HttpAdapter(unittest.TestCase):
    def test_initialize_returns_server_info(self):
        with _Node() as node:
            status, headers, body = node.post({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "probe", "version": "1"}},
            })
            self.assertEqual(status, 200)
            self.assertIn("serverInfo", body["result"])
            self.assertIn("Mcp-Session-Id", headers)

    def test_session_id_binds_subsequent_requests(self):
        with _Node() as node:
            _, headers, _ = node.post({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"clientInfo": {"name": "probe", "version": "1"}},
            })
            sid = headers["Mcp-Session-Id"]
            node.post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session_id=sid)
            self.assertEqual(len(node.decoy.sessions), 1)
            self.assertIn("tools/list", node.decoy.sessions[sid].method_sequence)

    def test_notification_returns_202_with_no_body(self):
        with _Node() as node:
            status, _, body = node.post({
                "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}
            })
            self.assertEqual(status, 202)
            self.assertIsNone(body)

    def test_malformed_json_is_a_parse_error_not_a_crash(self):
        with _Node() as node:
            request = urllib.request.Request(
                node.url, data=b"{not json", method="POST",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(ctx.exception.code, 400)

    def test_oversized_request_is_refused(self):
        """A hostile client should not be able to make us buffer unboundedly."""
        with _Node() as node:
            request = urllib.request.Request(
                node.url, data=b"x" * 32, method="POST",
                headers={"Content-Type": "application/json",
                         "Content-Length": str(64 * 1024 * 1024)},
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(ctx.exception.code, 413)

    def test_server_does_not_advertise_itself(self):
        """A decoy that announces what it is defeats the purpose."""
        with _Node() as node:
            _, headers, _ = node.post({"jsonrpc": "2.0", "id": 1, "method": "ping"})
            self.assertNotIn("bitorus", headers.get("Server", "").lower())
            self.assertNotIn("python", headers.get("Server", "").lower())

    def test_transport_metadata_does_not_reach_the_fingerprint(self):
        """Regression, third of its kind: transport details vary with
        deployment and proxying, so letting them into the fingerprint would
        break cross-node linkage the same way outcome events did."""
        with _Node() as node:
            _, headers, _ = node.post({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "probe", "version": "1"}},
            })
            session = node.decoy.sessions[headers["Mcp-Session-Id"]]
            over_http = session.scaffold_fingerprint()
            self.assertTrue(session.transport)

            direct = DecoyServer(node_id="test", encoding=Encoding.HTML_COMMENT)
            offline = direct.open_session()
            direct.handle(offline, {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "probe", "version": "1"}},
            })
            self.assertEqual(over_http, offline.scaffold_fingerprint())


class DetectionOverHttp(unittest.TestCase):
    def test_agent_trips_canary_over_the_wire(self):
        with _Node(encoding=Encoding.HTML_COMMENT) as node:
            _, headers, _ = node.post({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "agent", "version": "1"}},
            })
            sid = headers["Mcp-Session-Id"]
            node.post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid)
            _, _, doc = node.post({
                "jsonrpc": "2.0", "id": 3, "method": "resources/read",
                "params": {"uri": "file:///runbooks/oncall.md"},
            }, sid)

            body = doc["result"]["contents"][0]["text"]
            self.assertIn(CANARY_TOOL, body)          # present in the bytes
            self.assertNotIn(CANARY_TOOL, body.split("<!--")[0])  # not in visible text

            node.post({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": CANARY_TOOL, "arguments": {"reason": "integrity-check"}},
            }, sid)

            session = node.decoy.sessions[sid]
            self.assertEqual(session.depth, Depth.TRIPPED_CANARY)
            self.assertTrue(session.is_agent_candidate()[0])

    def test_bare_get_is_not_an_agent(self):
        with _Node() as node:
            try:
                urllib.request.urlopen(f"{node.url}/", timeout=5)
            except urllib.error.HTTPError:
                pass
            self.assertEqual(len(node.decoy.sessions), 0)

    def test_healthz_does_not_create_a_session(self):
        """Load balancers must not appear in the corpus as candidates."""
        with _Node() as node:
            with urllib.request.urlopen(f"{node.url}/healthz", timeout=5) as response:
                self.assertEqual(response.status, 200)
            self.assertEqual(len(node.decoy.sessions), 0)


class BindSafety(unittest.TestCase):
    """Exposing a decoy must be a deliberate act, never a default."""

    def test_cli_defaults_to_loopback(self):
        from bitorus.decoy.http import build_parser

        self.assertEqual(build_parser().parse_args([]).host, "127.0.0.1")

    def test_serve_defaults_to_loopback(self):
        import inspect
        from bitorus.decoy.http import serve

        self.assertEqual(inspect.signature(serve).parameters["host"].default, "127.0.0.1")

    def test_exposure_requires_an_explicit_flag(self):
        from bitorus.decoy.http import build_parser

        self.assertEqual(build_parser().parse_args(["--host", "0.0.0.0"]).host, "0.0.0.0")


if __name__ == "__main__":
    unittest.main()
