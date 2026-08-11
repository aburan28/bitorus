"""Live MCP transport over Streamable HTTP.

The monitor connects to servers that may be hostile -- that is the entire
point of it -- so the client is the attack surface. Everything here is
defensive: the observer must not be compromised by the observed.

Concretely: resolve and vet every target before connecting, cap response
size, cap redirects and re-vet each hop, never carry headers across an
origin change, and time out everything.

VERIFY AGAINST THE CURRENT MCP SPEC BEFORE DEPLOYING. Transport details
(header names, session semantics, the JSON vs SSE response split) move, and
a client that mis-implements them will mis-read servers rather than fail
loudly.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

from .monitor import CrawlPolicy, PolicyViolation

PROTOCOL_VERSION = "2025-06-18"

# A hostile server should not be able to make us read an unbounded body.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_REDIRECTS = 3
DEFAULT_TIMEOUT = 20.0


class TransportError(RuntimeError):
    """Fetch failed. Recorded as unreachable rather than raised to the caller.

    Carries `retry_after` when the server told us how long to wait. A server
    asking us to slow down is authoritative -- it is the only party that
    knows what it can take -- so this overrides our own backoff.
    """

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class UnsafeTarget(PolicyViolation):
    """Target resolves somewhere we must not connect.

    A subclass of PolicyViolation so the monitor's existing skip-not-fail
    handling applies without special-casing.
    """


def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local     # includes 169.254.169.254, the cloud metadata endpoint
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def vet_url(url: str, *, allow_plaintext: bool = False, resolver: Callable | None = None) -> str:
    """Reject anything that would point the crawler inward.

    Returns the normalised URL. Raises UnsafeTarget otherwise.

    Residual risk, stated rather than hidden: this resolves the name and
    then hands the *name* to urllib, which resolves again. A server that
    controls its DNS can answer differently the second time (rebinding).
    Closing that needs connecting to a pinned IP with the Host header set
    manually, which urllib does not expose cleanly. Acceptable for a
    read-only client with no credentials and a response-size cap; not
    acceptable if either of those changes.
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")

    if parsed.scheme not in ("https", "http"):
        raise UnsafeTarget(f"unsupported scheme {parsed.scheme!r}")
    if parsed.scheme == "http" and not allow_plaintext:
        raise UnsafeTarget("plaintext http requires allow_plaintext")
    if not parsed.hostname:
        raise UnsafeTarget("no host in target")

    resolve = resolver or (lambda h: [ai[4][0] for ai in socket.getaddrinfo(h, None)])
    try:
        addresses = resolve(parsed.hostname)
    except Exception as exc:
        raise UnsafeTarget(f"cannot resolve {parsed.hostname}: {exc}") from exc

    if not addresses:
        raise UnsafeTarget(f"{parsed.hostname} resolved to nothing")
    for ip in addresses:
        if not _is_public(ip):
            raise UnsafeTarget(
                f"{parsed.hostname} resolves to non-public address {ip}; "
                "the monitor must not reach internal infrastructure"
            )

    return parsed.geturl()


def parse_sse(body: str) -> list[dict]:
    """Extract JSON payloads from a text/event-stream body.

    Tolerant by design: a server that emits comments, heartbeats, or
    unparseable events should not abort the whole read.
    """
    messages: list[dict] = []
    for block in body.replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(
            line[5:].lstrip() for line in block.split("\n") if line.startswith("data:")
        )
        if not data.strip():
            continue
        try:
            messages.append(json.loads(data))
        except json.JSONDecodeError:
            continue
    return messages


@dataclass
class HttpTransport:
    """Streamable-HTTP MCP client, discovery methods only.

    `opener` is injectable so the request path is testable without a
    network, and so a deployment can substitute a hardened opener.
    """

    timeout: float = DEFAULT_TIMEOUT
    allow_plaintext: bool = False
    max_bytes: int = MAX_RESPONSE_BYTES
    opener: Callable[[urllib.request.Request, float], tuple[int, dict, bytes]] | None = None
    resolver: Callable | None = None
    _session_ids: dict[str, str] = field(default_factory=dict)

    # -- request plumbing ------------------------------------------------

    def _open(self, request: urllib.request.Request) -> tuple[int, dict, bytes]:
        if self.opener:
            return self.opener(request, self.timeout)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    raise TransportError(f"response exceeded {self.max_bytes} bytes")
                return response.status, dict(response.headers), body
        except urllib.error.HTTPError as exc:
            body = exc.read(self.max_bytes) if hasattr(exc, "read") else b""
            return exc.code, dict(exc.headers or {}), body
        except urllib.error.URLError as exc:
            raise TransportError(str(exc.reason)) from exc
        except OSError as exc:
            raise TransportError(str(exc)) from exc

    def _rpc(self, url: str, policy: CrawlPolicy, method: str, params: dict | None,
             request_id: int | None) -> dict | None:
        """One JSON-RPC call. `request_id=None` sends a notification."""
        policy.check_method(method)

        payload: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        if request_id is not None:
            payload["id"] = request_id

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": policy.user_agent,
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        }
        if (session := self._session_ids.get(url)):
            headers["Mcp-Session-Id"] = session

        request = urllib.request.Request(
            url, data=json.dumps(payload).encode(), headers=headers, method="POST"
        )
        status, response_headers, body = self._open(request)

        lowered = {k.lower(): v for k, v in response_headers.items()}
        if (session := lowered.get("mcp-session-id")):
            self._session_ids[url] = session

        if status == 429 or status >= 500:
            from .scheduler import parse_retry_after

            raise TransportError(
                f"HTTP {status}", retry_after=parse_retry_after(lowered.get("retry-after"))
            )
        if status >= 400:
            raise TransportError(f"HTTP {status}")
        if request_id is None:
            return None

        text = body.decode("utf-8", errors="replace")
        if "text/event-stream" in lowered.get("content-type", ""):
            candidates = parse_sse(text)
        else:
            try:
                decoded = json.loads(text)
            except json.JSONDecodeError as exc:
                raise TransportError(f"non-JSON response: {exc}") from exc
            candidates = decoded if isinstance(decoded, list) else [decoded]

        for message in candidates:
            if message.get("id") == request_id:
                if "error" in message:
                    raise TransportError(f"{method}: {message['error']}")
                return message.get("result", {})
        raise TransportError(f"{method}: no response with id {request_id}")

    # -- Transport protocol ----------------------------------------------

    def discover(self, url: str, policy: CrawlPolicy) -> dict:
        """Full discovery handshake. Raises on failure; the monitor records
        that as an unreachable snapshot rather than losing the round."""
        policy.check_target(url)
        target = vet_url(url, allow_plaintext=self.allow_plaintext, resolver=self.resolver)

        initialize = self._rpc(target, policy, "initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "bitorus-ecosystem-monitor", "version": "0.1.0"},
        }, request_id=1)

        self._rpc(target, policy, "notifications/initialized", {}, request_id=None)

        tools = self._rpc(target, policy, "tools/list", {}, request_id=2)

        # Optional surfaces: a server may not implement them, and that is
        # not a failure of the crawl.
        try:
            resources = self._rpc(target, policy, "resources/list", {}, request_id=3)
        except TransportError:
            resources = {"resources": []}

        return {"initialize": initialize, "tools": tools, "resources": resources}
