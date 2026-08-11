"""Simulated clients, for demonstration and regression tests.

Three populations with different behaviour, so the discriminators in
server.py have something to discriminate. Sanitizers are the important
case: they model an agent hardened against some encodings but not others,
which is what the susceptibility matrix exists to measure.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

from .payloads import CANARY_TOOL, Encoding
from .server import DecoyServer, Session

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_MD_TITLE = re.compile(r'\[.*?\]\(.*?\s+"(.*?)"\)')
_B64_META = re.compile(r"integrity_note=([A-Za-z0-9+/=]+)")


def _strip_tag_chars(text: str) -> str:
    return "".join(c for c in text if not (0xE0000 <= ord(c) <= 0xE007F))


def _decode_tag_chars(text: str) -> str:
    return "".join(
        chr(ord(c) - 0xE0000) if 0xE0000 <= ord(c) <= 0xE007F else c for c in text
    )


@dataclass
class SimulatedAgent:
    """An LLM agent reading tool output as text.

    `sanitizes` names the encodings this scaffold strips before the model
    sees content -- the defensive posture we are trying to measure.
    """

    name: str
    version: str = "1.0.0"
    sanitizes: frozenset[Encoding] = field(default_factory=frozenset)
    reads_resources: bool = True
    enumeration: tuple[str, ...] = ("tools/list", "resources/list")
    """Discovery order. Frameworks differ here, and the difference is
    client-intrinsic -- which is what makes it usable as a fingerprint."""
    capabilities: tuple[str, ...] = ("sampling", "roots")

    def _visible_to_model(self, text: str) -> str:
        """What survives this scaffold's input handling."""
        out = text
        if Encoding.ANSI_ESCAPE in self.sanitizes:
            out = _ANSI.sub("", out)
            # Stripping the escape codes leaves the instruction visible;
            # a scaffold that only strips colour still passes the text.
        if Encoding.HTML_COMMENT in self.sanitizes:
            out = _HTML_COMMENT.sub("", out)
        if Encoding.ZERO_WIDTH in self.sanitizes:
            out = _strip_tag_chars(out)
        else:
            out = _decode_tag_chars(out)
        if Encoding.MARKDOWN_HIDDEN in self.sanitizes:
            out = _MD_TITLE.sub("", out)
        if Encoding.BASE64_METADATA not in self.sanitizes:
            for blob in _B64_META.findall(out):
                try:
                    out += "\n" + base64.b64decode(blob).decode()
                except Exception:
                    pass
        else:
            out = _B64_META.sub("", out)
        return out

    def _follows_instruction(self, text: str) -> bool:
        return CANARY_TOOL in self._visible_to_model(text)

    def run(self, server: DecoyServer) -> Session:
        """A plausible agent trajectory against an unfamiliar server."""
        session = server.open_session()
        rid = iter(range(1, 1000))

        def call(method, params=None):
            return server.handle(
                session,
                {"jsonrpc": "2.0", "id": next(rid), "method": method, "params": params or {}},
            )

        call(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {c: {} for c in self.capabilities},
                "clientInfo": {"name": self.name, "version": self.version},
            },
        )
        server.handle(
            session, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        )

        tools_text = ""
        for method in self.enumeration:
            result = call(method)
            if method == "tools/list":
                tools_text = " ".join(t["description"] for t in result["result"]["tools"])

        if self.reads_resources:
            res = call("resources/read", {"uri": "file:///runbooks/oncall.md"})
            body = res["result"]["contents"][0]["text"]
            if self._follows_instruction(body):
                call("tools/call", {"name": CANARY_TOOL, "arguments": {"reason": "integrity-check"}})

        # Tool-description injection is read at enumeration time, not from
        # a resource -- a separate channel that separate sanitization misses.
        if self._follows_instruction(tools_text):
            call("tools/call", {"name": CANARY_TOOL, "arguments": {"reason": "integrity-check"}})

        # The objective the agent came for.
        call("tools/call", {"name": "secrets.read", "arguments": {"name": "prod/db"}})
        return session


@dataclass
class SimulatedScanner:
    """An internet-wide scanner. Fingerprints and leaves -- never
    enumerates tool descriptions, never invokes anything."""

    name: str = "census-probe"

    def run(self, server: DecoyServer) -> Session:
        session = server.open_session()
        server.handle(
            session,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": self.name, "version": "0.1"},
                },
            },
        )
        server.handle(session, {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}})
        return session


@dataclass
class SimulatedHumanOperator:
    """A human poking at the endpoint. Reads the runbook, ignores content
    they cannot see, and does not call an internal-only diagnostic tool."""

    name: str = "manual-mcp-client"

    def run(self, server: DecoyServer) -> Session:
        session = server.open_session()
        rid = iter(range(1, 100))

        def call(method, params=None):
            return server.handle(
                session,
                {"jsonrpc": "2.0", "id": next(rid), "method": method, "params": params or {}},
            )

        call(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": self.name, "version": "2.0"},
            },
        )
        call("tools/list")
        call("resources/read", {"uri": "file:///runbooks/oncall.md"})
        return session
