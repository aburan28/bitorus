"""Canonical snapshots of a server's advertised surface.

The unit of longitudinal observation. A snapshot is everything a client
would see and act on before invoking anything: tool names, descriptions,
input schemas, resource manifests, and server identity.

Canonical hashing matters more than it looks. A rug pull is detected by
comparing digests across time, so the digest has to be stable under
irrelevant variation (key order, whitespace in JSON) and sensitive to
everything a model would read.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()[:16]


@dataclass(frozen=True)
class ToolSpec:
    """One advertised tool.

    `description` is the security-relevant field: it is read by the client's
    model and treated as authoritative, which is what makes it a delivery
    vector rather than documentation.
    """

    name: str
    description: str
    input_schema: dict = field(default_factory=dict)

    @property
    def digest(self) -> str:
        return _digest({"n": self.name, "d": self.description, "s": self.input_schema})

    @property
    def schema_digest(self) -> str:
        return _digest(self.input_schema)

    @property
    def required(self) -> set[str]:
        return set(self.input_schema.get("required", []))

    @property
    def properties(self) -> dict:
        return self.input_schema.get("properties", {}) or {}

    def constraint_of(self, prop: str) -> dict:
        """Constraints on one parameter, ignoring prose."""
        spec = dict(self.properties.get(prop, {}))
        spec.pop("description", None)
        return spec


@dataclass(frozen=True)
class ResourceSpec:
    uri: str
    name: str = ""
    mime_type: str = ""


@dataclass(frozen=True)
class ServerSnapshot:
    """One observation of one server, at one time."""

    server_url: str
    observed_at: str
    server_name: str = ""
    server_version: str = ""
    protocol_version: str = ""
    tools: tuple[ToolSpec, ...] = ()
    resources: tuple[ResourceSpec, ...] = ()
    reachable: bool = True
    error: str | None = None
    retry_after: float | None = None
    """Seconds the server asked us to wait, when it said so."""

    @property
    def digest(self) -> str:
        """Stable over the whole advertised surface."""
        return _digest(
            {
                "server": [self.server_name, self.server_version, self.protocol_version],
                "tools": sorted(t.digest for t in self.tools),
                "resources": sorted(r.uri for r in self.resources),
            }
        )

    @property
    def identity(self) -> str:
        """Publisher identity, deliberately excluding version.

        Version bumps are routine -- including them here would raise a
        high-severity takeover finding on every release, which is the kind
        of false positive that gets a detector switched off. A *name* change
        on a stable endpoint is the actual takeover signal.
        """
        return _digest([self.server_name])

    def tool(self, name: str) -> ToolSpec | None:
        return next((t for t in self.tools if t.name == name), None)

    @property
    def tool_names(self) -> set[str]:
        return {t.name for t in self.tools}

    def to_dict(self) -> dict:
        return {
            "server_url": self.server_url,
            "observed_at": self.observed_at,
            "server_name": self.server_name,
            "server_version": self.server_version,
            "digest": self.digest,
            "tools": [
                {"name": t.name, "description": t.description, "inputSchema": t.input_schema}
                for t in self.tools
            ],
        }


def from_mcp_responses(
    server_url: str,
    observed_at: str,
    initialize_result: dict,
    tools_result: dict,
    resources_result: dict | None = None,
) -> ServerSnapshot:
    """Build a snapshot from raw MCP method results.

    Kept separate from transport so the same construction path serves a live
    crawl, a replayed capture, and a test fixture.
    """
    info = initialize_result.get("serverInfo") or {}
    resources_result = resources_result or {}
    return ServerSnapshot(
        server_url=server_url,
        observed_at=observed_at,
        server_name=info.get("name", ""),
        server_version=info.get("version", ""),
        protocol_version=initialize_result.get("protocolVersion", ""),
        tools=tuple(
            ToolSpec(
                name=t.get("name", ""),
                description=t.get("description", "") or "",
                input_schema=t.get("inputSchema") or {},
            )
            for t in tools_result.get("tools", [])
        ),
        resources=tuple(
            ResourceSpec(
                uri=r.get("uri", ""),
                name=r.get("name", ""),
                mime_type=r.get("mimeType", ""),
            )
            for r in resources_result.get("resources", [])
        ),
    )
