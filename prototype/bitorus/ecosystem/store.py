"""Append-only snapshot persistence.

The whole value of this component is longitudinal, so losing history
destroys the product, not just a run. Two consequences shape the design:

  Append-only. A rug pull is proven by the *clean* snapshot that preceded
  it. Rewriting or compacting history would discard the evidence that makes
  the finding a finding.

  Line-delimited JSON. Survives partial writes -- a truncated final line is
  one lost observation, not a corrupt store -- and can be read by anything.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .snapshot import ResourceSpec, ServerSnapshot, ToolSpec
from .scheduler import host_of


def _encode(snapshot: ServerSnapshot) -> dict:
    return {
        "server_url": snapshot.server_url,
        "observed_at": snapshot.observed_at,
        "server_name": snapshot.server_name,
        "server_version": snapshot.server_version,
        "protocol_version": snapshot.protocol_version,
        "reachable": snapshot.reachable,
        "error": snapshot.error,
        "digest": snapshot.digest,
        "tools": [
            {"name": t.name, "description": t.description, "inputSchema": t.input_schema}
            for t in snapshot.tools
        ],
        "resources": [
            {"uri": r.uri, "name": r.name, "mimeType": r.mime_type} for r in snapshot.resources
        ],
    }


def _decode(record: dict) -> ServerSnapshot:
    return ServerSnapshot(
        server_url=record["server_url"],
        observed_at=record["observed_at"],
        server_name=record.get("server_name", ""),
        server_version=record.get("server_version", ""),
        protocol_version=record.get("protocol_version", ""),
        reachable=record.get("reachable", True),
        error=record.get("error"),
        tools=tuple(
            ToolSpec(t.get("name", ""), t.get("description", "") or "", t.get("inputSchema") or {})
            for t in record.get("tools", [])
        ),
        resources=tuple(
            ResourceSpec(r.get("uri", ""), r.get("name", ""), r.get("mimeType", ""))
            for r in record.get("resources", [])
        ),
    )


@dataclass
class SnapshotStore:
    """One JSONL file per host, under `root`."""

    root: Path

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, url: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in host_of(url))
        return self.root / f"{safe}.jsonl"

    def append(self, snapshot: ServerSnapshot) -> None:
        with self._path(snapshot.server_url).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(_encode(snapshot), ensure_ascii=False) + "\n")

    def load(self, url: str) -> list[ServerSnapshot]:
        path = self._path(url)
        if not path.exists():
            return []
        out = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # A truncated final line from an interrupted write. One lost
                # observation, not a corrupt store.
                continue
            if record.get("server_url") == url:
                out.append(_decode(record))
        return out

    def urls(self) -> list[str]:
        seen = []
        for path in sorted(self.root.glob("*.jsonl")):
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    url = json.loads(line).get("server_url")
                except json.JSONDecodeError:
                    continue
                if url and url not in seen:
                    seen.append(url)
        return seen

    def hydrate(self, monitor, urls: list[str] | None = None) -> int:
        """Reload prior history into a Monitor.

        Without this a restarted crawler treats every server as first-seen,
        which silently converts every rug pull into a baseline observation.
        """
        loaded = 0
        for url in urls if urls is not None else self.urls():
            snapshots = self.load(url)
            if snapshots:
                monitor.history[url] = snapshots
                loaded += len(snapshots)
        return loaded
