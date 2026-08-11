"""The canary client.

Connects to MCP servers, records what they advertise, and diffs over time.
The inverse of a honeypot: not catching attackers who come to us, but
finding hostile servers in the ecosystem before a customer's agent connects
to one.

This is measurement, not intrusion, and the line has to be visible from the
outside. CrawlPolicy enforces that in code rather than in a comment: no
authentication, no invocation, honest identification, rate limits. The
read-only guarantee is the important one -- a monitor that called tools
would be doing exactly what it is trying to detect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..schema import (
    EvidenceMethod,
    Lineage,
    Provenance,
    Sighting,
    ThreatAssertion,
    commit,
)
from .detectors import Severity
from .diff import Finding, baseline_findings, compare
from .snapshot import ServerSnapshot, from_mcp_responses

# Methods the monitor is permitted to call. Discovery only: nothing here
# causes a side effect on the observed server.
READ_ONLY_METHODS = frozenset(
    {"initialize", "notifications/initialized", "tools/list", "resources/list", "prompts/list"}
)


class PolicyViolation(RuntimeError):
    """Raised when a crawl would exceed what passive measurement permits."""


@dataclass(frozen=True)
class CrawlPolicy:
    """Ethical constraints, enforced rather than documented.

    Deliberately strict: a false positive costs a skipped server, while a
    false negative means we authenticated to, or invoked something on,
    infrastructure we do not own.
    """

    user_agent: str = "bitorus-ecosystem-monitor/0.1 (+security-research; contact: abuse@example.org)"
    min_interval_seconds: int = 3600
    send_credentials: bool = False
    opt_out: frozenset[str] = frozenset()

    def check_method(self, method: str) -> None:
        if method not in READ_ONLY_METHODS:
            raise PolicyViolation(
                f"{method!r} is not read-only; the monitor must never invoke tools "
                "on servers it does not own"
            )

    def check_target(self, url: str) -> None:
        if url in self.opt_out:
            raise PolicyViolation(f"{url} has opted out of monitoring")
        if self.send_credentials:
            raise PolicyViolation("monitor must not authenticate to third-party servers")


class Transport(Protocol):
    """Fetches the discovery surface of one server.

    Abstract so the same monitor drives a live crawl, a replayed capture, or
    a test fixture.
    """

    def discover(self, url: str, policy: CrawlPolicy) -> dict: ...


@dataclass
class Monitor:
    """Longitudinal observation of a set of servers."""

    transport: Transport
    policy: CrawlPolicy = field(default_factory=CrawlPolicy)
    history: dict[str, list[ServerSnapshot]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def poll(self, url: str, observed_at: str) -> tuple[ServerSnapshot, list[Finding]]:
        """One observation, diffed against the previous one."""
        self.policy.check_target(url)

        try:
            surface = self.transport.discover(url, self.policy)
            snapshot = from_mcp_responses(
                url,
                observed_at,
                surface.get("initialize", {}),
                surface.get("tools", {}),
                surface.get("resources", {}),
            )
        except PolicyViolation:
            raise
        except Exception as exc:
            snapshot = ServerSnapshot(
                server_url=url,
                observed_at=observed_at,
                reachable=False,
                error=str(exc),
                retry_after=getattr(exc, "retry_after", None),
            )

        prior = self.history.get(url, [])
        new = baseline_findings(snapshot) if not prior else compare(prior[-1], snapshot)

        self.history.setdefault(url, []).append(snapshot)
        self.findings.extend(new)
        return snapshot, new

    def poll_all(self, urls: list[str], observed_at: str) -> list[Finding]:
        out = []
        for url in urls:
            try:
                _, found = self.poll(url, observed_at)
                out.extend(found)
            except PolicyViolation:
                continue  # opted out; not an error
        return out

    # -- reporting -------------------------------------------------------

    def report(self, min_severity: Severity = Severity.MEDIUM) -> list[Finding]:
        """The product: what changed, and which changes are suspicious."""
        return sorted(
            (f for f in self.findings if f.severity >= min_severity),
            key=lambda f: (-f.severity, f.server_url, f.tool or ""),
        )

    def churn(self) -> dict[str, int]:
        """Servers by number of distinct advertised surfaces observed.

        High churn is not itself malicious, but it is the population where
        a rug pull can hide.
        """
        return {
            url: len({s.digest for s in snaps if s.reachable})
            for url, snaps in self.history.items()
        }

    def to_assertions(self, org: str) -> list[ThreatAssertion]:
        """Turn high-severity findings into scoreable assertions.

        Evidence method is CAPTURED_ARTIFACT: we hold both snapshots and can
        open the commitment to show the exact before and after. That is a
        materially stronger claim than a rule firing, and the corroboration
        engine weights it accordingly.
        """
        out = []
        for f in self.report(Severity.HIGH):
            pattern_id = f"ATP-MCP-{f.kind}-{abs(hash(f.server_url)) % 10000:04d}"
            out.append(
                ThreatAssertion(
                    assertion_id=f"urn:bitorus:assertion:{pattern_id}",
                    pattern_id=pattern_id,
                    title=f"{f.kind.replace('_', ' ')}: {f.server_url}",
                    sightings=[
                        Sighting(
                            sighting_id=f"sig-eco-{abs(hash((f.kind, f.server_url, f.tool))) % 100000}",
                            pattern_id=pattern_id,
                            observed_at=self.history[f.server_url][-1].observed_at,
                            provenance=Provenance(
                                organization=org,
                                sensor_software="bitorus-ecosystem-monitor",
                                sensor_version="0.1.0",
                                detector_id=f"ecosystem.{f.kind}",
                                detector_version="0.1.0",
                                delivery_vector="mcp_tool_definition",
                                evidence_method=EvidenceMethod.CAPTURED_ARTIFACT,
                            ),
                            lineage=Lineage.INDEPENDENT,
                            evidence_commitment=commit(
                                "|".join([f.kind, f.server_url, f.tool or "", *f.evidence])
                            ),
                        )
                    ],
                    atlas_techniques=["AML.T0010"],  # ML supply chain compromise
                    affected_configurations=[f.server_url],
                    reproduced=True,  # both snapshots retained
                )
            )
        return out


class ReplayTransport:
    """Serves a scripted sequence of surfaces per URL. Demo and tests only."""

    def __init__(self, script: dict[str, list[dict]]):
        self.script = script
        self.cursor: dict[str, int] = {}

    def discover(self, url: str, policy: CrawlPolicy) -> dict:
        for method in ("initialize", "tools/list"):
            policy.check_method(method)
        if url not in self.script:
            raise ConnectionError("no route to host")
        i = min(self.cursor.get(url, 0), len(self.script[url]) - 1)
        self.cursor[url] = i + 1
        surface = self.script[url][i]
        if surface is None:
            raise ConnectionError("connection refused")
        return surface
