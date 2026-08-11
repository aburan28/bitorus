"""MCP ecosystem monitoring: canary clients that diff advertised surfaces."""

from .snapshot import ServerSnapshot, ToolSpec, from_mcp_responses
from .detectors import Severity, Signal, scan
from .diff import Finding, compare, baseline_findings
from .monitor import Monitor, CrawlPolicy, PolicyViolation, ReplayTransport

__all__ = [
    "ServerSnapshot", "ToolSpec", "from_mcp_responses",
    "Severity", "Signal", "scan",
    "Finding", "compare", "baseline_findings",
    "Monitor", "CrawlPolicy", "PolicyViolation", "ReplayTransport",
]

from .transport import HttpTransport, TransportError, UnsafeTarget, vet_url, parse_sse
from .scheduler import Backoff, RateLimiter, Schedule, host_of, parse_retry_after
from .store import SnapshotStore

__all__ += [
    "HttpTransport", "TransportError", "UnsafeTarget", "vet_url", "parse_sse",
    "Backoff", "RateLimiter", "Schedule", "host_of", "parse_retry_after",
    "SnapshotStore",
]
