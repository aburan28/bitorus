"""Rate limiting and backoff.

CrawlPolicy declares `min_interval_seconds`; this enforces it. The
distinction matters -- a declared limit nobody applies is how a
well-intentioned crawler becomes an unintentional stress test on someone
else's infrastructure.

Clock and jitter are injectable so the behaviour is testable without
sleeping, and so a deployment can substitute a shared clock across
processes.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse


def host_of(url: str) -> str:
    """Rate limits apply per host, not per URL.

    Several catalogued endpoints may share one host, and that host sees the
    sum of our requests regardless of how we filed them.
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.hostname or url).lower()


@dataclass
class Backoff:
    """Exponential backoff with full jitter, per host.

    Full jitter rather than fixed multiples: a fleet of crawlers that all
    fail at once and all retry at exactly 2x, 4x, 8x re-synchronises into a
    thundering herd against a host that is already struggling.
    """

    base_seconds: float = 60.0
    max_seconds: float = 6 * 3600.0
    factor: float = 2.0
    jitter: Callable[[float], float] = field(default=lambda ceiling: random.uniform(0, ceiling))
    failures: dict[str, int] = field(default_factory=dict)

    def record_failure(self, url: str) -> None:
        host = host_of(url)
        self.failures[host] = self.failures.get(host, 0) + 1

    def record_success(self, url: str) -> None:
        self.failures.pop(host_of(url), None)

    def consecutive_failures(self, url: str) -> int:
        return self.failures.get(host_of(url), 0)

    def delay_for(self, url: str) -> float:
        """Seconds to wait before retrying this host. Zero when healthy."""
        n = self.consecutive_failures(url)
        if n == 0:
            return 0.0
        ceiling = min(self.base_seconds * (self.factor ** (n - 1)), self.max_seconds)
        return self.jitter(ceiling)


@dataclass
class RateLimiter:
    """Per-host minimum interval, honouring server-supplied Retry-After.

    A server asking us to slow down is authoritative and overrides our own
    interval -- it is the only party that knows what it can take.
    """

    min_interval_seconds: float = 3600.0
    clock: Callable[[], float] = time.monotonic
    last_seen: dict[str, float] = field(default_factory=dict)
    holds: dict[str, float] = field(default_factory=dict)

    def ready_in(self, url: str) -> float:
        """Seconds until this host may be polled. Zero means now."""
        host = host_of(url)
        now = self.clock()

        hold_until = self.holds.get(host, 0.0)
        if hold_until > now:
            return hold_until - now

        last = self.last_seen.get(host)
        if last is None:
            return 0.0
        return max(0.0, self.min_interval_seconds - (now - last))

    def is_ready(self, url: str) -> bool:
        return self.ready_in(url) <= 0.0

    def record_poll(self, url: str) -> None:
        self.last_seen[host_of(url)] = self.clock()

    def hold(self, url: str, seconds: float) -> None:
        """Honour a Retry-After, or a backoff decision."""
        self.holds[host_of(url)] = self.clock() + max(0.0, seconds)


def parse_retry_after(value: str | None, *, now: float | None = None) -> float | None:
    """Retry-After as seconds. Accepts delta-seconds; HTTP-date returns None.

    Date parsing is deliberately omitted rather than half-implemented: a
    wrong date parse produces a wrong hold, and falling back to normal
    backoff is safer than guessing.
    """
    if not value:
        return None
    try:
        return max(0.0, float(value.strip()))
    except ValueError:
        return None


@dataclass
class Schedule:
    """Decides which targets are due, and defers the rest.

    Deliberately returns *reasons* for deferral rather than silently
    filtering: a crawl that quietly skips half its targets looks identical
    to a crawl that covered everything, and the difference matters when the
    output is a claim about what the ecosystem is doing.

    Backoff is expressed as a *hold on the limiter*, not as a separate
    veto -- otherwise a failed host defers forever, because clearing the
    failure count requires a success and a success requires a poll.
    """

    limiter: RateLimiter
    backoff: Backoff

    def record_failure(self, url: str, *, retry_after: float | None = None) -> float:
        """Escalate backoff and hold the host. Returns the hold in seconds."""
        self.backoff.record_failure(url)
        delay = retry_after if retry_after is not None else self.backoff.delay_for(url)
        self.limiter.hold(url, delay)
        return delay

    def record_success(self, url: str) -> None:
        self.backoff.record_success(url)
        self.limiter.record_poll(url)

    def due(self, urls: list[str]) -> tuple[list[str], dict[str, str]]:
        ready, deferred = [], {}
        for url in urls:
            wait = self.limiter.ready_in(url)
            if wait <= 0:
                ready.append(url)
                continue
            failures = self.backoff.consecutive_failures(url)
            deferred[url] = (
                f"backing off {wait:.0f}s after {failures} consecutive failure(s)"
                if failures
                else f"rate limit, {wait:.0f}s remaining"
            )
        return ready, deferred
