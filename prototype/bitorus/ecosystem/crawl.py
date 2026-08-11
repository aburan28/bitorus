"""Crawler CLI.

    python3 -m bitorus.ecosystem.crawl --targets targets.txt --store ./data
    python3 -m bitorus.ecosystem.crawl --targets targets.txt --store ./data --dry-run

Wires transport, schedule, and store into one pass over a target list.
Designed to be run repeatedly -- by cron, or with --loop -- because a single
pass produces baselines and nothing else. The findings only exist in the
differences between passes.

Read the safety notes in transport.py before pointing this at anything.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .detectors import Severity
from .monitor import CrawlPolicy, Monitor, PolicyViolation
from .scheduler import Backoff, RateLimiter, Schedule
from .store import SnapshotStore
from .transport import HttpTransport, TransportError, UnsafeTarget, vet_url


def read_targets(path: Path) -> list[str]:
    """One URL per line; `#` comments and blanks ignored."""
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def run_pass(
    monitor: Monitor,
    schedule: Schedule,
    store: SnapshotStore,
    targets: list[str],
    *,
    verbose: bool = True,
) -> list:
    """One crawl pass. Returns findings."""
    ready, deferred = schedule.due(targets)

    if verbose and deferred:
        print(f"  deferred {len(deferred)}:")
        for url, reason in list(deferred.items())[:5]:
            print(f"    {url} -- {reason}")
        if len(deferred) > 5:
            print(f"    ... and {len(deferred) - 5} more")

    observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    findings = []

    for url in ready:
        try:
            snapshot, new = monitor.poll(url, observed_at)
        except PolicyViolation as exc:
            if verbose:
                print(f"  skip    {url} -- {exc}")
            continue

        store.append(snapshot)

        if snapshot.reachable:
            schedule.record_success(url)
            status = f"{len(snapshot.tools)} tool(s)"
        else:
            # Retry-After, when the server supplied one, is authoritative.
            delay = schedule.record_failure(url, retry_after=snapshot.retry_after)
            status = f"unreachable ({snapshot.error}); holding {delay:.0f}s"

        findings.extend(new)
        notable = [f for f in new if f.severity >= Severity.MEDIUM]
        if verbose:
            flag = f"  \033[93m{len(notable)} notable\033[0m" if notable else ""
            print(f"  polled  {url} -- {status}{flag}")

    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bitorus.ecosystem.crawl",
        description="Longitudinal MCP ecosystem monitor.",
    )
    parser.add_argument("--targets", type=Path, required=True, help="file of URLs, one per line")
    parser.add_argument("--store", type=Path, required=True, help="snapshot store directory")
    parser.add_argument("--interval", type=float, default=3600.0,
                        help="minimum seconds between polls of one host (default 3600)")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--contact", default="abuse@example.org",
                        help="contact address advertised in the User-Agent")
    parser.add_argument("--opt-out", type=Path,
                        help="file of hosts that have asked not to be monitored")
    parser.add_argument("--allow-plaintext", action="store_true",
                        help="permit http:// targets (default https only)")
    parser.add_argument("--loop", type=float, metavar="SECONDS",
                        help="repeat forever, sleeping this long between passes")
    parser.add_argument("--dry-run", action="store_true",
                        help="vet targets and report the schedule; make no requests")
    parser.add_argument("--min-severity", default="medium",
                        choices=[s.name.lower() for s in Severity])
    args = parser.parse_args(argv)

    targets = read_targets(args.targets)
    opt_out = frozenset(read_targets(args.opt_out)) if args.opt_out else frozenset()

    policy = CrawlPolicy(
        user_agent=(
            "bitorus-ecosystem-monitor/0.1 "
            f"(+security-research; contact: {args.contact})"
        ),
        min_interval_seconds=int(args.interval),
        opt_out=opt_out,
    )
    store = SnapshotStore(args.store)
    monitor = Monitor(
        transport=HttpTransport(timeout=args.timeout, allow_plaintext=args.allow_plaintext),
        policy=policy,
    )
    schedule = Schedule(
        limiter=RateLimiter(min_interval_seconds=args.interval),
        backoff=Backoff(),
    )

    restored = store.hydrate(monitor, targets)
    print(f"targets {len(targets)}  opt-out {len(opt_out)}  "
          f"restored {restored} prior observation(s)")

    if args.dry_run:
        print("\ndry run -- vetting targets, no requests made:\n")
        ok = 0
        for url in targets:
            try:
                policy.check_target(url)
                vet_url(url, allow_plaintext=args.allow_plaintext)
                history = len(monitor.history.get(url, []))
                print(f"  ok      {url}  ({history} prior)")
                ok += 1
            except (UnsafeTarget, PolicyViolation) as exc:
                print(f"  \033[91mrefused\033[0m {url} -- {exc}")
        print(f"\n{ok}/{len(targets)} targets would be crawled.")
        return 0

    min_severity = Severity[args.min_severity.upper()]

    while True:
        print(f"\npass at {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
        try:
            run_pass(monitor, schedule, store, targets)
        except KeyboardInterrupt:
            print("\ninterrupted")
            return 130

        report = monitor.report(min_severity)
        if report:
            print(f"\n{len(report)} finding(s) at {args.min_severity} or above:\n")
            for finding in report:
                print(finding)
                for evidence in finding.evidence[:3]:
                    print(f"             - {evidence}")
        else:
            print("\nno findings at or above threshold")

        if args.loop is None:
            return 0
        try:
            time.sleep(args.loop)
        except KeyboardInterrupt:
            return 130


if __name__ == "__main__":
    sys.exit(main())
