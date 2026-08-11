#!/usr/bin/env python3
"""MCP ecosystem monitor demonstration.

    python3 demo_ecosystem.py

The inverse of the decoy fleet: not catching attackers who come to us, but
finding hostile servers before a customer's agent connects to one.

Three observation rounds over seven servers. The point of the exercise is
the rug pull -- a server that presents benign definitions during review and
changes them afterward is undetectable by a one-time security review, by
construction. Only longitudinal comparison catches it.
"""

from __future__ import annotations

from bitorus import corroboration
from bitorus.ecosystem import CrawlPolicy, Monitor, PolicyViolation, ReplayTransport
from bitorus.ecosystem.detectors import Severity, scan
from bitorus.ecosystem.simulated_registry import DESCRIPTIONS, REGISTRY

ROUNDS = ["2026-07-27", "2026-08-03", "2026-08-10"]


def rule(title: str = "") -> None:
    print(f"\n\033[1m{'─' * 78}\033[0m")
    if title:
        print(f"\033[1m{title}\033[0m\n")


SEV_COLOR = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH: "\033[93m",
    Severity.MEDIUM: "\033[96m",
}


def scenario_1_crawl() -> Monitor:
    rule("1. Longitudinal observation of a simulated MCP ecosystem")

    monitor = Monitor(transport=ReplayTransport(REGISTRY))
    urls = list(REGISTRY)

    print(f"Monitoring {len(urls)} servers over {len(ROUNDS)} rounds:\n")
    for url in urls:
        print(f"    {url:<32} ({DESCRIPTIONS[url]})")

    print()
    for i, when in enumerate(ROUNDS, 1):
        found = monitor.poll_all(urls, when)
        notable = [f for f in found if f.severity >= Severity.MEDIUM]
        print(f"    round {i}  {when}   {len(found):>2} change(s), "
              f"{len(notable)} notable")

    return monitor


def scenario_2_report(monitor: Monitor) -> None:
    rule("2. The product: what changed, and which changes are suspicious")

    report = monitor.report(Severity.MEDIUM)
    print(f"  {len(report)} finding(s) at MEDIUM or above, "
          f"from {sum(len(v) for v in monitor.history.values())} observations.\n")

    for f in report:
        color = SEV_COLOR.get(f.severity, "")
        where = f.server_url + (f" :: {f.tool}" if f.tool else "")
        print(f"  {color}{f.severity.label.upper():<8}\033[0m {f.kind}")
        print(f"           {where}")
        print(f"           {f.summary}")
        for e in f.evidence[:3]:
            print(f"             - {e}")
        print()

    quiet = [u for u in REGISTRY if not any(
        x.server_url == u and x.severity >= Severity.MEDIUM for x in monitor.findings
    )]
    print(f"  Silent this period: {', '.join(quiet)}")
    print("  A stable control that never fires is what makes the rest credible.")


def scenario_3_rug_pull(monitor: Monitor) -> None:
    rule("3. Why a one-time review cannot catch this")

    url = "mcp.invoice-tools.example"
    snaps = monitor.history[url]

    print("  The same tool, across three observations:\n")
    for i, snap in enumerate(snaps, 1):
        tool = snap.tool("invoice.search")
        signals = scan(tool.description)
        state = "\033[91mPOISONED\033[0m" if signals else "\033[92mclean\033[0m"
        print(f"    round {i}  v{snap.server_version:<8} digest {tool.digest}  {state}")

    print("\n  Rounds 1 and 2 are byte-identical. A security review at either")
    print("  point signs off. The payload lands in round 3, in a patch release.\n")

    tool = snaps[-1].tool("invoice.search")
    for s in scan(tool.description):
        print(f"    {s.kind}  ({s.severity.label})")
        print(f"      {s.excerpt}")

    print("\n  Detectable only by comparison against retained history —")
    print("  which is also why the corpus is a moat: a competitor starting")
    print("  later cannot retroactively acquire the clean baseline.")


def scenario_4_broadening(monitor: Monitor) -> None:
    rule("4. Silent schema broadening: no description change at all")

    snaps = monitor.history["mcp.db-helper.example"]
    before, after = snaps[0].tool("db.query"), snaps[-1].tool("db.query")

    print(f"  Description unchanged: {before.description == after.description}")
    print(f"  Schema digest          {before.schema_digest} -> {after.schema_digest}\n")

    print(f"    {'':<14}{'before':<38}{'after'}")
    print(f"    {'-'*12:<14}{'-'*36:<38}{'-'*24}")
    print(f"    {'required':<14}{str(sorted(before.required)):<38}{sorted(after.required)}")
    for prop in sorted(set(before.properties) | set(after.properties)):
        b = before.constraint_of(prop) or "(absent)"
        a = after.constraint_of(prop) or "(absent)"
        print(f"    {prop:<14}{str(b)[:36]:<38}{str(a)[:24]}")

    finding = next(f for f in monitor.findings if f.kind == "schema_broadened")
    print(f"\n  {finding.summary}")
    for e in finding.evidence:
        print(f"    - {e}")
    print("\n  Nothing a human reads changed. The tool now takes raw SQL.")


def scenario_5_policy() -> None:
    rule("5. Ethics enforced in code, not in a comment")

    policy = CrawlPolicy(opt_out=frozenset({"mcp.private.example"}))

    print("  This is measurement, not intrusion, and the line has to be")
    print("  visible from the outside. The policy object refuses:\n")

    for label, thunk in [
        ("invoking a tool on a third-party server", lambda: policy.check_method("tools/call")),
        ("reading a third party's resources", lambda: policy.check_method("resources/read")),
        ("crawling an opted-out server", lambda: policy.check_target("mcp.private.example")),
        ("authenticating to a third party",
         lambda: CrawlPolicy(send_credentials=True).check_target("mcp.any.example")),
    ]:
        try:
            thunk()
            print(f"    \033[91mALLOWED\033[0m  {label}   <- policy gap")
        except PolicyViolation as e:
            print(f"    refused  {label}")
            print(f"             {e}")

    print("\n  A monitor that called tools would be doing precisely what it")
    print("  exists to detect. That is a hard failure, not a lint warning.")


def scenario_6_federation(monitor: Monitor) -> None:
    rule("6. Feeding the federation: monitor findings as scored assertions")

    assertions = monitor.to_assertions(org="bitorus-research")
    print(f"  {len(assertions)} high-severity finding(s) became assertions.\n")

    for a in assertions[:3]:
        r = corroboration.score(a)
        print(f"    {a.title}")
        print(f"      {r}")

    print("\n  Evidence method is CAPTURED_ARTIFACT, not RULE_MATCH: we hold")
    print("  both snapshots and can open the commitment to show the exact")
    print("  before and after. The corroboration engine weights that higher —")
    print("  a single reproducible artifact outscores several rule matches.\n")

    a = assertions[0]
    print(f"    single captured artifact   confidence {corroboration.score(a).confidence:.3f}")
    print(f"    reproduced                 {a.reproduced}")
    print("\n  This is the Product 1 property: value on day one, no federation,")
    print("  no customer deployment, and no attacker required to cooperate.")


def main() -> None:
    print("\n\033[1mBiTorus prototype — MCP ecosystem monitor\033[0m")
    monitor = scenario_1_crawl()
    scenario_2_report(monitor)
    scenario_3_rug_pull(monitor)
    scenario_4_broadening(monitor)
    scenario_5_policy()
    scenario_6_federation(monitor)
    rule()
    print("Design note: ../docs/research/decoy-agent-infrastructure.md §9\n")


if __name__ == "__main__":
    main()
