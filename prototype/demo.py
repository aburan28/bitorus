#!/usr/bin/env python3
"""End-to-end demonstration.

    python3 demo.py

Four scenarios:
  1. A decoy fleet separates agents from scanners and humans.
  2. Differential payloads build a susceptibility matrix no single node could.
  3. Effective corroboration defeats a Sybil amplification attack.
  4. Lineage tracking closes circular reporting.
"""

from __future__ import annotations

from bitorus import corroboration
from bitorus.decoy import Fleet
from bitorus.decoy.payloads import Encoding
from bitorus.decoy.simulated_clients import (
    SimulatedAgent,
    SimulatedHumanOperator,
    SimulatedScanner,
)
from bitorus.schema import (
    EvidenceMethod,
    Lineage,
    Provenance,
    Sighting,
    ThreatAssertion,
)

REGIONS = ["us-east", "eu-west", "ap-south", "sa-east", "af-south", "us-west"]


def rule(title: str = "") -> None:
    print(f"\n\033[1m{'─' * 76}\033[0m")
    if title:
        print(f"\033[1m{title}\033[0m\n")


def scenario_1_detection() -> Fleet:
    rule("1. Decoy fleet: separating agents from everything else")

    fleet = Fleet.deploy(REGIONS)
    print(f"Deployed {len(fleet.nodes)} nodes, one injection encoding each:")
    for n in fleet.nodes:
        print(f"    {n.node_id:<10} {n.encoding.value}")

    # A hardened scaffold that strips two encodings but not the rest.
    populations = [
        (
            SimulatedAgent("naive-agent", sanitizes=frozenset()),
            "agent, no sanitization",
        ),
        (
            SimulatedAgent(
                "hardened-agent",
                sanitizes=frozenset({Encoding.HTML_COMMENT, Encoding.ZERO_WIDTH}),
                # A different framework: enumerates prompts, discovers
                # resources first, negotiates no sampling capability.
                enumeration=("resources/list", "tools/list", "prompts/list"),
                capabilities=("roots",),
            ),
            "agent, partially hardened",
        ),
        (SimulatedScanner(), "internet scanner"),
        (SimulatedHumanOperator(), "human operator"),
    ]

    for client, label in populations:
        for node in fleet.nodes:
            client.run(node)
        print(f"\n  {label} ({client.name}) swept all {len(fleet.nodes)} nodes")

    print("\nVerdicts by interaction depth:\n")
    print(f"    {'client':<20} {'depth reached':<32} {'agent?'}")
    print(f"    {'-' * 20} {'-' * 32} {'-' * 6}")

    seen = {}
    for s in fleet.sessions():
        is_agent, reasons = s.is_agent_candidate()
        prev = seen.get(s.client_name)
        if prev is None or s.depth > prev[0].depth:
            seen[s.client_name] = (s, is_agent, reasons)

    for name, (s, is_agent, reasons) in seen.items():
        mark = "\033[91mYES\033[0m" if is_agent else "no "
        print(f"    {name:<20} {s.depth.label:<32} {mark}")

    print("\n  Evidence for the strongest verdict:")
    best = max(seen.values(), key=lambda t: t[0].depth)
    for r in best[2]:
        print(f"    - {r}")
    print(f"\n  Scaffold fingerprint: {best[0].scaffold_fingerprint()}")
    print("  (behavioural: survives IP rotation, excludes client-supplied name)")

    return fleet


def scenario_2_matrix(fleet: Fleet) -> None:
    rule("2. Susceptibility matrix: what only a coordinated fleet can measure")

    matrix = fleet.susceptibility_matrix()
    encodings = list(Encoding)

    header = "    " + " " * 26 + "".join(f"{e.value[:9]:<11}" for e in encodings)
    print(header)
    print("    " + " " * 26 + "".join(f"{'-' * 9:<11}" for e in encodings))

    label_for = {}
    for s in fleet.sessions():
        label_for[s.scaffold_fingerprint()] = s.client_name

    for scaffold, row in matrix.items():
        name = label_for.get(scaffold, "?")
        cells = "".join(
            f"{('TRIP' if row[e] else 'resist' if row[e] is False else '-'):<11}"
            for e in encodings
        )
        print(f"    {name[:24]:<26}{cells}")

    print("\n  A single node learns 'this agent fell for ANSI'.")
    print("  The fleet learns which sanitization each scaffold is missing —")
    print("  which is portable defensive guidance, and is not computable")
    print("  from any one node's logs.")

    linkage = fleet.cross_node_linkage()
    print(f"\n  Cross-node linkage: {len(linkage)} scaffolds seen on multiple nodes")
    for scaffold, nodes in list(linkage.items())[:2]:
        print(f"    {label_for.get(scaffold,'?'):<20} {len(nodes)} nodes: {', '.join(nodes[:4])}...")


def scenario_3_sybil(fleet: Fleet) -> None:
    rule("3. Sybil amplification: 10 correlated reports vs 3 independent")

    pattern = "ATP-2026-0001"

    def sighting(i: int, *, org: str, stack: str, detector: str, region: str) -> Sighting:
        return Sighting(
            sighting_id=f"sig-{org}-{i}",
            pattern_id=pattern,
            observed_at="2026-08-10T00:00:00Z",
            provenance=Provenance(
                organization=org,
                sensor_software=stack,
                sensor_version="3.1.0",
                detector_id=detector,
                detector_version="7",
                cloud_provider="aws",
                region=region,
                evidence_method=EvidenceMethod.RULE_MATCH,
            ),
        )

    # Ten "different organizations" -- all running an identical stack.
    sybil = ThreatAssertion(
        assertion_id="urn:bitorus:assertion:sybil",
        pattern_id=pattern,
        title="Amplified by correlated reporters",
        sightings=[
            sighting(i, org=f"shell-org-{i}", stack="acme-sensor", detector="rule.aa", region="us-east-1")
            for i in range(10)
        ],
    )

    # Three genuinely diverse reporters.
    genuine = ThreatAssertion(
        assertion_id="urn:bitorus:assertion:genuine",
        pattern_id=pattern,
        title="Corroborated by independent reporters",
        sightings=[
            sighting(0, org="bank-a", stack="acme-sensor", detector="rule.aa", region="us-east-1"),
            sighting(1, org="retail-b", stack="zeta-edr", detector="rule.bb", region="eu-west-1"),
            sighting(2, org="gov-c", stack="own-build", detector="analyst.cc", region="ap-south-1"),
        ],
    )

    for label, assertion in (("10 correlated", sybil), ("3 independent", genuine)):
        r = corroboration.score(assertion)
        bar = "█" * int(r.confidence * 40)
        print(f"  {label:<16} {r}")
        print(f"  {'':<16} confidence \033[92m{bar}\033[0m\n")

    sybil_r = corroboration.score(sybil)
    genuine_r = corroboration.score(genuine)
    print(f"  Three independent reports beat ten correlated ones: "
          f"{genuine_r.confidence:.3f} > {sybil_r.confidence:.3f}")
    print(f"  Naive counting would have ranked them "
          f"{sybil_r.naive_confidence:.3f} vs {genuine_r.naive_confidence:.3f} — backwards.")
    print(f"  Correlated volume inflated apparent evidence {sybil_r.inflation:.1f}x.")

    # Adversary cost curve.
    print("\n  Adversary cost to manufacture consensus:\n")
    empty = ThreatAssertion(assertion_id="probe", pattern_id=pattern, title="probe")

    def cheap(_: int) -> Sighting:
        return sighting(0, org="shell", stack="acme-sensor", detector="rule.aa", region="us-east-1")

    def expensive(i: int) -> Sighting:
        return sighting(i, org=f"org-{i}", stack=f"stack-{i}", detector=f"rule-{i}", region=f"r-{i}")

    print(f"    {'target confidence':<20}{'reusing one stack':<22}{'diverse stacks'}")
    print(f"    {'-'*18:<20}{'-'*20:<22}{'-'*16}")
    for target in (0.50, 0.80, 0.95, 0.99):
        c = corroboration.cost_to_reach(empty, target, cheap, independent=False)
        e = corroboration.cost_to_reach(empty, target, expensive, independent=True)
        print(f"    {target:<20.2f}{('unreachable' if c is None else f'{c} sightings'):<22}"
              f"{('unreachable' if e is None else f'{e} sightings')}")

    print("\n  Sybils hit a ceiling; genuine independence is the only way up.")
    print("  That gap is the defense — stated as a price, not as impossibility.")


def scenario_4_circular() -> None:
    rule("4. Circular reporting: the cheapest amplification attack")

    pattern = "ATP-2026-0002"
    origin = Sighting(
        sighting_id="sig-origin",
        pattern_id=pattern,
        observed_at="2026-08-01T00:00:00Z",
        provenance=Provenance(
            organization="origin-org",
            sensor_software="acme-sensor",
            sensor_version="3.1.0",
            detector_id="analyst.review",
            detector_version="1",
            evidence_method=EvidenceMethod.ANALYST_INFERENCE,
        ),
        lineage=Lineage.INDEPENDENT,
    )

    assertion_id = "urn:bitorus:assertion:circular"

    # Eight orgs install the distributed rule; it fires; they report.
    # Every one is causally downstream of the single original claim.
    downstream = [
        Sighting(
            sighting_id=f"sig-downstream-{i}",
            pattern_id=pattern,
            observed_at="2026-08-05T00:00:00Z",
            provenance=Provenance(
                organization=f"member-{i}",
                sensor_software=f"stack-{i}",
                sensor_version="1.0",
                detector_id="bitorus.dist.rule-441",
                detector_version="1",
                evidence_method=EvidenceMethod.RULE_MATCH,
            ),
            lineage=Lineage.FEDERATION_DERIVED,
            derived_from=assertion_id,
        )
        for i in range(8)
    ]

    assertion = ThreatAssertion(
        assertion_id=assertion_id,
        pattern_id=pattern,
        title="One unverified claim, redistributed",
        sightings=[origin, *downstream],
    )

    print("  One analyst inference, distributed as a rule, reported back by 8 members.")
    print("  Every downstream sighting is caused by the assertion it appears to confirm.\n")

    naive = corroboration.score(assertion, track_lineage=False)
    tracked = corroboration.score(assertion, track_lineage=True)

    print(f"    lineage ignored   {naive}")
    print(f"    lineage tracked   {tracked}")
    print(f"\n  Apparent consensus from 9 reports collapses to "
          f"{tracked.n_eff:.2f} effective observations.")
    print("  No Sybils required: one plausible assertion and a federation that")
    print("  redistributes detections without tracking lineage does it for free.")
    print("\n  Cost to defend: one enum and one artifact id per assertion —")
    print("  but only if it is in the schema before data collection starts.")


def scenario_5_loop(fleet: Fleet) -> None:
    rule("5. The loop: decoy observations entering the federation")

    assertion = fleet.to_assertion(
        org="bitorus-research",
        pattern_id="ATP-2026-0003",
        title="Indirect prompt injection via MCP resource content",
    )
    r = corroboration.score(assertion)

    print(f"  Assertion:   {assertion.title}")
    print(f"  ATLAS:       {', '.join(assertion.atlas_techniques)}")
    print(f"  ATT&CK:      {', '.join(assertion.attack_techniques)}")
    print(f"  Affected:    {len(assertion.affected_configurations)} scaffold(s)")
    print(f"  Reproduced:  {assertion.reproduced}")
    print(f"  Digest:      {assertion.digest()[:32]}...")
    print(f"\n  Scoring:     {r}")
    print(f"\n  {r.n_raw} sightings from one operator's fleet score as "
          f"{r.n_eff:.2f} effective observations —")
    print("  correct, because one operator's fleet is one observer however")
    print("  many regions it spans. Independent confirmation has to come")
    print("  from a different operator, which is what the federation is for.")


def main() -> None:
    print("\n\033[1mBiTorus prototype — decoy fleet + independence-aware corroboration\033[0m")
    fleet = scenario_1_detection()
    scenario_2_matrix(fleet)
    scenario_3_sybil(fleet)
    scenario_4_circular()
    scenario_5_loop(fleet)
    rule()
    print("Design notes: ../docs/research/decoy-agent-infrastructure.md")
    print("              ../docs/research/byzantine-robust-federation.md\n")


if __name__ == "__main__":
    main()
