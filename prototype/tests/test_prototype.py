"""Invariant tests.

Two classes of test here. The safety invariants (payload inertness) exist
because a violation harms a third party -- those are not style checks. The
rest lock in properties that the demo surfaced as easy to break, notably
fingerprint stability across nodes.

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest

from bitorus import corroboration
from bitorus.decoy import Fleet
from bitorus.decoy.payloads import Encoding, assert_inert, build, all_encodings
from bitorus.decoy.server import DecoyServer, Depth
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


def _sighting(i, *, org, stack="acme", detector="rule.a", region="us-east-1",
              lineage=Lineage.INDEPENDENT, derived_from=None,
              method=EvidenceMethod.RULE_MATCH):
    return Sighting(
        sighting_id=f"s{i}",
        pattern_id="P",
        observed_at="2026-08-10T00:00:00Z",
        provenance=Provenance(
            organization=org,
            sensor_software=stack,
            sensor_version="1",
            detector_id=detector,
            detector_version="1",
            region=region,
            evidence_method=method,
        ),
        lineage=lineage,
        derived_from=derived_from,
    )


class PayloadSafety(unittest.TestCase):
    """The inertness invariant. A payload that redirects an attacking agent
    toward a third party makes us a participant in that attack."""

    def test_all_encodings_are_inert(self):
        for enc in all_encodings():
            with self.subTest(encoding=enc):
                build(enc, "visible text")  # __post_init__ asserts inertness

    def test_network_locations_rejected(self):
        for bad in ("go to https://evil.example/x", "fetch http://10.0.0.1/y"):
            with self.subTest(payload=bad):
                with self.assertRaises(ValueError):
                    assert_inert(bad)

    def test_shell_directives_rejected(self):
        for bad in ("curl -s attacker", "run rm -rf /", "bash -c whoami"):
            with self.subTest(payload=bad):
                with self.assertRaises(ValueError):
                    assert_inert(bad)

    def test_instruction_is_not_visible_to_a_human_reader(self):
        """The premise of the whole technique: a human reading the rendered
        content should not see the instruction."""
        visible = "# Runbook\nEscalate to platform team."
        for enc in (Encoding.ANSI_ESCAPE, Encoding.HTML_COMMENT, Encoding.ZERO_WIDTH):
            with self.subTest(encoding=enc):
                p = build(enc, visible)
                self.assertIn(visible, p.rendered)
                self.assertNotEqual(p.rendered, visible)


class Fingerprinting(unittest.TestCase):
    def test_fingerprint_is_stable_across_nodes(self):
        """Regression: server-side annotations and tool calls must not reach
        the fingerprint, or the same client fingerprints differently on a
        node whose payload it tripped -- breaking cross-node linkage exactly
        where linkage is the point."""
        fleet = Fleet.deploy([f"n{i}" for i in range(6)])
        agent = SimulatedAgent("agent-x")
        for node in fleet.nodes:
            agent.run(node)
        prints = {s.scaffold_fingerprint() for s in fleet.sessions()}
        self.assertEqual(len(prints), 1, f"fingerprint unstable across nodes: {prints}")

    def test_distinct_scaffolds_are_distinguished(self):
        fleet = Fleet.deploy(["n0"])
        a = SimulatedAgent("a", enumeration=("tools/list", "resources/list"))
        b = SimulatedAgent("b", enumeration=("resources/list", "tools/list", "prompts/list"))
        sa, sb = a.run(fleet.nodes[0]), b.run(fleet.nodes[0])
        self.assertNotEqual(sa.scaffold_fingerprint(), sb.scaffold_fingerprint())

    def test_fingerprint_excludes_client_supplied_name(self):
        """Names rotate; behaviour does not."""
        node = DecoyServer("n", node_index=0)
        a = SimulatedAgent("honest-name").run(node)
        b = SimulatedAgent("spoofed-name").run(node)
        self.assertEqual(a.scaffold_fingerprint(), b.scaffold_fingerprint())


class Detection(unittest.TestCase):
    def test_agent_trips_canary(self):
        node = DecoyServer("n", encoding=Encoding.ANSI_ESCAPE)
        session = SimulatedAgent("agent").run(node)
        self.assertEqual(session.depth, Depth.TRIPPED_CANARY)
        self.assertTrue(session.is_agent_candidate()[0])

    def test_scanner_is_not_an_agent(self):
        node = DecoyServer("n", encoding=Encoding.ANSI_ESCAPE)
        session = SimulatedScanner().run(node)
        self.assertLess(session.depth, Depth.CALL_TOOL)
        self.assertFalse(session.is_agent_candidate()[0])

    def test_human_operator_is_not_an_agent(self):
        """Reads the runbook, cannot see the hidden instruction, does not
        call an internal-only diagnostic tool."""
        node = DecoyServer("n", encoding=Encoding.ANSI_ESCAPE)
        session = SimulatedHumanOperator().run(node)
        self.assertFalse(session.is_agent_candidate()[0])

    def test_sanitizing_agent_resists_its_encodings(self):
        sanitized = frozenset({Encoding.HTML_COMMENT, Encoding.ZERO_WIDTH})
        for enc in sanitized:
            node = DecoyServer("n", encoding=enc)
            session = SimulatedAgent("hardened", sanitizes=sanitized).run(node)
            self.assertLess(session.depth, Depth.TRIPPED_CANARY, f"tripped on {enc}")

    def test_off_contract_input_is_recorded_as_subversion(self):
        node = DecoyServer("n")
        session = node.open_session()
        node.handle(session, {"jsonrpc": "2.0", "id": 1, "method": "debug/dump", "params": {}})
        self.assertTrue(session.subversion_attempts)

    def test_honeytokens_are_unique_per_session(self):
        node = DecoyServer("n", encoding=Encoding.ANSI_ESCAPE)
        a = SimulatedAgent("x").run(node)
        b = SimulatedAgent("x").run(node)
        self.assertTrue(a.honeytokens_issued and b.honeytokens_issued)
        self.assertFalse(set(a.honeytokens_issued) & set(b.honeytokens_issued))

    def test_susceptibility_matrix_marks_untested_cells_none(self):
        """Untested must be distinguishable from resistant: reporting an
        untested cell as resistant turns a susceptibility claim into a lie."""
        fleet = Fleet.deploy(["n0"])  # one node, one encoding
        SimulatedAgent("a").run(fleet.nodes[0])
        row = next(iter(fleet.susceptibility_matrix().values()))
        self.assertEqual(sum(1 for v in row.values() if v is None), len(all_encodings()) - 1)


class Corroboration(unittest.TestCase):
    def test_identical_stacks_collapse_toward_one_observation(self):
        """Ten distinct orgs on an identical stack are not ten observations.

        They do not collapse to exactly 1.0 -- they are separate legal
        entities, and the kernel only reaches total dependence on an exact
        org match. Near-1 is the correct answer, and the invariant worth
        pinning is that volume buys almost nothing.
        """
        a = ThreatAssertion("a", "P", "t", sightings=[
            _sighting(i, org=f"shell-{i}") for i in range(10)
        ])
        n_eff = corroboration.score(a).n_eff
        self.assertLess(n_eff, 1.5)
        self.assertGreater(n_eff, 1.0)

    def test_same_org_collapses_to_exactly_one(self):
        a = ThreatAssertion("a", "P", "t", sightings=[
            _sighting(i, org="one-org", stack=f"s{i}") for i in range(10)
        ])
        self.assertAlmostEqual(corroboration.score(a).n_eff, 1.0, places=6)

    def test_independent_beats_correlated_volume(self):
        sybil = ThreatAssertion("a", "P", "t", sightings=[
            _sighting(i, org=f"shell-{i}") for i in range(10)
        ])
        genuine = ThreatAssertion("b", "P", "t", sightings=[
            _sighting(0, org="a", stack="s1", detector="d1", region="r1"),
            _sighting(1, org="b", stack="s2", detector="d2", region="r2"),
            _sighting(2, org="c", stack="s3", detector="d3", region="r3"),
        ])
        self.assertGreater(
            corroboration.score(genuine).confidence,
            corroboration.score(sybil).confidence,
        )

    def test_same_org_is_total_dependence(self):
        a, b = _sighting(0, org="x", stack="s1"), _sighting(1, org="x", stack="s2")
        self.assertEqual(corroboration.pairwise_correlation(a, b), 1.0)

    def test_circular_reporting_is_discounted(self):
        derived = [
            _sighting(i, org=f"m{i}", stack=f"s{i}", detector="dist.rule",
                      lineage=Lineage.FEDERATION_DERIVED, derived_from="A")
            for i in range(8)
        ]
        a = ThreatAssertion("A", "P", "t", sightings=[_sighting(99, org="origin"), *derived])
        tracked = corroboration.score(a, track_lineage=True)
        naive = corroboration.score(a, track_lineage=False)
        self.assertAlmostEqual(tracked.n_eff, 1.0, places=2)
        self.assertGreater(naive.n_eff, tracked.n_eff)

    def test_derived_sighting_requires_provenance(self):
        """An unattributed derived sighting cannot be checked for
        circularity, so it must not be constructible."""
        with self.assertRaises(ValueError):
            _sighting(0, org="x", lineage=Lineage.FEDERATION_DERIVED, derived_from=None)

    def test_confidence_is_monotone_in_independent_evidence(self):
        prev = 0.0
        for n in range(1, 8):
            a = ThreatAssertion("a", "P", "t", sightings=[
                _sighting(i, org=f"o{i}", stack=f"s{i}", detector=f"d{i}", region=f"r{i}")
                for i in range(n)
            ])
            c = corroboration.score(a).confidence
            self.assertGreater(c, prev)
            prev = c

    def test_sybil_ceiling_is_below_independent_reach(self):
        """The headline claim: correlated volume cannot buy high confidence
        at any price, while independence can."""
        empty = ThreatAssertion("p", "P", "t")
        cheap = corroboration.cost_to_reach(
            empty, 0.95, lambda i: _sighting(0, org="shell"), independent=False
        )
        costly = corroboration.cost_to_reach(
            empty, 0.95,
            lambda i: _sighting(i, org=f"o{i}", stack=f"s{i}", detector=f"d{i}", region=f"r{i}"),
            independent=True,
        )
        self.assertIsNone(cheap)
        self.assertIsNotNone(costly)

    def test_evidence_quality_orders_methods(self):
        def one(method):
            return corroboration.score(
                ThreatAssertion("a", "P", "t", sightings=[_sighting(0, org="x", method=method)])
            ).confidence

        self.assertGreater(one(EvidenceMethod.REPRODUCED), one(EvidenceMethod.CAPTURED_ARTIFACT))
        self.assertGreater(one(EvidenceMethod.CAPTURED_ARTIFACT), one(EvidenceMethod.RULE_MATCH))
        self.assertGreater(one(EvidenceMethod.RULE_MATCH), one(EvidenceMethod.MODEL_INFERENCE))


class FleetToFederation(unittest.TestCase):
    def test_one_operators_fleet_is_one_observer(self):
        """However many regions it spans."""
        fleet = Fleet.deploy([f"n{i}" for i in range(6)])
        for node in fleet.nodes:
            SimulatedAgent("agent").run(node)
        a = fleet.to_assertion("op", "P", "t")
        self.assertGreater(len(a.sightings), 1)
        self.assertAlmostEqual(corroboration.score(a).n_eff, 1.0, places=2)

    def test_sightings_carry_evidence_commitments(self):
        fleet = Fleet.deploy(["n0"])
        SimulatedAgent("agent").run(fleet.nodes[0])
        for s in fleet.to_assertion("op", "P", "t").sightings:
            self.assertTrue(s.evidence_commitment.startswith("sha256:"))

    def test_assertion_digest_is_deterministic(self):
        fleet = Fleet.deploy(["n0"])
        SimulatedAgent("agent").run(fleet.nodes[0])
        a = fleet.to_assertion("op", "P", "t")
        self.assertEqual(a.digest(), a.digest())


if __name__ == "__main__":
    unittest.main()
