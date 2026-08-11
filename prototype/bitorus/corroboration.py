"""Independence-aware corroboration.

Confidence is a function of *effective* sample size, never of raw sighting
count. Ten reports from one sensor stack are one observation; three from
genuinely independent stacks are three.

The formalism is the design effect from cluster sampling:

    n_eff = n / (1 + (n - 1) * rho_bar)

with rho_bar the mean pairwise correlation. The shape is what defeats
amplification: as rho_bar approaches 1 the marginal value of another
correlated sighting approaches zero, so an adversary adding sightings from
the same stack purchases asymptotically nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

from .schema import Lineage, Sighting, ThreatAssertion

# Weights for the independence kernel. Hand-specified and auditable by
# design: a customer can be shown why two sightings were discounted, and a
# learned kernel is itself a poisoning surface -- an adversary who can
# influence it can make their own sightings look independent.
W_SAME_SENSOR_STACK = 0.45
W_SAME_SENSOR_SOFTWARE = 0.25
W_SAME_DETECTOR_STACK = 0.35
W_SAME_DETECTOR_ID = 0.20
W_SAME_REGION = 0.15
W_SAME_ASN = 0.10
W_SAME_DELIVERY_VECTOR = 0.10
W_SAME_EVIDENCE_METHOD = 0.05


def pairwise_correlation(a: Sighting, b: Sighting) -> float:
    """Estimated dependence between two sightings, in [0, 1].

    Same organization is total dependence. Otherwise correlation accumulates
    over shared provenance attributes: identical stacks fail and fire
    identically, so they are close to one observation however many
    organizations they are spread across.
    """
    pa, pb = a.provenance, b.provenance

    if pa.organization == pb.organization:
        return 1.0

    rho = 0.0

    if pa.sensor_stack == pb.sensor_stack:
        rho += W_SAME_SENSOR_STACK
    elif pa.sensor_software == pb.sensor_software:
        rho += W_SAME_SENSOR_SOFTWARE

    if pa.detector_stack == pb.detector_stack:
        rho += W_SAME_DETECTOR_STACK
    elif pa.detector_id == pb.detector_id:
        rho += W_SAME_DETECTOR_ID

    if pa.cloud_provider and pa.cloud_provider == pb.cloud_provider and pa.region == pb.region:
        rho += W_SAME_REGION
    if pa.asn and pa.asn == pb.asn:
        rho += W_SAME_ASN
    if pa.delivery_vector and pa.delivery_vector == pb.delivery_vector:
        rho += W_SAME_DELIVERY_VECTOR
    if pa.evidence_method == pb.evidence_method:
        rho += W_SAME_EVIDENCE_METHOD

    return min(rho, 1.0)


def _lineage_weight(sighting: Sighting, assertion: ThreatAssertion, *, track: bool) -> float:
    """How much a sighting counts toward *veracity* of this assertion.

    A detection produced by a rule derived from this very assertion is
    causally downstream of it and corroborates nothing -- that is circular
    reporting, and it is the cheapest amplification attack available: one
    plausible assertion, redistributed, bootstraps itself into apparent
    consensus with no new evidence and no Sybils required.

    `track=False` reproduces the naive behaviour, for demonstration.
    """
    if not track:
        return 1.0
    if sighting.lineage is Lineage.FEDERATION_DERIVED:
        # Downstream of the artifact under evaluation: no independent weight.
        if sighting.derived_from in (assertion.assertion_id, assertion.pattern_id):
            return 0.0
        return 0.15
    if sighting.lineage is Lineage.FEDERATION_PRIMED:
        # Honest middle case: local logic, but the analyst knew to look.
        return 0.5
    return 1.0


@dataclass
class Corroboration:
    """Result of scoring an assertion."""

    n_raw: int
    n_eff: float
    rho_bar: float
    confidence: float
    distinct_orgs: int
    naive_confidence: float

    @property
    def inflation(self) -> float:
        """How much the naive count overstates the evidence."""
        return self.n_raw / self.n_eff if self.n_eff > 0 else float("inf")

    def __str__(self) -> str:
        return (
            f"n={self.n_raw} orgs={self.distinct_orgs} "
            f"rho={self.rho_bar:.2f} n_eff={self.n_eff:.2f} "
            f"confidence={self.confidence:.3f} (naive {self.naive_confidence:.3f})"
        )


def mean_pairwise_correlation(sightings: list[Sighting]) -> float:
    if len(sightings) < 2:
        return 0.0
    pairs = list(combinations(sightings, 2))
    return sum(pairwise_correlation(a, b) for a, b in pairs) / len(pairs)


def effective_n(sightings: list[Sighting], rho_bar: float) -> float:
    """Design effect. n_eff = n / (1 + (n-1) * rho_bar)."""
    n = len(sightings)
    if n == 0:
        return 0.0
    return n / (1.0 + (n - 1) * rho_bar)


def confidence(n_eff: float, quality: float) -> float:
    """Saturating confidence from effective observations of given quality.

    1 - (1-q)^n_eff: zero observations give zero, better evidence saturates
    faster, and no amount of correlated volume can substitute for
    independence because n_eff is what enters the exponent.
    """
    if n_eff <= 0:
        return 0.0
    return 1.0 - (1.0 - quality) ** n_eff


def score(
    assertion: ThreatAssertion,
    *,
    track_lineage: bool = True,
    reproduction_bonus: float = 0.10,
) -> Corroboration:
    """Score an assertion's confidence from its sightings.

    Reproduction is handled as a bonus rather than as another sighting: a
    pattern a clean-room harness can reproduce is true in the only sense
    that matters operationally, largely independent of who reported it.
    """
    sightings = assertion.sightings
    if not sightings:
        return Corroboration(0, 0.0, 0.0, 0.0, 0, 0.0)

    weights = [_lineage_weight(s, assertion, track=track_lineage) for s in sightings]
    weighted = [s for s, w in zip(sightings, weights) if w > 0]

    rho_bar = mean_pairwise_correlation(weighted)
    base_n_eff = effective_n(weighted, rho_bar)

    # Scale by mean lineage weight so partially-derived evidence is
    # discounted rather than either dropped or fully counted.
    live = [w for w in weights if w > 0]
    n_eff = base_n_eff * (sum(live) / len(live)) if live else 0.0

    mean_quality = sum(s.quality for s in weighted) / len(weighted) if weighted else 0.0

    conf = confidence(n_eff, mean_quality)
    if assertion.reproduced:
        conf = min(1.0, conf + reproduction_bonus)

    naive_quality = sum(s.quality for s in sightings) / len(sightings)

    return Corroboration(
        n_raw=len(sightings),
        n_eff=n_eff,
        rho_bar=rho_bar,
        confidence=conf,
        distinct_orgs=len({s.provenance.organization for s in sightings}),
        naive_confidence=confidence(len(sightings), naive_quality),
    )


def cost_to_reach(
    assertion: ThreatAssertion,
    target_confidence: float,
    make_sighting,
    *,
    independent: bool,
    limit: int = 500,
) -> int | None:
    """Adversary cost to manufacture consensus, in sightings.

    The headline robustness metric: not "can this be forged" but "what does
    forging it cost". Returns the number of sightings needed to reach
    `target_confidence`, or None if unreachable within `limit`.

    `make_sighting(i)` builds the i-th attacker sighting; `independent`
    selects whether the attacker can field genuinely diverse stacks (which
    is expensive) or is reusing one (which is cheap and gets discounted).
    """
    probe = ThreatAssertion(
        assertion_id=assertion.assertion_id,
        pattern_id=assertion.pattern_id,
        title=assertion.title,
        sightings=list(assertion.sightings),
    )
    for i in range(1, limit + 1):
        probe.sightings.append(make_sighting(i if independent else 0))
        if score(probe).confidence >= target_confidence:
            return i
    return None
