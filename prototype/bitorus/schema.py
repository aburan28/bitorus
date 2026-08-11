"""Assertion schema.

The three fields that are cheap now and impossible to retrofit, per
docs/research/README.md: the provenance vector, `intelligence_lineage`,
and coverage assertions. Every sighting collected without them is
permanently ambiguous, so they are structural here rather than optional.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum


class Lineage(str, Enum):
    """How the reporter came to detect this.

    The distinction that closes circular reporting: a sighting produced by
    a federation-distributed rule is causally downstream of the assertion
    that rule was derived from, so it corroborates nothing about veracity.
    It still counts for prevalence -- a different question.
    """

    INDEPENDENT = "independent"
    """Detected by tenant-local logic with no federation input for this pattern."""

    FEDERATION_DERIVED = "federation_derived"
    """Detected by a rule, indicator, or evaluation the federation distributed."""

    FEDERATION_PRIMED = "federation_primed"
    """Local detection logic, but the analyst had seen the advisory."""


class EvidenceMethod(str, Enum):
    """Epistemic class of the observation. Captured artifact and
    fired-a-rule are not the same kind of claim."""

    CAPTURED_ARTIFACT = "captured_artifact"
    REPRODUCED = "reproduced"
    RULE_MATCH = "rule_match"
    ANALYST_INFERENCE = "analyst_inference"
    MODEL_INFERENCE = "model_inference"


# Per-sighting evidence quality, used as the base rate in confidence().
# Deliberately hand-set and visible rather than learned -- an adversary who
# can influence a learned weighting can make their own sightings look strong.
EVIDENCE_QUALITY: dict[EvidenceMethod, float] = {
    EvidenceMethod.REPRODUCED: 0.90,
    EvidenceMethod.CAPTURED_ARTIFACT: 0.75,
    EvidenceMethod.RULE_MATCH: 0.45,
    EvidenceMethod.ANALYST_INFERENCE: 0.35,
    EvidenceMethod.MODEL_INFERENCE: 0.20,
}


@dataclass(frozen=True)
class Provenance:
    """The dependence-bearing attributes of a sighting.

    Every field here exists because it drives correlation between two
    sightings. Nothing is recorded for its own sake.
    """

    organization: str
    sensor_software: str
    sensor_version: str
    detector_id: str
    detector_version: str
    cloud_provider: str | None = None
    region: str | None = None
    asn: str | None = None
    delivery_vector: str | None = None
    evidence_method: EvidenceMethod = EvidenceMethod.RULE_MATCH

    @property
    def sensor_stack(self) -> str:
        return f"{self.sensor_software}@{self.sensor_version}"

    @property
    def detector_stack(self) -> str:
        return f"{self.detector_id}@{self.detector_version}"


@dataclass(frozen=True)
class Sighting:
    """One reporter's claim to have observed a pattern.

    `derived_from` names the federation artifact that produced the
    detection. It is meaningless unless lineage is FEDERATION_DERIVED, and
    required when it is -- an unattributed derived sighting cannot be
    checked for circularity, so treat it as fully dependent.
    """

    sighting_id: str
    pattern_id: str
    observed_at: str
    provenance: Provenance
    lineage: Lineage = Lineage.INDEPENDENT
    derived_from: str | None = None
    evidence_commitment: str | None = None

    def __post_init__(self) -> None:
        if self.lineage is Lineage.FEDERATION_DERIVED and not self.derived_from:
            raise ValueError(
                f"{self.sighting_id}: federation_derived requires derived_from; "
                "an unattributed derived sighting cannot be checked for circularity"
            )

    @property
    def quality(self) -> float:
        return EVIDENCE_QUALITY[self.provenance.evidence_method]


@dataclass(frozen=True)
class CoverageAssertion:
    """A reporter's declaration of what it was watching for and did not see.

    The denominator. Threat intelligence is systematically numerator-only:
    hits are reported, misses never are, so prevalence is uncomputable and
    suppression is undetectable. A zero count also leaks far less than a
    positive detection, so these can move under a more permissive policy.

    Generated from the sensor's active detection set, never hand-declared --
    hand-declared coverage is aspirational and will be wrong.
    """

    assertion_id: str
    window_start: str
    window_end: str
    configuration_class: str
    provenance: Provenance
    observations: dict[str, int] = field(default_factory=dict)
    """pattern_id -> count, explicitly including zeros."""

    def monitored(self, pattern_id: str) -> bool:
        return pattern_id in self.observations

    def count(self, pattern_id: str) -> int:
        return self.observations.get(pattern_id, 0)


@dataclass
class ThreatAssertion:
    """A claim about an attack pattern, backed by sightings.

    Confidence is computed from effective corroboration, never from raw
    sighting count -- see corroboration.py.
    """

    assertion_id: str
    pattern_id: str
    title: str
    sightings: list[Sighting] = field(default_factory=list)
    atlas_techniques: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    affected_configurations: list[str] = field(default_factory=list)
    reproduced: bool = False

    def digest(self) -> str:
        """Deterministic digest over the assertion's semantic content."""
        payload = {
            "pattern_id": self.pattern_id,
            "title": self.title,
            "atlas": sorted(self.atlas_techniques),
            "attack": sorted(self.attack_techniques),
            "configs": sorted(self.affected_configurations),
            "sightings": sorted(s.sighting_id for s in self.sightings),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode()).hexdigest()

    def to_dict(self) -> dict:
        return asdict(self) | {"digest": self.digest()}


def commit(evidence: bytes | str) -> str:
    """Commitment to evidence that is not itself disclosed.

    A fabricator cannot open a commitment to evidence they never had, which
    is what converts "trust me" into "prove it on demand" without routine
    raw disclosure.
    """
    if isinstance(evidence, str):
        evidence = evidence.encode()
    return "sha256:" + hashlib.sha256(evidence).hexdigest()
