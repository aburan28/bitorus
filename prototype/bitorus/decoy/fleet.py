"""Fleet coordination.

The claim that a coordinated fleet is worth more than N independent nodes
has to cash out in something computable. It cashes out here: the
susceptibility matrix is a cell-by-cell map of which agent scaffolds fall
for which injection encodings, and no single node can populate more than
one column of it.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..schema import (
    EvidenceMethod,
    Lineage,
    Provenance,
    Sighting,
    ThreatAssertion,
    commit,
)
from . import payloads
from .payloads import Encoding
from .server import DecoyServer, Depth, Session


@dataclass
class Fleet:
    """A set of decoy nodes with differential payload assignment."""

    nodes: list[DecoyServer] = field(default_factory=list)

    @classmethod
    def deploy(cls, regions: list[str]) -> "Fleet":
        """One node per region, encodings assigned round-robin.

        A fleet of at least len(Encoding) nodes covers every column of the
        susceptibility matrix, so any agent sweeping the fleet is tested
        against every variant we know.
        """
        return cls(
            nodes=[DecoyServer(node_id=r, node_index=i) for i, r in enumerate(regions)]
        )

    def node(self, node_id: str) -> DecoyServer:
        for n in self.nodes:
            if n.node_id == node_id:
                return n
        raise KeyError(node_id)

    def sessions(self) -> list[Session]:
        return [s for n in self.nodes for s in n.sessions.values()]

    def susceptibility_matrix(self) -> dict[str, dict[Encoding, bool | None]]:
        """scaffold -> encoding -> tripped?

        None means untested: the scaffold never reached a node serving that
        encoding. Distinguishing untested from resistant matters, because
        reporting an untested cell as resistant is how a susceptibility
        claim becomes a lie.
        """
        matrix: dict[str, dict[Encoding, bool | None]] = {}
        for session in self.sessions():
            if session.depth < Depth.READ_RESOURCE:
                continue  # never exposed to a payload
            fp = session.scaffold_fingerprint()
            row = matrix.setdefault(fp, {e: None for e in payloads.all_encodings()})
            tripped = session.depth >= Depth.TRIPPED_CANARY
            # Sticky: one trip anywhere proves susceptibility.
            row[session.encoding] = bool(row[session.encoding]) or tripped
        return matrix

    def cross_node_linkage(self) -> dict[str, list[str]]:
        """scaffold -> node ids visited.

        Linkage by behaviour rather than by network identifier. A scaffold
        fingerprint is a property of the client implementation, so it
        survives IP rotation and proxy chains -- which are exactly what
        defeats conventional campaign correlation.
        """
        linkage: dict[str, set[str]] = defaultdict(set)
        for session in self.sessions():
            if session.depth >= Depth.HANDSHAKE:
                linkage[session.scaffold_fingerprint()].add(session.node_id)
        return {k: sorted(v) for k, v in linkage.items() if len(v) > 1}

    def to_sightings(self, org: str, pattern_id: str) -> list[Sighting]:
        """Turn agent-candidate sessions into signed sightings.

        Note the provenance these carry: every decoy node is the same
        software and the same detector, so sightings from one fleet are
        *correlated by construction*. The corroboration engine will discount
        them accordingly, which is correct -- one operator's fleet is one
        observer, however many regions it spans.
        """
        out = []
        for session in self.sessions():
            is_candidate, reasons = session.is_agent_candidate()
            if not is_candidate:
                continue
            out.append(
                Sighting(
                    sighting_id=f"sig-{session.node_id}-{session.session_id[:6]}",
                    pattern_id=pattern_id,
                    observed_at=f"{session.started_at:.0f}",
                    provenance=Provenance(
                        organization=org,
                        sensor_software="bitorus-decoy-mcp",
                        sensor_version="0.1.0",
                        detector_id="decoy.canary-trip",
                        detector_version="0.1.0",
                        region=session.node_id,
                        delivery_vector=session.encoding.value,
                        evidence_method=EvidenceMethod.CAPTURED_ARTIFACT,
                    ),
                    lineage=Lineage.INDEPENDENT,
                    evidence_commitment=commit(
                        "|".join(session.method_sequence) + "|" + "|".join(reasons)
                    ),
                )
            )
        return out

    def to_assertion(self, org: str, pattern_id: str, title: str) -> ThreatAssertion:
        sightings = self.to_sightings(org, pattern_id)
        scaffolds = {
            s.scaffold_fingerprint()
            for s in self.sessions()
            if s.is_agent_candidate()[0]
        }
        return ThreatAssertion(
            assertion_id=f"urn:bitorus:assertion:{pattern_id}",
            pattern_id=pattern_id,
            title=title,
            sightings=sightings,
            atlas_techniques=["AML.T0051"],  # LLM prompt injection
            attack_techniques=["T1552"],  # unsecured credentials
            affected_configurations=sorted(scaffolds),
            # Reproducible by construction: we hold the exact payload and
            # the exact method sequence that produced the trip.
            reproduced=bool(sightings),
        )
