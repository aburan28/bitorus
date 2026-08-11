"""Structural diffing between snapshots.

Where the rug pull is caught. A one-time security review cannot detect a
server that presents benign definitions during review and changes them
afterward -- by construction, it only ever sees one snapshot. Only
longitudinal comparison can, which is the whole argument for running this
continuously rather than auditing once.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .detectors import Severity, Signal, scan
from .snapshot import ServerSnapshot, ToolSpec

# Parameter names that meaningfully widen what a tool can do.
_DANGEROUS_PARAM = re.compile(
    r"(raw_?sql|query|command|cmd|shell|exec|eval|script|path|file(name|path)?|url|uri|"
    r"endpoint|host|token|key|secret|credential|password)",
    re.I,
)

# Constraints whose removal broadens the accepted input.
_CONSTRAINTS = (
    "enum", "maxLength", "minLength", "maximum", "minimum",
    "pattern", "format", "maxItems", "const",
)


@dataclass
class Finding:
    """One suspicious change, with the evidence that produced it."""

    kind: str
    severity: Severity
    server_url: str
    summary: str
    tool: str | None = None
    evidence: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        where = f"{self.server_url}" + (f" :: {self.tool}" if self.tool else "")
        return f"[{self.severity.label:<8}] {self.kind:<22} {where}\n{' ' * 12}{self.summary}"


def _schema_broadening(old: ToolSpec, new: ToolSpec) -> list[str]:
    """Ways the new schema accepts input the old one rejected.

    Broadening is the quiet version of a rug pull: the description is
    untouched, the tool name is untouched, and the tool now accepts an
    argument it previously refused.
    """
    reasons: list[str] = []

    dropped_required = old.required - new.required
    if dropped_required:
        reasons.append(f"required fields no longer required: {sorted(dropped_required)}")

    added = set(new.properties) - set(old.properties)
    for prop in sorted(added):
        if _DANGEROUS_PARAM.search(prop):
            reasons.append(f"new high-capability parameter {prop!r}")
        else:
            reasons.append(f"new parameter {prop!r}")

    for prop in sorted(set(old.properties) & set(new.properties)):
        before, after = old.constraint_of(prop), new.constraint_of(prop)
        for key in _CONSTRAINTS:
            if key in before and key not in after:
                reasons.append(f"{prop!r}: {key} constraint removed")
            elif key == "enum" and key in before and key in after:
                lost = set(map(str, before[key])) - set(map(str, after[key]))
                gained = set(map(str, after[key])) - set(map(str, before[key]))
                if gained:
                    reasons.append(f"{prop!r}: enum widened with {sorted(gained)}")
                elif lost:
                    reasons.append(f"{prop!r}: enum narrowed, dropped {sorted(lost)}")
        if before.get("type") != after.get("type"):
            reasons.append(
                f"{prop!r}: type changed {before.get('type')!r} -> {after.get('type')!r}"
            )

    if not old.input_schema.get("additionalProperties") and new.input_schema.get(
        "additionalProperties"
    ):
        reasons.append("additionalProperties now permitted")

    return reasons


def _new_signals(old_text: str, new_text: str) -> list[Signal]:
    """Signals present now that were not present before.

    Comparing by kind rather than by exact text so that a rewording of an
    already-flagged issue does not read as a fresh compromise.
    """
    before = {s.kind for s in scan(old_text)}
    return [s for s in scan(new_text) if s.kind not in before]


def compare(old: ServerSnapshot, new: ServerSnapshot) -> list[Finding]:
    """All findings between two observations of the same server."""
    findings: list[Finding] = []
    url = new.server_url

    if old.reachable and not new.reachable:
        findings.append(
            Finding("server_unreachable", Severity.LOW, url,
                    f"previously reachable, now failing: {new.error}")
        )
        return findings

    if not old.reachable and new.reachable:
        findings.append(
            Finding("server_returned", Severity.INFO, url, "reachable again after an outage")
        )

    if old.identity != new.identity:
        findings.append(
            Finding(
                "publisher_identity_changed", Severity.HIGH, url,
                "publisher name changed -- the endpoint may have changed hands",
                evidence=[f"{old.server_name!r}  ->  {new.server_name!r}"],
            )
        )
    elif old.server_version != new.server_version:
        # Routine. Recorded as context for correlating other findings in the
        # same round, never as a finding in its own right.
        findings.append(
            Finding(
                "version_changed", Severity.INFO, url,
                f"version {old.server_version} -> {new.server_version}",
            )
        )

    for name in sorted(new.tool_names - old.tool_names):
        tool = new.tool(name)
        signals = scan(tool.description)
        sev = max((s.severity for s in signals), default=Severity.LOW)
        findings.append(
            Finding(
                "tool_added",
                max(sev, Severity.LOW),
                url,
                f"new tool appeared: {name}",
                tool=name,
                evidence=[f"{s.kind}: {s.detail}" for s in signals],
            )
        )

    for name in sorted(old.tool_names - new.tool_names):
        findings.append(
            Finding("tool_removed", Severity.INFO, url, f"tool withdrawn: {name}", tool=name)
        )

    for name in sorted(old.tool_names & new.tool_names):
        before, after = old.tool(name), new.tool(name)
        if before.digest == after.digest:
            continue

        if before.description != after.description:
            fresh = _new_signals(before.description, after.description)
            if fresh:
                # The signature detection: clean when first observed,
                # carrying hidden or manipulative content now.
                findings.append(
                    Finding(
                        "rug_pull",
                        max(s.severity for s in fresh),
                        url,
                        f"description gained {len(fresh)} suspicious signal(s) after first observation",
                        tool=name,
                        evidence=[f"{s.kind}: {s.detail} | {s.excerpt}" for s in fresh],
                    )
                )
            else:
                findings.append(
                    Finding(
                        "description_changed", Severity.LOW, url,
                        "description changed with no suspicious content",
                        tool=name,
                        evidence=[f"was: {before.description[:70]}", f"now: {after.description[:70]}"],
                    )
                )

        if before.schema_digest != after.schema_digest:
            reasons = _schema_broadening(before, after)
            if reasons:
                dangerous = any("high-capability" in r for r in reasons)
                findings.append(
                    Finding(
                        "schema_broadened",
                        Severity.HIGH if dangerous else Severity.MEDIUM,
                        url,
                        f"input schema now accepts input it previously rejected ({len(reasons)} change(s))",
                        tool=name,
                        evidence=reasons,
                    )
                )
            else:
                findings.append(
                    Finding("schema_narrowed", Severity.INFO, url,
                            "input schema changed without broadening", tool=name)
                )

    return findings


def baseline_findings(snapshot: ServerSnapshot) -> list[Finding]:
    """Findings from a first observation, with no history to compare against.

    A server already carrying hidden instructions when first seen is not a
    rug pull -- it was always hostile. Naming the distinction matters,
    because the response differs: one is a compromised or malicious
    publisher, the other may be a compromised update channel.
    """
    findings: list[Finding] = []
    for tool in snapshot.tools:
        signals = scan(tool.description)
        if not signals:
            continue
        # One finding per tool, not per signal: a description carrying four
        # manipulations is one hostile tool, and splitting it inflates the
        # count without adding information.
        findings.append(
            Finding(
                "hostile_on_first_observation",
                max(s.severity for s in signals),
                snapshot.server_url,
                f"{len(signals)} suspicious signal(s) present at first observation "
                "-- always hostile, not a rug pull",
                tool=tool.name,
                evidence=[f"{s.kind}: {s.detail}" + (f" | {s.excerpt}" if s.excerpt else "")
                          for s in signals],
            )
        )
    return findings
