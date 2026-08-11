# Research notes

Supporting research for the [BiTorus business plan](../BUSINESS_PLAN.md). Each note states its own date and evidence provenance; treat specific figures as directional and re-verify before external use.

> A runnable vertical slice of the two research positions lives in [../../prototype](../../prototype/README.md) — decoy MCP fleet, susceptibility matrix, and the corroboration engine, with the Sybil and circular-reporting attacks demonstrated end to end.

## Landscape surveys

| Note | Covers |
|---|---|
| [threat-intelligence-landscape-2026.md](threat-intelligence-landscape-2026.md) | Bleeding edge of CTI, the infosec practitioner cut per function, and honeypot state of the art (Aug 2026) |
| [distributed-honeypot-coordination.md](distributed-honeypot-coordination.md) | Novel and experimental approaches to distributed, coordinated honeypots, organised by four axes of coordination |
| [observation-architecture.md](observation-architecture.md) | Observing attacks without becoming compromised — the ladder from eBPF through hypervisor VMI, record/replay, hardware tracing, bare metal, and DPU-based introspection; egress design; and why the plane inverts for agent attackers |

## Research positions

Design notes staking out defensible ground. Neither is implemented.

| Note | Position |
|---|---|
| [byzantine-robust-federation.md](byzantine-robust-federation.md) | Byzantine robustness for *assertion-space* deception federation. Byzantine-robust FL solves a neighbouring problem over gradients; deception-federation papers assume honest participants. Core mechanisms: effective corroboration via design-effect, intelligence lineage against circular reporting, coverage assertions for denominators. |
| [decoy-agent-infrastructure.md](decoy-agent-infrastructure.md) | Coordinated decoy MCP servers and agent identities. Verified zero arXiv results for MCP honeypots. Core mechanisms: differential payload assignment across a fleet, staged cross-node injections for IP-rotation-resistant campaign linkage, and the MCP ecosystem monitor. |

### Why these two

Both generate proprietary corpus *before* a federation exists, which is the [Product 1 requirement](../BUSINESS_PLAN.md#373-why-customers-pay-before-network-effects). Both also compose: coverage assertions from the Byzantine work supply the denominators that the decoy fleet's prevalence and blast-radius estimates need.

### A convergence worth noting

Two independent lines of evidence point at the same under-instrumented plane. The verified absence of MCP honeypot literature says the agent protocol surface is unclaimed. Separately, the observation-cost argument says that for LLM-agent attackers the conventional analysis ladder is largely unnecessary — intent is text on the wire, so I/O capture yields directly what memory forensics spends a hardware budget reconstructing. Different reasoning, same conclusion: **the agent I/O plane is where the value is, and it is cheap to instrument.** That is also, independently, the plane the business plan's [execution trace](../BUSINESS_PLAN.md#7-ai-execution-trace-and-data-model) already targets.

### Cheap now, expensive later

Three items are effectively impossible to retrofit and should land in the [Month 0–1 schema freeze](../BUSINESS_PLAN.md#43-immediate-180-day-execution-plan):

1. **Provenance vector + `intelligence_lineage`** on every assertion — every record collected without it is permanently ambiguous.
2. **Coverage assertions** — unlocks prevalence, suppression detection, and false-positive blast-radius estimation.
3. **Behavioural fingerprint collection** on decoys — labelled ground truth for agent detection is only collectable while payload-trip detection still works.
4. **Environment-detection probes** as a recorded trace event — an attacker testing for the observer is a sophistication signal, at every layer of the stack.

## Proposed business-plan amendments

[BUSINESS_PLAN.md](../BUSINESS_PLAN.md) is a faithful transcription of the signed v4.4 PDF and is deliberately not edited with new research, so it stays synchronised with the canonical source. Amendments proposed for a future revision are collected in [observation-architecture.md §11](observation-architecture.md#11-proposed-amendments-to-the-business-plan).
