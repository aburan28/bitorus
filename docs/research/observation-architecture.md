# Observing attacks without becoming compromised

**Status:** research note / architecture survey.
**Date:** August 2026.
**Relates to:** [§14.1.9 Sacrificial adversarial-research infrastructure](../BUSINESS_PLAN.md#1419-sacrificial-adversarial-research-infrastructure), [§13 Response architecture and safety](../BUSINESS_PLAN.md#13-response-architecture-and-safety), [§5.2 Threats against AI systems](../BUSINESS_PLAN.md#52-threats-against-ai-systems), [ADR-AI-001](../BUSINESS_PLAN.md#24-architecture-decisions).

The organising principle, which every technique below is a variation on:

> **The observer must sit in a trust domain the target cannot reach, and the data must leave through a path the target cannot influence.**

Both halves are load-bearing, and the second is the one people skip. An observation stack whose logs are writable from the observed network is not an observation stack.

The most consequential finding for BiTorus is in [§7](#7-the-2026-inversion-for-agent-attackers-the-plane-is-io-not-memory): **for LLM-agent attackers this entire ladder is largely beside the point**, the high-value observation plane is I/O rather than memory, and almost nobody has built for it. That is an independent argument for the position already staked out in [decoy-agent-infrastructure.md](decoy-agent-infrastructure.md).

## Table of contents

- [1. The same principle at three layers](#1-the-same-principle-at-three-layers)
- [2. The observation ladder](#2-the-observation-ladder)
- [3. Egress: the half everyone underrates](#3-egress-the-half-everyone-underrates)
- [4. Assume the escape](#4-assume-the-escape)
- [5. Confidential computing works against you](#5-confidential-computing-works-against-you)
- [6. The honest limit, and instrumenting the probe](#6-the-honest-limit-and-instrumenting-the-probe)
- [7. The 2026 inversion: for agent attackers the plane is I/O, not memory](#7-the-2026-inversion-for-agent-attackers-the-plane-is-io-not-memory)
- [8. Two-tier observation with escalation](#8-two-tier-observation-with-escalation)
- [9. Reference architectures by budget](#9-reference-architectures-by-budget)
- [10. Implications for BiTorus](#10-implications-for-bitorus)
- [11. Proposed amendments to the business plan](#11-proposed-amendments-to-the-business-plan)
- [12. Sources](#12-sources)

---

## 1. The same principle at three layers

Worth stating before the survey, because it unifies this research with architecture the business plan already commits to.

"The observer must be outside the observed" recurs at every layer of the stack:

| Layer | Observed | Observer | Boundary |
|---|---|---|---|
| Hardware | Host CPU complex | DPU / coprocessor (§2.5) | PCIe, separate silicon |
| System | Guest VM | Hypervisor / VMM (§2.1) | EPT, ring -1 |
| **Agent** | **The model** | **Capability broker + execution receipts** | **Policy engine outside the inference loop** |

The third row is [ADR-AI-001](../BUSINESS_PLAN.md#24-architecture-decisions) — "authorization is external to the model" — and [§13](../BUSINESS_PLAN.md#13-response-architecture-and-safety)'s requirement that "the model receives execution results but cannot alter receipts."

**That is the VMI principle applied at the agent layer**, and recognising it as the same principle is useful in two directions. It tells you the design is well-founded: it is the architecture the systems-security community converged on after twenty years of attackers escaping in-guest monitors. And it tells you where the design will fail — in exactly the ways VMI fails. A semantic gap (§2.1) exists at the agent layer too: the broker sees typed tool calls, not intent, and reconstructing "what is this agent actually trying to do" from tool-call sequences is the same class of reconstruction problem as recovering `struct task_struct` from physical memory, with the same attackability.

## 2. The observation ladder

Ordered by how far below the attacker the observer sits.

### 2.0 In-guest agents and eBPF — same trust domain

An EDR agent or eBPF probe is cheap and semantically rich, but it lives inside the thing being observed. eBPF is meaningfully better than a userspace agent — kernel-verified, hard to tamper with from userland — but kernel compromise ends the conversation, and the logs are inside the blast radius too.

**Use as one signal, never the only one.** This is exactly the argument the business plan makes for why customer-local sensors sign their observations and why evidence commitments matter: a sensor inside the trust domain being attacked is a sensor that can eventually lie.

### 2.1 Hypervisor VMI — the mainstream state of the art

Observer in the VMM, target in the guest. **DRAKVUF** on Xen + LibVMI remains the reference implementation.

Its central trick is worth understanding because it is the cleverest thing in this space:

> **Xen `altp2m` / EPT view-splitting.** Maintain multiple guest-physical → machine-physical mappings for one guest. The *execute* permission points at a page containing `int3` breakpoints; the *read* permission points at the pristine page. Malware that self-checksums its own code reads clean bytes while the CPU executes instrumented ones.

Because the active view is set per-vCPU, breakpoints work correctly on SMP guests — which is where naive VMI historically fell over. It is agentless: nothing installed in the guest, execution initiated from outside, so there is no launcher artifact.

ARM has equivalent work (*Hiding in the Shadows*, Proskurin et al.); **RapidVMI** addresses multi-core active introspection performance.

**The permanent tax is the semantic gap.** From the hypervisor you see physical pages and register state, not "process", "file", or "socket". OS abstractions are reconstructed from kernel structure offsets, which breaks on kernel updates and is directly attackable by an adversary who corrupts the structures being parsed (DKSM-style attacks). Recent work applies learned and robustness-oriented structure recovery to this.

### 2.2 Record-and-replay — the strongest answer to "deep analysis without detectable instrumentation"

**The most underused technique on this ladder.** PANDA (full-system QEMU with deterministic record/replay) separates capture from analysis:

- **Recording is cheap** — log nondeterministic inputs only. Minimal observable footprint.
- **Replay is offline and deterministic** — now instrument arbitrarily heavily: whole-system taint tracking, per-instruction tracing, memory diffing, symbolic execution. Run twenty different analyses over the same execution.

The key property, and it is a strong one:

> **The expensive instrumentation is not present during the attacker's execution, so it cannot be detected or evaded.** Timing side channels do not help the adversary, because the analysis happens in a different universe from the one they ran in.

It also makes incidents *reproducible* — the exact execution can be handed to a colleague, or to a customer, or replayed against a new detector six months later. That last property is the one that matters commercially: a recorded execution is an asset that appreciates as analysis tooling improves. The same idea appears in **IRIS** for hardware-assisted virtualization fuzzing.

**Cost:** emulation-based recording is itself fingerprintable — QEMU has well-known CPU-emulation tells. Pair with §2.3 or §2.4.

### 2.3 Hardware tracing — near-zero-footprint control flow

Intel PT (and ARM CoreSight/ETM) record complete control flow into a hardware buffer with low overhead and **no code modification** — no breakpoints, no hooks, nothing for self-checksumming code to find. Trace decoding is offline.

The demonstration that this is more than a curiosity: hardware-assisted loop profiling for malware unpacking (USENIX Security '23), which performs automatic unpacking without touching the sample.

**Limitation:** control flow, not data. Combine with periodic memory snapshots via VMI for both.

### 2.4 Bare metal — when the target is VM-aware

For malware that refuses to detonate under any hypervisor: run on real hardware, observe from outside the machine entirely. **BareBox** and transparent-snapshot work do fast restore without an in-guest agent. Observation reduces to network capture at a physical tap plus disk/memory diffing between snapshots.

Coarse, but genuinely transparent. **Increasingly worth the cost** as VM detection has become table stakes in commodity loaders.

### 2.5 Off-host, separate CPU complex — the exotic answer that is now buyable

The strongest available trust boundary, and the least commonly deployed.

**BlueGuard** (USENIX Security '25) runs host and guest introspection on an NVIDIA BlueField **DPU** — a separate ARM system-on-NIC with its own cores, memory, and OS. It reads host memory over PCIe, scans processes, kernel modules and credentials, and triggers VLAN isolation of the infected host on detection.

Why it beats hypervisor VMI on trust:

- The observer is not merely at a lower ring — it is **on different silicon, across the PCIe boundary**.
- BlueField's **Zero Trust mode** explicitly prevents the host administrator from reaching the DPU at all; control is only via the ARM cores or the BMC.
- Therefore **a full host compromise, including hypervisor escape, still does not reach the monitoring stack or the logs.**

Same family, older: coprocessor integrity monitors (Copilot PCI card), SMM-based monitors (HyperSentry), DMA acquisition over PCIe/Thunderbolt (PCILeech). The DPU version is the one that can actually be bought and deployed today.

This also solves half of §3 for free — if the collector lives on the DPU, the egress path is already outside the observed trust domain.

### 2.6 Network plane — cheap and effectively undefeatable

Passive optical tap → full PCAP on a host with **no route back** to the monitored segment. The attacker cannot detect a passive tap and cannot tamper with the capture.

One technique worth knowing:

> **For TLS, extract session keys from guest memory via VMI rather than running a MITM proxy.** A MITM is detectable — cert pinning, JA3/JA4 mismatch. Memory extraction is not. You get plaintext without touching the connection.

## 3. Egress: the half everyone underrates

An observation architecture is only as good as its egress path.

- **Unidirectional transport.** A data diode — or an optical tap, or a serial console to a separate box — makes log tampering *physically* impossible rather than policy-impossible. **If the log sink is reachable from the observed network, assume the logs are attacker-editable.**
- **Append-only, external sink.** Ideally on the DPU, or a collector the workload cannot address at all.
- **Egress control is a liability question, not only a security one.** This deserves emphasis for anyone running decoys:

> A convincing decoy is an attacker-controlled box with internet access. Rate-limit, sinkhole, or fully block outbound. **Plenty of research honeypots have been used to attack third parties.**

That last point is a hard constraint on the decoy programme, and it composes with the payload-inertness rule in [decoy-agent-infrastructure.md §10.1](decoy-agent-infrastructure.md#101-payload-inertness). Inert payloads stop *us* from directing an agent at a third party; egress control stops *the agent* from getting there on its own initiative. Both are required — neither substitutes for the other.

The business plan's [§14.1.9](../BUSINESS_PLAN.md#1419-sacrificial-adversarial-research-infrastructure) already requires forcing "egress through controlled proxies". This research says that is necessary but under-specified: the control must be default-deny with explicit allowlisting, and the log path must be architecturally separate from the controlled-egress path, not merely a different rule on the same device.

## 4. Assume the escape

Hypervisors are a defense *layer*, not a boundary guarantee. QEMU, VMware, VirtualBox and Hyper-V all have escape CVEs, and the confidential-VM stack is no exception — roughly nine TDX CVEs against forty-nine for SEV by mid-2024, mostly host↔guest vectors, and *Heckler* breaks CVMs with malicious interrupts.

So layer it, accepting that no layer is absolute:

```
microVM (Firecracker / gVisor)
  inside a hardware VM
    on a physically segmented VLAN
      on hardware you are willing to reimage from an external source
        with monitoring on the DPU rather than the host
```

Each layer buys **detection time** even though none is a guarantee. That is the correct mental model, and it is the same one the business plan applies to federation compromise in [§14.1](../BUSINESS_PLAN.md#141-compromise-resilient-network-security-architecture): the objective is not to claim compromise is impossible, but to prevent any single compromise from silently becoming total.

## 5. Confidential computing works against you

Counterintuitive and worth flagging prominently.

SEV-SNP, TDX and Arm CCA are designed to make the guest **opaque to the host**. That is precisely the property you do not want when the guest is the thing being studied: memory is encrypted, VMI is blinded, EPT tricks do not apply.

Two consequences:

1. **Confidential computing is a fine tool for protecting the analysis stack** — run the analyzer inside the attested enclave, where the host cannot tamper with it.
2. **From the observer's seat, a CVM is an anti-analysis primitive.** Malware that runs itself inside a CVM specifically to defeat introspection is an obvious move, and the research community is beginning to look at it.

**This belongs in the AI threat taxonomy.** An agent runtime deliberately placed inside a CVM to defeat tenant-side introspection is the agentic version of the same trick, and it directly undermines the sensor product's ability to reconstruct execution traces. See §11 for the proposed amendment.

## 6. The honest limit, and instrumenting the probe

Full transparency is asymptotic, not achievable. Every technique above leaks something: EPT-violation handling has a timing signature; PT buffer configuration is readable in principle; DPU DMA has measurable PCIe effects; even bare metal has restore-time artifacts.

The realistic goal is **raising the adversary's detection cost above their willingness to pay** — the same shape as [adversary cost to manufacture consensus](byzantine-robust-federation.md#122-headline-metric) in the federation work. Neither claims impossibility; both quantify price.

And the corollary that turns a weakness into a sensor:

> **Instrument the detection attempt itself.** An attacker probing for hypervisor timing anomalies has told you something valuable about their sophistication.

This is the same move as subversion detection in [decoy-agent-infrastructure.md §4.1](decoy-agent-infrastructure.md#41-port-the-shellgames-toolkit) — an agent probing a decoy for inconsistency is exhibiting deception-aware behaviour, which is a distinct and more advanced adversary class. In both cases the *attempt to detect the observer* is higher-value intelligence than the interaction it was trying to protect. Log environment-detection probes as a first-class event type at every layer.

## 7. The 2026 inversion: for agent attackers the plane is I/O, not memory

The most strategically important section in this note.

**If the attacker is an LLM agent, the entire ladder above is largely beside the point.**

You do not need whole-system taint tracking to understand an agent. **Its reasoning is text on the wire.** Prompt and response capture, tool-call logs, and reverse-prompt-injection extraction (the Palisade technique) yield intent and objectives *directly*, at a tiny fraction of the engineering cost of VMI.

The cost differential is not marginal, it is categorical:

| | Conventional malware | LLM agent attacker |
|---|---|---|
| Where intent lives | Compiled logic, unpacked at runtime, deliberately obfuscated | **Natural-language text in the I/O stream** |
| To recover it | VMI + record/replay + taint tracking + hardware tracing | **Read the transcript** |
| Engineering cost | Multi-engineer-year capability | Comparatively trivial |
| Semantic gap | Severe — reconstruct OS abstractions from physical memory | **Nearly absent — the agent explains itself** |
| Anti-analysis | Packing, VM detection, self-checksumming, CVMs | Mostly not yet present |

An agent that is prompt-injected into attempting credential access **says so**, in tokens, on a channel you already terminate. The observation problem that conventional malware analysis spends a hardware budget solving is, for agentic attackers, largely solved by logging.

**Almost nobody has built for this.** That is consistent with the verified gap in [decoy-agent-infrastructure.md §1](decoy-agent-infrastructure.md#1-scoping-the-novelty-claim-honestly) — zero arXiv results for MCP honeypots — and it arrives at the same conclusion from an entirely different direction. Two independent lines of reasoning converging on "the agent I/O plane is under-instrumented and high-value" is meaningfully stronger evidence than either alone.

**Where the ladder still matters.** The inversion is not total, and overstating it would be a design error. When an agent's tool calls become *native execution* — it drops a payload, runs a binary, establishes conventional persistence — you are back to conventional analysis with all its costs. The correct architecture is therefore two-tier (§8), not I/O-only.

**The strategic read for BiTorus:** the sensor product is an I/O-plane observer, and the plan's [execution trace](../BUSINESS_PLAN.md#7-ai-execution-trace-and-data-model) is exactly the right object. This research is independent confirmation that the architecture is pointed at the right plane — and that the plane is cheap to instrument relative to the intelligence it yields, which is a good position to be in commercially.

## 8. Two-tier observation with escalation

Synthesising §7 with [ADLAH's escalation model](distributed-honeypot-coordination.md#32-adlah--rl-driven-escalation-between-interaction-tiers):

**Tier 1 — agent I/O plane (default, always on).** Prompt/response commitments, retrieval lineage, tool calls with typed arguments, policy decisions, memory mutations, execution receipts. Cheap, high semantic value, no special hardware. This is the business plan's execution trace, and it covers the large majority of agentic attack activity.

**Tier 2 — system plane (escalated, selective).** When a session crosses into native execution — a payload is written, a binary runs, an unexpected outbound connection opens — route the workload into an instrumented sandbox: record/replay for reproducibility, VMI for memory, hardware tracing for control flow, passive tap for network.

**The escalation trigger is a policy decision**, which means it belongs to the capability broker and follows the same [risk-class model](../BUSINESS_PLAN.md#13-response-architecture-and-safety) as any other response action. Escalating a session into a high-fidelity sandbox has cost and blast radius; it is an `Observe`-class action at minimum and may be `Constrain`-class if it changes the execution environment the agent perceives.

This gives a coherent story that neither literature has: **ADLAH escalates between honeypot interaction tiers; this escalates between observation planes.** The RL formulation transfers directly — the decision is "is this session worth the cost of deeper observation", with the same cost/fidelity trade and the same reward structure.

Design note: the escalation must not be perceptible to the agent, or it becomes a detection oracle. Record/replay (§2.2) is the natural fit precisely because heavy instrumentation happens offline — the agent's timeline is unaffected by whether analysis later occurs.

## 9. Reference architectures by budget

| Tier | Stack | Buys you |
|---|---|---|
| **Low budget** | Xen + DRAKVUF for behaviour; passive tap for network; logs shipped one-way to an external collector; hard egress filtering | Most of the value. This is the sensible default |
| **Add depth** | PANDA record/replay for anything interesting, so deep analysis never runs in the attacker's timeline; Intel PT if control flow at speed is needed | Undetectable heavy analysis; reproducible incidents |
| **Add trust** | Move detection and log collection onto a **DPU in Zero Trust mode** | **The single biggest architectural upgrade available, and the least commonly deployed.** Survives full host compromise |
| **Add coverage** | A small bare-metal restore rig | VM-aware samples that refuse to detonate under a hypervisor |
| **Agent-specific** | Tier-1 I/O capture (§7) as the always-on default, with §8 escalation into the above | The plane where agentic attack intent actually lives |

## 10. Implications for BiTorus

1. **§14.1.9 is under-specified.** "Ephemeral VMs or hardened disposable sandboxes" is the right instinct; this note supplies the concrete architecture — layered isolation (§4), default-deny egress with an architecturally separate log path (§3), and DPU-hosted collection where budget allows (§2.5).
2. **The agent I/O plane is the right bet, and now has independent support** (§7). Two separate lines of evidence — the MCP honeypot gap and the observation-cost argument — converge on it.
3. **Escalation between observation planes** (§8) is a genuinely novel synthesis worth building and worth publishing. It also gives the research harness a principled cost model rather than "sandbox everything".
4. **The CVM inversion (§5) is a threat-taxonomy gap.** An agent runtime inside a confidential VM defeats tenant-side introspection. The sensor product should detect and flag this configuration; the taxonomy should name it.
5. **Egress control is a liability control for the decoy programme** (§3), not merely a security one. It needs to be in the pre-launch checklist alongside the [safety constraints](decoy-agent-infrastructure.md#10-safety-ethics-and-legal-constraints).
6. **Record/replay makes incidents reproducible**, which composes directly with the [reproduction-as-arbiter](byzantine-robust-federation.md#63-reproduction-as-the-strongest-arbiter) mechanism in the federation work. A recorded execution is the strongest possible form of an evidence commitment — and it appreciates as analysis tooling improves.
7. **Instrument the probe** (§6) at every layer. Environment-detection attempts are a sophistication signal and should be a first-class event type in the trace schema — which means it is a schema-freeze item, not a later addition.

## 11. Proposed amendments to the business plan

[BUSINESS_PLAN.md](../BUSINESS_PLAN.md) is a faithful transcription of the signed v4.4 PDF and is deliberately **not** edited with new research — doing so would desynchronise it from the canonical source. The following are proposed amendments for a future v4.5, recorded here so they are not lost.

| Target | Proposed change |
|---|---|
| [§5.2 Threats against AI systems](../BUSINESS_PLAN.md#52-threats-against-ai-systems) | Add a threat class: **Anti-introspection** — agent runtimes placed inside confidential VMs or otherwise opaque enclaves to defeat tenant-side execution tracing. Primary controls: configuration attestation, detection of unobservable runtimes, policy refusal to grant capabilities to agents whose execution cannot be traced |
| [§7.1 Required trace events](../BUSINESS_PLAN.md#71-required-trace-events) | Add **environment-detection probes** as a recorded event type (§6) |
| [§13 Response architecture](../BUSINESS_PLAN.md#13-response-architecture-and-safety) | Add **escalate-observation** as an explicit `Observe`-class action with its own cost and perceptibility constraints (§8) |
| [§14.1.9](../BUSINESS_PLAN.md#1419-sacrificial-adversarial-research-infrastructure) | Expand: default-deny egress; log path architecturally separate from the controlled-egress path; DPU-hosted collection where available; explicit statement that decoy egress is a third-party-harm liability control (§3) |
| [§15.1 Core services](../BUSINESS_PLAN.md#151-core-services) | Note that the research harness has a two-tier observation architecture (§8), not a single sandbox type |
| [§18 Security assurance](../BUSINESS_PLAN.md#18-security-assurance-and-evaluation) | Add a test: verify that observation escalation is not perceptible to the observed agent |

## 12. Sources

Supplied with the research brief and reproduced with their original citations. Individual claims here have **not** been independently re-verified against the primary sources; the DRAKVUF/PANDA/Intel-PT material is well-established, while the 2025–26 items (BlueGuard, Heckler, the CVM CVE analysis) should be checked before external use.

**Hypervisor VMI**
- [Scalability, Fidelity and Stealth in the DRAKVUF Dynamic Malware Analysis System (ACSAC)](https://dl.acm.org/doi/10.1145/2664243.2664252)
- [Improving the Stealthiness of Virtual Machine Introspection on Xen (altp2m)](https://xenproject.org/blog/improving-the-stealthiness-of-virtual-machine-introspection-on-xen/)
- [RapidVMI: Fast and multi-core aware active VMI](https://dl.acm.org/doi/fullHtml/10.1145/3465481.3465752)
- [Hiding in the Shadows: Empowering ARM for Stealthy VMI](https://www.sec.in.tum.de/i20/publications/hiding-in-the-shadows-empowering-arm-for-stealthy-virtual-machine-introspection)
- [Bridging the Semantic Gap in VMI and Forensic Memory Analysis (arXiv 2503.05482)](https://arxiv.org/pdf/2503.05482)

**Record and replay**
- [Repeatable Reverse Engineering with PANDA](https://dl.acm.org/doi/10.1145/2843859.2843867) · [Building a custom malware sandbox with PANDA](https://adalogics.com/blog/Building-a-custom-malware-sandbox-with-PANDA-Part-1)
- [IRIS: Record and Replay for Hardware-assisted Virtualization Fuzzing (arXiv 2303.12817)](https://arxiv.org/pdf/2303.12817)

**Hardware tracing**
- [On the Feasibility of Malware Unpacking via Hardware-assisted Loop Profiling (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/cheng-binlin)

**Bare metal**
- [BareBox: Efficient Malware Analysis on Bare-Metal (ACSAC)](https://sites.cs.ucsb.edu/~chris/research/doc/acsac11_barebox.pdf)
- [Transparent Snapshot for Bare-metal Malware Analysis](https://www.ittc.ku.edu/~bluo/pubs/p339-guan.pdf)

**Off-host / DPU**
- [BlueGuard: Accelerated Host and Guest Introspection Using DPUs (USENIX Security '25)](https://www.usenix.org/system/files/usenixsecurity25-orenbach.pdf)
- [BlueField Modes of Operation / Zero Trust](https://docs.nvidia.com/doca/sdk/bluefield-modes-of-operation/index.html)

**Confidential computing as anti-analysis**
- [Confidential VMs Explained: Empirical Analysis of SEV-SNP and TDX](https://dl.acm.org/doi/10.1145/3700418)
- [Heckler: Breaking Confidential VMs with Malicious Interrupts (arXiv 2404.03387)](https://arxiv.org/pdf/2404.03387)

**Internal**
- [decoy-agent-infrastructure.md](decoy-agent-infrastructure.md)
- [byzantine-robust-federation.md](byzantine-robust-federation.md)
- [distributed-honeypot-coordination.md](distributed-honeypot-coordination.md)
- [threat-intelligence-landscape-2026.md](threat-intelligence-landscape-2026.md)
