# Novel and experimental approaches to distributed, coordinated honeypots

Research notes, August 2026. Literature survey via the arXiv API; claims are sourced to specific papers with dates so staleness is visible. Relevant to [6.2 Federation Plane](../BUSINESS_PLAN.md#62-federation-plane), [12. Privacy-preserving federation](../BUSINESS_PLAN.md#12-privacy-preserving-federation), and [14.1.7 Federation poisoning and false-intelligence resistance](../BUSINESS_PLAN.md#1417-federation-poisoning-and-false-intelligence-resistance) in the business plan.

Companion to [threat-intelligence-landscape-2026.md](threat-intelligence-landscape-2026.md), which covers honeypot SOTA generally (LLM-powered honeypots, reverse prompt injection as an agent detector). This note covers specifically the *distributed coordination* question: what is novel or experimental in running many honeypots as one coordinated system.

## Table of contents

- [1. Framing: four axes of coordination](#1-framing-four-axes-of-coordination)
- [2. Topology as the sensing instrument](#2-topology-as-the-sensing-instrument)
- [3. Orchestration: cloud-native honeynets and dynamic escalation](#3-orchestration-cloud-native-honeynets-and-dynamic-escalation)
- [4. Federated learning across honeypot operators](#4-federated-learning-across-honeypot-operators)
- [5. Game-theoretic placement and allocation](#5-game-theoretic-placement-and-allocation)
- [6. Coordination against agentic attackers](#6-coordination-against-agentic-attackers)
- [7. Genuinely experimental / fringe](#7-genuinely-experimental--fringe)
- [8. What is missing from the literature](#8-what-is-missing-from-the-literature)
- [9. Relevance to BiTorus](#9-relevance-to-bitorus)
- [10. Sources](#10-sources)

---

## 1. Framing: four axes of coordination

"Distributed honeypots" conflates four separable things. Most papers do exactly one of them, which is why the literature reads as more mature than it is. Separating the axes makes the actual gaps visible:

| Axis | Question it answers | Maturity (Aug 2026) |
|---|---|---|
| **Topological** | Where do sensors sit, and does the geometry itself produce signal? | Deployed, credible results |
| **Orchestration** | How are sensors provisioned, escalated, and torn down as a fleet? | Prototype → early production |
| **Learning** | How does what one sensor learns improve the others? | Benchmark-stage; real-world validation thin |
| **Strategic** | Where *should* deception be placed against a reasoning adversary? | Theory-rich, deployment-poor |

The interesting recent work is where two axes combine. The unclaimed ground is where three or four do.

## 2. Topology as the sensing instrument

The most underrated idea: geographic and topological distribution isn't just for coverage — the *pattern of which sensors fire* is itself the measurement.

**Anycast amplification honeypots** (Degen et al., July 2026) are the cleanest example. A globally anycast honeypot deployment attracts requests from topologically nearby sources. Because anycast routing sends a request to whichever instance is nearest, the *set of honeypots that received spoofed traffic*, combined with TTL variation, becomes an estimator for how many distinct network locations a spoofing campaign originates from. Over 287 days of amplification attacks, at least 21.0% originated from multiple network locations.

Why this matters conceptually: single-vantage-point honeypots can't distinguish "one source" from "many coordinated sources." Distribution converts an unanswerable attribution question into a measurable one. The honeypot network is a sensor array, not a set of independent traps — closely analogous to the tsunami-buoy framing in the [executive summary](../BUSINESS_PLAN.md#executive-summary) of the business plan.

Supporting deployments in the same vein:

- **MURHCAD** (Jan 2026) — multi-regional cloud honeypot dataset, 132,425 events from Cowrie/Dionaea/SentryPeer across four geographically dispersed Azure VMs. The finding worth noting is **platform- and region-specific bias**: SentryPeer captured concentrated SIP floods in North America and Southeast Asia, Cowrie logged Telnet/SSH scans predominantly from Western Europe and the US, Dionaea recorded SMB exploits around European nodes. Any single-region deployment produces a systematically skewed threat picture.
- **HoneyTrap** (Dec 2025) — 60.3M events over 24 days across geographically distributed nodes, with ASN enrichment and salted SHA-256 pseudonymization. Notable for treating privacy preservation as part of the distributed-collection design rather than an afterthought.

**Takeaway**: the correlated-firing pattern across a sensor array is a primitive most deception programs don't exploit. It is also the primitive that most directly requires coordination — you cannot compute it from one operator's logs.

## 3. Orchestration: cloud-native honeynets and dynamic escalation

### 3.1 Holoscope — the reference architecture for multi-institution sensor fleets

**Holoscope** (Sordello, Mellia, Drago et al.; IEEE Communications Magazine, updated June 2026) is the most directly relevant deployed system. It is an open, lightweight, cloud-native platform for deploying and managing both telescope (passive) and honeypot (active) sensors, built on **K3s and WireGuard**, with automated sensor onboarding, secure connectivity, resilient operation in resource-constrained environments, dynamic sensor orchestration, automated recovery, and Infrastructure-as-Code deployment. It has been built, deployed, and operated **across multiple institutions and cloud networks in Europe and Brazil**.

The design choices worth stealing: WireGuard mesh for sensor-to-collector connectivity, K3s so a sensor is a lightweight Kubernetes node rather than a bespoke appliance, and IaC-driven onboarding so a new participating institution is a config change rather than a project. The hard problem in multi-org honeypot federation has always been operational, not scientific — Holoscope is the strongest published answer.

### 3.2 ADLAH — RL-driven escalation between interaction tiers

**ADLAH** (Möller, Dec 2025) addresses the fidelity/risk/cost trilemma structurally rather than with a better LLM. A reinforcement-learning agent decides **in real time when a session should be escalated from a low-interaction sensor node to a dynamically provisioned high-interaction honeypot**. Cheap low-interaction sensors are the wide net; expensive, risky high-interaction environments are spun up only for sessions that look worth the cost.

It also pursues automated extraction, clustering, and **versioning of bot attack chains** — motivated by the empirical observation that exposed services are dominated by automated traffic. Bot versioning is a genuinely good idea and maps directly onto the affected-configuration intelligence concept.

Honest caveat, stated by the author: this is an architectural blueprint with a functional prototype of the decision mechanism. Sufficient live data were unavailable, so **field-scale validation is not claimed**. Treat as a design to test, not a result to build on.

### 3.3 Selective redirection as a fleet-level control

Several 2026 systems treat `HONEYPOT_REDIRECT` as a first-class response action alongside `ALLOW` and `ISOLATE` — a policy decision made per-flow by a learned agent rather than a static network placement. A Kubernetes-specific variant (Jan 2026) redirects all access from attacking IPs to honeypot pods while adjusting HPA parameters, isolating attack traffic so it doesn't drive autoscaler expansion.

This reframes the honeypot from *a place on the network* to *a destination a policy engine can route to*, which is what makes fleet-wide coordination tractable.

## 4. Federated learning across honeypot operators

The most active 2026 research line, and also the one where claimed results most exceed demonstrated ones.

Two closely-related IoMT frameworks (Haider et al., June 2026) — **Federated TGCN-A2C** and **LDT-FRL** — share an architecture worth summarizing because it is becoming the template:

- A temporal graph or attention encoder does flow-level threat classification.
- Lightweight LSTM **digital twins**, trained only on normal traffic, produce per-device anomaly scores that gate the classifier.
- A **federated RL agent** (A2C or PPO) selects among `ALLOW` / `ISOLATE` / `HONEYPOT_REDIRECT` from a seven-dimensional state capturing confidence, entropy, anomaly magnitude, and traffic composition.
- Federated aggregation uses EMA-smoothed per-client validation losses as inverse-weighted FedAvg coefficients, to stabilize under non-IID client distributions.
- The honeypot layer converts redirected traffic into threat intelligence with adaptive thresholds.

Reported accuracy is 99.5–99.95% on CICDDoS 2019 and TON-IoT. **Discount these heavily**: both are public benchmark datasets, not live federated deployments, and near-ceiling numbers on CICDDoS are common enough to be uninformative about field performance. The *architecture* is the contribution — specifically, that the honeypot-redirect decision is the learned policy, and the learning is federated so no operator ships raw flows.

The non-IID weighting detail is the practically important part: honeypot operators have wildly different traffic distributions (see the MURHCAD regional bias above), so naive FedAvg across deception operators would be actively harmful.

**Open and unaddressed**: none of this work models a *malicious* federation participant. Federated honeypot learning where some operators submit poisoned observations is, as far as this survey found, unstudied. That is precisely the [independence-aware corroboration](../BUSINESS_PLAN.md#adr-ai-011-independence-aware-corroboration) problem.

## 5. Game-theoretic placement and allocation

Where to put deception against an adversary who knows deception exists is a game, and the literature treats it as one.

- **Bayesian Stackelberg games for adaptive honeypot allocation in multi-attacker networks** (May 2025) — allocation against a population of attacker types with differing objectives, rather than a single assumed adversary.
- **Hypergame-theoretic deep RL (HT-DRL)** for mission surveillance (Wan, Cho, Anwar, Kamhoua, Singh; March 2026) — *hypergame* theory is the notable ingredient: it models players having **different and incorrect perceptions of the game being played**, which is the correct formalism for deception (the attacker's model of the network is the thing you're manipulating). Applied to UAV "honey drones" that bait DoS attacks by emitting stronger radio signals at battery cost; folding hypergame solutions into the DRL network avoids long convergence times, and outperforms non-HD baselines up to 2× on mission performance.
- **Deceptive Stackelberg control of UCB bandit followers** (June 2026) — formal proof that the optimism-under-uncertainty principle making UCB statistically efficient also creates a predictable exploitable vulnerability. A leader pays a bounded signaling cost in a "honeypot phase" to inflate the UCB index of a chosen action, then switches to a selfish distribution in a "trap phase" while the follower stays locked in. Manipulation cost bounded at O(√(T ln T)).

That last one is worth flagging beyond its stated framing: **it is a template for deceiving any exploration-driven learning agent**, and autonomous attack agents are exploration-driven. It is offense-flavored in the paper but reads as a defensive primitive against RL-based attackers.

- **Descriptive model of attacker engagement decisions** (Turner et al., Dec 2025) — five components (belief, scepticism, deception fidelity, reconnaissance, experience) modeling whether an attacker engages *at all*. Fills a real gap: game-theoretic, Bayesian, MDP, and RL models nearly all assume engagement has already happened. Note the experiments described in the paper **have not been conducted** — it is a proposal.

## 6. Coordination against agentic attackers

This is where the newest and most consequential proposals sit.

**"Detecting Offensive Cyber Agents: A Detection-in-Depth Approach"** (Mittelsteadt, Kraprayoon, Staes-Polet, Galeev, Wehner, Covino, Ee; May 2026, 95pp) is the key document. It frames the detection gap opening between offensive cyber agents and traditional capabilities, and proposes five mechanisms — two of which are directly about coordinated deception:

- **Agent Honeypots** as a named detection mechanism (the Palisade reverse-prompt-injection lineage, elevated to policy infrastructure).
- **An Agentic Cybersecurity Exchange (ACE)** — an institution modeled on the **Global Signal Exchange** that brings together model and cloud providers to detect offensive cyber agent threats *at their origin point* and coordinate ecosystem-wide agentic threat disruption.
- Plus: Agent Identifiers for Critical Infrastructure, AI-automated alert triage, and an Agentic Security Alert Standard.

ACE is the most ambitious coordination proposal in this space: detection at the *provider* layer rather than the target layer. If an agent honeypot fingerprints an attacking agent and can attribute it to a model/provider, disruption happens upstream of every potential victim. That inverts the usual honeypot economics — one sensor firing protects the whole ecosystem, not just the operator.

It is a policy proposal, not a running system. But it is the clearest articulation of why distributed agent honeypots are worth more coordinated than standalone.

**GroupGuard** (March 2026) is a different flavor of the same instinct: defending multi-agent systems against *group collusive attacks* where multiple agents coordinate to mislead a system. Its defense combines continuous graph-based monitoring, **active honeypot inducement**, and structural pruning; group collusive attacks raised attack success rate up to 15% over individual attacks, and GroupGuard detects up to 88%. Honeypots as an internal component of a multi-agent system, rather than perimeter infrastructure.

## 7. Genuinely experimental / fringe

Worth knowing about, none ready to build on:

- **Quantum honeypot traffic partitioning** (Cogburn, DeCusatis, Spillane; June 2026). Honeypot traffic partitioning mapped to weighted MaxCut, solved with QAOA on 100+ qubit IBM processors; largest benchmark 110 nodes / 181 edges across three IBM backends. The authors are refreshingly honest: **simple classical heuristics solve these benchmark graphs, so this is not a quantum advantage claim.** It is a hardware-feasibility and architecture-benchmark framework. Value is methodological.
- **HoneySat** (NDSS 2026) — first high-interaction satellite honeypot, convincingly simulating a CubeSat; 90% of surveyed SmallSat operators judged it realistic, and it performed a hardware-in-the-loop operation communicating with a real in-orbit SmallSat. Relevant here because satellite ground infrastructure is inherently geographically distributed — coordination is a precondition, not an enhancement.
- **SimProcess** (CPSS 2025) — ranks ICS honeypot *fidelity* by estimating how closely simulated physical-process noise matches a real system, using only a timeseries from the real system. A distributed-fleet application nobody has published: use it to verify that sensors across a federation are equally convincing, since the weakest-fidelity node is what fingerprints the whole network.
- **Blockchain + adaptive honeypots for IoT** (April 2025) — on-demand high-interaction honeypots whose extracted attack patterns are stored on-chain. The blockchain here is doing authentication and tamper-evident storage. A **Merkle transparency log achieves the same integrity properties without the consensus overhead**, which is the position the business plan already takes ([executive summary](../BUSINESS_PLAN.md#executive-summary): "a Merkle transparency log for provenance and equivocation detection, not a blockchain data plane").
- **EtherBee** (May 2025) — Ethereum node metrics + honeypot interaction logs from ten geographically diverse vantage points over three months. Interesting as a case of honeypots embedded *inside* a P2P network rather than at its edge.

## 8. What is missing from the literature

Gaps that are real rather than merely unfashionable:

1. **Byzantine-robust honeypot federation.** Federated honeypot learning uniformly assumes honest participants. A compromised or adversarial sensor operator submitting crafted observations to steer a shared model is unstudied. This is the highest-value open problem for anyone building a federation.
2. **Cross-operator session correlation without raw log sharing.** Determining that the same actor hit sensors at three organizations currently requires sharing enough to be a privacy problem. Private set intersection over session fingerprints is the obvious approach and is essentially unpublished for deception.
3. **Fleet-wide fidelity as a coupled property.** Every fidelity paper evaluates a single honeypot. In a coordinated network, an attacker who fingerprints one node can enumerate the rest — fidelity is a *network* property with a weakest-link structure, and nobody models it that way.
4. **Coordinated deception against agentic attackers.** Everything published on reverse prompt injection assumes a single honeypot and an attacker unaware of the trap. Multi-node variants — different injection payloads per node to fingerprint which agent scaffold is being used, or staged injections across nodes that only resolve when an agent visits several — are unclaimed.
5. **Decoy agent infrastructure at federation scale.** Decoy MCP servers, fake agent registrations, honeytoken credentials scoped to nonexistent agents. Given ~7,000 internet-exposed MCP servers and active mass scanning, and near-zero legitimate traffic to a decoy MCP server, the signal-to-noise ratio should be exceptional. A *coordinated* decoy-MCP network would additionally reveal scanning campaign structure via the topological method in §2.
6. **Ecological validity everywhere.** Palisade's 8 candidate AI agents out of 8.1M attempts is the honest baseline for how thin agent-behavior data still is. Multi-site, long-horizon deployment is the boring necessary work, and it is exactly what a federation is for.

Gaps 1 and 2 are addressed in [byzantine-robust-federation.md](byzantine-robust-federation.md); gaps 4 and 5 in [decoy-agent-infrastructure.md](decoy-agent-infrastructure.md). The related question of *when a fleet should spend expensive observation on a session* is developed in [observation-architecture.md §8](observation-architecture.md#8-two-tier-observation-with-escalation), which transfers ADLAH's cost/fidelity formulation from interaction tiers to observation planes.

## 9. Relevance to BiTorus

Direct connections to the plan, stated as design implications rather than product commitments:

- **§2 topological correlation is the sensor-array thesis, already stated.** The business plan's tsunami-buoy analogy is literally the anycast-honeypot method. Worth making explicit that correlated-firing-pattern analysis is a federation-plane capability, not a per-tenant one — it is computable *only* with coordination, which is a clean answer to "why join the federation."
- **Holoscope is the closest published prior art for the sensor fleet**, and its stack (K3s + WireGuard + IaC onboarding) is compatible with the [Kubernetes-first packaging](../BUSINESS_PLAN.md#154-self-hosted-technical-requirements) the plan already commits to.
- **ADLAH's escalation policy maps onto the [risk-class response model](../BUSINESS_PLAN.md#13-response-architecture-and-safety)** — escalating a session to a high-interaction environment is a `Constrain`/`Isolate`-class action with cost and blast radius, and belongs under the same local-authorization rules.
- **Byzantine-robust federation (§8.1) is the single largest overlap with an existing differentiator.** [§14.1.7](../BUSINESS_PLAN.md#1417-federation-poisoning-and-false-intelligence-resistance) already specifies independence-aware corroboration and evidence commitments. The literature has *not* solved this for honeypot federations. That is a defensible research position, not a catch-up item.
- **ACE (§6) is a strategic signal worth tracking.** If provider-layer agentic threat disruption becomes institutionalized, it is either a distribution channel or a competitor for the intelligence layer, depending on positioning. Reassess when it moves past proposal stage.
- **Decoy agent infrastructure (§8.5) is unclaimed ground** that aligns with the plan's existing focus on MCP/tool inventory and the [adversarial research lab](../BUSINESS_PLAN.md#35-executive-build-recommendation). It would generate proprietary corpus data before any federation exists — i.e. it feeds [Product 1](../BUSINESS_PLAN.md#371-three-product-sequence), which is the revenue that doesn't depend on network effects.

## 10. Sources

Ordered roughly by relevance to distributed coordination.

- [Holoscope: Open and Lightweight Telescope & Honeypot Platform (arXiv 2512.19842)](https://arxiv.org/abs/2512.19842) — IEEE Communications Magazine, DOI [10.1109/MCOM.001.2500784](https://doi.org/10.1109/MCOM.001.2500784)
- [Detecting Offensive Cyber Agents: A Detection-in-Depth Approach (arXiv 2605.21956)](https://arxiv.org/abs/2605.21956)
- [Spoofer or Spoofers? Estimating a Lower Bound on the Number of DRDoS Sources Using Anycast Honeypots (arXiv 2607.14832)](https://arxiv.org/abs/2607.14832)
- [An Adaptive Multi-Layered Honeynet Architecture for Threat Behavior Analysis via Deep Learning — ADLAH (arXiv 2512.07827)](https://arxiv.org/abs/2512.07827)
- [Privacy-Preserving Federated Temporal Graph Learning with Digital Twin–Guided Adaptive Deception for Cyber-Resilient IoMT (arXiv 2606.21513)](https://arxiv.org/abs/2606.21513)
- [Federated Temporal Attention Intelligence for Cyber-Resilient IoMT — LDT-FRL (arXiv 2606.21422)](https://arxiv.org/abs/2606.21422)
- [Cyber Deception for Mission Surveillance via Hypergame-Theoretic Deep Reinforcement Learning (arXiv 2603.20981)](https://arxiv.org/abs/2603.20981)
- [Optimism as a Vulnerability: Deceptive Stackelberg Control of UCB Bandit Followers (arXiv 2607.05423)](https://arxiv.org/abs/2607.05423) — ICML 2026 NExT-Game Workshop
- [Adaptive Honeypot Allocation in Multi-Attacker Networks via Bayesian Stackelberg Games (arXiv 2505.16043)](https://arxiv.org/abs/2505.16043)
- [GroupGuard: Modeling and Defending Collusive Attacks in Multi-Agent Systems (arXiv 2603.13940)](https://arxiv.org/abs/2603.13940)
- [Characterizing Large-Scale Adversarial Activities Through Large-Scale Honey-Nets — HoneyTrap (arXiv 2512.06557)](https://arxiv.org/abs/2512.06557) — IEEE UEMCON 2025
- [Descriptor: Multi-Regional Cloud Honeypot Dataset — MURHCAD (arXiv 2601.05813)](https://arxiv.org/abs/2601.05813) — DOI [10.1109/IEEEDATA.2026.3687845](https://doi.org/10.1109/IEEEDATA.2026.3687845)
- [Network and Device Level Cyber Deception for Contested Environments Using RL and LLMs (arXiv 2603.17272)](https://arxiv.org/abs/2603.17272)
- [ShellGames: Speculative LLM-Driven SSH Deception (arXiv 2606.17986)](https://arxiv.org/abs/2606.17986)
- [A Descriptive Model for Modelling Attacker Decision-Making in Cyber-Deception (arXiv 2512.03641)](https://arxiv.org/abs/2512.03641)
- [Hardware-Aware QAOA for Honeypot Traffic Partitioning on 100+ Qubit IBM Quantum Processors (arXiv 2606.09469)](https://arxiv.org/abs/2606.09469)
- [HoneySat: A Network-based Satellite Honeypot Framework (arXiv 2505.24008)](https://arxiv.org/abs/2505.24008) — NDSS 2026
- [SimProcess: High Fidelity Simulation of Noisy ICS Physical Processes (arXiv 2505.22638)](https://arxiv.org/abs/2505.22638) — CPSS 2025
- [Blockchain Meets Adaptive Honeypots: A Trust-Aware Approach to Next-Gen IoT Security (arXiv 2504.16226)](https://arxiv.org/abs/2504.16226)
- [EtherBee: A Global Dataset of Ethereum Node Performance Measurements Coupled with Honeypot Interactions (arXiv 2505.18290)](https://arxiv.org/abs/2505.18290)
- [Automatic Adjustment of HPA Parameters and Attack Prevention in Kubernetes Using Random Forests (arXiv 2601.13515)](https://arxiv.org/abs/2601.13515) — DOI [10.1145/3704304.3704320](https://doi.org/10.1145/3704304.3704320)
- [Adversarial Reinforcement Learning for Offensive and Defensive Agents in a Simulated Zero-Sum Network Environment (arXiv 2510.05157)](https://arxiv.org/abs/2510.05157)
