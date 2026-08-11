# Coordinated decoy agent infrastructure

**Status:** research position / design note. Not implemented.
**Date:** August 2026.
**Relates to:** [§35 Executive build recommendation](../BUSINESS_PLAN.md#35-executive-build-recommendation), [§37.1 Three-product sequence](../BUSINESS_PLAN.md#371-three-product-sequence), [§37.2 Agentic Threat Pattern](../BUSINESS_PLAN.md#372-core-proprietary-object-agentic-threat-pattern), [§43 Immediate 180-day execution plan](../BUSINESS_PLAN.md#43-immediate-180-day-execution-plan).

The thesis: decoy MCP servers and decoy agent identities are unclaimed ground with exceptional signal-to-noise, they are a *better* substrate for LLM-backed interactive deception than the shell honeypots the literature has focused on, and — critically — they generate proprietary corpus **before any federation exists**, which is exactly what Product 1 needs.

## Table of contents

- [1. Scoping the novelty claim honestly](#1-scoping-the-novelty-claim-honestly)
- [2. Why agent infrastructure is the right decoy surface](#2-why-agent-infrastructure-is-the-right-decoy-surface)
- [3. MCP inverts the LLM-honeypot trilemma](#3-mcp-inverts-the-llm-honeypot-trilemma)
- [4. Interactive decoys: the decoy is an agent](#4-interactive-decoys-the-decoy-is-an-agent)
- [5. Anatomy of a decoy MCP server](#5-anatomy-of-a-decoy-mcp-server)
- [6. Signals collected](#6-signals-collected)
- [7. Coordination: the fleet as one experiment](#7-coordination-the-fleet-as-one-experiment)
- [8. Beyond servers: decoy identities, registrations, and canary clients](#8-beyond-servers-decoy-identities-registrations-and-canary-clients)
- [9. The MCP ecosystem monitor](#9-the-mcp-ecosystem-monitor)
- [10. Safety, ethics, and legal constraints](#10-safety-ethics-and-legal-constraints)
- [11. Detection resistance and the arms race](#11-detection-resistance-and-the-arms-race)
- [12. Metrics and expected yield](#12-metrics-and-expected-yield)
- [13. What to build first](#13-what-to-build-first)
- [14. Risks to this position](#14-risks-to-this-position)
- [15. References](#15-references)

---

## 1. Scoping the novelty claim honestly

**Verified negative (August 2026):** arXiv full-text search returns **zero results** for `"Model Context Protocol" honeypot` and for `MCP server honeypot deception`. No academic work on MCP honeypots appears to exist.

**What does exist, and is prior art:**

- **Palisade Research's LLM Agent Honeypot** ([arXiv 2410.13919](https://arxiv.org/abs/2410.13919)) — the reverse-prompt-injection technique on a modified Cowrie SSH honeypot: ANSI-hidden multi-stage injections, goal hijacking, system-prompt stealing, timing analysis. 8 candidate AI agents from 8.13M attempts over ~3 months. **The technique is theirs; the substrate is what changes here.**
- **LLM-powered honeypot systems** — ShellGames, HoneyGPT, LLM-SSHH, HoneyLLMd, the LDAP honeypot. All target conventional protocols (SSH, HTTP, LDAP).
- **MCP security research** — CSA's MCP Security Crisis note, the OX Security systemic flaw, tool-poisoning and rug-pull analyses. This work catalogues *real* MCP servers and their vulnerabilities; it does not deploy decoys.
- **Honeytokens** — decades of practice. Decoy credentials scoped to nonexistent agents is an incremental application, not an invention.
- **The ACE proposal** ([arXiv 2605.21956](https://arxiv.org/abs/2605.21956)) — names "Agent Honeypots" as a policy-level detection mechanism, without specifying design.

**What appears genuinely unclaimed:**

1. Protocol-faithful **decoy MCP servers** as a deception and intelligence-collection surface.
2. **Differential payload assignment across a fleet** to fingerprint agent sanitization pipelines (§7.1).
3. **Split/staged injections across nodes** as a behavioural campaign-linkage primitive that survives IP rotation (§7.2).
4. **Canary MCP clients** continuously diffing the public ecosystem for tool-definition drift (§9).
5. **LLM-backed interactive decoys in the MCP setting specifically**, where the classic LLM-honeypot failure modes largely dissolve (§3).

**Caveat, same as always:** these negatives cover arXiv plus the surveys gathered. GitHub projects, vendor internals, and unpublished red-team tooling are not covered. Re-verify before any public novelty claim. Note especially that a decoy MCP server is a weekend project for a competent engineer — absence from the literature does not imply absence from the world.

## 2. Why agent infrastructure is the right decoy surface

### 2.1 Signal-to-noise

The core economic argument for any honeypot is that interaction implies malice. Conventional honeypots have a persistent noise problem: SSH and HTTP endpoints are swept continuously by benign internet-wide scanners, security researchers, and misconfigured clients. Separating attack from census is real work.

An MCP endpoint that was never advertised has **near-zero legitimate reason to receive a tool call**. Nobody's production agent stumbles onto an unadvertised MCP server and starts enumerating its tools.

Be precise about the residual noise, though — the "near-zero" claim is about *depth*, not connections:

| Interaction depth | Who does this | Signal value |
|---|---|---|
| TCP connect / TLS handshake | Everyone, constantly | None |
| HTTP probe, banner grab | Shodan, Censys, academic scanners | Low — census |
| MCP `initialize` handshake | Something that speaks MCP | **Moderate — already narrow** |
| `tools/list`, `resources/list` | Something enumerating capabilities | **High** |
| `tools/call` with plausible arguments | Something *using* the server | **Very high** |
| Tool call following injected instruction | An LLM agent, near-certainly | **Near-conclusive** |

The discriminator is depth, and the depth gradient here is much steeper than on SSH. A scanner fingerprints and leaves. An agent negotiates the protocol, reads tool descriptions, reasons about them, and calls one. **Protocol-native behaviour is itself the classifier** — which is a more durable discriminator than falling for an injection, and matters for §11.

### 2.1a The observation-cost argument arrives at the same place

An independent line of reasoning reaches this conclusion from the opposite direction. Surveying how to observe attacks without being compromised — VMI, record/replay, hardware tracing, DPU-based introspection — produces the finding that **for LLM-agent attackers that entire ladder is largely beside the point**: an agent's intent is natural-language text on the wire, so I/O capture yields directly what conventional malware analysis spends a hardware budget reconstructing from memory.

Two separate arguments — the verified MCP honeypot gap above, and the observation-cost asymmetry — converging on "the agent I/O plane is under-instrumented and high-value" is meaningfully stronger evidence than either alone. See [observation-architecture.md §7](observation-architecture.md#7-the-2026-inversion-for-agent-attackers-the-plane-is-io-not-memory).

### 2.2 The population is exactly the population of interest

An SSH honeypot catches everything: commodity botnets, credential stuffers, the occasional human, and — rarely — an AI agent. Palisade's ratio of 8 candidates in 8.13M attempts is the honest baseline for agent density on conventional protocols.

MCP is agent-native. Only agent infrastructure speaks it. Total volume will be **far lower**, but the fraction of interactions that are agent-driven should be **far higher**. For a business whose product is agentic threat intelligence, that trade is strongly favourable: the plan needs depth on a narrow population, not breadth on a broad one.

### 2.3 Exposure is documented and large

~7,000 internet-exposed MCP servers catalogued, roughly half with no authentication, and an April 2026 systemic flaw implicating an estimated 200k instances. There is active mass scanning for this surface. A decoy fleet is therefore not speculative infrastructure waiting for a threat — it is instrumentation pointed at a known, ongoing, under-observed activity.

## 3. MCP inverts the LLM-honeypot trilemma

This section is the strongest technical argument in the document, and it directly supports building decoys as **interactive, LLM-backed** systems rather than static fakes.

The [SoK on LLM honeypots](https://arxiv.org/abs/2510.25939) and the systems that follow it identify four failure modes that keep LLM-powered deception in the prototype stage. **Each is dramatically weaker in the MCP setting.** Compare against an SSH shell, the substrate the literature has concentrated on:

| Failure mode | SSH shell | Decoy MCP server |
|---|---|---|
| **State loss / hallucinated inconsistency** — the dominant detection vector; the model forgets what it said, files vanish, `cd` breaks | Severe. A filesystem is enormous, implicit, and infinitely probeable. A few verification commands break most deployments | **Mild.** State is small, explicit, and typed: a tool catalog, a resource list, and whatever state the fake tools declare. Trivially held outside the context window in a real datastore |
| **Latency** — inference time vs. expected response time | Severe. A human at a shell notices a 2-second `ls` | **Nearly absent.** Tool calls are *expected* to be slow — they nominally hit databases, APIs, cloud services. Hundreds of ms to several seconds is normal. Inference latency hides inside the legitimate latency budget |
| **Output inconsistency** — malformed or implausible output reveals the model | Severe. Shell output is unstructured; any format slip is a tell | **Mechanically checkable.** Responses are JSON validated against the tool's own declared schema. Generate, validate, regenerate on failure. The protocol supplies the correctness oracle |
| **Fingerprinting surface** — protocol quirks that differ from the real implementation | Large. `uname`, `/proc`, dmesg, timing, terminal handling, dozens of edge cases | **Small.** JSON-RPC with a modest method set. Protocol-faithful implementation is achievable and testable against the real reference implementation |

**Conclusion: MCP is the most favourable substrate published or unpublished for LLM-backed interactive deception.** The trilemma that keeps LLM honeypots in the lab is substantially relaxed here — not by a better model, but by the properties of the protocol.

Two of these deserve emphasis because they invert the usual difficulty:

- **The typed schema is a correctness oracle.** Every LLM honeypot paper struggles with validating generated output. MCP hands you a machine-checkable contract. Generate a response, validate it against the declared `outputSchema`, and regenerate on failure. That loop is not available to a shell simulator.
- **Latency stops being a tell and becomes cover.** This is the failure mode with no good fix in the shell setting, and it simply does not apply here.

This is a defensible research claim in its own right, and a natural first publication: *the LLM-honeypot trilemma is substrate-dependent, and agent-protocol substrates relax it.*

## 4. Interactive decoys: the decoy is an agent

Given §3, the decoy should not be a static fake. It should be **interactive and adaptive** — an LLM-backed system that plays a role, sustains an engagement, and elicits information. The relevant techniques exist; the contribution is porting them to a substrate where they work far better.

### 4.1 Port the ShellGames toolkit

[ShellGames](https://arxiv.org/abs/2606.17986) combines five techniques for LLM-driven SSH deception. Each maps onto MCP, mostly more easily:

| ShellGames technique | MCP application |
|---|---|
| Automatic chain-of-thought + few-shot for correctness | Generate tool results consistent with the declared schema and the persona's fictional backing systems |
| Memory management for state coherency | **Easy here.** Keep fake state in a real datastore — a fake customer table, a fake secret store. The LLM renders views over durable state instead of inventing it |
| Speculative command execution to cut latency | Pre-compute likely next tool calls. Enumeration order is far more predictable than shell command order |
| Smart routing of complex interactions to a sandbox | Route a subset of tools to real sandboxed implementations. A fake `db.query` can front an actual throwaway database with synthetic data — perfectly consistent, zero hallucination |
| Subversion detection via constrained input-output domain | **Strongest here.** The input domain is JSON-RPC against declared schemas. Off-contract input is trivially detectable, and *attempts to subvert the decoy are themselves high-value signal* |

That last row deserves emphasis. An attacking agent that tries to break the decoy — probing for inconsistency, attempting to make it reveal that it is a simulation — is exhibiting *deception-aware* behaviour. That is a distinct and more advanced adversary class, and detecting the probe is more valuable than surviving it. Log subversion attempts as a first-class event type, not as an error.

### 4.2 Adaptive engagement

Because the decoy is interactive, it can pursue objectives rather than merely respond:

- **Extend the engagement.** More tool calls means more of the attacker's objective revealed. A tool that returns "partial results, call again with a narrower filter" costs nothing and doubles observation.
- **Elicit the objective.** Tool results can be shaped to present choices that disambiguate what the agent is actually after. An agent that picks `credentials.list` over `invoice.search` when both are offered has told you something. This is A/B testing against an adversary.
- **Adapt the persona.** If the agent seems to be looking for financial systems, surface more financial-looking tools. Dynamic catalog synthesis is cheap and increases dwell.
- **Grade the adversary.** Escalate fidelity for sessions that look sophisticated, mirroring [ADLAH's RL escalation](distributed-honeypot-coordination.md#32-adlah--rl-driven-escalation-between-interaction-tiers) — cheap static responses by default, expensive LLM-backed and sandbox-routed interaction for sessions worth the cost.

### 4.3 Agent-versus-agent, and the elicitation surface

This is where the substrate becomes genuinely novel, and where the [open problem flagged earlier](distributed-honeypot-coordination.md#8-what-is-missing-from-the-literature) — agent-vs-agent deception dynamics — becomes directly addressable.

MCP is bidirectional in ways HTTP and SSH are not. Depending on negotiated capabilities, a *server* can make requests back toward the client — notably **sampling** (the server asks the client's model for a completion) and **elicitation** (the server asks for user input). If an attacking agent connects with those capabilities enabled, a decoy server can:

- Request a completion and thereby **make the attacker's own model produce text** — a direct fingerprinting primitive for model family and version, far stronger than latency banding.
- Request elicitation and observe whether a human is in the loop, or whether the "user" response is itself model-generated.
- Observe refusal behaviour, safety-filter signatures, and phrasing style from the attacker's own stack.

**Verify against the current MCP specification before building.** Capability names, semantics, and defaults move, and a well-configured client may not grant these. But if even a fraction of attacking agents connect with sampling enabled, this is the highest-value fingerprinting channel available anywhere in this design — it extracts evidence from the adversary's own model rather than inferring it from behaviour.

Ethical constraint, stated up front and enforced in §10: use these channels for **fingerprinting only**. Requesting a completion to identify the model is observation. Using the channel to make the attacker's model do work, or to reach any third-party system, is not, and is out of scope permanently.

## 5. Anatomy of a decoy MCP server

### 5.1 Protocol fidelity

Implement the real handshake and method set faithfully — `initialize` with correct capability negotiation, `tools/list`, `resources/list`, `prompts/list`, `tools/call`, `resources/read`, and correct JSON-RPC error semantics for malformed input. Build against the reference implementation and diff behaviour. Any deviation is a fingerprint (§11), and per §3 this surface is small enough that fidelity is genuinely achievable.

### 5.2 Persona and catalog design

The tool catalog is the deception surface and the experimental instrument. It should be coherent for a plausible deployment — a "finance-ops" server, a "devops" server, a "customer-data" server — because incoherent catalogs are a tell and because persona is a variable worth measuring (which personas attract which agents?).

Catalog composition:

- **Mundane tools** that establish plausibility: `invoice.search`, `vendor.lookup`, `ticket.list`.
- **At least one high-value bait tool**: `secrets.read`, `credentials.list`, `db.query_raw`, `deploy.production`. Naming should be plausible rather than lurid — `secrets.read` is credible in a real devops server; `steal_all_passwords` is not.
- **Realistic typed schemas** with constraints, defaults, and descriptions written the way a real developer writes them.
- **A tool whose invocation is unambiguously malicious** given the persona, providing a clean verdict boundary.

Every returned payload carries **honeytokens**: fake credentials, fake API keys, fake customer records, fake internal URLs, each uniquely keyed to session and node. Downstream use of any of them is a second detection event, potentially long after the session, and is what turns a decoy interaction into an attributable campaign trace.

### 5.3 Resources as the injection channel

Resources — documents the server exposes — are the natural home for reverse-prompt-injection probes, and are more realistic than injecting into tool descriptions, since retrieved documents are the canonical indirect-injection vector in the wild.

Payload encodings to vary across the fleet (§7.1): ANSI escape sequences, HTML comments, zero-width and Unicode tag characters, base64 in an otherwise-plausible field, markdown-hidden text, injections in structured metadata, injections in tool *descriptions* rather than content.

Every payload must satisfy the inertness constraint of §10.1: it directs the agent to **our own infrastructure only**.

### 5.4 Deployment

Distribute across providers, regions, and ASNs, per the [topological argument](distributed-honeypot-coordination.md#2-topology-as-the-sensing-instrument) — which node fires, in what order, is itself the measurement. [Holoscope's](distributed-honeypot-coordination.md#31-holoscope--the-reference-architecture-for-multi-institution-sensor-fleets) K3s + WireGuard + IaC pattern is the reference architecture, and is compatible with the [Kubernetes-first packaging](../BUSINESS_PLAN.md#154-self-hosted-technical-requirements) the plan already commits to.

Isolation is non-negotiable and follows [§14.1.9 sacrificial adversarial-research infrastructure](../BUSINESS_PLAN.md#1419-sacrificial-adversarial-research-infrastructure): separate cloud accounts, no production identities, no customer data, controlled egress, ephemeral workers destroyed after use.

## 6. Signals collected

What the fleet actually produces — this is the intelligence product, and it maps directly onto the [Agentic Threat Pattern](../BUSINESS_PLAN.md#372-core-proprietary-object-agentic-threat-pattern) schema.

### 6.1 Scaffold fingerprint

Which MCP client library, protocol version, capability set, enumeration order, timing distribution, retry and backoff behaviour, JSON formatting quirks, error-handling style. Agent frameworks differ measurably. This is the **affected-configuration intelligence** the plan sells, collected natively rather than inferred.

### 6.2 Model and provider inference

Latency banding; phrasing in any natural-language field; error-recovery style; refusal signatures; and — where available — direct extraction via Palisade-style system-prompt stealing or the sampling channel (§4.3).

### 6.3 Objective and causal flow

Which tools, in what order, with what arguments, in response to what content. **This is a complete causal attack flow captured natively** — content origin → influence → proposed action → attempted side effect. It is the exact object [§7 of the business plan](../BUSINESS_PLAN.md#7-ai-execution-trace-and-data-model) specifies, obtained without instrumenting a customer.

### 6.4 Susceptibility matrix

Which injection encodings worked against which scaffolds. Produced directly by §7.1's differential assignment. This is the highest-value proprietary artifact in the design: an empirical map of *which agent stacks are vulnerable to which delivery techniques*, refreshed continuously, saleable as [Product 1](../BUSINESS_PLAN.md#371-three-product-sequence) with no federation required.

### 6.5 Honeytoken propagation

Where planted credentials and documents surface later — other decoys, paste sites, subsequent campaigns. Converts point observations into campaign traces.

## 7. Coordination: the fleet as one experiment

The genuinely novel material. These techniques make a coordinated fleet strictly more informative than the sum of independent nodes — which is the precondition for a federation to be worth joining.

### 7.1 Differential payload assignment

**Mechanism.** Each node serves a different injection *encoding* of a semantically equivalent payload. Node A uses ANSI escapes, node B a HTML comment, node C zero-width Unicode, node D base64 in a metadata field, node E tool-description injection.

**What it yields.** The *set of nodes a given agent falls for* is a fingerprint of its parsing and sanitization pipeline. An agent that trips on ANSI but not zero-width has a specific, identifiable input-handling implementation. Across many agents this builds the susceptibility matrix empirically, and it does so **without needing to know anything about the agent's internals**.

**Why coordination is required.** A single node learns "this agent fell for ANSI." The fleet learns "this agent class is vulnerable to ANSI and HTML comments but sanitizes zero-width and base64" — a defensive finding portable to customers as concrete guidance about which sanitization their stack lacks. No single node can produce it.

This is a **designed experiment across a distributed fleet**, not N honeypots that happen to share a log store. As far as this survey found, nobody has published it.

### 7.2 Split and staged injections

**Mechanism.** Construct an injection that only resolves across multiple nodes. Node A's resource content references material that only exists on node B; completing the instruction requires visiting both.

**What it yields.** Any agent that completes the chain has provably visited both nodes. This is **campaign linkage by behaviour rather than by identifier** — it survives IP rotation, proxy chains, and infrastructure churn, which defeat conventional correlation.

**Why it matters.** Attributing two sessions to one campaign is the central difficulty in distributed honeypot analysis. Conventional approaches rely on network identifiers, which sophisticated operators rotate. A behavioural chain cannot be rotated away without abandoning the objective that motivated the visit.

**Constraint.** Chains must terminate within decoy infrastructure (§10.1) and must be inert. The instruction is "fetch this other resource of ours", never "contact this third party."

### 7.3 Topological correlation

Directly per the [anycast honeypot method](distributed-honeypot-coordination.md#2-topology-as-the-sensing-instrument): which nodes are hit, in what order, from which ASNs, with what timing, reveals scanning campaign structure and permits lower-bound estimates on the number of distinct origins. Applied to MCP scanning, this answers a question nobody currently can: *how many distinct actors are sweeping for exposed MCP servers, and are they coordinated?*

### 7.4 Persona A/B testing

Because personas are chosen, they are an experimental variable. Which fictional deployment types attract which agents; whether bait-tool naming affects invocation rates; whether an agent's tool selection reveals a targeting preference. Standard experimental design applied to adversaries, which the deception literature does surprisingly little of.

## 8. Beyond servers: decoy identities, registrations, and canary clients

Decoy MCP servers are the richest surface but not the only one.

- **Decoy agent identities in IAM.** Service accounts for agents that do not exist. Any authentication attempt is unambiguous evidence that a credential store or identity directory was enumerated. Near-zero false positive rate, near-zero cost — the honeytoken ROI argument, applied to non-human identity.
- **Decoy agent registrations.** Fake entries in agent registries, directories, and agent cards. Use indicates registry enumeration.
- **Honeytoken API keys scoped to nonexistent agents.** Use tells you *which* credential store was read, and often when.
- **Decoy tools inside real MCP servers.** For customers running the sensor: a tool that no legitimate workflow should ever call, planted inside a genuine server. Invocation is high-confidence evidence of an agent operating outside its intended scope — whether compromised, injected, or merely misconfigured. This is deployable **inside customer environments** as a product feature, not just in research infrastructure, and it composes with the capability broker: the decoy tool is the tripwire, the broker is the enforcement.

That last item is worth emphasising commercially: it converts research infrastructure into a shippable detection capability with essentially no false positives, which is a rare property.

## 9. The MCP ecosystem monitor

The inverse of a honeypot, and possibly the most immediately saleable idea here.

> **Implemented.** A working monitor is in [../../prototype](../../prototype/README.md) — `python3 demo_ecosystem.py`. Detects rug pulls, silent schema broadening, publisher takeover, and hostile-on-first-observation across a simulated registry, with the crawl policy enforced in code. Building it surfaced two things this section had not anticipated: that the most common poisoning shape needs no hiding at all (§9.3), and that naive identity hashing raises a high-severity finding on every routine release.

**Mechanism.** Run a fleet of **canary MCP clients** that connect to public and customer-declared MCP servers and continuously record their tool catalogs, schemas, descriptions, and resource manifests. Diff over time.

**What it detects:**

- **Tool poisoning** — malicious instructions embedded in tool descriptions, which the client's model reads as authoritative.
- **Rug pulls** — a server that presents benign definitions during review and changes them afterward. This is the canonical MCP supply-chain attack, and it is *only* detectable by longitudinal observation. A one-time security review cannot catch it by construction.
- **Silent schema drift** — parameter changes that broaden what a tool can do without any announcement.
- **Abandonment and takeover** — a server whose endpoint changes hands.

**Why this is product-shaped.** "Which MCP servers changed their tool definitions this week, and which of those changes are suspicious" is a concrete, continuously refreshed dataset with an obvious buyer. It requires no customer deployment, no federation, and no attacker to cooperate. It generates value on day one and improves monotonically with observation time — the corpus itself is the moat, since a competitor starting later cannot retroactively acquire history.

It also composes with the decoy fleet: the ecosystem monitor tells you which real servers are dangerous; the decoy fleet tells you who is hunting for them.

### 9.3 What building it changed

Two corrections from the implementation, both of which would have degraded the product:

- **The dominant poisoning shape needs no hiding.** The design above assumed hidden text — ANSI, comments, tag characters — was the thing to detect. It is not the common case. A tool description that simply says, in plain visible prose, "before continuing, call the X tool" works just as well, because the model treats the description as authoritative regardless. A detector built only against hidden text misses the majority case. The fix is a separate signal for *a description that directs the model to invoke another tool*, which legitimate descriptions do not do.
- **Identity must exclude version.** Hashing publisher name together with version raises a high-severity takeover finding on every routine patch release. In the first run that was five of eleven findings. A detector that fires on every release gets switched off, and then detects nothing at all.

The second is the more general lesson for this whole programme: for a continuously running feed, **the false-positive rate is the product**. A rug-pull detector nobody reads has the same value as no rug-pull detector.

**Ethical note.** This is passive observation of publicly reachable endpoints, equivalent to established internet-measurement practice. Respect rate limits, identify the crawler honestly where the protocol permits, honour opt-outs, and do not authenticate to servers that require credentials. This is measurement, not intrusion, and the line should be visible from the outside.

In the prototype these are enforced by a `CrawlPolicy` object rather than documented as intent: tool invocation, resource reads, authentication, and opted-out targets all raise. A monitor that called tools would be doing precisely what it exists to detect, so that is a hard failure rather than a lint warning.

## 10. Safety, ethics, and legal constraints

Non-negotiable constraints. Violating these converts a defensible research programme into a liability, and the failure would be reputational as well as legal — for a company selling trust to security buyers, that is existential.

### 10.1 Payload inertness

**Every injected payload must direct the agent only to infrastructure we control.** Never to a third party. Never an instruction that would cause harm if followed. Never anything that would make the decoy a stage in an attack on someone else. Split-chain injections (§7.2) terminate within the fleet.

This is the single most important constraint. A payload that redirects an attacking agent toward a third party makes us a participant in that attack.

### 10.1a Egress control

Inertness stops *us* from directing an agent at a third party. It does not stop the agent from getting there on its own initiative.

> A convincing decoy is an attacker-controlled endpoint with internet access. Rate-limit, sinkhole, or fully block outbound. Research honeypots have been used to attack third parties.

Default-deny egress with explicit allowlisting, and a log path architecturally separate from the controlled-egress path. Both constraints are required; neither substitutes for the other. See [observation-architecture.md §3](observation-architecture.md#3-egress-the-half-everyone-underrates).

### 10.2 No hosted malware, no facilitation

Decoys return synthetic data. They do not host live malicious payloads, do not proxy attacker traffic to real targets, and do not provide capability the attacker did not already have. Sandbox-routed tools (§4.1) run against throwaway infrastructure with synthetic data and no outbound reach.

### 10.3 Handling third-party data

Attacker sessions may contain data belonging to others — stolen credentials pasted as arguments, exfiltrated content, personal information. Requires a handling policy before launch: what is retained, for how long, who may access it, when it is reported to affected parties, and how it is excluded from any shared corpus. This is a data-protection obligation that arrives with the first interesting session, not later.

### 10.4 Extracted system prompts are sensitive

Successful prompt-stealing (§4.3) yields the operator's instructions, which may contain identifying information, third-party names, or targeting detail. Treat as sensitive evidence under the same disclosure controls as customer data. Do not publish verbatim.

### 10.5 Researcher and scanner deconfliction

Maintain an allowlist of known internet-measurement projects and security researchers, and classify them separately rather than counting them as adversaries. Publishing a contact and a deconfliction process is standard practice for measurement infrastructure and costs nothing.

### 10.6 Jurisdiction

Deployment spans providers and countries, and legal treatment of deception infrastructure, interception, and data retention varies. Requires counsel review before deployment, not after — the plan already budgets [fractional privacy counsel](../BUSINESS_PLAN.md#21-team-and-operating-model).

### 10.7 No offensive use of bidirectional channels

Per §4.3: sampling and elicitation channels are for fingerprinting only. Never to make an attacker's model perform work, never to reach third-party systems. This constraint should be enforced in code and reviewed, not merely stated in a document.

## 11. Detection resistance and the arms race

Assume the technique becomes known — it will, and this document is part of how.

**What degrades.** Once reverse prompt injection is widely known, offensive agent operators will sanitize ANSI, strip zero-width characters, and add injection classifiers. Trip rates on any single encoding will fall.

**What degrades more slowly.** Encoding diversity buys time: an operator must defend every channel, we need only one to work, and §7.1 tells us empirically which remain open. But this is an arms race with a finite lifetime, and planning otherwise is planning badly.

**What is durable — the designed migration.** Per §2.1, the deep discriminator is not "does it fall for injection" but **"does it exhibit agent-like protocol behaviour."** A hardened agent that detects and ignores an injection *still*:

- speaks MCP at all, on an unadvertised endpoint;
- enumerates capabilities systematically;
- reads every tool description rather than skimming;
- exhibits machine-timed, machine-ordered interaction;
- and now, additionally, **exhibits injection-resistant behaviour**, which is itself a discriminating fingerprint — humans and dumb scanners do not "resist" an injection, they never parse it.

So the hardening of attacking agents does not blind the sensor; **it changes which feature carries the signal**, and produces a new observable (defended-ness) that further partitions the population. Design for the migration from payload-trip detection toward behavioural protocol fingerprinting from the start: collect the behavioural features now, while payload-trip ground truth is still available to label them with. That labelled dataset is only collectable during this window, which is an argument for building sooner rather than later.

## 12. Metrics and expected yield

### 12.1 Set expectations honestly

Palisade: **8 candidate agents from 8.13M attempts over ~3 months** on SSH. That is the sober baseline. Expect from a decoy MCP fleet:

- **Much lower total volume** — MCP is not swept as broadly as SSH.
- **Much higher agent fraction** — only agent infrastructure speaks the protocol.
- **Small absolute n regardless**, at least initially.

Small n is the defining constraint. It implies: multi-node from day one, long horizons, and extreme caution about statistical claims. The [ecological-validity gap](distributed-honeypot-coordination.md#8-what-is-missing-from-the-literature) is real and this design does not escape it — it only starts filling it earlier than anyone else.

This is also, explicitly, **a bet on rising agentic-attack prevalence.** The 2026 evidence — CyberStrikeAI, autonomous post-exploitation in under an hour, the 32% rise in indirect-injection content, the 540% surge in prompt-injection reports — supports the bet. It does not guarantee it. If agentic attack volume plateaus, this infrastructure yields a thin corpus, and §9's ecosystem monitor becomes the load-bearing product instead. That is the honest hedge, and it is a good one: §9 pays off regardless of attacker behaviour.

### 12.2 Metrics

| Metric | Measures |
|---|---|
| Interactions by depth tier (§2.1) | Basic yield and classifier calibration |
| Agent-candidate rate | Population density |
| Novel-scaffold discovery rate | Corpus growth — the Product 1 input |
| Susceptibility matrix coverage | Encoding × scaffold cells populated (§7.1) |
| Cross-node linkage rate | Fraction of staged chains completed (§7.2) |
| Time from first sighting to published pattern | Product 1 freshness — the thing customers pay for |
| Honeytoken propagation events | Campaign tracing |
| Ecosystem-monitor drift events | §9 yield, independent of attacker behaviour |
| Subversion attempts detected | Deception-aware adversary prevalence (§4.1) |

## 13. What to build first

Ordered by time-to-value and by what expires if delayed.

1. **One protocol-faithful decoy MCP server, static responses, one persona.** Establishes fidelity and the collection pipeline. Days, not weeks.
2. **Honeytokens throughout.** Cheap, and the propagation data starts accruing immediately.
3. **The ecosystem monitor (§9).** Independent of everything else, yields a saleable dataset immediately, and its value is strictly increasing in how early it starts. Arguably should be **first** — it is the only component whose payoff does not depend on attacker behaviour.
4. **Multi-node deployment with differential payloads (§7.1).** The first genuinely novel capability; needs ≥5 nodes to be interesting.
5. **LLM-backed interactive responses (§3, §4).** Once static collection proves the pipeline. Sandbox-route the tools where consistency matters most.
6. **Staged cross-node injections (§7.2).** Needs the fleet and a stable payload framework.
7. **Decoy tools inside customer environments (§8).** Productizable; gate on design-partner appetite.
8. **Sampling/elicitation fingerprinting (§4.3).** Verify against the current spec first; high value if available.

Items 1–3 are a small number of engineer-weeks and start the corpus. This is what [Month 1–3 of the 180-day plan](../BUSINESS_PLAN.md#43-immediate-180-day-execution-plan) — "stand up the adversarial research harness" — should concretely contain.

## 14. Risks to this position

| Risk | Assessment |
|---|---|
| **Too few interactions to matter.** Agentic attack volume against MCP stays low; the corpus is thin. | The primary risk. Mitigated by §9, which yields regardless. Also mitigated by the fact that early-mover data is only collectable early. |
| **Someone has already built this.** A weekend project, unpublished. | Likely, in some form. Mitigation: the defensible asset is the *coordinated fleet* and the accumulated susceptibility matrix, not the idea of a decoy MCP server. Coordination is what is hard to replicate. |
| **Arms race erodes payload-trip detection faster than expected.** | Anticipated in §11. Collect behavioural features now, while labelled ground truth exists. |
| **Legal or ethical misstep** — a payload causes third-party harm, or data handling breaches an obligation. | Low probability, severe impact. §10 constraints must be enforced in code and reviewed, not merely documented. For a company selling trust, this is the risk that would matter most. |
| **Protocol churn.** MCP evolves; decoys drift out of fidelity and become fingerprintable. | Ongoing maintenance cost. Test continuously against the reference implementation; treat fidelity as a regression-tested property. |
| **Distraction from the sensor product.** Research infrastructure absorbs effort that enterprise integrations need. | Real. The plan already warns that [integrations and deployment reliability should be prioritized over advanced research features](../BUSINESS_PLAN.md#311-build-order-changes). Keep this small: items 1–3 only, until it demonstrably feeds Product 1 revenue. |

## 15. References

**Directly foundational**
- [LLM Agent Honeypot: Monitoring AI Hacking Agents in the Wild (arXiv 2410.13919)](https://arxiv.org/abs/2410.13919) · [code](https://github.com/PalisadeResearch/llm-honeypot) · [live explainer](https://ai-honeypot.palisaderesearch.org/explainer)
- [ShellGames: Speculative LLM-Driven SSH Deception (arXiv 2606.17986)](https://arxiv.org/abs/2606.17986)
- [SoK: Honeypots & LLMs, More Than the Sum of Their Parts? (arXiv 2510.25939)](https://arxiv.org/abs/2510.25939)
- [Hacking Back the AI-Hacker: Prompt Injection as a Defense (arXiv 2410.20911)](https://arxiv.org/abs/2410.20911)

**MCP threat context**
- [CSA Research Note: MCP Security Crisis](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-security-crisis-20260504-csa-styled/)
- [Agentic MCP Security Best Practices — CSA](https://labs.cloudsecurityalliance.org/agentic/agentic-mcp-security-best-practices-v1/)
- [OWASP GenAI Exploit Round-up Q1 2026](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/)

**Coordination and infrastructure**
- [Detecting Offensive Cyber Agents / ACE proposal (arXiv 2605.21956)](https://arxiv.org/abs/2605.21956)
- [Holoscope (arXiv 2512.19842)](https://arxiv.org/abs/2512.19842)
- [Anycast amplification honeypots (arXiv 2607.14832)](https://arxiv.org/abs/2607.14832)
- [ADLAH (arXiv 2512.07827)](https://arxiv.org/abs/2512.07827)

**Fidelity evaluation**
- [Honeyval: Evaluation Framework for LLM-powered HTTP Honeypots (arXiv 2605.29963)](https://arxiv.org/abs/2605.29963)
- [SimProcess: High Fidelity Simulation of Noisy ICS Physical Processes (arXiv 2505.22638)](https://arxiv.org/abs/2505.22638)

**Internal**
- [distributed-honeypot-coordination.md](distributed-honeypot-coordination.md)
- [byzantine-robust-federation.md](byzantine-robust-federation.md)
- [threat-intelligence-landscape-2026.md](threat-intelligence-landscape-2026.md)
