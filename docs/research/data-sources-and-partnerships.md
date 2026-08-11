# Data sources and B2B relationships

**Status:** strategy note.
**Date:** August 2026.
**Relates to:** [§37.1 Three-product sequence](../BUSINESS_PLAN.md#371-three-product-sequence), [§16 Product surfaces and integrations](../BUSINESS_PLAN.md#16-product-surfaces-and-integrations), [§11 AI supply-chain and release security](../BUSINESS_PLAN.md#11-ai-supply-chain-and-release-security), [§26 Competitive landscape](../BUSINESS_PLAN.md#26-competitive-landscape-and-positioning).

What BiTorus needs to ingest, and who it needs a relationship with, to make [Product 1](../BUSINESS_PLAN.md#371-three-product-sequence) real before any federation exists.

## Table of contents

- [1. The organising principle](#1-the-organising-principle)
- [2. Tier 0: free, public, and clock-limited — start now](#2-tier-0-free-public-and-clock-limited--start-now)
- [3. GitHub, in detail](#3-github-in-detail)
- [4. Model providers: hardest to get, most valuable](#4-model-providers-hardest-to-get-most-valuable)
- [5. The MCP and agent-framework ecosystem](#5-the-mcp-and-agent-framework-ecosystem)
- [6. Noise separation: the unglamorous dependency](#6-noise-separation-the-unglamorous-dependency)
- [7. Standards and community: credibility as distribution](#7-standards-and-community-credibility-as-distribution)
- [8. Enterprise distribution and mitigation targets](#8-enterprise-distribution-and-mitigation-targets)
- [9. The reciprocity trap](#9-the-reciprocity-trap)
- [10. Sequencing](#10-sequencing)

---

## 1. The organising principle

Not every feed is worth having. A source earns its place if it does one of four things:

| Function | Why it matters | Example |
|---|---|---|
| **Numerator** | Tells you an attack happened | Decoy fleet, customer sensors, provider abuse signals |
| **Denominator** | Tells you how many were exposed | Package registries, framework adoption, [coverage assertions](byzantine-robust-federation.md#8-negative-observations-and-the-numerator-only-problem) |
| **Configuration** | Tells you *what* is affected | Model version streams, MCP registries, AI-BOM inputs |
| **Noise floor** | Tells you what to ignore | Scanner classification, proxy/VPN attribution |

Most CTI programmes over-invest in numerators, because hits feel like intelligence. The susceptibility matrix and every population-risk claim the [Collective Defense product](../BUSINESS_PLAN.md#381-subscription-architecture) makes depend on the other three. **Denominators are the scarce input, and they are mostly free.**

## 2. Tier 0: free, public, and clock-limited — start now

The same argument that applies to the ecosystem monitor applies to the whole corpus: **collection is clock-limited, not engineering-limited.** Partnerships take months to negotiate. Public collection can start this week, and the history you are not accumulating is the history you cannot retroactively acquire.

Sources needing no relationship whatsoever:

| Source | Yields |
|---|---|
| **GH Archive / GitHub Events** | Repo and release history for open-source MCP servers and frameworks — see §3 |
| **MCP registries and directories** | The target list for the ecosystem monitor; new-server appearance rate |
| **Hugging Face API** | Model, adapter, tokenizer, and dataset provenance; the AI-BOM substrate |
| **npm / PyPI / crates** | Framework and MCP-server adoption counts — the denominators |
| **GHSA / Dependabot advisory DB / OSV** | Vulnerability intelligence keyed to the packages above |
| **MITRE ATT&CK, ATLAS, Attack Flow** | The ontologies the assertions map onto |
| **CISA KEV, FIRST EPSS** | Exploitation context for the conventional half |
| **Model provider changelogs and deprecation notices** | Version binding, which assertions expire against |

This set alone supports a credible first intelligence feed. None of it requires anyone's permission, and the corpus compounds from the day it starts.

## 3. GitHub, in detail

Several genuinely distinct streams, not one relationship. Ordered by value to us.

### 3.1 The retroactive rug-pull dataset

**The most actionable item in this document.**

The ecosystem monitor's constraint is that a rug pull needs a clean baseline and a later change, so it cannot see backwards. That is true for *closed* servers. It is not true for open-source ones:

> **The git history of every open-source MCP server is a rug-pull dataset that already exists.** Tool definitions live in source. `git log` over a tool schema or description is exactly the longitudinal diff the monitor produces — available today, retroactively, for the whole open-source population.

This partially dissolves the clock-limited problem. You can mine a susceptibility and tool-drift corpus *now* rather than waiting weeks for live observation, and use it to calibrate the detectors before they ever point at a live server — which directly addresses the biggest gap in the prototype, that the detectors are uncalibrated against a real corpus.

Concretely: clone the open-source MCP server population, walk each commit touching tool definitions, run `ecosystem/detectors.py` and `ecosystem/diff.py` over consecutive versions. Every finding is a labelled example. Every clean transition is a negative example — and negatives are what let you measure a false-positive rate, which per the identity-hashing bug is the number that decides whether anyone reads the feed.

It also gives something the live crawler never can: **attribution**. A poisoned tool description in git has an author, a commit, and a timestamp.

### 3.2 Secret scanning partner program

GitHub operates a programme where a vendor registers a token pattern and receives notification when a matching token appears in a public repository.

For the honeytoken design this is close to ideal. Every decoy interaction emits credentials uniquely keyed to session and node. Registering that pattern turns GitHub into a **propagation sensor**: when an attacker pastes a captured honeytoken into a public repo, gist, or CI config, you learn it — with attribution, and potentially long after the original session.

Low cost, high leverage, and it directly upgrades the [honeytoken propagation signal](decoy-agent-infrastructure.md#65-honeytoken-propagation) from "sometimes we notice" to a real channel. Requires application; worth starting early because it is a partnership with a queue.

### 3.3 GH Archive and the Events API

The public event firehose — pushes, releases, repo creation, issues — available as hourly dumps and via BigQuery. Uses:

- **Ecosystem census.** Rate of new MCP servers, framework releases, adoption curves. Denominators.
- **Release tracking.** Assertions bind to exact versions; this is how you know a version changed.
- **Agent-authored activity at population scale.** Commit trailers, bot accounts, and characteristic patterns give a measurable baseline for how much development is now agent-driven — context nobody currently quantifies well.

### 3.4 Advisories and code search

- **GHSA + Dependabot DB + OSV** — free, structured vulnerability data keyed to the same packages you are already counting.
- **Code search API** — exposed `mcp.json` and client config files, hardcoded credentials in agent configurations, MCP servers committed with secrets. Rate-limited, and worth treating carefully: finding someone's leaked key creates a disclosure obligation, not a data point. Have the disclosure process before you run the query.

### 3.5 GitHub as distribution

A GitHub App is both a distribution channel and, if customers install it, a first-party telemetry source for the coding-agent workflow that [§30](../BUSINESS_PLAN.md#30-go-to-market-plan) names as a landing wedge. Worth designing for, not building yet.

## 4. Model providers: hardest to get, most valuable

Four distinct things, in ascending order of difficulty:

1. **API access at research scale.** The adversarial lab cannot run without it. Ordinary commercial terms mostly suffice; budget for it as research infrastructure, not overhead.
2. **Version and deprecation streams.** Assertions bind to exact model versions, and [the plan's own risk register](../BUSINESS_PLAN.md#23-risk-register) names silent provider behaviour change as a live risk. Mostly public, but a direct channel gets you advance notice rather than post-hoc surprise.
3. **Coordinated disclosure.** When the lab finds a model-specific agentic vulnerability, there needs to be somewhere to send it. Establishing this *before* you need it is much easier than during an incident.
4. **Trust-and-safety / abuse exchange.** Providers see offensive agent traffic at its origin. This is the highest-value signal in the entire space and the hardest to obtain.

That fourth item is exactly what the [ACE proposal](observation-architecture.md) would institutionalise — an exchange bringing model and cloud providers together to disrupt offensive agents at their origin point. **Being an established participant before that becomes a formal body is a real strategic position**, and the cost of starting now is a few conversations. If it does formalise, the alternative is applying to join something already shaped by others.

## 5. The MCP and agent-framework ecosystem

**Registries and directories** are the operational input to the monitor — they *are* the target list. Prefer servers that advertised themselves in a public registry over unlisted endpoints found by scanning: a listed server invited discovery, and that distinction is both legally and reputationally material.

**Framework maintainers** — the agent frameworks, MCP server authors, and gateway projects — matter three ways:

- **Version streams** so the susceptibility matrix tracks releases rather than snapshots.
- **Coordinated vulnerability disclosure.** The research lab will find framework-level issues. A CVD relationship converts a potentially adversarial interaction into a credibility-building one.
- **Distribution.** A framework that ships your detection, or adopts your schema, is worth more than a signed customer.

**Spec maintainers** — MCP moves, and the prototype's transport is explicitly flagged as needing verification against the current spec. A channel for spec-change notification is cheap and prevents the monitor from silently mis-reading servers.

## 6. Noise separation: the unglamorous dependency

Underrated, and load-bearing for the decoy fleet.

Every internet-exposed decoy is swept continuously by benign scanners, academic measurement projects, and misconfigured clients. The [depth gradient](decoy-agent-infrastructure.md#21-signal-to-noise) handles most of this, but at small *n* — and *n* will be small — a handful of misclassified scanner sessions materially distorts the population claims.

What helps:

- **Internet background-noise classification** (GreyNoise and equivalents) to separate mass scanning from targeted activity.
- **Proxy, VPN, and hosting-provider attribution** (Spur, IPinfo, and similar) — an agent behind a residential proxy looks different from one on cloud infrastructure, and it changes what a sighting means.
- **Known-researcher allowlists**, which per [§10.5](decoy-agent-infrastructure.md#105-researcher-and-scanner-deconfliction) should be maintained anyway.

None of this is glamorous. All of it directly determines whether the agent-candidate rate is a real number.

## 7. Standards and community: credibility as distribution

For a company whose product is *trust in intelligence*, standards participation is not marketing — it is how the intelligence becomes actionable in someone else's system.

- **MITRE ATLAS** — contributing techniques is the clearest signal that the research is real, and it makes assertions portable by construction.
- **MITRE Center for Threat-Informed Defense** — Attack Flow is the format the causal graph should speak.
- **OWASP GenAI Security Project** — the Top 10 for Agentic AI is the document practitioners actually start from. Participation is cheap and the distribution is substantial.
- **Cloud Security Alliance** — already publishing the MCP security work this research builds on.
- **Sigma, STIX/TAXII, OpenC2/CACAO** — the formats the [portable mitigation compiler](../BUSINESS_PLAN.md#262-defensible-differentiation) must emit. Compiler correctness is a standards-conformance problem.
- **FIRST** — coordinated disclosure norms, and EPSS.
- **Academic groups** publishing the honeypot and agent-security work. Co-authorship is inexpensive credibility and a recruiting channel into a very thin talent pool.

## 8. Enterprise distribution and mitigation targets

Later-stage, but they shape the schema now, because a mitigation compiler that cannot emit a partner's format is not portable.

- **Enforcement and runtime vendors** — the MIT-licensed runtime governance layer, OPA/Cedar, MCP gateways, and the AI-security platforms. Per [§26](../BUSINESS_PLAN.md#26-competitive-landscape-and-positioning) these are sensors and mitigation targets, not competitors.
- **SIEM/SOAR** — Splunk, Elastic, Sentinel, Chronicle, Panther; Tines, Torq, XSOAR. Detection-content distribution.
- **Identity and NHI platforms** — agent identity is the highest-leverage control per the [practitioner cut](threat-intelligence-landscape-2026.md#23-identity-and-access--the-highest-leverage-control), and NHI vendors are the natural integration point.
- **ISACs** (FS-ISAC, H-ISAC, IT-ISAC) — pre-assembled federation members with existing sharing norms and trust structures. The fastest path to [Product 3](../BUSINESS_PLAN.md#371-three-product-sequence) is probably a sector federation rather than a general one.
- **Cloud marketplaces** — an enterprise procurement path more than a channel.
- **Government** — CISA/JCDC for the [§41.1](../BUSINESS_PLAN.md#411-government-and-national-security-market) market.

## 9. The reciprocity trap

Worth stating plainly, because it is where a data-partnership strategy quietly breaks the product's core promise.

**Most intelligence relationships are reciprocal.** You receive because you contribute. That means every partnership is a potential egress path for customer data — and a partnership agreement is exactly the kind of thing that gets negotiated by people who are not thinking about minimization.

The discipline that applies to the federation applies identically here:

- Share **minimized assertions**, never raw traces, prompts, or customer documents — the same default as [§12](../BUSINESS_PLAN.md#12-privacy-preserving-federation).
- Every outbound sharing arrangement gets a **data classification** and a **named approver**, and appears in the same audit trail as federation disclosures.
- Contributions to a partner carry the same **provenance and lineage** fields as federation assertions. Otherwise intelligence you gave a partner returns to you via a third party and gets counted as independent corroboration — [circular reporting](byzantine-robust-federation.md#5-circular-reporting-as-a-first-class-hazard) across organisational boundaries, which is harder to see and just as corrosive.
- The [§3.2 non-goal](../BUSINESS_PLAN.md#32-explicit-non-goals) — no central collection of raw prompts or customer documents by default — binds partnerships too, not just the product.

A customer will forgive a missed detection. They will not forgive discovering their prompts reached a partner through a sharing agreement they never saw.

## 10. Sequencing

| When | Do | Why |
|---|---|---|
| **Now** | Tier 0 public collection; mine open-source MCP git history (§3.1) | Clock-limited. The retroactive corpus also calibrates the detectors, which is the prototype's biggest gap |
| **Now** | Apply to GitHub secret scanning partner program (§3.2) | Long queue, low cost, upgrades honeytoken propagation to a real channel |
| **Weeks** | Noise-separation feeds (§6) | Decoy population claims are not credible without them |
| **Weeks** | MCP registries as monitor targets; framework version streams | Operational input to what is already built |
| **Months** | Model provider CVD and abuse channels (§4) | Slow to establish, highest value, and better started before any exchange formalises |
| **Months** | ATLAS / OWASP / CTID contribution (§7) | Credibility compounds and cannot be bought later |
| **Product 2+** | Enforcement, SIEM, NHI, ISAC, marketplace (§8) | Shape the schema now, build when a customer asks |

The two things to start this week are the retroactive git-history corpus and the secret-scanning application. Both are cheap, both are gated on elapsed time rather than effort, and neither needs anyone's agreement.
