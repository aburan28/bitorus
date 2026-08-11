# Byzantine-robust deception federation

**Status:** research position / design note. Not implemented.
**Date:** August 2026.
**Relates to:** [§12 Privacy-preserving federation](../BUSINESS_PLAN.md#12-privacy-preserving-federation), [§14.1.7 Federation poisoning and false-intelligence resistance](../BUSINESS_PLAN.md#1417-federation-poisoning-and-false-intelligence-resistance), [§14.1.13 Security acceptance tests](../BUSINESS_PLAN.md#14113-security-acceptance-tests), [ADR-AI-011](../BUSINESS_PLAN.md#24-architecture-decisions).

The thesis: BiTorus's federation plane must assume some participants are hostile. The academic literature has solved a *neighbouring* problem (Byzantine-robust federated learning over gradients) and has essentially not touched this one (robust corroboration over signed observations). That gap is defensible ground, and the plan already gestures at the right answer. This note makes the position precise enough to build and to publish.

## Table of contents

- [1. Scoping the novelty claim honestly](#1-scoping-the-novelty-claim-honestly)
- [2. Why gradient-space defenses do not transfer](#2-why-gradient-space-defenses-do-not-transfer)
- [3. Adversary taxonomy](#3-adversary-taxonomy)
- [4. Core mechanism: effective corroboration](#4-core-mechanism-effective-corroboration)
- [5. Circular reporting as a first-class hazard](#5-circular-reporting-as-a-first-class-hazard)
- [6. Challenge protocol and evidence commitments](#6-challenge-protocol-and-evidence-commitments)
- [7. Unifying Sybil resistance with correlation discounting](#7-unifying-sybil-resistance-with-correlation-discounting)
- [8. Negative observations and the numerator-only problem](#8-negative-observations-and-the-numerator-only-problem)
- [9. Poisoned mitigations: when the assertion is true and the rule is the payload](#9-poisoned-mitigations-when-the-assertion-is-true-and-the-rule-is-the-payload)
- [10. Privacy and robustness are in tension](#10-privacy-and-robustness-are-in-tension)
- [11. Incentive design is attack surface](#11-incentive-design-is-attack-surface)
- [12. Evaluation: adversary cost to manufacture consensus](#12-evaluation-adversary-cost-to-manufacture-consensus)
- [13. What to build first](#13-what-to-build-first)
- [14. Risks to this position](#14-risks-to-this-position)
- [15. References](#15-references)

---

## 1. Scoping the novelty claim honestly

Overclaiming here would be both embarrassing and commercially damaging, so state the boundary precisely.

**What is well-studied (do not claim novelty):**

- *Byzantine-robust federated learning.* A large, mature literature on aggregating model updates when some clients are malicious: Krum and Multi-Krum, coordinate-wise median and trimmed mean, Bulyan, geometric-median aggregation (RFA), FLTrust (server-side root-of-trust dataset), FoolsGold (Sybil resistance via gradient-diversity), FLAME, DeepSight.
- *Attacks on that setting.* "A Little Is Enough", inner-product manipulation, optimized local model poisoning, distributed backdoor attacks, and the important sceptical result that realistic FL poisoning is often weaker than the attack literature implies.
- *Privacy-preserving aggregate statistics with malicious clients.* Prio-style systems, where secret-shared validity proofs bound what a single client can contribute to an aggregate.
- *Trust and reputation in CTI sharing.* MISP-ecosystem trust groups, taxonomies, warning lists, STIX confidence, TLP handling, and a modest academic literature on ISAC trust dynamics.
- *Sybil resistance in open networks* generally.

**What is absent (verified as far as reasonable search allows):**

- Byzantine robustness for **deception/honeypot federations specifically**. Every federated-honeypot and federated-IDS system surveyed in [distributed-honeypot-coordination.md](distributed-honeypot-coordination.md) — the IoMT federated-RL frameworks, Holoscope, ADLAH, the multi-site honeynet datasets — assumes honest participants. None models a malicious sensor operator.
- Robust aggregation where the shared object is a **signed, structured assertion with provenance and evidence commitments** rather than a gradient vector. The robustness structure is materially different (see §2).
- **Independence-aware confidence** as an implemented mechanism rather than a stated aspiration. The concept exists informally in intelligence tradecraft; a computable version with an explicit dependence model does not appear in the CTI systems literature.
- **Negative/coverage observations** as a shared assertion class (see §8).

**Evidentiary caveat.** The negative claims rest on arXiv-indexed literature plus the surveys already gathered. They do not cover industry work that was never published, vendor internals, or classified programs. Before making any public novelty claim, re-run the search and check non-academic sources. Treat "unstudied" as "not found in the literature we searched", which is the honest and still-useful version.

**The defensible framing:** *we adapt mature robust-aggregation and evidence-independence ideas to a new object — the signed threat assertion — and to an adversary model the deception-federation literature has not considered.* That is a real contribution and it does not require anyone to have been asleep.

## 2. Why gradient-space defenses do not transfer

This is the intellectual core of the position, and it is worth stating carefully because it determines the entire mechanism design.

Byzantine-robust FL works by **geometric outlier suppression in a high-dimensional continuous space**. Its correctness rests on three assumptions:

1. Honest updates cluster — benign gradients are concentrated, so a robust statistic (median, trimmed mean, nearest-neighbour selection) tracks the honest majority.
2. The aggregate is a single statistic — the output is one model, so one robust estimator suffices.
3. Contributions are exchangeable — client *i* and client *j* are interchangeable inputs to the estimator; identity carries no structure beyond the update itself.

**All three fail for assertion-space federation.**

| | Gradient-space FL | Assertion-space deception federation |
|---|---|---|
| Shared object | Dense real vector, ~10⁶ dims | Structured record: behavior graph, ATT&CK/ATLAS mappings, affected configs, evidence commitment, signature |
| Aggregation | Average or robust statistic | Corroboration — does independent evidence support this claim? |
| Honest contributions | Cluster tightly | Legitimately heterogeneous; one org seeing a novel attack first is the *valuable* case, not an outlier to suppress |
| Exchangeability | Assumed | **False.** Two reports from the same sensor stack are not two observations |
| Verification | None — a gradient cannot be checked | **Available.** Evidence commitments can be opened; patterns can be reproduced |
| Failure of naive method | Model degraded | Confidently wrong global verdict, distributed as a signed mitigation, executed at scale |

The third row is the sharpest. In FL, an outlying update is presumptively suspicious. In threat intelligence, **the first true report of a novel attack is an outlier by construction.** A robust estimator that suppresses outliers suppresses exactly the signal the network exists to propagate. Any design that treats "far from consensus" as "probably malicious" destroys the product's core value proposition — early warning.

The fifth row is the opportunity. Gradients are unverifiable; assertions need not be. Deception federation has a primitive that FL lacks: **the claim can be checked.** Evidence commitments, reproduction harnesses, and challenge protocols convert robustness from a statistical problem into a partly cryptographic and partly experimental one. That is a strictly stronger position, and it is the one to build on.

**Consequence for design:** do not import robust statistics as the primary defense. Build on (a) dependence modelling, (b) verifiability, (c) bounded influence. Robust statistics apply only to the narrow path where genuinely scalar aggregates are computed (prevalence counts — see §10).

## 3. Adversary taxonomy

The plan's §14.1.7 addresses inflation-by-volume. A complete model needs more roles. Each is stated with goal, capability, and the mechanism that addresses it.

### 3.1 Fabricator

**Goal:** inject assertions for attacks that never occurred.
**Why:** waste defender resources; induce a mitigation that breaks something real. The most damaging version targets availability — a fabricated pattern whose "mitigation" blocks a widely used legitimate service. This is the [false mass quarantine](../BUSINESS_PLAN.md#17-reliability-support-and-incident-operations) runbook, triggered deliberately.
**Capability:** valid membership, valid signing key, ability to author plausible structured records.
**Defense:** evidence commitments plus challenge (§6); reproduction requirement for high-impact patterns; local-authority invariant so no external assertion can directly execute a consequential action ([§14.1.2](../BUSINESS_PLAN.md#1412-separate-intelligence-from-execution-authority)).

### 3.2 Amplifier / Sybil

**Goal:** inflate corroboration for a chosen assertion, whether fabricated or real-but-trivial.
**Capability:** multiple identities, or a single identity with many nominally distinct sensors, or collusion among several members.
**Defense:** effective corroboration (§4) plus empirical independence auditing (§7). Note that authenticated membership raises the cost of Sybil identities but does **not** establish independence — two genuinely distinct member organisations running identical stacks are statistically correlated without any malice.

### 3.3 Suppressor

**Goal:** keep a real attack *out* of the corpus, or force retraction of a true assertion.
**Why:** an attacker who has a working technique benefits from its absence from the corpus. Suppression is the natural adversarial response once the network is valuable.
**Capability:** withhold observations; abuse the challenge/correction workflow to force retraction of true claims; contribute noise to depress a true pattern's confidence.
**Defense:** this is the least-studied direction and needs negative observations (§8) to be detectable at all. Challenge abuse needs rate limiting and reputational cost symmetry — a member who repeatedly challenges claims that survive verification should lose challenge budget.

### 3.4 Mitigation poisoner

**Goal:** submit an assertion that is *true* but crafted so the derived detection or mitigation carries the payload.
**Why:** far subtler than fabrication. The assertion survives verification because it describes a real attack. The harm is in the compiled artifact — a rule with a chosen false-positive profile, or a deliberate blind spot at a specific offset.
**Defense:** §9. This is the most under-appreciated role in the taxonomy and the one most specific to a network that distributes *executable* defensive artifacts.

### 3.5 Inference adversary

**Goal:** learn about other participants rather than corrupt the corpus — who is being hit by what, which orgs run which vulnerable configurations.
**Capability:** honest-looking membership; correlation of published assertions with external signals; challenge requests crafted to elicit disclosure.
**Defense:** minimization by default; disclosure scoped to a challenge and logged; careful review of whether "affected configurations" fields leak per-member exposure. Note the direct conflict with §7 — independence auditing wants provenance detail, privacy wants less of it.

### 3.6 Compromised sensor

**Goal:** attacker-controlled observations from a legitimate, non-malicious member.
**Why distinguish from §3.1:** response differs. A compromised sensor means revoke the sensor key and re-baseline; a malicious member means eject and reassess everything they ever contributed. Conflating them produces either over-reaction against victims or under-reaction against attackers.
**Defense:** per-sensor identity and software/config fingerprinting ([§14.1.3](../BUSINESS_PLAN.md#1413-organizational-and-sensor-identity)); anomaly detection on a sensor's own contribution pattern; retrospective re-scoring of a compromised sensor's history.

### 3.7 Equivocating publisher / split view

Already covered by the transparency log and independent witnesses in [§14.1.6](../BUSINESS_PLAN.md#1416-transparency-logs-and-independent-witnesses). Listed for completeness because a robustness story that omits it is incomplete.

### 3.8 Free-rider

Not a security role, but it shapes incentive design, and incentive design creates attack surface — see §11.

## 4. Core mechanism: effective corroboration

The plan states the requirement: "compute an effective corroboration score that discounts correlated sources." Here is a concrete, defensible way to do it.

### 4.1 The statistical framing

Borrow the **design effect** from cluster sampling and meta-analysis. Given *n* sightings with mean pairwise correlation ρ̄, the effective sample size is

```
n_eff  =  n / (1 + (n - 1) · ρ̄)
```

Interpretation, and why it is the right shape:

- ρ̄ = 0 (fully independent sightings) → `n_eff = n`. Ten independent confirmations count as ten.
- ρ̄ = 1 (fully dependent) → `n_eff = 1`. Ten reports from one source count as one, regardless of volume.
- Intermediate ρ̄ interpolates smoothly, and **the marginal value of an additional correlated sighting approaches zero** — which is exactly the property that defeats amplification attacks. An adversary adding sightings from the same stack purchases asymptotically nothing.

Confidence is then a function of `n_eff` and per-sighting evidence quality, never of raw *n*.

### 4.2 Estimating pairwise correlation

ρ_ij is estimated from a **provenance vector** attached to every sighting. Required fields:

| Field | Why it drives dependence |
|---|---|
| Organization | Same org → near-total dependence |
| Sensor software + version | Identical stacks fail and fire identically |
| Detector / rule / model version | Two instances of the same detector are one detector |
| Deployment context (cloud, region, ASN) | Shared exposure and shared blind spots |
| Delivery vector observed | Same vector may indicate same campaign slice, not independent discovery |
| Evidence method | Captured artifact vs. inferred-from-rule are different epistemic classes |
| **Intelligence lineage** | Did this detection derive from federation-distributed content? See §5 |

Start with a **hand-specified kernel** over these attributes — transparent, auditable, and defensible to a customer, which matters more than marginal accuracy for a security control. A learned kernel is a later refinement, and carries its own poisoning surface (an adversary who can influence the correlation model can make their own sightings look independent). If a learned component is ever introduced, its training data must itself be subject to §7 auditing. Prefer the boring version.

### 4.3 Why this is publishable

Applying design-effect/effective-sample-size reasoning to CTI corroboration is a small, clean, correct idea that the field appears not to have implemented. It is also immediately legible to security buyers, who already intuit that "ten reports from one vendor's customers" is not ten confirmations. Small correct ideas with obvious operational meaning are better research positions than elaborate ones.

## 5. Circular reporting as a first-class hazard

The single highest-value and cheapest mechanism in this document.

**The failure:** BiTorus distributes a detection derived from org A's assertion. Org B installs it. It fires. Org B reports a sighting. The federation now counts B as corroborating A — but B's observation is causally *downstream* of A's. Confidence rises with no new evidence. Iterate across the membership and a single unverified assertion bootstraps itself into apparent consensus.

This is **circular reporting**, long recognised in human intelligence analysis, and structurally identical to ascertainment bias in epidemiology (you find more cases where you looked harder, because you were told to look).

**Why it is a security issue, not just a quality issue:** it is the cheapest possible amplification attack. A fabricator does not need Sybils. They need one plausible assertion and a federation that redistributes detections without tracking lineage. The network amplifies the attack on the attacker's behalf.

**Mechanism:** every assertion carries an `intelligence_lineage` field:

- `independent` — detected by tenant-local logic with no federation input for this pattern
- `federation_derived` — detected by a rule, indicator, or evaluation distributed by the federation (with the artifact ID)
- `federation_primed` — analyst was aware of the advisory; detection logic was local

`federation_derived` sightings contribute ~0 to corroboration of the assertion they descend from. They remain valuable for **prevalence** ("how widespread is this?") — a different question from **veracity** ("is this real?"). Keeping those two questions separate, with separate denominators, is the design principle.

`federation_primed` is the honest middle case and should be discounted but not zeroed. It requires self-reporting, which is imperfect; instrument it where possible from tooling rather than relying on attestation.

**Cost to implement:** one enum and one artifact ID per assertion, plumbed through the schema. **Value:** closes the cheapest amplification path in the system. This should be in the schema freeze at [Month 0-1](../BUSINESS_PLAN.md#43-immediate-180-day-execution-plan), because retrofitting lineage into a deployed schema is painful and every assertion collected before it exists is permanently ambiguous.

## 6. Challenge protocol and evidence commitments

Deception federation's structural advantage over FL: **claims can be checked.** Build the protocol that exercises it.

### 6.1 Commit, then open on demand

Assertions carry a commitment (hash) to evidence, not the evidence. Any member — or the federation, or a designated verifier — may **challenge** an assertion, obliging the publisher to open a specified portion of the commitment to a named verifier under a disclosure policy.

Properties this buys:

- A fabricator cannot open a commitment to evidence they never had. Fabrication becomes detectable rather than merely improbable.
- Routine operation requires no raw disclosure — privacy is preserved in the common case, and paid for only when a claim is contested.
- The disclosure is scoped, logged, and policy-governed, consistent with [§12](../BUSINESS_PLAN.md#12-privacy-preserving-federation).

### 6.2 Challenge economics

A challenge protocol with no cost is itself an attack surface (§3.3 — suppression by challenge spam). Make it symmetric:

- Challenges are rate-limited per member.
- A member whose challenges repeatedly fail (the assertion verifies) loses challenge budget.
- A publisher who repeatedly fails to answer challenges loses source reputation, and their historical assertions are re-scored.
- All challenges and outcomes are recorded in the transparency log — the *history of contestation* is itself intelligence about source quality.

Deliberately **reputational rather than financial**. Financial staking imports a body of griefing and market-manipulation attacks, and conflicts with the plan's stated rejection of token incentives.

### 6.3 Reproduction as the strongest arbiter

For high-impact patterns, escalate beyond commitment-opening to **independent reproduction**. The plan already specifies a reproduction harness as part of the Agentic Threat Pattern ([§37.2](../BUSINESS_PLAN.md#372-core-proprietary-object-agentic-threat-pattern)). The security framing: reproduction is not a quality feature, it is the anti-fabrication mechanism. A pattern that a clean-room harness can reproduce against the claimed configuration is true in the only sense that matters operationally, regardless of who reported it or how many times.

This inverts the usual CTI trust model in a way worth stating plainly: **for reproducible patterns, source reputation becomes nearly irrelevant.** That is a strong privacy and decentralization property — a distrusted or anonymous contributor can still supply verifiable intelligence. Reserve reputation for the residue that cannot be reproduced.

## 7. Unifying Sybil resistance with correlation discounting

A framing that appears to be novel and is architecturally simplifying.

Conventional treatment separates two problems:

- **Sybil resistance** — is this member a distinct real entity? (identity problem, solved by authenticated membership)
- **Correlated sensors** — are these observations statistically independent? (statistics problem, solved by discounting)

**Observation: for corroboration purposes these are the same problem.** Consider two members whose sightings are near-duplicates. Either:

1. They are the same actor behind two identities (Sybil), or
2. They are distinct orgs running identical stacks with identical exposure (innocent correlation).

**The correct handling is identical in both cases**: discount their joint contribution. The corroboration engine does not need to know which case obtains. Identity-based Sybil detection is hard, adversarial, and privacy-invasive; **behavioural independence measurement is easy, non-accusatory, and directly measures the quantity that actually matters.**

**Mechanism — empirical independence auditing.** For each member pair, track observed co-occurrence of sightings against the base rate expected if independent. Pairs whose observations co-occur far above base rate get an elevated ρ_ij regardless of declared provenance. This:

- Catches Sybils without needing to prove they are Sybils.
- Catches innocent-but-correlated members, which pure Sybil defense misses entirely and which is probably the more common real case.
- Catches *declaration lying* — a member who misreports their sensor stack to appear independent is still caught by their behaviour.

That last property matters. Declared provenance (§4.2) is self-reported and therefore attackable. Empirical co-occurrence is not. **Use declared provenance as the prior and measured co-occurrence as the correction.** A member whose measured correlation greatly exceeds what their declared provenance predicts is exhibiting a specific, investigable anomaly — either misconfiguration or deception.

**Privacy tension, stated honestly:** co-occurrence auditing requires the federation to hold per-member sighting timelines, which is exactly what §3.5's inference adversary wants. This tension is real and is not fully resolved here. Partial mitigations: compute correlations over coarsened time buckets; hold the audit state in a restricted component with its own access controls and audit trail; consider computing co-occurrence under secure aggregation so the federation learns pairwise correlation without per-member timelines. That last option is worth prototyping — it may be the cleanest resolution, and if it works it is itself a publishable result.

## 8. Negative observations and the numerator-only problem

**The gap:** CTI is systematically **numerator-only.** Feeds report hits. They almost never report misses. Nobody publishes "I run configuration C, I have coverage for pattern P, and I did not see it this week."

Consequences of missing denominators:

- **Prevalence is uncomputable.** "47 sightings" means nothing without knowing how many environments were looking. Yet the plan sells population risk estimation as a core Collective Defense feature ([§38.1](../BUSINESS_PLAN.md#381-subscription-architecture)) — that promise requires denominators.
- **Suppression is undetectable.** With no expectation of what a member *should* have seen, a member that stays silent about a real attack is indistinguishable from a member that wasn't targeted.
- **Susceptibility claims are unfalsifiable.** "Framework F is affected" needs the contrast case: environments running F that did *not* exhibit the behaviour.

**Mechanism — coverage assertions.** A shareable, privacy-cheap assertion class:

```
CoverageAssertion:
  window:              time range
  configuration_class: coarsened config fingerprint (framework, model family, tool classes)
  patterns_monitored:  [pattern IDs with active detection]
  observations:        [pattern ID -> count, including zero]
  detector_versions:   provenance for the above
```

Properties:

- **Privacy-cheap.** A zero count leaks far less than a positive detection. Most members can share these on a much more permissive policy than sightings.
- **Enables real prevalence** with proper denominators, and therefore honest confidence intervals.
- **Makes suppression detectable.** A member declaring coverage for P and reporting zero, when comparable members report hits, is a signal — of a detection gap, a compromised sensor, or suppression. All three are worth investigating.
- **Makes susceptibility claims falsifiable.** Negative results at scale are how "which configurations are affected" stops being anecdote.

**This is arguably the highest-value idea in this document** and the least like anything currently deployed. It is also the easiest to underestimate, because negative results feel like non-events. They are the denominators, and every quantitative claim the Collective Defense product wants to make depends on them.

Design note: coverage assertions should be **generated automatically by the sensor** from its active detection set, never hand-declared. Hand-declared coverage is aspirational and will be wrong.

## 9. Poisoned mitigations: when the assertion is true and the rule is the payload

The subtlest role in §3, and the one most specific to a network that distributes **executable** defensive artifacts.

**Attack:** submit a genuine, reproducible attack pattern — chosen so that the natural detection or mitigation derived from it has an attacker-desired side effect. Variants:

- **False-positive weaponization.** The pattern's distinguishing feature overlaps a competitor's legitimate traffic, or a widely used library's normal behaviour. The compiled rule causes broad disruption. The submitter is never caught fabricating, because they did not fabricate.
- **Deliberate blind spot.** The pattern is described precisely enough to be reproducible but narrowly enough that the derived rule misses a superset the attacker actually uses. Defenders believe they have coverage. This is worse than no coverage.
- **Compiler targeting.** Craft the pattern so that the *portable mitigation compiler* ([§26.2](../BUSINESS_PLAN.md#262-defensible-differentiation)) emits something harmful in one specific target format — the assertion is fine, the Rego is fine, the SIEM rule is not.

Note that verification-by-reproduction (§6.3) **does not defend against this at all.** The pattern reproduces. That is why it is listed separately from fabrication, and why "reproducibility solves poisoning" is wrong.

**Defenses:**

1. **Every distributed mitigation ships with a false-positive test suite**, and consumers run it against their own traffic in dry-run before promotion. The plan already ships regression tests as first-class artifacts; the security framing is that **the FP suite is an anti-poisoning mechanism**, not a quality nicety. It must include benign-traffic corpora, not just attack cases.
2. **Deterministic, reproducible compilation.** A third party must be able to re-derive the mitigation from the assertion and get a bit-identical artifact. Non-reproducible compilation means nobody can check whether the rule follows from the claim.
3. **Blast-radius estimation before distribution.** Estimate what fraction of observed benign traffic a candidate rule would match — using the coverage-assertion corpus from §8, which is exactly the denominator data this needs. The two mechanisms compose.
4. **Observe-first rollout as a hard default**, already in the [business risk register](../BUSINESS_PLAN.md#33-updated-business-risk-register). A rule that has never run in observe mode against real traffic should not be promotable, and the platform should enforce that rather than recommend it.
5. **Semantic diffing of compiler output** across versions and target formats, so a rule that behaves differently in one backend is flagged.

## 10. Privacy and robustness are in tension

State this explicitly, because a design that pretends otherwise will fail in a predictable place.

**The tension:** robustness wants to inspect contributions (who sent what, how correlated, does the evidence open). Privacy wants contributions to be unlinkable and minimal. Differential privacy and Byzantine robustness are known to fight — DP noise is precisely the cover an adversary needs, and robust aggregation needs the per-contribution visibility DP removes.

**Resolution — split the paths by what each actually needs:**

| Path | Object | Privacy approach | Robustness approach |
|---|---|---|---|
| **Assertions** (veracity) | Structured, signed, attributable | Minimization + commitments. **No DP.** | Full provenance, challenge, reproduction |
| **Prevalence** (counting) | Scalar counts, coverage stats | Secure aggregation; DP acceptable on outputs | **Bounded influence** via validity proofs |
| **Matching** (indicator overlap) | Set intersection | PSI | Bounded set sizes; authenticated membership |

The assertion path does not need DP because it is already minimized and deliberately attributable — attribution is load-bearing for corroboration, and an unattributable assertion cannot be challenged. Trying to add DP here fights the mechanism.

The prevalence path is where robust aggregation genuinely applies, and where the FL literature transfers cleanly. **Prio-style validity proofs are the right primitive**: a participant proves in zero knowledge that their contribution is well-formed and within range, so a single malicious member cannot inject an enormous count into an aggregate that nobody can inspect. Without bounded influence, secure aggregation is *strictly worse* than plaintext for robustness — you have hidden the contributions from yourself as well as from the adversary. This is a trap worth naming: **privacy technology applied without influence bounds converts a detectable attack into an undetectable one.**

This directly refines the plan's position that MPC/FHE should be gated behind measured use cases ([§31.1](../BUSINESS_PLAN.md#311-build-order-changes)). The refinement: when secure aggregation *is* deployed, validity proofs are not optional.

## 11. Incentive design is attack surface

Short section, important point.

**Any contribution incentive is a fabrication incentive.** A federation that rewards volume gets volume. A federation that rewards novelty gets manufactured novelty. A federation that rewards being-first gets premature low-confidence assertions. This is not hypothetical — it is the observed failure mode of every bug-bounty and threat-feed program that paid per item.

Implications:

- The plan's rejection of token incentives is correct and should be treated as a **security** decision, not merely a philosophical one.
- Reputation systems are incentive systems. A reputation score that increases with contribution volume has the same failure mode as payment. Reputation should key on **verified** contributions and should *decrease* on failed challenges.
- The right incentive is access: contribution improves the quality of what you receive, because it genuinely does (denominators, corroboration). Align the incentive with the mechanism rather than bolting a currency on top.
- Free-riding (§3.8) is a business problem to solve with packaging ([§38.1](../BUSINESS_PLAN.md#381-subscription-architecture) already separates intelligence from Collective Defense entitlements), not a security problem to solve with rewards.

## 12. Evaluation: adversary cost to manufacture consensus

The plan's [§14.1.13](../BUSINESS_PLAN.md#14113-security-acceptance-tests) already includes "submit many correlated fake sightings and verify that independence scoring prevents false global confidence." Expand into a proper benchmark — this is the publishable artifact and the thing that turns the position from a claim into evidence.

### 12.1 Harness

A simulation environment with configurable membership, sensor-stack diversity, ground-truth attack events, and an adversary mix drawn from §3. Must include innocent correlation (members with genuinely identical stacks) so that defenses are not credited for trivially separating malice from honesty when the real difficulty is separating malice from coincidence.

### 12.2 Headline metric

> **Adversary cost to manufacture consensus** — the minimum resource expenditure (identities, sensors, distinct stacks, elapsed time) required to drive a fabricated pattern to a target confidence C.

This is the right headline because it is (a) monotone in defense quality, (b) directly meaningful to a buyer, (c) comparable across designs, and (d) honest — it never claims impossibility, only cost. It should be reported as a curve over C, not a single number, since cheap low-confidence injection may be acceptable while cheap high-confidence injection is not.

### 12.3 Supporting metrics

| Metric | Attack it measures |
|---|---|
| False-confidence rate under Sybil pressure | §3.2 |
| Time-to-correct after a fabricated pattern reaches distribution | §3.1 |
| Detection latency degradation under suppression | §3.3 |
| Blast radius of a poisoned mitigation reaching production | §3.4 |
| Amplification factor from circular reporting, lineage on vs. off | §5 |
| Per-member exposure inferable by an honest-but-curious participant | §3.5 |
| **Novel-attack propagation latency** | *the counter-metric* |

That last row is essential and easy to forget. Every robustness mechanism in this document slows or discounts something. A design that scores perfectly on adversary cost while taking three weeks to propagate a true novel attack has failed at the product's actual purpose. **Report the counter-metric alongside every robustness result**, and treat a robustness improvement that degrades novel-attack latency as a trade requiring justification, not a win. §2's warning — that the first true report is an outlier — is the failure mode this metric detects.

## 13. What to build first

Ordered by (value × cheapness) ÷ retrofit-pain. Aligns with [Month 0-1 schema freeze](../BUSINESS_PLAN.md#43-immediate-180-day-execution-plan).

1. **Provenance vector + `intelligence_lineage` in the assertion schema (§4.2, §5).** Cheapest, highest value, and *impossible to retrofit* — every assertion collected before this exists is permanently ambiguous. Must be in the schema freeze.
2. **Coverage assertions (§8).** Also schema-time. Unlocks prevalence, suppression detection, and blast-radius estimation. Auto-generated from the sensor's active detection set.
3. **Effective corroboration with a hand-specified kernel (§4).** Implementable in days once provenance exists. Transparent and auditable.
4. **Commitment + challenge protocol (§6).** Needed before any external contribution is accepted.
5. **Simulation harness and the adversary-cost benchmark (§12).** Build early — it is how every later mechanism gets justified, and it is the publishable artifact.
6. **False-positive suites and reproducible compilation (§9).** Required before the first mitigation is distributed to anyone.
7. **Empirical independence auditing (§7).** Needs accumulated history; design the storage for it early, enable later.
8. **Prio-style validity proofs (§10).** Only when secure aggregation is actually deployed — but do not deploy secure aggregation without them.

Items 1, 2 and 5 are the ones that are cheap now and expensive later. Everything else can follow demand.

## 14. Risks to this position

Stated plainly, because a research position that only lists its strengths is marketing.

| Risk | Assessment |
|---|---|
| **The gap gets closed while we build.** Byzantine-robust FL researchers notice deception federation and publish first. | Plausible; the adjacent literature is large and active. Mitigation: the durable asset is the instrumented corpus with provenance and coverage data, not the algorithm. A paper does not produce denominators. |
| **The novelty claim is wrong** — prior work exists in industry or in venues not searched. | Real. §1 scopes the claim to what was searched. Re-verify before any public claim, and prefer "we implement" over "we invented". |
| **Complexity without demonstrated benefit.** Customers may not pay for robustness against attacks they have not experienced. | The most likely commercial failure. Mitigation: lead with the benefits that pay off immediately with zero adversary present — prevalence, denominators, calibrated confidence, blast-radius estimation. Robustness is then a property of a system bought for other reasons. |
| **Over-discounting kills the product.** Aggressive independence discounting suppresses novel-attack propagation. | The technical failure mode identified in §2. Mitigation: §12.3's counter-metric, treated as a gate rather than a footnote. |
| **Privacy/robustness tension proves unresolvable** at acceptable cost (§7, §10). | Possible. Mitigation: the secure-aggregation approach to co-occurrence is the escape hatch; prototype it early enough to know. |
| **Small-n reality.** Federation robustness matters at scale; early deployments have few members, where independence estimates are noisy and the whole apparatus is over-engineered. | Accept it. These mechanisms are designed for [Product 3](../BUSINESS_PLAN.md#371-three-product-sequence). Build the schema now, the scoring later. Do not let robustness work delay Product 1. |

## 15. References

Foundational and adjacent work this position builds on and departs from. Byzantine-FL and Prio citations are given by name rather than link because they are stable, well-known results; verify exact versions before citing formally.

**Byzantine-robust federated learning (the neighbouring solved problem)**
- Krum / Multi-Krum — Blanchard et al., NeurIPS 2017
- Coordinate-wise median and trimmed mean — Yin et al., ICML 2018
- Bulyan — El Mhamdi et al., ICML 2018
- Robust aggregation via geometric median (RFA) — Pillutla et al.
- FLTrust — Cao et al., NDSS 2021
- FoolsGold (Sybil resistance via gradient diversity) — Fung et al.
- Attacks: "A Little Is Enough" (Baruch et al., NeurIPS 2019); local model poisoning (Fang et al., USENIX Security 2020); distributed backdoor attacks (Xie et al., ICLR 2020)
- Sceptical counterpoint on realistic threat: Shejwalkar et al., IEEE S&P 2022

**Private aggregate statistics with malicious clients**
- Prio — Corrigan-Gibbs & Boneh, NSDI 2017 (secret-shared validity proofs; the model for §10)

**Deception federation assuming honest participants (the gap)**
- [Holoscope (arXiv 2512.19842)](https://arxiv.org/abs/2512.19842)
- [Federated TGCN-A2C (arXiv 2606.21513)](https://arxiv.org/abs/2606.21513)
- [LDT-FRL (arXiv 2606.21422)](https://arxiv.org/abs/2606.21422)
- [ADLAH (arXiv 2512.07827)](https://arxiv.org/abs/2512.07827)

**Coordination context**
- [Detecting Offensive Cyber Agents / ACE proposal (arXiv 2605.21956)](https://arxiv.org/abs/2605.21956)
- [Anycast amplification honeypots (arXiv 2607.14832)](https://arxiv.org/abs/2607.14832)

**Internal**
- [distributed-honeypot-coordination.md](distributed-honeypot-coordination.md)
- [decoy-agent-infrastructure.md](decoy-agent-infrastructure.md)
- [threat-intelligence-landscape-2026.md](threat-intelligence-landscape-2026.md)
