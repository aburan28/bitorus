# BiTorus prototype

A runnable vertical slice of the two research positions in [../docs/research](../docs/research/README.md): coordinated decoy agent infrastructure, and independence-aware corroboration. Python 3.11+, **standard library only** — no install step.

```bash
python3 demo.py             # decoy fleet + corroboration
python3 demo_ecosystem.py   # MCP ecosystem monitor
python3 -m unittest discover -s tests -t .

# live crawler — read prototype/README.md#live-crawling first
python3 -m bitorus.ecosystem.crawl --targets targets.txt --store ./data --dry-run
```

This is a demonstration of mechanism, not a product. It shows the ideas are concrete and testable, and it makes the schema decisions real early enough to be cheap.

## What it demonstrates

**`demo.py` — inbound: catching agents that come to us**

| Scenario | Claim under test |
|---|---|
| 1. Decoy fleet | Interaction *depth* separates agents from scanners and humans on an unadvertised MCP endpoint |
| 2. Susceptibility matrix | Differential payloads across a fleet measure which sanitization each scaffold lacks — not computable from one node |
| 3. Sybil amplification | Three independent reports beat ten correlated ones; naive counting ranks them backwards |
| 4. Circular reporting | Lineage tracking collapses 9 reports to 1 effective observation |
| 5. The loop | Decoy observations become signed assertions, scored by the same engine |

**`demo_ecosystem.py` — outbound: finding hostile servers before a customer connects**

| Scenario | Claim under test |
|---|---|
| 1. Longitudinal crawl | Seven servers, three rounds, one failure mode each |
| 2. The report | 5 findings from 21 observations; the stable control stays silent |
| 3. Rug pull | Two byte-identical rounds, then a payload in a patch release — invisible to a one-time review |
| 4. Schema broadening | Description untouched; the tool now accepts raw SQL |
| 5. Crawl policy | Tool invocation, resource reads, auth, and opt-out refused in code |
| 6. Federation | Findings become assertions scored by the same engine |

## Layout

```
bitorus/
  schema.py            assertion types: provenance, lineage, coverage
  corroboration.py     effective corroboration, independence kernel, adversary cost
  decoy/
    payloads.py        six injection encodings + the inertness invariant
    server.py          protocol-faithful decoy MCP server
    fleet.py           differential assignment, susceptibility matrix, linkage
    simulated_clients.py   agents / scanner / human, for demo and tests
  ecosystem/
    snapshot.py        canonical, hashable capture of an advertised surface
    detectors.py       hidden-instruction and manipulation detection
    diff.py            structural diff, rug-pull and schema-broadening findings
    monitor.py         canary client, crawl policy, assertion generation
    transport.py       live MCP over Streamable HTTP, hardened
    scheduler.py       per-host rate limiting, jittered exponential backoff
    store.py           append-only JSONL snapshot history
    crawl.py           CLI
    simulated_registry.py  seven servers, one failure mode each
demo.py                five scenarios end to end
demo_ecosystem.py      six scenarios end to end
tests/                 96 tests, including the safety invariants
```

## Live crawling

`crawl.py` turns the monitor into something that can run against real servers. It is the only part of this prototype that touches a network, and it is written on the assumption that **the servers it connects to may be hostile** — that is, after all, what it is looking for. The client is therefore the attack surface, and the same trust-domain principle applies: the observer must not be compromised by the observed.

**Target vetting.** Every URL is resolved and checked before connecting. Loopback, RFC1918, link-local (including `169.254.169.254`, the cloud metadata endpoint), multicast and reserved addresses are refused, as are non-HTTP schemes and plaintext without explicit opt-in. A multi-answer resolution is only as safe as its worst address, so any non-public answer refuses the whole target.

One residual risk is documented rather than hidden: vetting resolves the name, then hands the *name* to `urllib`, which resolves again. A server controlling its DNS can answer differently the second time. Closing that needs a pinned-IP connection with a manual `Host` header, which `urllib` does not expose cleanly. Acceptable for a read-only client with no credentials and a response-size cap — not acceptable if either changes.

**Politeness is enforced, not declared.** Per-host minimum interval (not per-URL — several endpoints on one host still hit one server), jittered exponential backoff with a cap, and server-supplied `Retry-After` treated as authoritative over our own schedule. Full jitter rather than fixed multiples, so a fleet of crawlers that fail together does not re-synchronise into a thundering herd against a host that is already struggling.

**Deferrals are reported with reasons.** A crawl that silently skips half its targets looks identical to one that covered everything, and the difference matters when the output is a claim about what the ecosystem is doing.

**History is append-only.** A rug pull is proven by the *clean* snapshot that preceded it, so compaction would discard the evidence that makes the finding a finding. One JSONL file per host; a truncated final line costs one observation, not the store.

Start with `--dry-run`, which vets every target and reports the schedule without making a request:

```
refused https://localhost -- localhost resolves to non-public address ::1;
        the monitor must not reach internal infrastructure
refused http://mcp.example.com -- plaintext http requires allow_plaintext
refused file:///etc/passwd -- unsupported scheme 'file'
```

**Before pointing this at real infrastructure:** verify the transport against the current MCP specification. Header names, session semantics, and the JSON-vs-SSE response split move, and a client that mis-implements them will mis-*read* servers rather than fail loudly — which produces confident wrong findings, the worst possible output for this component.

## The two halves are built against the same encoding set

`decoy/payloads.py` encodes instructions a human reader cannot see. `ecosystem/detectors.py` finds them. Anything we can hide, we can detect — and there is a test asserting exactly that, iterating every encoding the decoy can generate through the detector.

This is not symmetry for its own sake. It is why the red-team half improves the blue-team half: see the second bug below.

## The core mechanism

Confidence comes from *effective* sample size, never raw count. The design effect from cluster sampling:

```
n_eff = n / (1 + (n - 1) * rho_bar)
```

As `rho_bar` approaches 1 the marginal value of another correlated sighting approaches zero, so an adversary adding reports from the same stack purchases asymptotically nothing. Observed in scenario 3:

```
10 correlated    n=10 orgs=10 rho=1.00 n_eff=1.00 confidence=0.450 (naive 0.997)
3 independent    n=3  orgs=3  rho=0.05 n_eff=2.73 confidence=0.804 (naive 0.834)
```

The naive column is what a count-based system would report — it ranks the Sybil attack *above* genuine corroboration.

The robustness metric is a price, not a claim of impossibility:

```
target confidence   reusing one stack     diverse stacks
0.95                unreachable           7 sightings
0.99                unreachable           12 sightings
```

## Safety invariants

`payloads.assert_inert` runs on every payload at construction and is covered by tests. It rejects any payload containing a network location or shell directive.

Every payload directs an agent only to a canary tool on the serving node. A payload that redirected an attacking agent toward a third party would make us a participant in that attack — see [decoy-agent-infrastructure.md §10](../docs/research/decoy-agent-infrastructure.md#10-safety-ethics-and-legal-constraints). This is enforced in code, not by convention.

The prototype has no network listener. Adding one requires the egress controls in [observation-architecture.md §3](../docs/research/observation-architecture.md#3-egress-the-half-everyone-underrates) first: a decoy with unrestricted outbound access is an attacker-controlled box with internet access.

## Bugs the demos surfaced

Worth recording. Each was found by building the thing rather than by reasoning about it.

**Fingerprint instability.** The scaffold fingerprint originally included the full method sequence — which contains `tools/call` and the server's own `canary.tripped` annotation. Both are *outcome*-dependent, so the same client fingerprinted differently on a node whose payload it tripped. That breaks cross-node linkage precisely where linkage matters: the agents you most want to correlate are the ones that behaved differently across nodes.

Fixed structurally rather than by filtering strings: `Event.client_originated` separates what the client did from what we recorded about it, and only client-originated non-invocation events reach the fingerprint. Locked in by `test_fingerprint_is_stable_across_nodes`.

The general lesson: **anything the observer does must be excluded from what the observer measures.** The same trust-domain principle the observation ladder is built on, applied to a data structure.

**A detector gap, found by the red-team half.** The test that runs every decoy encoding through the ecosystem detector failed on one: `TOOL_DESCRIPTION`, which hides nothing at all — it appends the instruction in plain visible text. The hidden-text detectors correctly found nothing, and the manipulation patterns missed it.

That is the *most common real-world tool-poisoning shape*: no hiding is needed, because the model treats a tool description as authoritative regardless. A detector built only against hidden text would have missed the majority case. Fixed by adding `tool_invocation_directive` — a description that directs the model to invoke *another* tool, which legitimate descriptions do not do.

**A false positive that would have killed the product.** `publisher_identity_changed` originally hashed name *and* version, so every routine patch release raised a HIGH-severity takeover finding. Five of eleven findings in the first run were version bumps. A detector that fires on every release gets switched off, and then detects nothing at all. Identity is now name-only; version changes are recorded at INFO as correlation context. Two tests pin it.

**A regex that could not parse its own target.** `_TOOL_DIRECTIVE` used `[^.!?]` to stay inside one sentence — which also excluded the dot in `diagnostics.verify_session`, so it never matched a directive naming a namespaced tool. Now `(?:[^.!?\n]|\.(?=\w))`: a dot is allowed only when it joins word characters.

**Backoff that never expired.** The scheduler originally treated "this host has consecutive failures" as a separate veto in `due()`. But clearing the failure count requires a success, and a success requires a poll — so the first failure removed a host permanently. Backoff is now expressed as a *hold on the rate limiter*, which expires on its own. `test_failed_host_recovers_after_backoff` pins it.

This one is worth noting as a category: three of these five bugs are **state that can only be cleared by an event the bug itself prevents.** Worth grepping for that shape directly.

## Known gaps

Deliberate omissions, so the slice stays legible:

- **No signatures.** `commit()` hashes evidence; assertions are unsigned. Real deployment needs the role-separated signing hierarchy of [§14.1.4](../docs/BUSINESS_PLAN.md#1414-key-hierarchy-and-role-separation).
- **No transport.** `DecoyServer.handle` takes and returns dicts and `Transport` is a protocol, so stdio/HTTP is a thin wrapper in both directions — but protocol fidelity must be verified against the reference implementation before any deployment.
- **The transport has never touched a real server.** Its request path is fully covered through an injected opener, and the socket call is a thin layer over `urllib` — but "tested without a network" is not "verified against reality". Expect the first real crawl to find spec mismatches.
- **No detector calibration.** Seven hand-written fixtures are not a corpus. Precision and recall against real MCP servers are unmeasured, and per the identity-hashing bug above, the false-positive rate is what decides whether anyone reads the feed.
- **No DNS pinning.** See the rebinding note under Live crawling.
- **No concurrency.** One target at a time. Fine for hundreds of servers on an hourly interval; not fine for tens of thousands.
- **No coverage assertions in the demo.** The type exists in `schema.py`; prevalence estimation over it is not built.
- **No empirical independence auditing.** The kernel uses declared provenance only. Measured co-occurrence — which catches members who *misreport* their stack — needs accumulated history.
- **No challenge protocol.** `evidence_commitment` is populated but nothing opens it.
- **Simulated clients only.** Sanitization behaviour is modelled, not observed. Real scaffold behaviour is an empirical question and the entire point of deploying.
