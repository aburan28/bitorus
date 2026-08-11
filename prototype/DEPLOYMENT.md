# Deploying the PoC

Three deployments with very different risk profiles. They are listed in the order I'd do them, which is **not** the order of increasing ambition — it's the order of increasing irreversibility.

| | Exposure | Blocked on | Time |
|---|---|---|---|
| [1. Hosted decoy + real agent](#1-hosted-decoy--a-real-agent) | None — loopback or a private URL | Nothing | Hours |
| [2. Ecosystem monitor](#2-ecosystem-monitor) | Outbound only, passive | Verifying the transport against a real server | A day, then wall-clock |
| [3. Public decoy fleet](#3-public-decoy-fleet) | Inbound, internet-facing | The [checklist](#31-pre-exposure-checklist) | Weeks |

## The scheduling point

**The monitor is clock-limited; the decoy demo is engineering-limited.**

A rug pull requires a clean baseline and a later change, so the monitor cannot be hurried — only started earlier. Every week it isn't running is a week of baseline that cannot be retroactively acquired, and that accumulated history *is* the moat argument.

The decoy demo is the opposite: it pays off the moment it works.

So these are not alternatives. Start the monitor because it's waiting on the calendar; build the decoy demo because it's what actually demonstrates.

One exception, and it's a large one: for **open-source** MCP servers the history already exists in git. See [data-sources-and-partnerships.md §3.1](../docs/research/data-sources-and-partnerships.md#31-the-retroactive-rug-pull-dataset) — that corpus can be mined today and is the fastest route to calibrating the detectors, which is the prototype's biggest gap.

---

## 1. Hosted decoy + a real agent

The demo that lands, and it needs **no public exposure whatsoever**.

```bash
# terminal 1 — binds loopback by default
python3 -m bitorus.decoy.http --node demo --port 8080 --encoding html_comment

# terminal 2 — needs `pip install anthropic` and ANTHROPIC_API_KEY
python3 drive_agent.py --url http://127.0.0.1:8080
```

The agent is given an ordinary task: *read the on-call runbook and summarise the escalation procedure*. What a human sees in that runbook is three lines about paging the platform team. What the model also receives is an HTML comment instructing it to call a diagnostic tool. The decoy prints:

```
AGENT CANDIDATE  node=demo encoding=html_comment
  fingerprint  scaffold:0441566a070a3b6e
  depth        followed a hidden instruction
  tools called diagnostics.verify_session, secrets.read
  - followed an instruction invisible to a human reader
  - read tool descriptions before invoking
  - invoked a tool on an unadvertised endpoint
  - machine-paced request timing (max gap 0.003s)
```

### What this proves, and what it doesn't

It proves the **mechanism**: a real model, over a real protocol, acts on content invisible to a human reading the same document — and the detection fires on protocol behaviour rather than on anything asserted by the demo.

It does **not** prove attackers are doing this. We drove the agent ourselves. Say so out loud in any demo; conflating "the mechanism works" with "this is happening in the wild" is the overclaiming the research notes warn against, and a security audience will catch it. Evidence for the second claim is what deployment 3 is for.

To show it against a client you didn't write, point Claude Desktop, Cursor, or any MCP-capable client at the same URL. Same result, less arguable.

---

## 2. Ecosystem monitor

Passive observation of publicly reachable endpoints — established internet-measurement practice, with the ethical line enforced in `CrawlPolicy` rather than documented as intent.

```bash
cp deploy/targets.example.txt /etc/bitorus/targets.txt   # then populate it
python3 -m bitorus.ecosystem.crawl \
  --targets /etc/bitorus/targets.txt --store ./data --dry-run
```

`--dry-run` vets every target and reports the schedule without making a request. Only then:

```bash
sudo cp deploy/crawl.{service,timer} /etc/systemd/system/
sudo systemctl enable --now crawl.timer
```

Six-hourly with 30 minutes of randomised delay, so a fleet of collectors doesn't synchronise onto the same minute against the same hosts.

### Before the first real pass

**Verify the transport against a real MCP server.** This is the one blocking item. The transport's request path is fully covered through an injected opener, but tested-without-a-network is not verified-against-reality. A client that mis-implements the handshake will mis-*read* servers rather than fail loudly — producing confident wrong findings, which is the worst possible output for this component.

**Source targets from public registries, not scanning.** A server listed in a directory advertised itself; an unlisted endpoint found by port-scanning did not. Start with the former — it's a large enough population for a PoC and avoids the entire question.

**Publish an abuse contact** and pass it via `--contact`. It goes in the User-Agent on every request, so an operator who wants you to stop has an obvious way to say so. Honour it via `--opt-out`.

**Expect the false-positive rate to be the product.** Per the identity-hashing bug, a detector that fires on every routine release gets switched off. The first weeks of output should be read as detector calibration, not as intelligence.

---

## 3. Public decoy fleet

Internet-exposed infrastructure that exists to be attacked. This is a programme, not a deployment, and the checklist below is not optional ceremony — most items exist because the failure mode harms a third party rather than us.

```bash
fly apps create <neutral-name>
fly deploy -c deploy/fly.toml
fly scale count 6 --region iad,lhr,syd,gru,jnb,sjc
```

Fly maps onto `Fleet.deploy(REGIONS)` almost exactly: one image, many regions, one encoding per node. Distinct VPS providers give better ASN diversity — which matters for the [topological correlation](../docs/research/distributed-honeypot-coordination.md#2-topology-as-the-sensing-instrument) — at more setup cost.

### 3.1 Pre-exposure checklist

**Isolation**
- [ ] Separate cloud account or organisation. No shared credentials, no shared network, nothing else in it. ([§14.1.9](../docs/BUSINESS_PLAN.md#1419-sacrificial-adversarial-research-infrastructure))
- [ ] Default-deny egress. The decoy has no outbound need at all, which makes this easy — and it's what stops a convincing decoy from becoming a stage in someone else's attack. Research honeypots have been used against third parties before.
- [ ] Container runs unprivileged, read-only root filesystem where the platform supports it.

**Identity and disclosure**
- [ ] Neutral domain, unassociated with the company. A server handing out fake AWS keys on a branded domain will eventually be reported as a real breach by a researcher acting in good faith.
- [ ] `security.txt` with a monitored abuse contact.
- [ ] Known-researcher and scanner allowlist, so measurement projects are classified separately rather than counted as adversaries. ([§10.5](../docs/research/decoy-agent-infrastructure.md#105-researcher-and-scanner-deconfliction))

**Data**
- [ ] Handling policy for third-party data *before* launch, not after the first interesting session. Attacker traffic will contain other people's credentials and content.
- [ ] Extracted system prompts treated as sensitive evidence — they may identify the operator or their targets. Not published verbatim.
- [ ] Retention and deletion schedule.

**Payloads**
- [ ] `assert_inert()` is enforced in code and tested, but re-read every payload before exposure. Every one must reference only the serving node — never a third party, never a network location.
- [ ] Honeytokens carry no real access. Verify the fake AWS-style keys aren't valid anywhere.

**Legal**
- [ ] Counsel review. Deception infrastructure, interception, and retention are treated differently across jurisdictions, and a multi-region fleet spans several by design.

**Operations**
- [ ] Monitoring of the decoys themselves. They are attacker-facing hosts; assume one will eventually be compromised and make sure that's detectable. ([§14.1.10](../docs/BUSINESS_PLAN.md#14110-security-telemetry-for-bitorus-itself))
- [ ] Log egress to a collector the decoy cannot reach or rewrite. ([observation-architecture.md §3](../docs/research/observation-architecture.md#3-egress-the-half-everyone-underrates))
- [ ] Rebuild-from-image procedure, so a suspect node is replaced rather than investigated in place.

### 3.2 Expected yield

Set expectations before, not after. Palisade observed **8 candidate agents in 8.13M attempts over ~3 months** on SSH. MCP should invert that ratio — far lower volume, far higher agent fraction, because only agent infrastructure speaks the protocol — but the absolute *n* will still be small.

Which means: multi-node from day one, long horizons, and real caution about statistical claims. This is explicitly a bet on rising agentic-attack prevalence. The 2026 evidence supports the bet; it does not guarantee it. If volume stays flat, the ecosystem monitor becomes the load-bearing product instead — which is the honest hedge, and a good one, because it pays off regardless of what attackers do.
