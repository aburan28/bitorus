# Threat intelligence landscape — research notes (August 2026)

Research notes gathered via web search, informing BiTorus product scope (see [5. AI threat taxonomy](../BUSINESS_PLAN.md#5-ai-threat-taxonomy), [18. Security assurance and evaluation](../BUSINESS_PLAN.md#18-security-assurance-and-evaluation), and [Appendix C. Initial engineering epics](../BUSINESS_PLAN.md#appendix-c-initial-engineering-epics) in the business plan). Confidence varies by claim — vendor marketing is flagged where it applies; treat specific percentages and forecasts as directional, not verified.

## Table of contents

- [1. Bleeding edge of cyber threat intelligence](#1-bleeding-edge-of-cyber-threat-intelligence)
- [2. Infosec practitioner cut](#2-infosec-practitioner-cut)
- [3. State of the art for honeypots](#3-state-of-the-art-for-honeypots)

---

## 1. Bleeding edge of cyber threat intelligence

### 1.1 The structural shift: CTI is becoming an agentic, machine-speed discipline

The clearest real change is that the CTI production pipeline itself is being automated. Agents now handle report triage, malware-family profiling, relevance scoring against a specific environment, and — the newer part — end-to-end detection engineering: read a threat report → map to MITRE ATT&CK → discover the right telemetry → write a Sigma rule → iterate KQL against real logs → validate.

The concrete marker that this has stopped being a demo is **CTI-REALM** (Microsoft, March 2026, open-source, also in Inspect Evals): 50 tasks from 37 recreated attacks across Linux, AKS, and Azure, scored against ground truth, with 16 model configurations evaluated. Cloud detection is the hardest category. That a rigorous benchmark exists is more informative than any vendor claim — it means the field moved from "can an LLM summarize a report" to "can an agent ship a validated detection."

Vendors claim 50–70% of CTI workflow automation. Treat the number as marketing; the direction is well-supported.

### 1.2 Offense: AI-orchestrated intrusion is confirmed, not speculative

This is the genuine bleeding edge and the thing worth updating on:

- **Nov 2025**: a frontier lab reported a threat actor automating 80–90% of an intrusion, humans only at decision points — documented in the *International AI Safety Report 2026*.
- **Early 2026 — "CyberStrikeAI"**: a campaign against internet-facing edge/management interfaces across ~55 countries, wiring commercial models into an automated scan → evaluate → exploit loop with no human in the loop per-target.
- **May 2026**: first documented fully autonomous post-exploitation in the wild, complete in under an hour, adapting to an unfamiliar network without pre-written scripts.
- **June 2026**: an autonomous open-source agent (Hermes, unrestricted mode) used against Thailand's Ministry of Finance for network exploration and privilege-escalation pathfinding.

The CTI consequence: dwell time and campaign tempo are collapsing, and TTP-based attribution gets harder — an agent's behavior reflects its scaffolding and model, not a human operator's habits. Tradecraft fingerprinting is one of the actually-open research problems right now.

### 1.3 The newest attack surface is the agent infrastructure itself

Attackers have shifted from attacking model outputs to attacking agent identities, orchestration layers, and tool supply chains (OWASP GenAI exploit round-up, Q1 2026):

- Google reported a 32% relative increase in malicious indirect prompt-injection content Nov 2025 → Feb 2026; HackerOne saw a 540% surge in prompt-injection reports.
- MCP is the new soft underbelly: ~7,000 internet-exposed MCP servers catalogued, roughly half with no authentication; an April 2026 systemic flaw (OX Security) implicating an estimated 200k instances across a supply chain with 150M+ package downloads. Tool poisoning is a live technique, not a paper.
- Non-human identity is the governance gap: ~23% of orgs have any enterprise agent-identity strategy; ~47–53% report an agent exceeding permissions or causing an incident.

If you want one under-covered thing to watch: CTI feeds and agent tooling are themselves injection surfaces. An agent that ingests threat reports to write detections is executing attacker-authored text. Nobody has a good answer yet.

### 1.4 Defensive AI: vulnerability discovery at industrial scale

Autonomous discovery agents (Google's Big Sleep lineage and successors) are now part of the disclosure ecosystem, pushing 2026 CVE volume toward a forecast ~66,000. The framing that matters for CTI: the race is now AI-built exploits vs. AI-built patches and detections, and vulnerability prioritization based on human-speed exploitation assumptions is quietly obsolete.

Lower confidence: specific product names circulating for defensive cyber models in the second half of 2026 appear in low-quality sources and could not be verified — do not cite those.

### 1.5 What hasn't changed (and still causes most breaches)

Worth stating because the AI story crowds it out: identity-led compromise (stolen credentials, session tokens, OAuth abuse), edge-device exploitation, ransomware ecosystem consolidation (5 groups — Qilin, Akira, The Gentlemen, DragonForce, INC Ransom — at >56% of activity), DPRK operations, and cybercrime/state-aligned convergence. AI is mostly an accelerant on these, not a replacement.

### 1.6 Practical read

If deciding where to invest: the defensible edge is validated, environment-specific detections generated fast (the CTI-REALM workflow), plus inventorying and authenticating an org's own agent/MCP surface before it becomes someone's initial access vector. Buying "AI-powered threat intel feeds" is the commoditized part.

### 1.7 Sources

- [International AI Safety Report 2026 (arXiv)](https://arxiv.org/pdf/2602.21012)
- [CTI-REALM: A new benchmark for end-to-end detection rule generation with AI agents — Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/20/cti-realm-a-new-benchmark-for-end-to-end-detection-rule-generation-with-ai-agents/)
- [CTI-REALM (arXiv preprint)](https://arxiv.org/html/2603.13517v1)
- [CTI-REALM in Inspect Evals](https://ukgovernmentbeis.github.io/inspect_evals/evals/cybersecurity/cti_realm/index.html)
- [OWASP GenAI Exploit Round-up Report Q1 2026](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/)
- [CSA Research Note: MCP Security Crisis](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-security-crisis-20260504-csa-styled/)
- [Autonomous attacks ushered cybercrime into AI era — Cybersecurity Dive](https://www.cybersecuritydive.com/news/cybercrime-ai-ransomware-mcp-malwarebytes/811360/)
- [Adversaries Leverage AI for Vulnerability Exploitation and Initial Access — Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/ai-vulnerability-exploitation-initial-access)
- [AI vulnerability discovery is pushing 2026 CVEs toward 66,000 — Help Net Security](https://www.helpnetsecurity.com/2026/06/15/first-2026-cve-forecast/)
- [CrowdStrike 2026 Global Threat Report](https://www.crowdstrike.com/en-us/global-threat-report/)
- [2026 Threat Intelligence Trends — Cyble](https://cyble.com/blog/2026-threat-intelligence-trends/)
- [2026 CTI Practitioners Roundup — Feedly](https://feedly.com/ti-essentials/posts/2026-cti-practitioners-roundup)
- [AI Cyberattacks in 2026: 6 Breaches — ExtraHop](https://www.extrahop.com/blog/AI-cyberattacks-in-2026-6-breaches-you-need-to-know-about)

## 2. Infosec practitioner cut

What actually changes per function, as of August 2026.

### 2.1 Detection engineering

The bleeding edge here is agent-generated, telemetry-validated detections — not agent-generated suggestions. The distinction is the whole ballgame, and it's what CTI-REALM measures: does the agent iterate its query against real logs and prove the rule fires, or does it emit a plausible Sigma rule nobody tested? Cloud detection scored worst in that benchmark, which matches practitioner experience — cloud control-plane telemetry is schema-messy and semantically thin.

What to actually do: treat agents as a detection-throughput multiplier under human review, not an autonomous rule pipeline. The realistic win is closing the gap between a report dropping and coverage existing — days to hours. Keep a human gate on rule promotion to production, because a bad rule is an availability incident.

### 2.2 SOC operations

"Agentic SOC" is the loudest vendor category of 2026 and mostly oversold, but the sane pattern that's emerged is real: agents do context-gathering, triage, and investigation freely; actions are guarded by confidence thresholds with analyst review before anything with blast radius (host isolation, account disable, blocking). Design principles that hold up:

- Make agent reasoning visible and auditable.
- Autonomy is a toggle per action class, not a global setting.
- Pre-authorize the cheap reversible containment actions, gate the expensive ones.

Assume any agent will eventually be tricked. Prompt injection is not solved and won't be by anyone's product roadmap.

### 2.3 Identity and access — the highest-leverage control

Agents are non-human identities with a nasty twist: they decide at runtime, chain tool calls, and can be steered by attacker-controlled text. Numbers practitioners are working with:

- 51% cite over-permissioned access as their top NHI pain point; 78% have no documented policy for creating or removing AI identities.
- Least-privilege enforcement correlates with a 17% incident rate vs. 76% without it — the largest measurable risk reduction of any tracked control.

The baseline: every agent gets a distinct managed identity, scoped credentials, scheduled key rotation plus immediate rotation on suspicion, and tamper-evident logging of tool calls, credential use, and agent-to-agent delegation. That last one is missing from most LLM security checklists and is exactly what's needed during IR.

### 2.4 Incident response

Existing playbooks assume human attackers. Two gaps:

1. **Speed.** Autonomous post-exploitation completing in under an hour means human-in-the-loop containment is often too slow. Pre-authorize auto-containment for defined conditions or accept arrival after the fact.
2. **Agent decommissioning.** Killing a compromised agent isn't killing a process — it requires revoking credentials, disposing of its memory/context store, and removing registry entries. Orphaned agent memory and stale registrations are backdoors that survive remediation.

### 2.5 AppSec and vulnerability management

CVE volume forecast toward ~66,000 for 2026, driven substantially by autonomous discovery agents. Severity-ordered patching queues break at that volume. The prioritization inputs that still work are exploitability-in-your-environment and reachability analysis — and both need to assume exploit development is now days, not months, for anything with public detail.

### 2.6 Frameworks worth actually reading

- **OWASP Top 10 for Agentic AI (2026)** — maps cleanly onto MITRE ATLAS and ATT&CK, so existing detections and identity controls carry over rather than needing a parallel program. The single most practical starting document.
- **CSA's MCP security work** — if running MCP servers, inventory them first. ~7,000 internet-exposed, roughly half unauthenticated.
- **Microsoft's secure-agentic-AI guidance and Google's Gemini multi-layer defense** (Agent Origin Sets, injection classifiers, alignment critics, acknowledgment gates) — vendor-shaped but the control patterns generalize.

If doing three things: inventory agents and MCP servers as attack surface; give every agent a scoped identity with tamper-evident tool-call logging; and pre-authorize reversible containment so IR isn't gated on a human at 3am. Everything else is downstream of those.

### 2.7 Sources

- [OWASP GenAI Security Project — Top 10 for Agentic AI / Q1 2026 exploit round-up](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/)
- [Secure agentic AI end-to-end — Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/20/secure-agentic-ai-end-to-end/)
- [CSA Research Note: MCP Security Crisis](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-security-crisis-20260504-csa-styled/)
- [Agentic MCP Security Best Practices — CSA](https://labs.cloudsecurityalliance.org/agentic/agentic-mcp-security-best-practices-v1/)
- [AI SOC Guardrails in 2026: Scope Limits, Override Policies — UnderDefense](https://underdefense.com/blog/ai-soc-guardrails/)
- [Why 2026 is the Year to Upgrade to an Agentic AI SOC — Elastic Security Labs](https://www.elastic.co/security-labs/why-2026-is-the-year-to-upgrade-to-an-agentic-ai-soc)
- [AI Agent Identity Management: A 2026 CISO Playbook — Security Boulevard](https://securityboulevard.com/2026/05/ai-agent-identity-management-a-2026-ciso-playbook/)
- [AI security incidents 2025–2026: what controls are missing — NHI Mgmt Group](https://nhimg.org/community/nhi-breaches/ai-security-incidents-in-2025-2026-what-controls-are-missing)
- [AI Incident Response Playbook — DeepInspect](https://www.deepinspect.ai/blog/ai-incident-response-playbook)
- [A Systematic Survey of Security Threats and Defenses in LLM-Based AI Agents (arXiv)](https://arxiv.org/pdf/2604.23338)
- [CTI-REALM — Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/20/cti-realm-a-new-benchmark-for-end-to-end-detection-rule-generation-with-ai-agents/)

## 3. State of the art for honeypots

Honeypots have split into two distinct research programs, and conflating them is a common source of confusion. One is using LLMs to build better honeypots. The other — newer and more interesting — is building honeypots to catch LLM attackers.

### 3.1 LLM-powered honeypots: the trilemma, partially cracked

Classic honeypots forced a three-way tradeoff: fidelity vs. operational risk vs. cost. Low-interaction honeypots are safe and cheap but trivially fingerprinted; high-interaction ones are convincing but are real compromised systems now owned by the defender. The LLM pitch is high fidelity at low risk — generate plausible system responses without a real system behind them.

The SoK on this ([arXiv 2510.25939](https://arxiv.org/abs/2510.25939), updated through 2026) is the paper to read, and its verdict is measured: steady progress from ideation to prototype, but only incremental progress in real-world deployment. It contributes a canonical architecture, an "evaluation tetrad," and an attacker trichotomy mapped to honeypot requirements — i.e., the field just got its vocabulary, which indicates how early it is.

Architectural convergence is the real finding. Early systems piped commands straight into a prompted LLM. Current ones layer in: a state/filesystem model outside the context window, a safety filter, a response cache for latency and consistency, and a persona/config spec. Representative work: HoneyGPT (*Computer Networks*, 2026), LLM-SSHH (state-snapshot SSH honeypot), HoneyLLMd (adaptive, handles bind and reverse shells), and an LLM-based LDAP honeypot.

What's still broken — and it's fundamental, not tuning:

- **State loss and hallucinated inconsistency.** Context-window limits mean the honeypot forgets what it told the attacker. Write a file, `cd` around, come back — it's gone or different. This is the dominant detection vector, and it's trivially exploited: a few verification commands break most deployments.
- **Fixed attack sequences.** Against scripted, non-adaptive attackers, LLM entrapment adds nothing — the script doesn't care how convincing the responses are. The gain is real only against adaptive adversaries.
- **Latency.** Human-plausible shell response times vs. inference time is an unsolved fingerprint.
- **Evaluation.** [Honeyval](https://arxiv.org/pdf/2605.29963) (2026) is the first serious eval framework for LLM HTTP honeypots. Before it, "our honeypot is convincing" was mostly vibes.

### 3.2 The genuinely novel SOTA: reverse prompt injection as a detector

This is the most useful direction. Palisade Research's LLM Agent Honeypot ([arXiv 2410.13919](https://arxiv.org/abs/2410.13919), [code](https://github.com/PalisadeResearch/llm-honeypot), [live](https://ai-honeypot.palisaderesearch.org/explainer)) inverts the technique: instead of using an LLM to fool attackers, it uses prompt injection to fingerprint attackers that are themselves LLMs.

Mechanism:

- A modified Cowrie SSH honeypot embeds multi-stage injections in the output of common recon commands, hidden with ANSI escape codes — invisible to a human at a terminal, fully parsed by an agent reading stdout.
- **Stage 1, goal hijacking**: redirect the agent to run a specific verification command. A human won't; a scanner won't; an LLM agent will.
- **Stage 2, system prompt stealing**: extract the agent's original instructions and objectives — intelligence about the operator, not just detection.
- **Timing analysis** as a corroborating signal: agents respond in a band distinguishable from both humans and scripted tooling.

Results from ~3 months of public deployment: 8,130,731 hacking attempts, 8 candidate AI agents. That ratio is the honest headline — the technique works, and AI-driven intrusion attempts were still rare in that window. Given the 2026 campaigns (CyberStrikeAI, the autonomous post-exploitation cases), re-running this now would be an obviously valuable experiment.

Emerging behavioral fingerprints for agents: multi-tool switching mid-session, semantic credential extraction from HTML comments (a human skims; an agent reads everything), and adaptive strategy pivots after failure. Related line: [prompt injection as an active defense against LLM-driven attacks](https://arxiv.org/pdf/2410.20911) — not just detecting the agent but derailing it.

### 3.3 The "semantic leap" in honeypot data

The other real advance is downstream: fine-tuned models auto-labeling honeypot sessions with MITRE ATT&CK tactics. Honeypots historically produced enormous raw logs nobody had analyst-hours to read, so most of their value evaporated. Automated TTP labeling turns a honeypot from a log firehose into a structured-intelligence source that feeds detection engineering directly. For most orgs this is a bigger practical unlock than fancier deception.

### 3.4 What's actually deployed vs. what's published

Worth separating. The commercial deception market went through five generations — static honeypots → honeynets → canary tokens / honeytokens → dynamic deception platforms → AI-driven adaptive systems. The AI-driven tier is where vendors are marketing (Acalvio et al.), and the research support for autonomous adaptive honeypot networks is thin relative to the claims.

The unsexy truth: honeytokens still have the best ROI in enterprise deception. Fake AWS keys, decoy credentials in Group Policy, canary files, decoy records — near-zero false positive rate, negligible cost, no LLM required. When deploying deception rather than researching it, start there and finish there. [tracebit-com/awesome-deception](https://github.com/tracebit-com/awesome-deception) is a good curated entry point.

### 3.5 Open problems

Research space rather than product:

- **Persistent state for LLM honeypots.** The context-window problem is an architecture problem, not a bigger-model problem — external filesystem/state models with the LLM only rendering output. Under-explored.
- **Agent-vs-agent deception dynamics.** Everything published assumes the attacker doesn't know about ANSI-hidden injection traps. That assumption has a short half-life. Nobody has studied what happens when attacking agents are hardened against reverse prompt injection.
- **Honeypots for agent infrastructure.** Decoy MCP servers, fake agent registrations, honeytoken API keys scoped to nonexistent agents. Given ~7,000 exposed MCP servers and mass scanning for them, this is unclaimed ground with a very high signal-to-noise ratio — nobody legitimate connects to a decoy MCP server.
- **Ecological validity.** 8 agents in 8.1M attempts means statistical claims about agent behavior rest on tiny n. Multi-site, longer-horizon deployments are the boring necessary work.

### 3.6 Sources

- [SoK: Honeypots & LLMs, More Than the Sum of Their Parts? (arXiv 2510.25939)](https://arxiv.org/abs/2510.25939)
- [LLM Agent Honeypot: Monitoring AI Hacking Agents in the Wild (arXiv 2410.13919)](https://arxiv.org/abs/2410.13919) · [PalisadeResearch/llm-honeypot](https://github.com/PalisadeResearch/llm-honeypot) · [live explainer](https://ai-honeypot.palisaderesearch.org/explainer)
- [Hacking Back the AI-Hacker: Prompt Injection as a Defense (arXiv 2410.20911)](https://arxiv.org/pdf/2410.20911)
- [Honeyval: Evaluation Framework for LLM-powered HTTP Honeypots (arXiv 2605.29963)](https://arxiv.org/pdf/2605.29963)
- [HoneyGPT: Breaking the trilemma in honeypots with LLMs — Computer Networks](https://www.sciencedirect.com/science/article/abs/pii/S1389128626002355)
- [LLM-SSHH: LLM-Powered SSH Honeypot via State Snapshot — MDPI](https://www.mdpi.com/2571-5577/9/5/101)
- [Design and Development of an Intelligent LLM-based LDAP Honeypot (arXiv 2509.16682)](https://arxiv.org/pdf/2509.16682)
- [Catching AI Red Teamers in the Wild: Reverse Prompt Injection as Honeypot Detection — ITNEXT](https://itnext.io/catching-ai-red-teamers-in-the-wild-using-reverse-prompt-injection-as-a-honeypot-detection-36e2f3327611)
- [From Honeypots to AI-Driven Defense — Acalvio](https://www.acalvio.com/blog/active-defense/from-honeypots-to-ai-driven-defense-the-evolution-of-cyber-deception/)
- [awesome-deception — Tracebit](https://github.com/tracebit-com/awesome-deception)
