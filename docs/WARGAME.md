# Paddock Wargame: the version people pay for

> **Paddock Wargame answers one question with evidence: can anyone reach what
> you care about, and is the door proven shut?** It works backward from your
> crown jewels over a model of your environment, proves every hop it claims,
> proves every closed route it claims, and never runs an exploit against
> anything.

This document turns the Wargame row in [VISION.md §5](VISION.md) into a
product spec and a business case. It stays inside the hard rules in
[SECURITY.md §6](../SECURITY.md), [README](../README.md) and
[CONTRIBUTING](../CONTRIBUTING.md). Where an idea would cross them, it is
listed under [Decisions for the owner](#11-decisions-for-the-owner) rather
than assumed.

Market facts below came from secondary sources gathered in November 2026.
Anything marked *(verify)* needs a primary source before it goes in a pitch.

---

## 0. What changed from the first draft, and why

| First draft | This version | Why |
|---|---|---|
| Run the real exploit on a sandboxed replica | **Replica verification**: prove the exploit's *preconditions* on a replica, then prove the fix removes them **and doesn't break the service** | Running PoCs breaks SECURITY.md §6, CONTRIBUTING and the PR safety gate. Preconditions give buyers most of the proof value. "The patch won't take down the infusion-pump gateway" is what hospital and plant change boards actually block on. |
| Solver proves "no path" | Solver proof **plus a certificate, stated assumptions and an expiry**, re-proved on every change | A proof without assumptions is the credibility trap the first draft warned about. Make the assumptions part of the artifact. |
| Sentry cross-checks the solver | **Impossible traffic**: any flow the model says can't exist is a top-severity alert | Turns the twin's biggest weakness (drift, missed devices) into its sharpest detection, and it heals the model. |
| Continuous, against a twin | Also **before** changes: a gate on firewall changes and IaC PRs | PCI 11.4.5 requires a segmentation test *after every segmentation change*. Prevention is what network and cloud teams pay for. |
| Minimal set of fixes | **Cost-weighted** minimal cut with compensating controls for what can't be patched | A PLC can't be patched on Tuesday, but its conduit rule can change. |
| "Share of paths proven closed" | **Crown-Jewel Closure** reported next to **Model Coverage** | A closure number without a coverage number is the stat that gets you sued. |
| Sell to CISOs | Sell **evidence artifacts** to the people who have to produce them: QSAs, OT and network engineers, change boards, insurers | A dashboard is optional. An auditor-accepted segmentation report is a line item. |

The positioning line stays, made concrete:

> Strix tells you an app has holes. Paddock tells you whether anyone can reach
> what you care about, **proves each step without exploiting anything, proves
> the fix before it ships, and alarms the moment reality disagrees with the
> proof.**

---

## 1. The ethics decision on Part 2: replica verification, not replica exploitation

**Recommendation: Paddock never executes exploit code, not even against its
own replicas.** Replicas are used to prove the conditions an exploit needs,
and to prove a fix.

Why hold the line when nothing real is touched:

1. **It's the moat, not a handicap.** SECURITY.md §6 says it: "A detector that
   cannot be turned into a weapon has a dramatically smaller blast radius if
   it is itself compromised." Wargame already produces a ranked map of routes
   to the crown jewels. Pair that with a working exploit runner and you've
   built the attacker's kit, one compromise away from being used for real.
2. **Buyers in regulated sectors can approve it.** Hospital and utility
   security reviews ask "can this tool attack?" A plain *no* closes the deal
   faster than "only in a sandbox".
3. **The proof value is mostly in the preconditions.** A CVE is exploitable on
   a hop when the version is in range, the vulnerable feature is enabled, the
   vulnerable code is reachable from the exposed interface, and the interface
   is reachable from the previous hop. Paddock can prove each of these without
   a payload. Assessor already does version and config proof, and
   `codeanalysis/` already does call-graph reachability.
4. **Real exploit evidence can still enter the graph**, labelled with its
   source. A customer's pentest firm, their own Strix runs, or their red team
   can import results through the existing SARIF and universal ingest. Paddock
   records the evidence and never runs it.

### What replica verification does

For each suspect hop whose component can be rebuilt (container image, SBOM
plus IaC, the customer's own code):

1. **Rebuild** the component in an isolated sandbox with no network egress,
   from the customer's own artifacts: same image digest, same config, secrets
   replaced by synthetic values. No production data goes in.
2. **Prove the preconditions** with the existing safe-check envelope (GET,
   HEAD, TLS handshake, TCP connect, banner read) plus inspection of the
   filesystem and package DB: the version is in range, the flag is on, the
   endpoint is exposed, the vulnerable function is reachable.
3. **Apply the proposed fix to the replica** (Farrier's diff).
4. **Prove two things:** the preconditions are gone, and the service still
   passes its health and smoke checks (the customer's own, or ones generated
   from observed traffic shapes).
5. **Record** the replica's digest, the checks run and the results as
   evidence, hash-chained like every other ledger entry.

Step 4 is the selling point the first draft missed. Hospitals and plants
mostly know what's vulnerable. They don't patch because they can't prove the
patch is safe. "This fix closes the route and the service still works" gets a
change approved.

---

## 2. The product: six capabilities

### 2.1 Backward search from crown jewels → the minimal cut

- **Crown jewels** come from what exists today (`metadata.crown_jewel`,
  cloud tags, ServiceNow criticality, data-store classification) plus a
  required onboarding step. In the first session the customer names up to 10
  jewels and why each one matters (cardholder data, patient records, safety
  PLC, signing keys).
- **Search runs backward** over a **directed, rule-aware** graph: from each
  jewel, find every predecessor that can reach it. Entry points include
  identities and third parties as well as network edges: vendor VPN
  accounts, remote-support tools, shared admin credentials (detected, never
  tested), and guest and IoT segments.
- **Output: the cost-weighted minimum cut.** Each candidate fix carries a cost
  (change risk, downtime, team, whether a patch is even possible). The
  solver returns the cheapest set of changes that severs every route:
  "these 3 changes close 41 of 44 routes to the CDE, and the other 3 need a
  vendor patch." In OT and medical environments it prefers compensating
  controls (a conduit rule, an allowlist, a Sentry watch) over patches.
- Everything off a route to a jewel is shown as *not on a crown-jewel route*.
  It's still findable, but it no longer competes for attention.

### 2.2 Prove each hop: the evidence ladder

Every edge and every route carries exactly one label. The labels are strict
and shown everywhere, including reports and the API.

| Label | Meaning | Source |
|---|---|---|
| **Observed** | Traffic on this hop was seen | Sentry / `can_reach_observed` |
| **Proved (config)** | The solver shows the rules permit it | Firewall, cloud and route model |
| **Proved (replica)** | Exploit preconditions confirmed on a rebuilt copy | Replica verification |
| **Proved (live safe check)** | Preconditions confirmed on the in-scope asset with the safe-check envelope | Assessor |
| **Imported** | A third party demonstrated it | Pentest or red-team result via ingest, attributed |
| **Inferred** | The graph suggests it; nothing has proved it | Heuristics, fingerprints |
| **Unknown** | The model can't see this part | Coverage gap |

A route is only as strong as its weakest hop, and the UI says so: "Proved
except hop 3 (inferred: proprietary PLC firmware)."

### 2.3 Prove closed routes stay closed: certificates, not claims

- **The solver** works over the full rule semantics (priority, deny, CIDR and
  security-group references, NACLs, route tables, NAT), not the current
  "world-open" summaries. The approach follows AWS's Tiros/Zelkova and
  Batfish: SMT/Datalog over the parsed config, no packets sent.
- **Each "closed" verdict ships as a certificate** containing:
  - the claim (*no route from guest Wi-Fi to the CDE on any port*),
  - the exact config snapshot hashes it was proved against,
  - the **stated assumptions** (*no unmodelled links; physical and serial
    paths out of model; no compromised firewall; identity paths modelled only
    for listed IdPs*),
  - the **corroboration window** (*Sentry observed 0 flows across this
    boundary in 30 days on 3 sensors*),
  - an **expiry**: it re-proves on every config change and at least daily, and
    a lapsed certificate shows as lapsed.
- Certificates are signed and hash-chained using the existing audit anchoring,
  so an auditor or insurer can check one without access to Paddock.

### 2.4 Impossible traffic: when reality disagrees with the proof

If Sentry sees a flow across a boundary the solver proved closed, one of
three things is true: the model is missing something, a rule isn't doing what
its config says, or someone is bypassing controls. All three deserve top
priority.

- It's raised as one alert with the certificate it contradicts attached. It
  goes in as a new `behavior.py` detector alongside `iot_crosses_segment`.
- The certificate is downgraded to *contradicted* until it's resolved.
- Resolving it adds the missing device or link, so **the twin corrects itself
  from its own contradictions.** That is the answer to "one missed device
  sinks your credibility": the missed device announces itself.

No forward-searching exploit tool can make this alert, because none of them
holds a proof to contradict.

### 2.5 The change gate: prove it before it ships

- **IaC:** a CI check on Terraform and CloudFormation plans. "This PR opens a
  route from `subnet-guest` to `rds-payments` on 5432. Here's the route." It
  uses the same solver against the planned state.
- **Firewall changes:** a ServiceNow or Jira change-ticket integration
  attaches a before/after proof to every rule change. That gives you PCI
  11.4.5's "after any change to segmentation controls" evidence at the moment
  of the change.
- The gate is advisory by default and blocking by policy. It runs before the
  change is applied, so it touches nothing.

### 2.6 "Are we exposed?" in minutes

When a new KEV entry lands or an EPSS score spikes, Herald re-runs Wargame
for the affected components. The answer is a route list, not a CVE count:
"This CVE is on 14 hosts, and 2 sit on a route to a crown jewel. Here's the
cut." A board asks this question after every headline vulnerability, and
today it takes a team a week.

---

## 3. The numbers: Crown-Jewel Closure and Model Coverage

Report two numbers together, never one alone:

- **Crown-Jewel Closure** = proved-closed (entry, jewel) pairs ÷ all
  (entry, jewel) pairs in model. It's broken down by label: *proved closed /
  open-proved / open-inferred / unknown*.
- **Model Coverage** = share of observed devices and flows the model explains,
  plus a list of known blind spots (serial links, out-of-band management,
  sites with no sensor).

Board line: *"91% of routes to cardholder data are proved closed, over a model
that explains 97% of observed traffic. The remaining 4 open routes have
scheduled fixes, and 2 are proved on replicas."* That sentence is the product.
The trend line is what a CISO shows the board each quarter, and what an
insurer asks for at renewal.

---

## 4. Who pays, for what

Ranked by how fast they pay. "Trigger" is the event that unlocks budget.
"Artifact" is the thing they'd hold up in a meeting.

| # | Buyer | Trigger | Artifact they pay for | Today's alternative |
|---|---|---|---|---|
| 1 | **PCI service providers and multi-site retail and hospitality** (network or compliance lead; QSA is the influencer) | 11.4.5 annual segmentation test, 11.4.6 every 6 months for service providers, plus re-tests after every segmentation change | Continuous segmentation certificates per CDE boundary, change-gate proofs per change, and an evidence pack for the QSA | Manual segmentation pentest, roughly $12–25k per engagement *(verify)*, stale the day after |
| 2 | **Hospitals and health systems** (CISO, clinical engineering, change board) | Flat networks full of unpatchable medical IoT; the proposed HIPAA rule adds segmentation and annual testing *(not final)*; ransomware | Routes from guest and clinical Wi-Fi to the EHR and PACS; fixes proved on replicas not to break; impossible-traffic alerts | Passive asset tools that show devices but not routes; production pentests they won't allow near devices |
| 3 | **Utilities, water and manufacturing** (OT security lead, plant engineer) | IEC 62443 zones and conduits, NERC CIP-005 and CIP-015 INSM, TSA directives, insurer segmentation questions | Conduit-holds certificates per zone pair; impossible-traffic alerts across zones; Edge deployment, air-gapped | Config-file segmentation review (Dragos/Network Perception NP-View), OT twin pentest simulation (Frenos) |
| 4 | **Cyber insurers and brokers** (as a channel, not first buyer) | Underwriting is moving from self-attestation to verified evidence | Signed certificates checked without vendor access; the closure and coverage trend | Questionnaires |
| 5 | **MSPs** | Want a premium managed service | "Proven segmentation" as a monthly line item per client, via the existing MSP console | Quarterly scans |

**Lead with #1.** It has a recurring, mandated, already-budgeted test, a
named influencer (the QSA) and a clear before/after. A narrow scope (one CDE,
a handful of firewalls and a cloud account) fits a 30-day pilot. #2 and #3
share almost all of the same engine and add Sentry, which is Paddock's
strongest differentiator.

One caution from the research: PCI and DORA language still assumes a human or
production test. Position Wargame as **continuous evidence between and after
required tests, and the thing that makes the required test pass first
time**, not a replacement for it, until a QSA confirms otherwise.

---

## 5. Where this sits against the field

| Vendor (research, Nov 2026) | What they do | What Paddock Wargame does that they don't |
|---|---|---|
| Horizon3 NodeZero, Pentera, XBOW, RunSybil | Autonomous exploitation against **production** | Nothing real is exploited; proves closed routes; a regulated buyer can switch it on |
| Strix (open source) | App-level agentic pentest with PoCs | Environment-level reachability; imports Strix results as *Imported* hops |
| XM Cyber, Wiz attack paths | Graph-based attack paths, simulated | Per-hop evidence labels, replica-proven fixes, solver certificates, impossible-traffic alerts |
| Frenos (OT twin + AI simulated pentest), TopHat | OT digital twin and simulated attacks | Backward from jewels, minimum cut, replica fix proof, live passive cross-check with Sentry, IT+cloud+OT in one model |
| Dragos/Network Perception NP-View | OT firewall-config segmentation review | Continuous, sensor-corroborated, change-gated, signed certificates, IT and cloud too |
| Forward Networks, Batfish, AWS Reachability | Formal network reachability | Crown-jewel framing, vulnerability and identity hops, the fix and its proof, observation of drift |
| Tufin, AlgoSec | Firewall policy management | Proof per crown jewel rather than per rule; the attacker's view |

The lesson of Skybox (model-and-path platform, shut down February 2025 after
raising over $330M): a modelling product that produces *findings* loses. A
product that produces **evidence someone is required to have** survives. Every
capability above ends in an artifact that lands in an audit, a change ticket
or a renewal.

---

## 6. Pricing hypotheses (to test, not to publish)

Pricing follows the thing being protected, not the asset count. That makes it
predictable, and it scales with the value the buyer gets.

| Package | Unit | Hypothesis | Anchor |
|---|---|---|---|
| **Segmentation Proof** | per scoped boundary (one CDE, one PHI zone) per year | $15–30k | 1–2 manual segmentation tests per year plus re-tests after changes |
| **Wargame Site** | per site with Sentry, per year | $40–90k | OT and hospital assessments; Horizon3 tiers reportedly $25–42.5k for 500 assets *(verify)* |
| **Change Gate** | per gated repo or firewall estate | Bundled into either | Opens the door with network and platform teams |
| **MSP** | per client boundary, monthly | Wholesale of Segmentation Proof | Existing MSP console |

All of this sits in Enterprise and Edge as a new gated capability, via
`orchestrator/app/licensing.py`, as EDITIONS.md allows. Nothing that's free
today gets gated.

---

## 7. Guardrails specific to Wargame

The routes Wargame outputs are the most sensitive data Paddock holds: a ranked
map to the customer's crown jewels. Treat them like key material.

1. **No exploit execution, anywhere.** Replicas get the safe-check envelope
   and filesystem inspection only. The existing narrative rule and
   reject-token list (`attackpath.py`, `policy.py`) apply unchanged to route
   narratives: impact and fix only, never steps or commands.
2. **Replica isolation.** A replica runs with no network egress in an
   ephemeral microVM or gVisor sandbox. It's built only from the customer's
   own artifacts, with secrets replaced by synthetic values and no production
   data, and it's destroyed after verification. Replica builds are
   scope-checked like targets: the artifact must belong to an in-scope
   asset.
3. **The route map is classified.** Routes inherit the highest classification
   on them (the existing ABAC). Full route exports need four-eyes approval and
   are audited. Reports for auditors and insurers carry certificates and
   counts, not topology.
4. **Read-only inputs.** Firewall, cloud and IdP connectors stay read-only.
   The change gate comments and blocks; it never applies a change.
5. **Honest outputs.** Every "closed" carries its assumptions and expiry.
   Every route shows its weakest label. Anything that can't be proved says
   *inferred* or *unknown*, never *closed*. This follows VERIFICATION.md's
   "No false 'fixed'".
6. **Warden watches Wargame.** The agent may only call the solver, read the
   twin, request replica verification, and request live safe checks through
   Assessor under the normal scope and proof-of-control rules. It has no other
   tools. Unsafe-action attempts are scored in evals and must be zero.

---

## 8. What it's built from

| Exists today | Needs building |
|---|---|
| Attack-path engine (`correlation/app/engine/attackpath.py`): forward Dijkstra, undirected | **Directed, rule-aware graph, backward search, cost-weighted min-cut** |
| Cloud connectors (`aws.py`, `gcp.py`, `azure.py`) reduce rules to world-open summaries | **Full rule models** (priority, deny, references, NACLs, routes) and on-prem firewall parsers (Palo Alto, Fortinet, pfSense/OPNsense first) |
| None | **Solver** (SMT or Datalog) with certificates, assumptions and expiry |
| Sentry `can_reach_observed`, `behavior.py` detectors | **Impossible-traffic detector** against certificates |
| Assessor version, config and reachability proof; safe checks; verification ledger | **Replica verification** sandbox and runner; health and smoke checks after fix |
| Farrier remediation, gate and GitHub PR | Fix applied to replica before PR; change-gate CI check and ticket integration |
| Provenance (`provenance.py`), audit anchoring | Evidence-ladder labels on edges and routes; signed certificates |
| Crown-jewel heuristics, CMDB criticality | Required crown-jewel onboarding |
| SARIF and universal ingest | Map third-party pentest results to *Imported* hops |
| Eval harness (`hardening/evals/`) | **Digital-twin ranges**: synthetic orgs with known open and closed routes, so closure claims are measured before they're sold |

**Build order** (each step ships something sellable):

1. Rule models, solver and certificates for **one cloud plus one firewall
   vendor** → Segmentation Proof for buyer #1.
2. Change gate for Terraform and firewall tickets.
3. Backward search, min-cut and the evidence ladder over the existing graph.
4. Impossible-traffic detection with Sentry → buyers #2 and #3.
5. Replica verification for containers and the customer's own code.
6. "Are we exposed?" via Herald.

---

## 9. How we get from "should sell" to "certain it sells"

Certainty doesn't come from a document. It comes from design partners paying.
The test, run with the 3–5 pilots already planned in READINESS.md:

**Pass (build on):**
- At least **2 of 5** partners convert to paid at the hypothesis price within
  60 days.
- At least **1 QSA** accepts the certificate pack as supporting evidence for
  11.4.5 or 11.4.6.
- The change gate catches **at least 1 real route-opening change** in a pilot.
- Impossible-traffic alerts are useful: at least 1 finds a real unmodelled
  device or rule bypass, and false positives stay under 1 per site per week
  once tuned.

**Kill or reshape:**
- Partners like the demo but won't pay without a human tester's signature →
  sell through pentest firms as their continuous-evidence layer.
- Twin coverage stays under ~90% after 30 days on a site → the certificates
  can't be trusted there. Narrow to cloud-only Segmentation Proof, where the
  model *is* the config.
- Replica builds succeed for under half of suspect hops in practice → drop
  replica verification to a later tier and lead with solver plus Sentry.

---

## 10. Honest limits

- **Proofs are about the model.** Every certificate states its assumptions,
  and Model Coverage sits next to every closure number. Impossible-traffic
  alerts shrink the gap; they don't remove it.
- **Replicas only exist for what can be rebuilt**: containers, open source,
  the customer's own code. Proprietary PLCs, infusion pumps and appliances stay
  *inferred* for their internal flaws. Their *reachability* can still be
  proved by solver and sensor, and that is usually what matters.
- **Preconditions aren't exploitation.** A hop proved on a replica means "every
  condition the exploit needs is present", not "we watched it work". Say so
  in the UI. Buyers who need demonstrated exploitation can import it from a
  human tester.
- **Identity and physical paths** (stolen sessions, serial links, a USB stick)
  are partly or wholly out of model. List them as assumptions, never as
  closed.
- **Competition is real.** Frenos (with a Claroty partnership) and Dragos's
  NP-View are close in OT. Win on IT, cloud and OT in one model, on
  certificates plus sensor corroboration, and on the change gate. Don't win on
  "AI attacker" alone.

---

## 11. Decisions for the owner

1. **Confirm the Part 2 stance:** replica *verification*, not exploitation,
   which keeps SECURITY.md §6 as written. If you want replica exploitation, it
   needs an explicit amendment to SECURITY.md §6, README, CONTRIBUTING and the
   PR safety gate. Section 1 explains why this doc recommends against it.
2. **Lead wedge:** PCI Segmentation Proof first (recommended), or OT first.
3. **Landing page:** Wargame would be a fifth agent card and the copy says
   "Four agents". The landing UI is owner-protected, so nothing has been
   changed there.
4. **Pricing hypotheses** in §6, to take into pilots.
