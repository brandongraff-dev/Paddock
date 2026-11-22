# Paddock Wargame: the version people pay for

> **Paddock Wargame answers one question with evidence: can anyone reach what
> you care about, and is the door shut?** It works backward from your crown
> jewels over a model of your environment, labels every hop with the evidence
> behind it, tells your change board what each change opens and breaks before
> it ships, and never runs an exploit against anything.

This document turns the Wargame row in [VISION.md §5](VISION.md) into a
product spec and business case. It stays inside the hard rules in
[SECURITY.md §6](../SECURITY.md), [README](../README.md) and
[CONTRIBUTING](../CONTRIBUTING.md). Where an idea would cross them, it is
listed under [Decisions for the owner](#12-decisions-for-the-owner) rather
than assumed.

**How this version was made.** It was drafted from the repo's rules and a
market scan from November 2026. It was then reviewed adversarially by four
personas who would have to say yes: a hospital CISO, a PCI QSA, a utility OT
lead and a Series A investor. Every change below answers an objection one of
them raised. Market facts come from secondary sources; anything marked
*(verify)* needs a primary source before it goes in a pitch.

---

## 0. The idea, sharpened

| Original idea | This version | Why |
|---|---|---|
| Run the real exploit on a sandboxed replica | **Change-impact proof** leads. **Replica verification** (preconditions, never payloads) is a later tier for rebuildable components | Running PoCs breaks SECURITY.md §6. Clinical and OT devices can't be rebuilt anyway. What change boards block on is "what will this change open, and what will it break?", and config plus observed flows answers that for every device. |
| Solver proves "no path" | Solver proof **plus safe-check probes** across each boundary, reconciled against **observed flows**, in a three-way agreement report | "No packets sent" proves what the config *intends*. A QSA needs to see the boundary *operating*. TCP-connect probes inside the existing safe-check envelope supply that, with no exploitation. |
| A Sentry sensor everywhere | **Ingest-first**: read-only flows and assets from the tools customers already own (firewall logs, NetFlow, Zeek, Dragos, Claroty, Armis). Sentry is optional | Plants and hospitals veto new SPAN ports. Ingest gets a first route map in days, not months. |
| "Share of paths proven closed" | **Per-boundary pass/fail** for auditors; Crown-Jewel Closure for boards, always shown with a coverage figure that's honest about where the sensors are | Segmentation passes or fails per boundary, so "91% closed" reads to an auditor as a failure. |
| Minimal set of fixes | **Minimum-cost fix set** (a hitting-set problem, solved with an ILP) over (entry, jewel) pairs, with customer-chosen cost classes | Counting enumerated paths explodes combinatorially, and invented weights don't survive a change board. |
| Sell to CISOs | Sell **auditor-formatted evidence for review-type requirements**, through the pentest and QSA-aligned firms that sign the reports | Review requirements (PCI 1.2.5, 1.2.7, 12.5.2; NERC CIP-005, CIP-010) accept tool output as evidence. The partner holds the relationship and the signature. |

The positioning line, made concrete:

> Strix tells you an app has holes. Paddock tells you whether anyone can reach
> what you care about, shows the evidence behind every step, tells your change
> board what a change opens and breaks before it ships, and alarms when the
> network stops matching the proof. Nothing is ever exploited.

---

## 1. The ethics decision on Part 2: no exploit code, ever, including on replicas

**Recommendation: Paddock never executes exploit code, not even against its
own replicas.**

1. **It's the moat.** As SECURITY.md §6 puts it: "A detector that cannot be
   turned into a weapon has a dramatically smaller blast radius if it is
   itself compromised." Wargame produces a ranked map of routes to the crown
   jewels. A map plus an exploit runner is an attacker's kit.
2. **Regulated buyers can approve it.** "Can this tool attack?" gets a plain
   *no*, and that's what a hospital security committee wants to hear.
3. **The proof buyers need doesn't require it.** Change boards need
   change-impact proof (§2.3). Auditors need boundary evidence (§2.2).
   Neither involves a payload.
4. **Demonstrated-exploit evidence can still come in**, labelled *Imported*:
   pentest-firm results, the customer's own Strix runs, red-team reports, via
   the existing SARIF and universal ingest. Paddock records them and never
   runs them.

---

## 2. The product: what it does, in the order it sells

### 2.1 Backward from crown jewels → the minimum-cost fix set

- **Crown jewels** come from what exists today (`metadata.crown_jewel`,
  cloud tags, ServiceNow criticality, data-store classification) plus a
  required onboarding step: name up to 10, and say why.
- **Search runs backward** over a **directed, rule-aware** graph. Entry points
  include identities and third parties, not just network edges: vendor VPNs,
  remote-support tools, shared admin credentials (detected by fingerprint,
  never tested), guest and IoT segments, dual-homed hosts.
- **The unit is the (entry, jewel) pair and the boundary**, not enumerated
  paths.
- **The fix set** is a minimum-cost hitting set solved with an ILP: a fix is a
  rule change that removes many edges at once. Costs come from classes the
  customer sets (*rule change on a non-clinical VLAN* = low, *firmware patch
  on a clinical device* = needs vendor). Paddock doesn't invent risk weights.
  It prefers compensating controls where patches aren't possible.
- Anything off a route to a jewel is marked *not on a crown-jewel route*. It's
  still visible; it just stops competing for attention.

### 2.2 Boundary evidence: config proof, probes and observation, reconciled

Each crown-jewel boundary (CDE, PHI zone, an IEC 62443 conduit) gets three
independent kinds of evidence:

1. **Config proof (no packets).** A solver over full rule semantics: priority,
   deny, object and security-group references, NAT, route tables, NACLs. The
   approach follows Batfish and AWS Tiros. Some features are runtime state
   and can't be proved from config: App-ID and User-ID, FQDN objects, dynamic
   address groups, EDLs, SD-WAN, Kubernetes NetworkPolicy and service mesh.
   Rules that depend on them are labelled **Conditional**, never *closed*.
2. **Safe-check probes (packets, inside the rules).** A small probe agent sits
   on each out-of-scope segment. It's a deployment of the existing active
   worker, not Sentry, which stays listen-only. It runs **TCP connect and
   banner read only** against in-scope, proof-of-control-verified ranges on
   the far side, rate-capped, through the existing scope gate, egress wrapper
   and ledger. It's on by default for IT and PCI estates. It's opt-in per
   segment for OT and clinical networks, and never pointed at device ranges
   the customer marks fragile.
3. **Observed flows.** Firewall allow and deny logs, NetFlow, Zeek, Sentry,
   or the customer's Dragos, Claroty or Armis.

The **three-way agreement report** is the core artifact. For every boundary
and port class it says whether config, probe and observation agree, and if
not, which one disagrees and why. Disagreement is where the real findings
are.

### 2.3 Change-impact proof: the change board's attachment

This is the headline capability. It works for every device, rebuildable or
not.

- **Input:** a proposed firewall, ACL, NAC or security-group change, from a
  ServiceNow or Jira change ticket, or a Terraform or CloudFormation plan in
  CI.
- **Output, attached to the ticket or PR before the change is applied:**
  - **Routes it opens or closes** to each crown jewel, from the solver, before
    and after.
  - **Live flows it would break**, from 30 days of observed flows: *"This ACL
    would block 3 of 41,000 flows seen in 30 days, including the pump →
    drug-library sync at 02:00 nightly."*
  - Which regulatory boundaries it touches (CDE, ESP, zone/conduit).
- It's advisory by default and blocking by policy. It never applies anything.

This answers the question that actually stalls hospital, plant and PCI
change boards, and it's also the evidence PCI expects after a segmentation
change. Tufin and AlgoSec sell pre-change risk checks. Paddock adds crown-jewel
routes and the flows-it-breaks proof.

### 2.4 The evidence ladder

A hop can carry **several labels**: it can be Observed *and* Proved (config).
Strength is shown explicitly. Seeing traffic proves reachability, not
exploitability.

| Label | Means | Proves |
|---|---|---|
| **Proved (config)** | The solver shows the rules permit this hop | Reachability per config |
| **Tested (probe)** | A safe-check TCP connect crossed the boundary | Reachability in operation |
| **Observed** | Traffic on this hop was seen, with a completed handshake or a destination-side view | Reachability in use |
| **Proved (live safe check)** | Exploit preconditions confirmed on the in-scope asset (Assessor: version, config, exposure) | Vulnerable-and-reachable |
| **Proved (replica)** | Preconditions confirmed on a rebuilt copy (§2.7) | Vulnerable-and-reachable, for rebuildable components |
| **Imported** | A third party demonstrated exploitation, with attribution | Exploited, by someone else |
| **Conditional** | Depends on runtime state the model can't prove | — |
| **Inferred** | The graph suggests it | Nothing yet |
| **Unknown** | Outside the model | — |

Every route shows its weakest hop: "Proved except hop 3 (inferred:
proprietary PLC firmware)."

### 2.5 Impossible traffic, made quiet enough to trust

If a flow crosses a boundary that config and probes say is closed, the model
is wrong, a rule isn't enforcing, or something is bypassing controls.

To keep the alert quiet:
- **It only fires on** a completed handshake, a destination-side observation,
  or a firewall *allow* log. A source-side SYN the firewall dropped proves the
  boundary works.
- **Suppressed:** ARP, mDNS, DHCP and other L2 broadcast; load-balancer health
  checks; the firewall's own management plane; known NAT and VPN
  encapsulation.
- **A human resolves it, with a cited reason.** Paddock never auto-adds the
  edge to "heal" the model, because that could legitimise an attacker's
  tunnel. The resolution options are: *missing asset added*, *rule defect
  confirmed*, or *escalated as an incident*.
- It's a new `behavior.py` detector next to `iot_crosses_segment`. For
  utilities it's emitted as CIP-015 INSM anomaly evidence.

### 2.6 "Are we exposed?" in minutes

When a KEV entry lands or an EPSS score spikes, Herald re-runs the affected
routes. The answer: "This CVE is on 14 hosts; 2 sit on a route to a crown
jewel, and here's the fix set." Boards ask this after every headline
vulnerability.

### 2.7 Replica verification (later tier, rebuildable components only)

For components built from container images, the customer's own code or open
source:
- **Rebuild** in a no-egress microVM or gVisor sandbox from the customer's
  artifacts (same digest and config). Secrets are replaced by synthetic
  values. No production data or captured traffic payloads go in, so no PAN or
  PHI enters the sandbox.
- **Prove preconditions** with the safe-check envelope plus filesystem and
  package-DB inspection. **Apply the fix**, then show the preconditions are
  gone and the customer-supplied health checks still pass.
- **Scope is deliberately limited.** Many services won't boot without their
  database, licence server or IdP, so they're marked *not rebuildable* rather
  than faked. Precondition content covers KEV entries on crown-jewel routes
  only, to avoid a Nessus-style plugin treadmill.

---

## 3. The numbers

- **For auditors: per-boundary verdicts.** *Pass* means config, probe and
  observation all agree the boundary is closed. Otherwise the verdict is
  *fail* (with the route), *conditional*, or *insufficient evidence*. These
  are binary and dated.
- **For boards: Crown-Jewel Closure.** Proved-closed (entry, jewel) pairs ÷
  all pairs in model, broken down by label.
- **Next to every closure figure: sensor coverage**, with its limits stated:
  - Which boundaries have an observation point on the *protected* side. Zero
    flows seen from the source side alone is absence of evidence, and is
    labelled that way.
  - Asset reconciliation: twin assets versus CMDB, DHCP leases, NAC and the
    customer's IoT tool.
  - A named list of known blind spots (serial links, cellular modems,
    out-of-band management, sites with no observation point).
- **Measured accuracy.** Every release is scored on seeded **twin ranges**
  (synthetic orgs with known open and closed routes) in `hardening/evals/`.
  The false-"closed" rate is published per release. Nobody should trust a
  certificate until that number exists.

Board line: *"All 3 cardholder-data boundaries passed this quarter; config,
probes and observed traffic agree. 2 of 14 routes to the EHR are open, both
with fixes approved by the change board and scheduled."*

---

## 4. Who pays, for what, in what order

### Wedge: PCI service providers, sold through pentest and QSA-aligned firms

**Why this buyer:** a mandate with a fast cadence, and someone else already
holding the relationship and the signature. Service providers must test
segmentation every 6 months (11.4.6) and confirm scope every 6 months
(12.5.2.1).

**What they buy (continuous, auditor-formatted, hash-chained):**

| PCI DSS 4.0 requirement | Type | Paddock artifact |
|---|---|---|
| **1.2.5** allowed services, protocols and ports identified, approved, justified | Review | Every allowed flow into the CDE, with the rule, its observed use and an owner justification field |
| **1.2.7** NSC configurations reviewed at least every 6 months | Review | Continuous config review with diffs, signed per period |
| **1.3.1 / 1.3.2** inbound and outbound CDE traffic restricted | Review | Solver proof plus observed traffic per boundary |
| **12.5.2 / 12.5.2.1** scope confirmed (every 6 months for service providers) | Review | Asset reconciliation and observed flows that touch the CDE, which surfaces systems that are in scope but undocumented |
| **11.4.5 / 11.4.6** segmentation testing | Test | **Expansion:** the three-way agreement report in the testing-procedure format, which the partner tester reviews, extends and signs |

**Why sell through partners:** pentest firms run segmentation tests
manually. Paddock cuts their labour per engagement and gives them a
recurring evidence product to resell. The QSA-acceptance question is answered
by the partner signing, not by Paddock claiming. Lead with the review
requirements, where tool evidence is normal, and earn 11.4.5/11.4.6 through
the partner.

### Second motion: hospitals, ingest-only, change-impact first

- **Product:** change-impact proof (§2.3) plus routes from guest and clinical
  Wi-Fi to the EHR and PACS. It's built on flows and assets read from the
  medical IoT tool they already own (Armis, Claroty/Medigate, Ordr, Cynerio),
  so there's no new sensor. Probes are opt-in and kept off clinical-device
  ranges.
- **Mapping:** output maps to HHS 405(d) HICP practices *(verify the mapping
  scope)*. The HIPAA segmentation rule is a stalled proposal, so it's not
  part of the pitch.
- **Deployment:** Paddock Edge on-prem. The route map never leaves the site,
  and the keys are customer-held.
- **Price** per health system, not per site.
- **Prerequisites Paddock must clear first:** a BAA, SOC 2 Type II, a
  third-party pentest of Paddock itself, and a published Paddock SBOM.

### Third, deferred: utilities and OT

Wait until Dragos and Claroty ingest exists and these evidence packs ship:
- **NERC CIP-005 R1:** electronic security perimeter and access-point
  permissions.
- **CIP-010 R1:** baseline change, with change-impact proof before the
  change.
- **CIP-015:** impossible-traffic events as INSM anomaly evidence.
- **IEC 62443-3-2:** a zone and conduit assessment that models industrial
  protocol function codes (for example, Modbus or S7 *write*) wherever DPI
  firewalls enforce them.

Air-gapped Edge with offline updates is assumed. Frenos and Dragos NP-View
are entrenched here, so Paddock enters with IT, cloud and OT in one model
plus the change gate, not as a fourth OT console.

### Channel later: insurers and MSPs

- **Insurers** get the per-boundary verdicts and coverage trend. A signature
  proves origin and integrity, not truth, so the insurer's trust rests on the
  published accuracy rate and the partner's signature.
- **MSPs** resell boundary evidence per client through the existing MSP
  console.

---

## 5. The 60-minute "aha" (the demo that sells)

1. The prospect uploads exports for 3 firewalls and grants read-only access
   to one cloud account. No sensors are needed.
2. Within the hour, the screen shows their CDE, every (entry, jewel) pair
   reaching it, and the single rule that opens the worst route. For example:
   *guest Wi-Fi → a smart fridge on the corporate VLAN → the POS controller →
   the payment database*.
3. The presenter edits that rule in a mock change ticket. The change-impact
   proof shows the route closing, and lists the 2 live flows the edit would
   break.

That's time to value in an hour, and it doesn't depend on replicas or new
hardware.

---

## 6. Where this sits against the field

| Vendor (research, Nov 2026) | What they do | Paddock's difference |
|---|---|---|
| Horizon3 NodeZero, Pentera, XBOW, RunSybil | Autonomous exploitation against production | Nothing exploited; boundary evidence an auditor can use; change-impact proof |
| Strix (open source) | App-level agentic pentest with PoCs | Environment-level reachability; imports Strix results as *Imported* hops |
| XM Cyber (choke points), Wiz attack paths | Graph attack paths; choke points are close to a fix set | Probe- and flow-reconciled boundaries, change-impact proof, auditor packs |
| Tufin, AlgoSec | Policy management, pre-change risk checks | Crown-jewel routes and the live-flows-it-breaks proof on every change |
| Frenos (OT twin + AI simulated pentest), TopHat | OT twin and simulated attacks | IT, cloud and OT in one model; observed-flow reconciliation; change gate |
| Dragos/Network Perception NP-View | OT firewall-config segmentation review | Continuous, probe- and flow-corroborated, change-gated, plus IT and cloud |
| Forward Networks, Batfish, AWS Reachability and Network Access Analyzer | Formal network reachability; AWS's is free in-cloud | Crown-jewel framing, multi-vendor on-prem, vulnerability and identity hops, audit packs |

**The Skybox lesson, stated correctly.** Skybox *did* sell PCI and
change-management evidence, and it still shut down in February 2025 after
raising over $330M. Evidence alone isn't enough. What killed model-and-path
products was the cost of multi-vendor parser fidelity against a broad,
direct-sales motion. Paddock answers that in four ways:
- Parsers capped at the 3 vendors the beachhead runs.
- One buyer.
- Sales through partners who already own the relationship.
- An accuracy rate measured on twin ranges, rather than promised.

---

## 7. Pricing hypotheses (to test, not to publish)

| Package | Unit | Hypothesis | Anchor |
|---|---|---|---|
| **Boundary Evidence** (PCI Req 1 + 12.5.2 + change gate) | per service-provider estate, per year, wholesale to partners | $20–40k list, partner margin 30–40% | Partner labour saved on two segmentation tests and two scope confirmations a year. Segmentation is often bundled into the annual pentest, so the pitch is "cheaper and continuous", not an extra line item *(verify with 3 partners)* |
| **Segmentation test assist** (11.4.5/11.4.6 report) | per test, to partners | per-engagement fee | Partner hours saved |
| **Health system** | per health system, per year | test in pilots | Change-board time saved; incident risk |
| **OT site** | per site, later | test in pilots | CIP and 62443 assessment cost |

All of these sit in Enterprise and Edge as new gated capability via
`orchestrator/app/licensing.py`, as EDITIONS.md allows. Nothing that's free
today gets gated.

---

## 8. Guardrails specific to Wargame

The route map is the most sensitive thing Paddock holds. Treat it like key
material.

1. **No exploit execution, anywhere.** Probes are TCP connect and banner read
   inside the existing safe-check envelope. Replicas get the same envelope
   plus filesystem inspection. The narrative rule and reject-token list
   (`attackpath.py`, `policy.py`) apply unchanged: impact and fix only, never
   steps or commands.
2. **Sentry stays listen-only.** Probing is a separate, visible, opt-in
   deployment of the active worker, under the scope invariant
   (SECURITY.md §3) and proof-of-control.
3. **Fragile ranges are untouchable.** The customer marks clinical and OT
   device ranges as *no-probe*. A probe aimed at one is a hard failure, the
   same way out-of-scope is.
4. **The route map is classified.**
   - Routes inherit the highest classification on them (existing ABAC).
   - Full exports need four-eyes approval and are audited.
   - Edge keeps the map on-site with customer-held keys.
   - Auditors see config snapshots in a controlled, logged review session,
     not in a shared file.
5. **Read-only inputs.** Firewall, cloud, IdP and IoT-tool connectors are
   read-only. The change gate comments and blocks; it never applies a
   change.
6. **Humans resolve contradictions.** The model is never changed
   automatically to explain away an impossible-traffic alert.
7. **Honest outputs.** Every route shows its weakest label. Runtime-dependent
   rules are *Conditional*. Anything unproved says *inferred* or *unknown*,
   never *closed*. This follows VERIFICATION.md's "No false 'fixed'".
8. **Warden watches Wargame.** The agent may only read the twin, call the
   solver and request probes or safe checks through Assessor under the normal
   scope rules. Unsafe-action attempts are scored in evals and must be zero.

---

## 9. What it's built from, and in what order

### Implementation status (engine)

A tested engine now lives in `correlation/app/engine/wargame/` (pure
Python, no new deps, ~390 tests). Built so far:

- **Solver + backward search + fix set + evidence ladder** — `rules.py`,
  `reachability.py`, `mincut.py`, `model.py`.
- **Closed-boundary certificates** (assumptions + expiry + signature) —
  `certificate.py`.
- **Config parsers → vendor-neutral rule model** — `parsers/` for AWS
  (SG + NACL), Cisco ASA, FortiGate, Palo Alto, with the honesty rule
  (runtime-only / unresolved → *conditional*).
- **Change-impact proof** (routes opened/closed + live flows it would
  break) — `changegate.py`; **Terraform-plan parser** —
  `parsers/terraform.py`.
- **Three-way agreement report** — `agreement.py`; **scorecard**
  (closure always shown with coverage) — `report.py`.
- **Impossible-traffic** detection and **replica verification**
  (preconditions only, no exploit) — `impossible.py`, `replica.py`.
- Runnable demos: `python -m app.engine.wargame.demo` and
  `… .demo_changegate`.

Not yet built: live connector wiring (read-only firewall/cloud/IoT-tool
ingest and the topology that maps rule sets onto graph edges), probe
deployment mode, auditor-formatted compliance packs, the sandbox runner
behind `replica.ReplicaRunner`, twin ranges with a published
false-"closed" rate, and the dashboard. A known gap: Terraform rule ids
(resource addresses) don't match the AWS parser's ids, so remove/modify
across the two needs an id-mapping layer (add composes today).

| Exists today | Needs building |
|---|---|
| Attack-path engine (`attackpath.py`): forward Dijkstra, undirected | Directed, rule-aware graph; backward search; ILP fix set over (entry, jewel) pairs |
| Cloud connectors reduce rules to world-open summaries | Full rule models; on-prem parsers for **Fortinet, Cisco ASA/FTD, Palo Alto (L3/L4)** first, then Check Point |
| None | Solver with *Conditional* handling for runtime features |
| Active worker, safe checks, scope gate, egress wrapper, ledger | Probe deployment mode for out-of-scope segments; *no-probe* ranges |
| Sentry, `behavior.py`, 21 connectors | Flow ingest (firewall logs, NetFlow, Zeek) and IoT-tool ingest (Armis, Claroty, Dragos); impossible-traffic detector with handshake and allow-log gating |
| Remediation gate, GitHub PR, ServiceNow and Jira connectors | Change-impact proof on tickets and IaC plans |
| Provenance, audit anchoring, report control catalogues (PCI DSS 4.0, IEC 62443 exist) | Multi-label evidence ladder; auditor-formatted packs for 1.2.5, 1.2.7, 1.3.x, 12.5.2, 11.4.5/6 |
| Eval harness (`hardening/evals/`) | **Twin ranges** with known open and closed routes; a published false-"closed" rate |
| Assessor, verification ledger | Replica verification (last) |

**Build order.** Each step is sellable on its own:

1. Firewall parsers (3 vendors) plus one cloud, the solver, and the
   Requirement 1 and 12.5.2 packs → the 60-minute demo and the partner
   product.
2. Change-impact proof (solver plus flow ingest) on ServiceNow and Jira and
   in Terraform CI.
3. Probe mode and the three-way agreement report → the 11.4.5/11.4.6
   expansion.
4. Backward search, the fix set and the evidence ladder over the full graph.
5. IoT-tool ingest and impossible traffic → hospitals.
6. "Are we exposed?" via Herald.
7. CIP and 62443 packs → OT.
8. Replica verification.

---

## 10. How we get from "should sell" to "certain it sells"

A document can't make it certain. Paying design partners can. Run this with
the pilots planned in READINESS.md, recruiting **2 pentest or QSA-aligned
firms** as the first partners:

**Pass (build on):**
- **2 QSAs on record** accept the Requirement 1 and 12.5.2 packs as evidence.
- **At least 2 partners** resell to paying service providers within 90 days.
- The change gate flags at least 1 real route-opening change, and the change
  board says the flows-it-breaks list changed a decision.
- The three-way report finds at least 1 real disagreement per pilot estate:
  a rule that doesn't enforce, or an undocumented system that's in scope.
- The false-"closed" rate on twin ranges is under an agreed bound, and
  published.

**Kill or reshape:**
- Partners won't resell → sell Boundary Evidence direct to service providers'
  compliance teams as a Requirement 1 tool. That's a smaller product, but it
  still has a mandate.
- Parser fidelity against real configs stays poor after 2 vendors → narrow to
  cloud plus one firewall vendor. In cloud-only, compete on audit packs and
  change-impact proof, not on reachability itself; AWS's is free.
- Impossible-traffic stays noisy after gating → ship it as a weekly review
  queue rather than an alert.

---

## 11. Honest limits

- **Proofs are about the model.** Coverage, blind spots and the measured
  false-"closed" rate sit next to every claim.
- **Config can't prove runtime features** (App-ID, FQDN objects, dynamic
  groups, mesh). Those rules are *Conditional*, and probes and observation
  carry the evidence for them.
- **Probes prove reachability, not exploitability.** Preconditions aren't
  exploitation. Buyers who need demonstrated exploitation import it from a
  human tester.
- **OT's real routes** (dual-homed workstations, cellular modems, serial
  converters, USB) are often outside the model. They're listed as blind
  spots, never closed.
- **Replicas cover a minority of components.** That's why they're the last
  tier, not the pitch.
- **Paddock holding a crown-jewel route map is a risk in itself.** Edge
  deployment, customer-held keys, SOC 2 Type II and a third-party pentest of
  Paddock are prerequisites for the hospital and OT segments, not
  nice-to-haves.

---

## 12. Decisions for the owner

1. **Confirm the Part 2 stance:** no exploit execution, including on replicas.
   This keeps SECURITY.md §6 as written.
2. **Approve probe mode:** the active worker deployed on out-of-scope segments
   to TCP-connect into in-scope ranges. It's within today's safe-check
   envelope and scope rules, but it's a new deployment shape and changes what
   "active" means in a customer network.
3. **Wedge:** PCI service providers through pentest and QSA-aligned partners
   (recommended).
4. **Landing page:** Wargame would be a fifth agent card, and the copy says
   "Four agents". The landing UI is owner-protected, so nothing has been
   changed there.
5. **Pricing hypotheses** in §7, to test with partners.
