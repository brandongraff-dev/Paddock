# Paddock — product vision

> **One system that knows everything you're responsible for — every server,
> repo, laptop, camera, refrigerator, PLC and Wi-Fi network — understands how
> an attacker would move through it, and safely closes the path before they do.**

Paddock today is a strong MVP of an attack-surface tool. This document is the
plan for turning it into the defensive equivalent of the best in the field:

- **What makes Strix powerful** is autonomy *with proof*: agents do the expert
  work end to end and only report what they can demonstrate. Our answer:
  autonomous **defensive** agents whose every finding carries *non-destructive
  evidence*, and whose every fix is *verified* after it lands.
- **What makes Palantir powerful** is not dashboards. It is (1) an **ontology**:
  one living model of the real world that every tool reads and writes, (2) an
  **action layer**: decisions turn into governed, audited changes, and (3)
  **deployment anywhere**, including disconnected and classified edges. Our
  answer: a **defensive digital twin** of everything that connects, a **safe
  action layer**, and **Paddock Edge** for factories, hospitals, ships and
  stores.

Everything below stays inside the hard rules: no exploitation, no credential
attacks, no evasion, nothing out of scope. Wireless and OT features are
**passive**. That restraint is the product. It is what lets a hospital, a
utility or a refrigerator maker actually deploy us.

---

## 1. The architecture: sense → model → reason → act → prove

```
  SENSE                     MODEL                  REASON                   ACT                     PROVE
  ─────                     ─────                  ──────                   ───                     ─────
  internet surface   ┐                       ┌ attack-path engine     ┌ propose → approve     ┌ re-verify fix
  cloud accounts     │                       │ twin attack simulation │ → apply → verify      │ evidence packs
  code + SBOM        ├──►  Defensive Twin  ──┤ triage w/ evidence     ├ auto-rollback         ├ hash-chained audit
  hosts (agent)      │     (ontology graph)  │ investigation (Ask)    │ tiered autonomy       │ compliance mapping
  IoT / OT (Sentry)  │                       │ anomaly baselines      │ blast-radius preview  └ MTTR / risk trend
  Wi-Fi / RF         ┘                       └ fix drafting           └ playbooks
```

Each column already has a seed in the repo. The work is to widen the sensors,
make the twin the single source of truth, and close the loop to *proven* risk
reduction.

---

## 2. Sense — collect everything that connects

| Sensor | What it sees | Status |
|---|---|---|
| **External surface** | DNS, CT logs, ASN ranges, ports, TLS, web exposure | ✅ exists (hardened this release) |
| **Code & supply chain** | SBOM, SCA, SAST, reachability, typosquats | ✅ exists (rule packs restored this release) |
| **Host agent** | inventory, local blocks via approve-gate | ✅ exists |
| **Cloud connectors** | read-only AWS/GCP/Azure inventory + IAM + network paths | 🔜 |
| **Paddock Sentry** (new) | passive network + RF sensor for IoT/OT/Wi-Fi | 🔜 builds on `otdiscovery` |
| **Identity** | IdP users, groups, MFA status, stale accounts (Okta/Entra/Google) | 🔜 |
| **Firmware** | SBOM + secrets + vuln match from firmware images | 🔜 |

### Paddock Sentry: the hardware-shaped wedge

A small box (or a container on an existing switch/router) that plugs into a
**mirror/SPAN port** and, optionally, carries a **Wi-Fi radio in monitor
mode**. It never transmits at devices; it only listens.

- **Device identity for "things"**: DHCP/mDNS/SSDP/UPnP/LLDP/TLS-JA4/HTTP
  fingerprints → *"Samsung Family Hub fridge, firmware 2.1"*, *"Hikvision
  camera"*, *"Siemens S7-1200 PLC"*, *"Baxter infusion pump"*. (`otdiscovery`
  already parses pcaps and these announcement protocols.)
- **Behavioural baselines per device class**: a fridge should talk to its
  vendor cloud and NTP. A fridge that starts scanning the subnet, talking to
  the POS VLAN, or beaconing to a new ASN is an incident. Baselines are learned
  per *model*, so the 500th customer's fridge is protected on day one
  (cross-tenant network effect).
- **Segmentation map**: who can actually reach whom, observed from traffic and
  not from the firewall's intent, with "this flat network lets the lobby TV
  reach the payment server" as an attack path.
- **OT protocol awareness (passive)**: Modbus, DNP3, S7, BACnet, EtherNet/IP,
  OPC-UA. It flags unexpected function codes (e.g. a *write* from a laptop to a
  PLC) without ever sending one.
- **Wireless IDS (passive)**: rogue and **evil-twin APs** (same SSID, unknown
  BSSID or vendor), deauth/disassoc floods, open or WEP/WPA-TKIP networks,
  weak WPA2-PSK *configuration* (never cracking), guest networks bridging into
  corporate VLANs.

---

## 3. Public Wi-Fi: two products from one engine

### 3.1 For venues that **run** public Wi-Fi
Cafés, hotels, airports, retail, hospitals, stadiums. The classic breach path
is *guest Wi-Fi or an HVAC/IoT device → flat network → point-of-sale*.

- **Continuous isolation verification**: Sentry checks that client isolation
  holds and that guest, IoT, POS and staff segments can't see each other. This
  is passive observation plus authorised, scope-proven reachability checks from
  the venue's own guest segment.
- **Evil-twin watch** around the premises: someone broadcasting your SSID from
  the parking lot gets an alert with signal-strength location hints.
- **Captive-portal and DNS hygiene**: TLS on the portal, no credential capture
  over HTTP, DNS filtering health.
- **PCI DSS segmentation evidence** generated continuously instead of yearly.

### 3.2 For people who **use** public Wi-Fi
**Paddock Shield**: a lightweight desktop/mobile client for an organisation's
travelling staff (and later consumers).

- Detects **evil twins** (known-network fingerprint pinning), **ARP/DHCP
  spoofing**, **DNS hijacking**, **TLS interception** (unexpected issuer),
  and **captive-portal phishing**.
- On risk, it auto-enables a **WireGuard tunnel** to a trusted egress and tells
  the user why in one sentence.
- Fleet telemetry feeds the twin: *"14 employees joined a spoofed 'Hilton
  Honors' network in Lisbon this week"* becomes a threat-intel signal for every
  tenant.

---

## 4. Model — the Defensive Twin (the Palantir-grade core)

One typed graph that every sensor writes to and every agent reads from:

- **Objects**: org, person/identity, device (server, laptop, phone, IoT, OT,
  medical), network segment, access point, cloud resource, repo, package,
  service, data store (with sensitivity), vendor, site/building.
- **Links**: *resolves-to, runs, depends-on, can-reach (observed vs.
  intended), authenticates-as, owns, located-in, stores-data-of*.
- **Time**: every object and link is versioned. You can ask *"what did our
  exposure look like the day before the incident?"* and *"what changed?"*.
- **Ownership and criticality**: every node knows its owner, business service
  and crown-jewel score. That turns "a CVE" into "*the payments team's*
  problem, 2 hops from cardholder data".
- **Governance built in**: classification/ABAC on every object (exists), so
  one twin can serve the SOC, the plant engineer and the auditor with
  different views.

The `ontology` service and attack-path engine are the seed. The step change
is making the twin **the** API: sensors are writers, agents are readers, and
the UI is just one client.

---

## 5. Reason — defensive agents with Strix-level autonomy

| Agent | Job | Why it is defensible and safe |
|---|---|---|
| **Outrider** (discovery) | keeps the twin complete across all sensors | passive by default; active only in proven scope |
| **Herald** (intel) | "are we affected?" in minutes when KEV/EPSS moves | reads the twin; no target interaction |
| **Assessor** (triage) | turns raw findings into **evidence-backed** ones: version proof, config proof, reachability proof, all *non-destructive*; auto-closes what it can't substantiate | the defensive analogue of a PoC: proof without exploitation |
| **Wargame** (simulation) | runs ATT&CK-style attacker playbooks **against the twin, not production**: "from guest Wi-Fi, can an attacker reach the PLC?" | zero production risk; answers the red-team question safely |
| **Farrier** (fix) | drafts the change where it lives (IaC PR, firewall rule, VLAN move, config, dependency bump) | human approval gate; verify-after-apply |
| **Warden** (guardrails) | enforces scope and autonomy policy on every other agent | the agent that watches the agents |
| **Ask** (investigation) | natural-language questions over the twin, with citations | read-only, RBAC-filtered |

**Evaluation harness** (how we know agents work): a library of seeded
"digital-twin ranges", synthetic orgs with known paths and planted
misconfigurations. Every agent release is scored on precision, recall, time to
correct answer and unsafe-action attempts (must be zero). The same idea made
the scope fuzzer go from 77,554 disagreements per million to 0: measure,
don't guess.

---

## 6. Act and prove — the safe action layer

- **Playbooks**: isolate a device (switch/AP/firewall API → quarantine VLAN),
  block at the edge, disable an account, rotate a leaked secret, open a fix PR,
  file a vendor ticket.
- **Pipeline**: *propose → preview blast radius → approve → apply → verify →
  auto-rollback on failure*. The host agent already implements
  propose/approve/apply. Extend it to network gear (UniFi, Meraki, Aruba,
  pfSense/OPNsense, Fortinet, Palo Alto) and cloud (security groups, bucket
  policy).
- **Tiered autonomy**: policy decides what may auto-apply (e.g. *quarantine an
  IoT device that starts scanning, at night, on non-production segments*) and
  what always needs a human.
- **Proof of risk reduction**: every closed path is re-tested by Assessor, and
  the twin keeps the before/after. Output: *"exposure index down 41 % this
  quarter; 312 paths to crown jewels closed and verified"*. That number is
  what a CISO, board or insurer buys.

---

## 7. Deploy anywhere — Paddock Edge

Critical infrastructure, plants, ships, hospitals and many government sites
can't stream data to a SaaS.

- The same stack runs **on-prem or fully air-gapped** on a single node.
- **Signed, offline updates** for rules, fingerprints, intel and models, from
  sneakernet bundles with verified signatures.
- **Federation**: sites sync *signed diffs* of their twin to a parent when
  connected. A utility sees all its substations; each substation still works
  alone.
- This is the moat the big platforms have and most security startups don't.

---

## 8. Markets this unlocks

| Segment | Pain | Paddock package |
|---|---|---|
| **SMBs (via MSPs)** | no security staff, flat networks, smart devices everywhere | Sentry box + agent + plain-English weekly brief; MSP multi-tenant console |
| **Retail and hospitality** | guest Wi-Fi + POS + IoT on one network; PCI | Public-Wi-Fi venue pack (§3.1) |
| **Healthcare** | unpatched medical IoT, HIPAA | medical-device fingerprints, MDS2 data, segmentation proof |
| **Manufacturing, utilities, water** | OT exposure, IEC 62443, NERC CIP | passive OT sensing, zones/conduits model, Paddock Edge |
| **Smart buildings / real estate** | BACnet, HVAC, elevators, cameras reachable from tenants | building pack: per-floor/tenant segmentation verification |
| **Device makers** (fridges, routers, cameras) | **EU Cyber Resilience Act** (reporting duties from Sept 2026, full obligations Dec 2027), US Cyber Trust Mark | **Product security**: firmware SBOM, vuln monitoring of *shipped* fleets, VEX statements, disclosure intake, CRA evidence |
| **Enterprises** | sprawl across cloud, code, endpoints | full twin + agents + action layer |

The **device-maker** segment deserves special attention. It is a fresh,
regulation-driven, under-served market, and it reuses exactly what we have
(SBOM, SCA, vuln intel, fingerprints) pointed at firmware instead of repos.

---

## 9. Sequenced roadmap

**Phase 1: make the core trustworthy at scale (now → +3 months)**
1. Multi-tenancy + **proof-of-control** for scope (DNS/HTTP challenge, LOA
   upload) + per-tenant isolation (see `CLOUD_ROADMAP.md` §0).
2. Resolved-IP pinning in workers; keyed and anchored audit chain.
3. **Twin v1**: promote the ontology to the system of record, with time-
   versioned objects and owner/criticality on every node.
4. **Assessor v1**: evidence on every finding + auto-close of the
   unsubstantiated. This is the precision story.

**Phase 2: the wedge (+3 → +6 months)**
5. **Paddock Sentry v1**: container first (runs on a mini-PC or a UniFi/
   OpenWrt box), passive device identity + per-model baselines + segmentation
   map, built on `otdiscovery`.
6. **Wireless IDS** (evil twin, rogue AP, deauth floods) and the
   **public-Wi-Fi venue pack**.
7. Cloud connectors (AWS first), joined into attack paths.
8. **Exposure Watch** (KEV/EPSS → affected assets in minutes).

**Phase 3: autonomy and reach (+6 → +12 months)**
9. **Wargame** twin simulation and **Farrier** fix PRs with verify-after-apply.
10. Network-gear playbooks + tiered autonomy.
11. **Paddock Shield** client for travelling staff.
12. **Paddock Edge** (air-gapped, federated) + OT protocol depth.
13. **Firmware / CRA product-security** offering for device makers.

---

## 10. Why this wins

- **Breadth through one model**: competitors each see one slice (ASM, CSPM,
  IoT, WIDS). Paddock correlates all of them in one twin, which is the only
  way to see the guest-Wi-Fi → fridge → file-server path.
- **Precision through proof**: evidence-backed findings, verified fixes,
  fuzz-tested guardrails. Fewer, truer alerts.
- **Safety as a feature**: passive-by-default, scope-proven, approval-gated,
  audited. This is what lets regulated and critical-infrastructure buyers say
  yes.
- **Network effects**: every deployed Sentry improves device baselines and
  every evil-twin sighting improves intel for every tenant.
- **Deploy anywhere**: cloud, on-prem, air-gapped, federated.
