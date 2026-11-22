# Paddock Wargame — engine reference (what it does, and exactly how)

This is the implementation reference for the Wargame engine that lives in
`correlation/app/engine/wargame/`. For the product/business case see
[WARGAME.md](WARGAME.md); this document describes the code that exists:
every module, the data that flows between them, and the rules the code
enforces.

> **One sentence.** Wargame takes a model of your environment, works
> *backward* from the crown jewels to find who can reach them, labels every
> step with the evidence behind it, computes the cheapest set of changes
> that cuts every route, issues signed certificates for the routes it
> proves closed, cross-checks them against observed traffic, and emits
> auditor evidence — and it never runs an exploit against anything, real or
> replica.

It is pure Python (standard library only, no new third-party deps), lives
inside one service (`correlation`), is read by another (`orchestrator`),
and is covered by ~540 tests.

---

## 1. The defensive invariants (enforced in code, not just documented)

Everything below obeys the hard rules in [SECURITY.md §6](../SECURITY.md):

1. **No exploit execution, anywhere.** No payloads, no PoCs, no commands —
   not against production, not against replicas. Replica verification only
   checks whether an exploit's *preconditions* are present.
2. **No credential submission.** Credentials are fingerprinted/detected,
   never tested. Identity hops are therefore only ever *inferred* or
   *conditional* — a hard invariant asserted in `identity.py`.
3. **Read-only inputs.** Config sources, connectors and the change gate only
   read and advise; nothing is applied.
4. **No false "closed".** A route or boundary is only reported closed when
   the model proves it; anything the model can't prove is labelled
   *conditional*, *inferred* or *unknown* — never *closed*. This is
   measured (§13), not just claimed.
5. **Impact-only narrative.** Any free text that reaches a narrative,
   certificate claim or fix description is run through the correlation
   reject filter (`safety.py`), which rejects exploitation-shaped text.

`safety.py` is the chokepoint for 1, 2 and 5: `assert_safe_text` /
`safe_text` wrap the engine-wide reject tokens, and
`assert_precondition_allowed` enforces a hard allowlist of replica check
kinds.

---

## 2. The data model (`model.py`)

Everything shared is a frozen/plain dataclass or enum here. No logic, no I/O.

### The evidence ladder — `EvidenceLabel`

Every hop carries a set of labels; a route is only as strong as its weakest
hop. `LABEL_STRENGTH` orders them, and `weakest_label()` / `strongest_label()`
reduce a set.

| Label | Strength | Means |
|---|---|---|
| `IMPORTED` | 8 | A third party demonstrated exploitation (recorded, never run here) |
| `PROVED_REPLICA` | 7 | Exploit preconditions confirmed on a rebuilt copy |
| `PROVED_LIVE_SAFE_CHECK` | 6 | Preconditions confirmed on the in-scope asset (safe checks) |
| `OBSERVED` | 5 | Real traffic seen (completed handshake / dst-side) |
| `TESTED_PROBE` | 4 | A safe-check TCP connect crossed the boundary |
| `PROVED_CONFIG` | 3 | The rule solver shows the config permits the hop (no packets) |
| `CONDITIONAL` | 2 | Permitted only subject to runtime state the config can't prove |
| `INFERRED` | 1 | The graph suggests it; nothing has proved it |
| `UNKNOWN` | 0 | Outside the model |

The low-strength end is deliberately *weak* so a conditional/inferred hop can
never make a route read as proof of closure.

### The rule model

- `Proto` (tcp/udp/icmp/any), `PortRange(proto, low, high)` with `.contains()`.
- `Action` (allow/deny).
- `Rule(id, action, order, src_cidrs, dst_cidrs, ports, vendor, conditional,
  raw_ref, cost_class)` — vendor-neutral. `order` is evaluation position
  (lower wins under first-match). `conditional=True` marks a rule whose real
  effect depends on runtime state the config can't prove (App-ID, FQDN, …).
  `.matches(src_ip, dst_ip, proto, port)` does the CIDR+port test.
- `RuleSet(id, rules, default_action, vendor)` — the rules at one boundary.
- `Decision(allowed, matched_rule, conditional)` — a solver verdict.

### Topology and routes

- `Node(id, role, cidrs, reason, jewel_kind, metadata)`; `NodeRole` is
  `ENTRY` / `CROWN_JEWEL` / `INTERMEDIATE`.
- `Edge(src, dst, rule_set_id, port, base_labels, fix_candidate_id, metadata)`
  — a directed adjacency, optionally gated by a `RuleSet`. `rule_set_id=None`
  is an ungoverned adjacency (same segment, identity hop, observed flow).
- `Hop(src, dst, labels, port, rule_ref, fix_candidate_ids)` with
  `.weakest`; `Route(entry, jewel, hops)` with `.weakest_label`, `.length`,
  `.fix_elements` (the union of cuttable ids along it), `.pair`.
- `ReachabilityResult(routes, open_pairs, closed_pairs, conditional_pairs)`.

### Fix set, certificate, replica, flows

- `FixCandidate(id, kind, cost_class, description, cost, blocks)` and
  `FixSet(selected, total_cost, cuts_all, uncut_routes, optimality)`.
  `DEFAULT_COST_CLASSES` maps a change class to a weight (a rule change is
  cheap, a device patch is expensive) so the optimiser minimises a
  customer-set cost, never an invented risk number.
- `Certificate(claim, boundary_src, boundary_dst, port, config_hashes,
  assumptions, corroboration, issued_at, expires_at, status, fingerprint)`,
  with `Assumption(key, text)` and `Corroboration(observed_flows,
  window_days, sensor_on_protected_side, probe_tested)`.
- `Precondition` + `PreconditionKind` (a hard allowlist), `ReplicaPlan`,
  `ReplicaVerdict`.
- `Flow(src_ip, dst_ip, proto, dst_port, handshake_completed,
  dst_side_observed, firewall_allow_logged, is_broadcast, kind, ts)` and
  `ImpossibleTrafficAlert`.

---

## 3. The solver — `rules.py`

Decides whether a flow is permitted by a `RuleSet`, from config alone, with
no packets sent.

- `evaluate(ruleset, src_ip, dst_ip, proto, port) -> Decision`: first-match
  over `rules` sorted by `(order, id)`. The first rule that matches decides;
  `conditional` propagates from the deciding rule. No match → the
  `default_action` (deny unless stated).
- `permits(...) -> bool`: convenience.
- `boundary_permits(ruleset, src_cidrs, dst_cidrs, port) -> Decision`:
  whether *any* flow from any src CIDR to any dst CIDR on the port class is
  permitted, by testing a representative host from each CIDR. If none is
  allowed but a conditional rule matched, the verdict is
  `allowed=True, conditional=True` (config cannot prove it closed). The
  representative-IP approximation is documented in the module — a sub-CIDR
  deny carve-out can be over/under-counted, which is why probes and
  observation corroborate config in the three-way report (§9).

---

## 4. Backward search — `reachability.py`

`backward_reachability(nodes, edges, rulesets, *, max_hops=8,
max_routes_per_pair=16) -> ReachabilityResult`.

- Builds a **directed** adjacency and, for each crown jewel, searches
  **backward** to every entry, enumerating simple paths bounded by
  `max_hops`, capped per `(entry, jewel)` pair, with a global visit budget
  so a dense graph can't blow up. Output is deterministic (neighbours sorted;
  shortest routes first, then lexicographically).
- Each edge becomes a `Hop` whose labels are computed thus:
  - ungoverned edge → its `base_labels`, or `INFERRED` if it has none;
  - governed edge → `rules.boundary_permits(...)`: **denied ⇒ the hop is not
    traversable** (a closed boundary); allowed ⇒ `PROVED_CONFIG`;
    conditional ⇒ `CONDITIONAL` (never `PROVED_CONFIG`). Plus any
    `base_labels` (e.g. `OBSERVED`).
- A pair is **open** if ≥1 route survived, **closed** if not, and
  **conditional** if every open route depends on a conditional hop. These
  three sets drive the scorecard and certificates.

This is the structural heart: "can anyone reach what matters, and by what
route, and how good is the evidence for each step."

---

## 5. The minimum-cost fix set — `mincut.py`

The cheapest set of changes that cuts **every** open route. This is a
weighted **hitting set** (a route is broken when the fix set contains any one
of its cuttable elements), which is NP-hard — the module says so and never
calls a result "minimal" unless it is exact.

- `min_cost_fix_set(routes, candidates) -> FixSet`: exact branch-and-bound
  for small instances (≤24 distinct candidates) with a disjoint-route cost
  lower bound and most-constrained-route branching; cost-effective greedy
  fallback for larger instances (`optimality` records which ran).
- A route with no cuttable element (e.g. an inferred hop with no modelled
  control to change) cannot be cut: it is recorded in `uncut_routes` and
  forces `cuts_all=False`.
- `cost_for(cost_class, overrides)` resolves the weight; a compensating
  control naturally beats a device patch because it is cheaper.
- `fix_set_for(result, candidates)` pulls the open routes' `fix_elements`.

---

## 6. Closed-boundary certificates — `certificate.py`

A signed, expiring, assumption-bearing proof that no route crosses a
boundary.

- `build_certificate(..., assumptions, corroboration, issued_at, ttl_hours,
  claim=None)` — **refuses to build without assumptions** (a proof with no
  stated limits is forbidden), and when there is no protected-side sensor it
  injects an explicit "absence of evidence" assumption rather than implying
  observed closure. The claim text passes `safety.assert_safe_text`.
- `sign(cert, key)` computes an HMAC-SHA256 `fingerprint` over a canonical
  serialization of the *semantic* fields (claim, boundary, port, sorted
  config hashes, sorted assumptions, corroboration, issued/expires) —
  deliberately **excluding** `status`, so `mark_contradicted(cert)` can flag
  a cert without invalidating its signature. `verify(cert, key)` recomputes
  with `hmac.compare_digest`.
- `is_current(cert, now)` = `status=="valid"` and `now < expires_at`.
- `hash_snapshot(text)` is the config-provenance hash stored with the twin.

An auditor can verify a certificate's integrity and read its assumptions and
the exact config hashes it was proved against, without access to Paddock.

---

## 7. The modelled environment and change gate (`environment.py`, `changegate.py`)

- `Environment(nodes, edges, rulesets)` ties the model together;
  `.reachability()` runs the solver, `.boundary_decision(src, dst, port)`
  evaluates one boundary, `.copy()` is a safe structural clone.
- `ProposedChange` is a list of `ChangeOp`s (add/remove/modify rule,
  add/remove rule set, add/remove edge). `apply_change(env, change)` returns
  a **new** environment with the edit applied and never mutates the original;
  a malformed change (a rule on an unknown rule set, removing a missing edge)
  raises `ChangeError` rather than silently no-op'ing.
- `changegate.evaluate_change(env, change, *, flows=()) -> ChangeImpact`
  diffs crown-jewel reachability before vs after and checks observed `flows`
  against the affected rule sets, producing:
  - `routes_opened` / `routes_closed` (the `(entry, jewel)` pairs that flip),
  - `newly_denied_flows` — **the live flows the change would break** (allowed
    before, denied after) — and `newly_allowed_flows`,
  - a `verdict` of `safe` / `opens_route_to_crown_jewel` /
    `breaks_live_flows` / `opens_and_breaks`.
  `impact_table()` renders it for a change ticket. This is what a change
  board reads *before* applying a firewall change or merging an IaC PR.

---

## 8. Observed traffic and "impossible traffic" — `impossible.py`

- `flow_is_real(flow)` is True only for a completed handshake, a
  destination-side observation, or a firewall *allow* log — and never for
  broadcast/management noise (`SUPPRESSED_KINDS`). A dropped SYN proves the
  boundary *works*, so it is not "real".
- `ClosedBoundary` describes a boundary a certificate proved closed;
  `flow_crosses(flow, boundary)` tests CIDR+port containment.
- `classify_flow(flow, closed_boundaries) -> ImpossibleTrafficAlert | None`:
  a *real* flow across a *proved-closed* boundary raises a critical alert
  naming the contradicted certificate. The gating keeps it quiet.
- `resolve(alert, resolution, reason, resolved_by)` requires a human and a
  cited reason and returns an immutable record — the model is **never**
  auto-amended to explain a flow away (that could legitimise an attacker's
  tunnel).

---

## 9. Three-way agreement and the scorecard (`agreement.py`, `report.py`)

`agreement.py` combines three independent sources for a boundary into one
auditor verdict:

- `SourceVerdict` is `OPEN` / `CLOSED` / `UNKNOWN`. Config comes from the
  solver; the probe is a safe-check connect result (crossed = OPEN, blocked =
  CLOSED, none = UNKNOWN); observation is `OPEN` only if a real flow crossed,
  else `UNKNOWN` — **observation can never prove closed** (absence of evidence).
- `assess_boundary(evidence) -> AgreementReport`: any source `OPEN` →
  `fail_open`; a config verdict resting on a conditional rule → `conditional`;
  config+probe `CLOSED` with no open observation → `pass`; otherwise
  `insufficient` (e.g. no probe was run). `from_environment(...)` builds the
  evidence from an `Environment` plus an optional probe and observed flows.

`report.py` turns a `ReachabilityResult` into the board/auditor numbers:

- `ClosureScore` — total/open/closed/conditional `(entry, jewel)` pairs,
  `closure_pct`, and a histogram of each open pair's weakest-label.
- `Scorecard` with a `board_line` that **always** pairs closure with
  coverage ("… over a model explaining N% of observed traffic …", or
  "coverage not yet measured" when unknown) — closure is never shown without
  its honesty caveat — plus per-boundary verdicts (duck-typed from
  agreement reports) and named blind spots.

---

## 10. Config parsers (`parsers/`)

Turn real exports into vendor-neutral `RuleSet`s. `parse(vendor, raw) ->
ParseResult` dispatches to:

| Vendor key | Input | Notes |
|---|---|---|
| `aws` | `describe-security-groups` / `describe-network-acls` JSON | SG ingress/egress rule sets; **SG-to-SG references** resolved from supplied member CIDRs; NACLs ordered by rule number with deny semantics; subnet/ENI bindings |
| `cisco_asa` | ASA config text | objects + nested object-groups, extended ACLs with order/deny, named ports, `access-group` interface bindings |
| `fortinet` | FortiOS CLI | address/addrgrp (incl. FQDN), service custom/group, policies grouped into `srcintf>dstintf` rule sets, disabled policies skipped |
| `paloalto` | PAN-OS `set` format | objects, static vs **dynamic** address groups, security rules grouped by zone pair |
| `terraform` | `terraform show -json` plan | `parse_plan()` → a `ProposedChange` for the change gate |

The shared foundation `parsers/base.py` does the work that decides
correctness:

- **Nested object/group resolution** (`ObjectTable`) with cycle and depth
  guards; CIDR/netmask/Cisco-wildcard/range normalisation (`normalize_cidrs`);
  a named-service and protocol map. A user-defined object wins over a
  same-named built-in.
- **The honesty rule.** `ConditionalFeature` enumerates runtime-only features
  (FQDN, App-ID, User-ID, dynamic address groups, external dynamic lists,
  URL/geo categories, SD-WAN) and `UNRESOLVED`. Any rule that uses one — *or
  references an object the parser could not resolve* — is marked
  `conditional=True` and over-approximated toward *reachable* (resolve the
  unknown to "any"), so a parse gap can never prove a boundary closed. Every
  conditional/unresolved rule emits a `ParseWarning`.
- `build_rule(...)` assembles a `Rule` and applies the honesty rule;
  `ParseResult` carries `rulesets`, `bindings` (where each set is enforced)
  and `warnings`.

---

## 11. Assembling and enriching the model

### Routing and NAT — `routing.py`
`RoutingFabric` models route tables and NAT (`from_aws` parses
`describe-route-tables`): longest-prefix `reachable(src_cidr, dst_cidr)`,
blackhole routes = not reachable, **unmodelled routing = conservatively
reachable with a recorded assumption** (never claim closed because routing
wasn't modelled), and NAT exposed as a *conditional* (`crosses_nat` /
`translate`) rather than a silent block. Its `reachable` matches the
`RouteReachable` oracle the topology layer consumes, so a firewall allow with
no underlying route is not counted as a hop.

### Topology assembly — `fabric.py`, `topology.py`
`build_topology(spec, rulesets, *, bindings, observed_flows, extra_nodes,
extra_edges, route_reachable) -> TopologyResult` turns declared
`SegmentSpec`/`EdgeSpec`s plus parsed rule sets into an `Environment`:

- attaches rule sets to declared edges;
- **auto-wires** edges from rule-set bindings (zones/interfaces/subnets →
  segments);
- folds *real* observed flows into edges, surfacing drift as **discovered
  edges** (an observed flow no declared edge explains);
- drops an edge with no underlying route when a `route_reachable` oracle is
  supplied.

### Identity and credential paths — `identity.py`
`build_identity_layer(principals, assume_map, shared_cred_map) -> (nodes,
edges)` models vendor VPNs, remote support, shared admin creds, IAM role
assumption and service accounts as entry points and assumption hops.
`_assert_identity_label` enforces the hard invariant: a credential/identity
hop's labels are a subset of `{INFERRED, CONDITIONAL}` — never tested,
observed, proved or imported. Each hop carries a fix candidate so the fix
set can propose scoping/rotating the credential.

### Evidence ingest — `ingest.py`
`parse_flows(raw, fmt=...)` reads observed-flow logs (generic / Zeek
`conn.log` / firewall allow logs, auto-sniffed) into `Flow`s — Zeek `S0`/`REJ`
map to *not real* so a dropped attempt can't raise a false alert.
`parse_sarif(raw)` reads pentest results into `ImportedFinding`s, and
`imported_edges(findings, mapping)` turns them into `IMPORTED`-labelled edges
(a third party demonstrated the hop; Paddock records it, never runs it).

### Read-only config sources — `connectors.py`
`ConfigSource` (In-Memory / File / AWS-API, `describe-*` only, boto3 imported
lazily) feed the parsers; `collect(sources)` merges many into one
`ParseResult` and skips a failing source with a recorded warning.

### Legacy graph adapter — `graph_adapter.py`
`environment_from_graph(graph)` turns Paddock's existing asset graph into an
`Environment` when no rule-aware twin exists yet. It is honestly
**all-inferred** (the legacy graph carries no firewall rules) and never
fabricates a config proof.

---

## 12. OT/ICS — `ot.py`

Industrial protocol catalog (Modbus, S7, DNP3, EtherNet/IP, BACnet, OPC UA,
IEC 104, PROFINET) and read-vs-write function classes. `assess_conduit(...)`
encodes the IEC 62443 honesty case: an **L3/L4-only firewall that allows the
control port allows every function code**, so a conduit a plant believes is
read-only is actually write-capable and is marked *conditional* — only a
DPI-capable rule configured read-only proves the conduit holds.
`annotate_route(route, ...)` flags hops that reach an OT device on a control
port.

---

## 13. Self-evaluation — `ranges.py`

The credibility keystone. `library()` is nine synthetic environments with
**known-correct ground truth** (open path, deny-closed, conditional-only,
decoy branch, identity/ungoverned path, planted misconfig, multi-entry/
multi-jewel). `score(cases) -> EvalReport` runs the engine on each and
computes:

- **`false_closed_rate`** = `|engine-closed but truly open| / |engine-closed|`
  — the headline number; a certificate is worthless if this isn't ~0. A
  conditional pair never counts as closed.
- `false_open_rate`, `closure_precision`, `closure_recall`, per-case results.

`run_library()` measures **false_closed_rate = 0.0** and false_open 0.0
(precision/recall 1.0) — the engine never calls a truly-open pair closed on
the library. A test (`test_ranges.py`) fails the build if that regresses.

---

## 14. Replica verification (no exploit) — `replica.py`

For components that can be rebuilt (container image, SBOM, the customer's own
code). `verify_preconditions(plan, preconditions, facts)` checks only
allowlisted `PreconditionKind`s against a facts dict describing the rebuilt
copy — version-in-range, flag-enabled, endpoint-exposed, code-reachable,
file-present, config-value — gated by `safety.assert_preconditions_allowed`.
`verify_fix(plan, pres, facts_before, facts_after, health_results)` proves
the fix removed a precondition **and** the service still passes its health
checks — without ever running a payload. `ReplicaRunner` is a documented
`Protocol`; the sandbox itself is a deployment concern, not implemented here.

---

## 15. Persistence and the product API

### How it's stored
- The engine computes in the **correlation** service and writes Postgres;
  the **orchestrator** service reads those tables and serves the API —
  mirroring the existing attack-path feature.
- `store.py` — `assemble_bundle(...)` serialises a reachability result,
  scorecard, boundary agreements, certificates, fix set and evidence packs
  into rows (schema `039_wargame.sql`); `persist(db, bundle)` writes them in
  one transaction. Stable PortRange formatting and route fingerprints.
- `twin_store.py` — persists the rule-aware **twin** (rule sets, rules,
  segments, edges, config snapshots; schema `040_wargame_twin.sql`) with
  exact round-trip ser/de, and `load_environment(db)` rebuilds a searchable
  `Environment` from stored config.
- `assess.py` — `assess_environment(env, ...)` is the pure glue that runs
  reachability, builds per-boundary agreement, signs certificates **only for
  closed+pass boundaries**, computes the fix set and the scorecard, and
  returns a persistable bundle.

### The HTTP surface
Correlation (internal, not in the public OpenAPI):
- `POST /ingest-config` `{vendor, raw, source}` → parse → store rule sets in
  the twin (+ a config snapshot hash);
- `POST /set-topology` `{segments, edges}` → store the topology;
- `POST /compute-wargame` → assess the **persisted twin** when present
  (config-proved, with certificates), else the all-inferred asset graph, and
  persist the result.

Orchestrator (`/v1/wargame/*`, in the OpenAPI, with generated Python + TS
SDKs):
- `GET /v1/wargame/assessments`, `/{id}`, `/{id}/routes`, `/{id}/boundaries`,
  `/{id}/certificates`, `/{id}/fix-set`, `/{id}/evidence` — paged, read-only,
  tenant-scoped by row-level security;
- `POST /v1/wargame/recompute` — trigger a run (sync call to correlation,
  Redis fallback, never fails hard);
- `POST /v1/wargame/twin/config`, `/twin/topology`, `GET /v1/wargame/twin` —
  ingest config / declare topology / read a twin summary.

All read endpoints serve routes and narratives verbatim as the compute
service wrote them; no endpoint aids exploitation.

---

## 16. Auditor evidence — `compliance.py`

`pci_segmentation_pack(...)` and `cip_005_pack(...)` map the engine's output
to hash-chained, tamper-evident evidence items:

- PCI DSS 4.0 **1.2.5** (allowed services justified), **1.2.7** (NSC config
  reviewed), **1.3.1/1.3.2** (CDE traffic restricted), **12.5.2** (scope
  confirmed), **11.4.5/11.4.6** (segmentation testing); NERC **CIP-005 R1**.
- A boundary `pass` → `MET`, `fail_open` → `EXCEPTION`,
  `conditional`/`insufficient` → `NOT_ASSESSED` with the reason.
- **11.4.5/6 stay honest:** `MET` only when an active probe backed the pass —
  a no-packet proof is not a segmentation *test* on its own.
- Every closure statement carries its coverage caveat; each item is chained
  (`chain`) so `verify_chain(pack)` detects tampering; statements pass
  `safety.safe_text`.

---

## 17. End-to-end flow

```
config export ─parse─▶ RuleSet(s) ─┐
observed logs ─ingest─▶ Flow(s) ───┤
pentest SARIF ─ingest─▶ IMPORTED ──┤
identity decl ─────────────────────┤
topology decl ─build_topology──────▶ Environment ──backward_reachability──▶ routes + open/closed pairs
route tables ─routing─▶ oracle ─────┘                                          │
                                                                               ├─ mincut ──▶ cheapest fix set
                                                                               ├─ agreement + certificate ──▶ signed closed-boundary proofs
                                                                               ├─ report ──▶ scorecard (closure + coverage)
                                                                               ├─ compliance ──▶ PCI/CIP evidence pack
                                                                               └─ store/twin_store ──▶ Postgres ──▶ /v1/wargame/* API + SDKs
observed flow vs a closed certificate ──impossible──▶ critical alert (human-resolved)
proposed change ──changegate──▶ routes opened/closed + live flows it would break
ranges ──score──▶ measured false-"closed" rate (0.0 on the library)
```

Three runnable demos print this end to end:

- `python -m app.engine.wargame.demo` — the attacker walks guest Wi-Fi →
  fridge → POS → payments DB; the cheapest fix; a signed certificate; an
  impossible-traffic alert.
- `python -m app.engine.wargame.demo_changegate` — a Terraform plan "opens a
  route to cardholder data"; another change "would break this live flow"; the
  scorecard moves.
- `python -m app.engine.wargame.demo_assess` — the full pipeline: model →
  routes (one config-proved, one inferred identity path) → fix → agreement →
  PCI pack → scorecard.

---

## 18. What is not built yet

The dashboard UI; probe deployment mode (the active worker on out-of-scope
segments); the sandbox runner behind `replica.ReplicaRunner`. Known
follow-ups: the orchestrator Redis fallback for twin ingest jobs isn't yet
consumed by correlation's stream handler (the sync path works and is tried
first); certificates use a documented demo signing key pending real
per-tenant key wiring; with no live probe/flow the compute-side agreement
uses model reachability as its probe source (disclosed via the certificate's
sensor-absent assumption); and Terraform rule ids don't match the AWS
parser's ids, so remove/modify across the two needs an id-mapping layer.

See [WARGAME.md §9](WARGAME.md) for the build-order status and the product
context.
