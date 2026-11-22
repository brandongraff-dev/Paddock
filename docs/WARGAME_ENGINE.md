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
and is covered by roughly 900 tests in `correlation/tests/wargame` (plus
the orchestrator API tests and the CLI tests).

### Surfaces

There are three ways to use Wargame; all of them sit on this engine:

- **The API.** Orchestrator `/v1/wargame/*` (read assessments, routes,
  boundaries, certificates, fix set, evidence; recompute; ingest a twin and
  its evidence (flow logs, recorded probe results);
  `POST /v1/wargame/change-impact`). See §15.
- **The dashboard page.** `/wargame` (`dashboard/src/pages/Wargame.tsx`):
  scorecard, routes with per-hop evidence labels, the cheapest fix set,
  boundary verdicts and certificates, the change gate, and a setup walk-through
  for an empty tenant. `/wargame?sample=1` renders a clearly labelled
  fictional estate; it is opt-in and never stands in for a failed or empty API
  response.
- **The local CLI.** `paddock wargame init | check | plan` (see
  [CLI.md](CLI.md)): reads a `wargame.toml` plus config exports from disk, no
  server, prints routes, the verified fix set and (for a Terraform plan) the
  change-gate verdict.

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
- `ReachabilityResult(routes, open_pairs, closed_pairs, conditional_pairs,
  truncated_pairs, incomplete_pairs, inferred_pairs, witness_routes,
  budget_exhausted)` — the pair sets are exact; `routes` are examples (§4).

### Fix set, certificate, replica, flows

- `FixCandidate(id, kind, cost_class, description, cost, blocks)` and
  `FixSet(selected, total_cost, cuts_all, uncut_routes, optimality)`;
  `mincut.VerifiedFixSet` extends it (§5).
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
  permitted, decided **exactly** (header-space style, no sampling). The
  query is a set of boxes — (src family + interval, dst family + interval,
  protocol class ∈ tcp/udp/icmp/other, port interval); `port=None` is all
  traffic and `Proto.ANY` all four classes. Rules are walked in first-match
  order, subtracting each rule's matched part from the remaining disjoint
  boxes (≤ 6 pieces per subtraction); what is left gets the default action.
  A conditional rule's match is uncertain: a conditional allow makes its
  part *possibly open*, and both conditional allows and denies also fall
  through to later rules. Verdict: a certain path to an allow → proved
  open; else an uncertain path to an allow → `allowed=True,
  conditional=True`; else closed (so a conditional deny followed only by
  denies is closed either way). IPv4 and IPv6 never intersect. An
  unparsable rule CIDR is widened to "any" and made conditional; an
  address-less or unparsable query side, or a box set past `MAX_BOXES` /
  `MAX_WORK`, returns the sound `allowed=True, conditional=True` — never
  closed. Ports compare literally on every protocol, as
  `PortRange.contains` does (parsers model ICMP as 0-65535).

---

## 4. Backward search — `reachability.py`

`backward_reachability(nodes, edges, rulesets, *, max_hops=8,
max_routes_per_pair=16, visit_budget=None) -> ReachabilityResult`.

The module does two separate jobs.

**1. Deciding open / closed — exact, independent of route enumeration.**
Each edge is first reduced to a traversable hop (below); non-traversable
edges are dropped. For every crown jewel a **reverse breadth-first search**
over the traversable edges, with **no hop limit and no budget**, finds every
entry that can reach it. A pair `(entry, jewel)` is:

- **open** iff the jewel is reachable from the entry over the traversable
  edges (`entry == jewel` is never a pair);
- **closed** iff it is not open ("no route exists in the model");
- **conditional** (`conditional_pairs`) iff it is open but **not** open over
  the subgraph of edges carrying no `CONDITIONAL` label — i.e. every route, of
  any length, leans on at least one conditional hop;
- **inferred** (`inferred_pairs`) iff it is open but not open over the
  subgraph of edges whose weakest label is stronger than `INFERRED` — every
  route leans on a hop the model merely infers (`INFERRED`/`UNKNOWN`).
  Inferred pairs stay open (an ungoverned adjacency is permitted by default,
  the conservative direction) and are *not* folded into `conditional_pairs`;
  the two sets may overlap. They exist so a report or certificate can ask for
  corroboration.

Because this pass never enumerates, no hop limit, cap or budget can turn an
open pair into a closed one (invariant 1.4).

**2. Listing example routes — bounded.** Simple paths are enumerated by a
backward depth-first search with iterative deepening on route length
(shortest first), bounded by `max_hops`, `max_routes_per_pair`, and a
**per-jewel** visit budget (`_VISIT_BUDGET = 200_000`, overridable with
`visit_budget`), so a dense neighbourhood around one jewel cannot starve the
jewels after it. Routes are examples, not the definition of open. The result
says where the listing fell short:

- `truncated_pairs` — open pairs with **no** listed route (none fit inside the
  limits). They stay open; `witness_routes` holds one deterministic shortest
  route for each, with no hop limit (so possibly longer than `max_hops`).
- `incomplete_pairs` — open pairs whose listed routes may not be *all* their
  routes (cap hit, hop limit bit, budget ran out, or parallel-edge variants cut
  off by the cap); includes `truncated_pairs`. A fix set solved over such a
  listing is not proven to cut the pair (§5).
- `budget_exhausted` — some jewel's enumeration hit its visit budget. Open /
  closed is unaffected.

**Hops.** Each edge becomes a hop template whose labels are:
- ungoverned edge → its `base_labels`, or `INFERRED` if it has none;
- governed edge → `rules.boundary_permits(...)`: **denied ⇒ not traversable**
  (a closed boundary), as is an edge whose rule set is missing or whose
  endpoint is not in the model; allowed ⇒ `PROVED_CONFIG`; conditional ⇒
  `CONDITIONAL` (never `PROVED_CONFIG`). Plus any `base_labels` (e.g.
  `OBSERVED`).

**Parallel edges.** Several traversable edges between the same ordered node
pair are not collapsed into one hop (that dropped the other edges' fix ids, so
the min-cut could "cut" a hop a parallel edge still carried). Edges are grouped
by `fix_candidate_id` (same id, or none, are interchangeable for cutting); each
group is represented by its strongest edge (strongest weakest-label, then
`rule_ref`, then port), and each node path is expanded lazily into one **route
variant per combination of groups**, each hop a concrete edge. Cutting every
variant of a node path is exactly "for some hop, cut all of its parallel
edges", so the hitting set over variants is correct. With no differing fix ids
the output is one route per node path. The primary variant (strongest edge on
every hop) comes first, then variants deviating on one hop, two hops, …;
variants count toward `max_routes_per_pair`.

Output is deterministic: neighbours are visited in sorted id order, routes are
emitted per pair shortest first, then primary before alternate variants, then
by node-id sequence. `shortest_route(nodes, edges, rulesets, entry, jewel)`
returns a single no-hop-limit shortest route.

This is the structural heart: "can anyone reach what matters, and by what
route, and how good is the evidence for each step."

---

## 5. The minimum-cost fix set — `mincut.py`

The cheapest set of changes that cuts **every** open route. This is a
weighted **hitting set** (a route is broken when the fix set contains any one
of its cuttable elements), which is NP-hard — the module says so and never
calls a result "minimal" unless the exact search completed.

- `min_cost_fix_set(routes, candidates) -> FixSet`: solves over the route
  element-sets it is given (duplicates and superset routes are dropped first).
  Exact branch-and-bound for small instances (≤ 24 distinct candidate ids
  across the reduced routes) with a disjoint-route cost lower bound and
  most-constrained-route branching; cost-effective greedy for larger ones. The
  branch-and-bound carries a **node cap** (`_BNB_NODE_LIMIT = 250_000`); if the
  cap is hit the better of its incumbent and the greedy answer is returned.
  Negative or non-finite costs raise `ValueError`; an id with no
  `FixCandidate` is priced at `DEFAULT_UNKNOWN_COST` (5.0), never zero.
- **What "exact" and "greedy" mean.** `optimality="exact"` means the
  branch-and-bound **completed** (and, for `verified_fix_set`, that the result
  was also verified against the model). `"greedy"` means *not proven minimal*:
  greedy ran, the node cap was hit, or the fix set was not verified. The
  persisted schema admits only these two values; `VerifiedFixSet.solver`
  records what actually ran (`branch_and_bound`, `branch_and_bound_incomplete`,
  `greedy`, `none`).
- A route with no cuttable element (an inferred hop with no modelled control)
  cannot be cut: it is recorded in `uncut_routes` and forces `cuts_all=False`.
- `cost_for(cost_class, overrides)` resolves the weight; a compensating
  control naturally beats a device patch because it is cheaper.
- `fix_set_for(result, candidates)` solves over the **listed** open routes'
  `fix_elements`. Because the listing is bounded, if any open pair is in
  `incomplete_pairs` (or `budget_exhausted`) it reports `cuts_all=False` and
  `optimality="greedy"`: it will not claim to cut routes it never saw. It is
  used by the demos; the product paths use the verified version.

### `verified_fix_set` — checked against the model

`verified_fix_set(nodes, edges, rulesets, candidates, *, pairs=None,
max_iters=25, max_hops=8, max_routes_per_pair=16, result=None) ->
VerifiedFixSet`. `assess.assess_environment` and the CLI (`paddock wargame
check`) use this, not `fix_set_for`. It runs a **lazy-constraint loop**:

1. Take the open pairs of `backward_reachability` (or the caller's `result`
   for the same model and limits), optionally restricted to `pairs`, as the
   targets.
2. Re-run reachability with **every** candidate applied. Targets still open are
   **uncuttable** (e.g. an inferred hop with no control): reported in
   `uncuttable_pairs`, not targeted.
3. Solve the hitting set over the listed routes of the cuttable targets
   (`truncated_pairs` contribute their witness route).
4. `apply_fix_set(edges, selected)` removes every edge whose
   `fix_candidate_id` is selected; re-run exact reachability. If a target is
   still open, add its surviving routes (or a shortest witness) as new
   constraints — each avoids every selected fix, so it is genuinely new — and
   re-solve. Repeat until verified or `max_iters` rounds.
5. If the exact solver is out of reach (`proven` false), the selection is grown
   monotonically with greedy additions instead of re-solving from scratch
   (which can oscillate), and a reverse-delete pass at the end drops fixes the
   constraint pool does not need, keeping the result only if it still verifies.

Because each added constraint is a real route, every solve is over a
relaxation of the true problem, so an exact solve that verifies is the true
optimum. `VerifiedFixSet` adds `verified`, `target_pairs`, `uncut_pairs` (still
open after the fix: the uncuttable ones plus any not closed within
`max_iters`), `uncuttable_pairs`, `iterations`, `routes` (the constraint
routes, then example routes of the uncuttable pairs, which `uncut_routes`
indexes) and `solver`. `cuts_all` is `True` only when the post-fix model has no
open target pair; `optimality` is `"exact"` only when verified **and** the
final solve was a completed branch-and-bound.

`assess.py` stores `fix_set_verified`, `fix_set_solver`, `fix_set_uncut_pairs`
and `fix_set_uncuttable_pairs` in the assessment `metadata` (there is no
fix-set column for them; see §18).

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
  config hashes, sorted assumptions, corroboration, issued/expires normalised
  to UTC, and the `key_id`) — deliberately **excluding** `status`, so
  `mark_contradicted(cert)` can flag a cert without invalidating its
  signature (so `status` itself is not tamper-evident). `None` and the
  protocol-agnostic full port range canonicalise identically (they are stored
  identically), and a timestamp re-read from Postgres or written with `Z` /
  another offset verifies. `verify(cert, key)` recomputes with
  `hmac.compare_digest`.
- **Keys — `signing.py`.** `WARGAME_SIGNING_KEY` (or
  `WARGAME_SIGNING_KEY_FILE`; retired masters in
  `WARGAME_SIGNING_PREVIOUS_KEYS`, comma/space separated — the
  `AUDIT_HMAC_KEY` convention) is a master key read by
  `correlation/app/config.py`. A certificate is signed with a **per-tenant**
  key, `HMAC-SHA256(master, "paddock-wargame-cert/v1" || 0x00 || tenant_id)`,
  and records `key_id = "wg1-" + HMAC(master, "paddock-wargame-key-id/v1")[:16]`
  so `verify_with(cert, keyring, tenant)` picks the right master after
  rotation; `signature_status` returns `signed` / `unsigned-dev` / `invalid`.
  With **no key configured** the public development key is used, the
  certificate gets `key_id = "unsigned-dev"` and an `unsigned_dev_signature`
  assumption (inside the signed fields) saying it is not a signature, and the
  service logs a warning outside a dev `ENV`. Legacy certificates
  (`key_id = ""`) were all made with the public key and read as unsigned.
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
  Pairs are diffed by state (closed < conditional < open), so a closed pair
  turning **conditional** ("opens a route, possibly", `RouteDelta.conditional`)
  or a conditional route turning definite is an opened route — never `safe`.
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
- `resolve(alert, resolution, reason, resolved_by)` requires a human, a cited
  reason and a resolution from the `ImpossibleResolution` taxonomy (free text
  such as "false positive" is refused) and returns a read-only record — the model is **never**
  auto-amended to explain a flow away (that could legitimise an attacker's
  tunnel).
- In the product, the twin's **stored** flows (schema 044, §15) are
  classified on every twin assessment against the certificates of the
  previous twin assessment that are still valid; the alerts land in the
  assessment `metadata` (`impossible_traffic_alerts`,
  `impossible_traffic_sample`). The same flows make the crossed pair
  `fail_open` in that run, so it gets no new certificate.

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
  config `CLOSED` + a **real** probe `CLOSED` with no open observation →
  `pass`; config `CLOSED` with **no probe** → `proved_config` (a no-packet
  proof, not yet tested); otherwise `insufficient`. The full vocabulary is
  `agreement.VERDICTS`; `CERTIFIABLE_VERDICTS = {pass, proved_config}`.
- `from_environment(...)` checks ONE direct boundary (the rule set on the
  `src → dst` edge) plus an optional real probe and observed flows.
  `from_reachability(result, entry, jewel, ...)` is the **pair-level** check:
  its config verdict comes from the end-to-end search (open → OPEN,
  conditional → `conditional`, closed → CLOSED), never a direct-edge lookup —
  a multi-hop pair usually has no direct edge. A pair in `truncated_pairs` is
  open (it has no listed route, not no route) and reads as OPEN; a truncated
  pair that is somehow not open reads UNKNOWN, never closed. The probe is UNKNOWN unless a
  real probe result is passed; the model's own reachability is never fed in
  as a "probe" (that was circular evidence).

`report.py` turns a `ReachabilityResult` into the board/auditor numbers:

- `ClosureScore` — total/open/closed/conditional/unproven `(entry, jewel)`
  pairs, `closure_pct`, and a histogram of each open pair's weakest-label.
  `build_scorecard(..., closure_proven=False)` (a model with no rule data,
  e.g. the legacy graph) counts "no route found" as **unproven**, not closed:
  closure is 0% and the board line says closure is unproven. An empty model
  says no routes were assessed rather than "0% closed". `verdict_counts`
  separates probe-backed `pass` from config-only `proved_config`.
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
| `cisco_asa` | ASA config text | objects + nested object-groups, extended ACLs with order/deny, named ports, `access-group` interface and `global` bindings; **security-level default rule sets** (`asa:security-level:permit` / `:deny`) bound per interface pair when no ACL is bound, `same-security-traffic permit inter-interface` honoured; the global ACL is combined after the interface ACLs; object and twice NAT make affected rules conditional |
| `fortinet` | FortiOS CLI | address/addrgrp (incl. FQDN), service custom/group, policies grouped into `srcintf>dstintf` rule sets (`any` interfaces expanded), disabled policies skipped; **IPv6** (`address6` / `policy6`); address and service **negation** modelled as an exact complement; VIPs (destination NAT) and non-`always` schedules make rules conditional |
| `paloalto` | PAN-OS `set` format | objects (scoped `shared` / `vsys` / `device-group` tables, local shadows shared), static vs **dynamic** address groups, security rules grouped by zone pair in PAN-OS order **pre-rulebase → local rulebase → post-rulebase** (shared pre, device-group pre, local, device-group post, shared post); `rule-type` (intrazone / interzone / universal) honoured; default **intrazone ALLOW** rule sets and interzone DENY |
| `terraform` | `terraform show -json` plan | `parse_plan()` → a `ProposedChange` for the change gate |

The shared foundation `parsers/base.py` does the work that decides
correctness:

- **Nested object/group resolution** (`ObjectTable`) with cycle and depth
  guards; CIDR/netmask/Cisco-wildcard/range normalisation (`normalize_cidrs`);
  a named-service and protocol map. A user-defined object wins over a
  same-named built-in.
- **Address families.** `"0.0.0.0/0"` is **IPv4 only**: "any" is
  `ANY4_CIDRS = ("0.0.0.0/0",)` or `ANY6_CIDRS = ("::/0",)` by family, so an
  IPv4 any-rule never silently covers IPv6 (and vice versa).
- **The honesty rule.** `ConditionalFeature` enumerates runtime-only features
  (FQDN, App-ID, User-ID, dynamic address groups, external dynamic lists,
  URL/geo categories, SD-WAN, and `NAT` (translation changes the match),
  `SCHEDULE` (rule active only in a time window) and `PARTIAL_MATCH` (the rule
  also matches on a field the model lacks: source port, ICMP type, protocol
  number)) and `UNRESOLVED`. Group cycles, over-deep nesting, empty groups and
  unreadable masks are never read as a clean "any" or as "matches nothing": they
  become **conditional any** with a warning. Any rule that uses one — *or
  references an object the parser could not resolve* — is marked
  `conditional=True` and over-approximated toward *reachable* (resolve the
  unknown to "any"), so a parse gap can never prove a boundary closed. Every
  conditional/unresolved rule emits a `ParseWarning`.
- `build_rule(...)` assembles a `Rule` and applies the honesty rule;
  `ParseResult` carries `rulesets`, `bindings` (where each set is enforced)
  and `warnings`.

**Still open in the firewall parsers.** ASA: an interface bound with both an
`in` and an `out` ACL is not modelled as their conjunction. FortiGate:
`proxy-policy`, `multicast-policy` (and the 4-to-6 / 6-to-4 policy tables) and
local-in policies are skipped with a warning. PAN-OS: the Panorama
device-group **hierarchy** (parent/child inheritance) is not followed.

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

The credibility keystone. `library()` is **13** synthetic environments, scored
against ground truth the engine does not produce:

- Cases 1–9 have **hand-declared** truth: open path (`single_open`,
  `two_hop_open`), deny-closed (`deny_closes`, `broken_middle_hop`),
  conditional-only, decoy branch, identity/ungoverned path, planted
  misconfiguration, multi-entry/multi-jewel.
- Cases 10–13 are **adversarial** — built to break enumeration-based shortcuts
  — and take their truth from `ground_truth(env)`: `long_chain_open` (a 10-hop
  route, beyond the 8-hop listing limit), `dense_budget_starved` (a complete
  10-node mesh feeding one jewel, with a later jewel one hop away),
  `parallel_edges_split_fix` (two parallel firewalls with different fix ids),
  `sub_cidr_carveout` (allow/deny slices over part of a /24 source node).

**The independent oracle.** `ground_truth(env) -> (truly_open, truly_closed)`
is a brute-force checker that **shares no code with the engine**: it
re-implements first-match evaluation (a matching conditional rule counts as
"possible"), enumerates every host of every CIDR (CIDRs over 1024 addresses
are refused, so only tiny ranges) and every port breakpoint of every rule
inside the edge's port class, and runs its own graph search. It is how the
adversarial cases get their truth, and how fix sets are checked.

`score(cases) -> EvalReport` runs the real engine on each case and computes:

- **`false_closed_rate`** = `|engine-closed but truly open| / |engine-closed|`
  — the headline number; a certificate is worthless if this isn't 0. A
  conditional pair never counts as closed.
- `false_open_rate`, `closure_precision`, `closure_recall`, per-case results.
- **`false_cut_rate`** = `|cases where a fix set claimed cuts_all but the
  oracle still finds a target pair open after applying it| / |cases with a
  cuts_all claim|`. Both `fix_set_for` and `verified_fix_set` are checked; it
  must be 0. A case counts as correct only if there is no false closed, no
  false open and no false cut.

**Measured** (`python -c "from app.engine.wargame import ranges;
print(ranges.run_library().summary)"` in `correlation/`): 13 cases, 21 scored
pairs, 13/13 cases match ground truth; **false_closed_rate 0.0000**,
false_open_rate 0.0000, closure precision 1.0000, closure recall 1.0000,
**false_cut_rate 0.0000**. One case (`parallel_edges_split_fix`) produces a
`cuts_all` claim; the other twelve have no fix candidates on their edges (or
nothing open), so they make none — the rate is over that single claim.
`test_ranges.py` fails the build if any of these regress.

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
  into rows (schema `041_wargame.sql`); `persist(db, bundle)` writes them in
  one transaction. Stable PortRange formatting and route fingerprints.
- `twin_store.py` — persists the rule-aware **twin** (rule sets, rules,
  segments, edges, config snapshots; schema `042_wargame_twin.sql`) with
  exact round-trip ser/de, and `load_environment(db)` rebuilds a searchable
  `Environment` from stored config.
- `assess.py` — `assess_environment(env, ..., signing_key, probes,
  observed_flows)` is the pure glue that runs reachability, builds
  **pair-level** agreement (`from_reachability`), signs certificates **only
  for closed pairs whose verdict is `pass` or `proved_config`** (never
  `conditional`, open or truncated; a `proved_config` certificate carries a
  `proof_basis` assumption saying no probe stood behind it and
  `probe_tested=false`), computes the fix set and the scorecard, and returns
  a persistable bundle. `assess_unproven_environment(env)` is the legacy-graph
  ("auto") variant: no verdicts, no certificates, closure unproven.
- `evidence.py` + schema `044_wargame_evidence.sql` — the twin's **boundary
  evidence**: `wargame_observed_flows` (flows parsed from the customer's own
  logs) and `wargame_probe_results` (recorded probe results: `src_segment`,
  `dst_segment`, `proto`, `port`, `result` ∈ `crossed|blocked|error`,
  `observed_at`, `source`). Both tenant-scoped (RLS, as 042) and bounded:
  flows keep a rolling **30-day** window by `observed_at` (the flow's own
  timestamp when it parses and is not in the future, else the ingest time)
  and at most **100,000** rows per tenant, newest kept; probe results keep
  **30 days** and at most **50,000** rows. Pruning runs on every ingest.
  `_wargame_tenant` loads them and calls `assess_environment(probes=...,
  observed_flows=..., observation_window_days=..., standing_certificates=...)`
  (rules below).
- Schema `043_wargame_verdicts.sql` widens the boundary verdict CHECK with
  `proved_config` and adds `wargame_certificates.key_id` and
  `.corroboration` (so a stored certificate can be re-verified and shows
  whether a probe backed it). The API's `WargameCertificateOut` exposes
  `key_id`, `signed` and `corroboration`.

### Evidence: how stored flows and probes become verdicts

- **Pair mapping.** A probe result counts for an `(entry, jewel)` pair only if
  it was run from that entry segment **to** that jewel segment
  (`src == entry`, `dst == jewel`). Probes between other segments (hops) are
  stored but never inferred into a pair verdict: hop results do not compose
  into an end-to-end test. Per `(src, dst, proto, port)` the newest result
  wins; the pair reads *crossed* if any port's newest result crossed (a tie
  in time goes to crossed), else *blocked*.
- **Staleness.** A result older than the certificate TTL (`CERT_TTL_HOURS` =
  `evidence.PROBE_MAX_AGE_HOURS` = **24 h**) does not count, so a `pass`
  certificate never outlives the probe behind it; nor does one dated more
  than 5 minutes in the future. `error` results never count (an error is no
  probe). The age is measured from the result's own `observed_at`, not from
  when it was uploaded.
- **Verdicts.** Config-closed + a fresh mapped *blocked* probe + no real
  crossing → `pass` (certificate `probe_tested=true`, no `proof_basis`
  assumption). No mapped fresh probe → `proved_config`, as before. A mapped
  *crossed* probe, or a stored **real** flow (`impossible.flow_is_real`) from
  the entry's CIDRs to the jewel's, → `fail_open` and no certificate.
  Observation never proves closure.
- **Impossible traffic.** Real stored flows are classified against the
  previous twin assessment's still-valid certificates (and this run's); see
  §8. Metadata also records `probed_pairs`, `pass_pairs`, `observed_flows`
  and `observation_window_days` (the whole days the loaded flows span, ≤ 30).

**Where probe results come from.** Paddock does not send packets for this
path: `/twin/probes` records results the customer's own probe or scanner
produced. Wargame's own probe deployment (WARGAME.md §2.2, §12 "approve probe
mode") is not built. The existing active worker's **`open_port` safe check**
(`workers/active/app/modules/safe_checks/network_checks.py`, `tcp_banner`:
TCP connect + passive banner read, nothing sent, scope-gated and audited) is
the building block that mode would deploy. If its results are submitted, map
them conservatively:

| `tcp_banner` state | `/twin/probes` `result` | Why |
|---|---|---|
| `open` (handshake completed) | `crossed` | the connect got through |
| `filtered` (timeout, no answer) | `blocked` | dropped on the way |
| `closed` (connection refused / RST) | `error` | a RST may come from the far host (the boundary let the SYN through) or from a firewall that rejects with a reset; it is not proof of a block |
| `error` | `error` | no evidence |

and set `src` to the segment the worker ran in, `dst` to the target's
segment, `observed_at` to when the check ran. Today the worker runs from
Paddock's own vantage point, not from an entry segment, so its results map
onto a pair only when that vantage point *is* a declared entry segment.

### The HTTP surface
Correlation (internal, not in the public OpenAPI):
- `POST /ingest-config` `{vendor, raw, source}` → parse → store rule sets in
  the twin (+ a config snapshot hash);
- `POST /set-topology` `{segments, edges}` → store the topology;
- `POST /ingest-flows` `{raw, format: auto|zeek|generic|firewall, source}` →
  `ingest.parse_flows_detailed`, store only the flows that parse →
  `{flows_parsed, flows_skipped, flows_stored, warnings}`;
- `POST /ingest-probes` `{results: [{src, dst, proto=tcp|udp|icmp, port,
  result: crossed|blocked|error, observed_at, source}]}` (≤ 10,000) → a
  result naming a segment the twin does not hold, the same segment twice, or
  a future time is rejected (counted, with a warning), the rest are stored →
  `{stored, rejected, warnings}`; 409 when the tenant has no topology;
- `POST /compute-wargame` → assess the **persisted twin** when present
  (config-proved, with certificates), else the all-inferred asset graph, and
  persist the result;
- `POST /change-impact` `{plan, flows?, flows_format}` → the change gate
  against the tenant's persisted twin (below).

Size caps (each exceeded cap is a 413/422, never an OOM): config `raw` ≤ 8 MiB
of characters, ≤ 5,000 topology segments and ≤ 20,000 topology edges, `flows`
≤ 8 MiB of characters (`/change-impact` and `/ingest-flows`), ≤ 10,000 probe results,
and a `/change-impact` body ≤ 32 MiB. The orchestrator
enforces raw body caps **before** parsing (by `Content-Length` and by counting
streamed bytes): 16 MiB for `/v1/wargame/twin/config` and `/twin/flows`, 8 MiB
for `/twin/topology`, 4 MiB for `/twin/probes`, 32 MiB for `/change-impact`.

**Change impact.** Correlation `POST /change-impact` and orchestrator
`POST /v1/wargame/change-impact` (which proxies synchronously, 60 s timeout, no
Redis fallback — the caller needs the answer). Request: `plan` (the object from
`terraform show -json`), optional `flows` (raw firewall / Zeek / generic text)
and `flows_format` (`auto`, `zeek`, `generic`, `firewall`). It is **read-only**:
it loads the tenant's twin, applies the parsed plan to a copy, runs
`changegate.evaluate_change` before vs after, and persists and applies nothing.
Response: `verdict` (`safe`, `opens_route_to_crown_jewel`, `breaks_live_flows`,
`opens_and_breaks`; treat an unknown value as "needs review"),
`routes_opened` / `routes_closed` (`{entry, jewel}`), `newly_denied_flows` /
`newly_allowed_flows` (`{src_ip, dst_ip, proto, dst_port, ruleset_id}`),
`summary`, `warnings`, `change_title`, `affected_boundaries`, `flows_parsed`,
`flows_skipped`, and **`complete`**. `complete` is `false` when part of the plan
was **not** evaluated: a modelled resource type that failed to parse or was
malformed, or an operation on a rule set or rule the twin does not hold
(reported as a "not evaluated" warning, never silently dropped). Resource
types the gate does not model at all (instances, buckets, …) are noted in
`warnings` but do not clear `complete`. A `safe` verdict with
`complete=false` is **not a proof**, and the summary says so. Errors: 409 no
twin for the tenant, 422 not a `terraform show -json` plan (or not
evaluable), 413 oversize, 503 correlation unreachable or failing.

Orchestrator (`/v1/wargame/*`, in the OpenAPI, with generated Python + TS
SDKs):
- `GET /v1/wargame/assessments`, `/{id}`, `/{id}/routes`, `/{id}/boundaries`,
  `/{id}/certificates`, `/{id}/fix-set`, `/{id}/evidence` — paged, read-only,
  tenant-scoped by row-level security;
- `POST /v1/wargame/recompute` — trigger a run (sync call to correlation,
  Redis fallback, never fails hard);
- `POST /v1/wargame/change-impact` — the change gate (above);
- `POST /v1/wargame/twin/config`, `/twin/topology`, `/twin/flows`,
  `/twin/probes`, `GET /v1/wargame/twin` — ingest config / declare topology /
  store flow logs / record probe results / read a twin summary (row counts,
  including `flow_count`, `probe_count` and `probe_fresh_count`, the results
  young enough to count). The four writes are `admin` (a blocked probe
  upgrades a pair to `pass`, so submitting one is as sensitive as submitting
  the config); each falls back to a Redis job (`twin_ingest_config`,
  `twin_set_topology`, `twin_ingest_flows`, `twin_ingest_probes`) when
  correlation is unreachable, and passes a correlation 4xx through unqueued.

**Grants.** The correlation service role (`paddock_svc_correlation`) must be
granted the wargame tables. `schema/042_wargame_twin.sql` extends 029's
service-grant allow-list in `paddock_apply_service_grants()` with the eleven
tables (`wargame_assessments`, `_routes`, `_boundaries`, `_certificates`,
`_fix_sets`, `_evidence`, `_rulesets`, `_rules`, `_segments`, `_edges`,
`_config_snapshots`) so a later grant run does not revoke them, and also grants
`SELECT, INSERT, UPDATE, DELETE` on them directly. `044_wargame_evidence.sql`
extends the same allow-list (as 042 left it) with `wargame_observed_flows` and
`wargame_probe_results` the same way.

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
- `proved_config` (config-only) for the *configuration* controls 1.3.1/1.3.2
  and CIP-005 R1 (whose testing procedure is an NSC configuration review)
  counts toward `MET` **only with measured coverage ≥ 90%** — with no probe,
  the model's completeness is the only thing behind it; otherwise
  `NOT_ASSESSED`. Statements say how many boundaries are probe-backed vs
  config-only. 1.2.5 accepts it as assessed.
- **11.4.5/6 stay honest:** `MET` only when an active probe backed the pass —
  `proved_config` never satisfies them.
- 1.2.7 is not `MET` on `unsigned-dev`/legacy certificates, nor on one that
  has expired by `generated_at` (even if its stored status still says valid).
- `coverage_pct` is a fraction in [0, 1]; anything else raises (so 97.0 can't
  read as 9700%).
- Every closure statement carries its coverage caveat; each item is chained
  (`chain`) over every displayed field (control id, title, status, statement,
  evidence, refs) from a seed binding the pack header (framework,
  generated_at), so `verify_chain(pack)` detects an edited, reordered,
  inserted or deleted item, a relabelled header or a rewritten summary. The
  chain is unkeyed: it proves integrity against the recorded fingerprint.
  Statements pass `safety.safe_text`.

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
ranges ──score──▶ measured false-"closed" and false-cut rates (0.0 on the library)
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

Built since the earlier version of this list: the dashboard page
(`/wargame`), the change-impact endpoint, the `paddock wargame` CLI, and the
twin's boundary evidence (stored flows + recorded probe results, schema 044),
so a closed pair can now read `pass` and a real crossing `fail_open`.

Still missing:

- **Probe deployment mode** — the active worker on out-of-scope segments that
  would produce real probe results (an owner decision, WARGAME.md §12).
  Results from the customer's own probe or scanner can already be recorded
  (`/v1/wargame/twin/probes`, §15); Paddock itself sends none for Wargame.
- **The replica sandbox runner** behind `replica.ReplicaRunner` (only the
  precondition checks exist).
- **Redis fallback consumer: built, with limits.** Correlation's
  `app/jobs.py` consumes the `queue:correlate` stream (consumer group
  `correlation`, created at id `0` so jobs queued during an outage are still
  read) and handles `recompute_paths`, `recompute_wargame`,
  `twin_ingest_config` and `twin_set_topology`. Each job runs inside its own
  `tenant_id` (a job with none is rejected and acked, even when
  `TENANCY_STRICT` is off, never run cross-tenant) and calls the same function
  as the sync endpoint. Ack happens only after success. Poison jobs (bad JSON,
  invalid payload, a 4xx from the shared code, unknown `op`) are logged and
  acked. Transient failures stay pending, are re-claimed after 30 s, and after
  5 deliveries are copied to `queue:correlate:dead` and acked. Not covered: no
  tooling reads or replays the dead-letter stream.
- **`scripts/install.sh` does not generate `WARGAME_SIGNING_KEY`**, so an
  install without it signs with the labelled public development key
  (`unsigned-dev`).
- **Impossible-traffic alerts live in assessment `metadata`** (count + the
  first five), not in their own table, and a contradicted earlier certificate
  keeps its stored `status` (`valid`); there is no resolution workflow in the
  API yet (`impossible.resolve` exists in the engine only).
- **The fix set's uncut pairs live in assessment `metadata`**
  (`fix_set_uncut_pairs`, `fix_set_uncuttable_pairs`), not in a fix-set column,
  so the stored fix-set row alone does not say which pairs it fails to cut.
- Terraform ↔ AWS rule matching is partial: NACL rules use the AWS parser's
  ids directly and security-group rules are matched by content when the plan
  is parsed against the twin (`parse_plan(raw, env)`). A remove/modify that
  can't be matched (SG-to-SG references, prefix lists) keeps the live rule
  and is reported with a warning; the change-impact result then has
  `complete=false`.

See [WARGAME.md §9](WARGAME.md) for the build-order status and the product
context.
