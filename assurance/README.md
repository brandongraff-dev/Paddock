# paddock-assurance (0.2)

**Provable containment.** Declare what must never be reachable, then search for a
counterexample. Scope and design: [`docs/PROVABLE_CONTAINMENT_MVP.md`](../docs/PROVABLE_CONTAINMENT_MVP.md);
how the platform feeds and runs it: [`docs/ASSURANCE_P1.md`](../docs/ASSURANCE_P1.md).

This is a pure library and CLI: no database, no network, no clock except the one you pass in.
The orchestrator (`orchestrator/app/assurance/`) builds the graph from its tables and runs this
library; the library itself knows nothing about the platform. Version 0.2 made coverage
**directional and multi-source** and added the `covered` assertion; see *Coverage* below.

```bash
cd assurance
pip install -e '.[test]'

paddock-invariants std                      # the four shipped invariants
paddock-invariants lint std:no-internet-to-datastore
paddock-invariants test std:no-internet-to-datastore std:guest-cannot-reach-pos \
    std:public-ports-allowlist --graph examples/estate-violated.json     # exit 1, with witnesses
paddock-invariants test std:guest-cannot-reach-pos --graph examples/estate-clean.json   # exit 0
paddock-invariants explain std:guest-cannot-reach-pos --graph examples/estate-violated.json
pytest -q
```

Exit codes for `test`: `0` all hold, `1` any violated, `2` none violated but some `UNKNOWN`
or `EXPIRED`, `3` bad input.

## The four invariants

| id | Says |
|---|---|
| `std:no-internet-to-datastore` | From the internet, no data store is reachable (up to 6 hops), reaching but not passing through nodes labelled `app-tier`. |
| `std:guest-cannot-reach-pos` | Nothing in zone `guest` can reach anything in zone `pos`, through any chain of devices. |
| `std:public-ports-allowlist` | Everything the internet can connect to is limited to 80 and 443, unless an expiring, reasoned exception says otherwise. |
| `std:coverage-complete` | Every host, cloud instance, database, load balancer and device is covered **both inbound and outbound** by fresh evidence of at least `configured` strength. Each gap is named with its direction and reason. |

## How a verdict is reached

- **Directed graph.** `A -> B` means A may open connections to B on a protocol and ports, each
  edge tagged with the strength of its evidence: `declared < configured < observed < tested`.
- **Coverage lives on nodes, per direction** (next section). An unknown edge `u -> v` can exist
  only if `u` is not covered *outbound* **and** `v` is not covered *inbound*.
- **Verdicts:** `VIOLATED` (a witness path exists, always wins), `UNKNOWN` (a possible path
  through unknown edges, a selector that matches nothing, or coverage below the floor),
  `HOLDS` (no counterexample at this coverage), then `EXPIRED` once the stalest evidence used
  ages past `max_age`. `HOLDS` means **no counterexample found**, never "secure".
- **Application boundary (`via.stop_at`).** A normal web, app, database stack always links the
  internet to its database through the app. A boundary lets the search reach a node without
  passing through it. It is part of the invariant's digest and is reported in every result.
- **Exceptions** (`allow`) must carry a reason and an expiry; expired ones are ignored and
  reported, and so is one whose expiry is more than 400 days after the evaluation time
  (`invalid_reason: expiry_too_far`; `expired` for the ordinary case). A `HOLDS` that is
  evaluated while an exception is active is only valid until the end (23:59:59 UTC) of the
  earliest active exception's last day, as well as until its stalest coverage fact ages out:
  `valid_until` is the minimum of the two, and a `HOLDS` always has a finite `valid_until`.
- **Overlapping selectors.** A node selected by both `subjects.from` and `subjects.to` is a
  *target* for anything that starts at a different source; only the trivial self-path is
  excluded (a pos-tagged device sitting in the guest zone is exactly what `guest cannot reach pos`
  should catch). If no source/target pair exists at all (the one source is the one target) the
  answer is `UNKNOWN` (`empty_selector:no_distinct_pair`), never `HOLDS`. For `unreachable` an
  overlap of more than 64 nodes is `UNKNOWN` with `overlapping_selectors_too_large` and the
  overlapping nodes listed as blind spots (the search runs once per overlapping node); `exposes-only`
  is one pass over the edges, so its overlap is never capped.
- **Every violating target** is in `Result.to_dict()['violating_targets']` (sorted node refs, at
  most 5000; `violating_truncated` says when the cap bit). For `assert: covered` they are the
  uncovered nodes. `witnesses` stays the short readable sample (root causes first).
- **`unproven_targets`** (reach only; empty otherwise) lists, next to a `VIOLATED` verdict, the
  targets no known path reaches but a path through an unknown (blind) edge could. A consumer must
  never read "absent from `violating_targets`" as "proven safe": the findings sync closes a finding
  of a target that stopped violating only if it is in neither list. If the list is longer than the
  cap, `violating_truncated` is set so such a consumer closes nothing.
- Output is deterministic (sorted adjacency, no hidden clock) and every invariant has a
  content-addressed digest that is stable under key order and defaulted fields.

## Coverage

Coverage says "we know every connection of this node, in this direction, as of this time".
A connection `u -> v` needs `u` to open it **and** `v` to accept it, so one end being fully known
in the matching direction is enough to rule the edge out, and nothing else is. A security group's
ingress rules know what may reach an instance and say nothing about what the instance connects
to, so that source is `in` only.

- A node carries a **list of facts**. A fact is `{direction: in|out|both, tier, observed_at,
  source}`. The P0 single object (no `direction`) is still accepted and means `both`. A fact in a
  list **must** name its direction: guessing `both` would claim more than is known.
- **Qualified facts** (`origin`, `proto`, both optional). An outside-in TCP port scan knows what
  the *internet* can reach over TCP and nothing else, so its fact is
  `{direction: in, origin: internet, proto: tcp, ...}`. A qualified fact only rules out an unknown
  edge whose source and protocols it speaks for: `origin: internet` only for edges from the
  `internet` node (and only with `direction: in`), `proto` only when the invariant's
  `via.protocols` are all that protocol. Everything else ignores it, so it never makes a node
  count as covered, never satisfies `assert: covered`, and never rules out an edge from an
  internal source. Unknown qualifier values are a `GraphError`, and so is a qualifier that is present but not a
  non-empty string (`0`, `false`, `[]`, `""`, `null`): omit the key for "unqualified", because
  silently reading a mangled qualifier as unqualified would widen what the fact claims.
- A node is covered in a direction when some fact for that direction (or `both`) is **fresh**
  (`now - observed_at <= evidence.max_age`, not more than 5 minutes in the future) and at least
  `evidence.min_tier`. Several sources can each cover one direction.
- Both searches use the same rule: the augmented BFS for `unreachable` adds exactly the possible
  edges `u -> v` (`u` blind outbound, `v` blind inbound, `u != v`); `exposes-only` flags
  `s -> t` the same way. These are bipartite, not the P0 clique.
- **Evidence.** For every node-direction a `HOLDS` relied on, the best qualifying fact (highest
  tier, then freshest) is used; `evidence_tier` is the weakest of those and `valid_until` the
  earliest `observed_at + max_age`. The reliance is conservative and includes covered nodes off
  the found paths whose coverage is what keeps an unknown edge out (if it lapsed, the verdict
  could change), so a `HOLDS` stays true until its stated expiry (the randomized tests check it).
- `blind_spots[]` rows carry `direction` (`in`, `out`, `both`) next to `reason` and `relevant`.
  `coverage.covered / universe` counts a node as covered only when covered in **both**
  directions. The universe leaves out the pseudo-nodes `internet` and `cidr` (nothing can be
  installed on them), so a small, fully watched estate can meet a 0.95 floor.

### Asserting coverage

```yaml
assert: covered          # subjects.to required; no from, ports, via or allow
subjects: { to: { kind: [host, cloud_instance, cloud_db, cloud_lb, device] } }
```

`HOLDS` iff every selected node is covered in both directions at `min_tier` and `max_age`.
Otherwise `VIOLATED` with one **hop-less** witness per uncovered node
(`detail = {node, direction, reason, reason_in?, reason_out?}`), nodes nobody watches first, then
weak evidence, then quiet sensors. An empty selector is `UNKNOWN`. The graph-wide
`coverage.require` floor does not apply (the assertion *is* the coverage statement).

## Reach-graph file

```json
{ "version": 1, "now": "2026-12-01T09:00:00Z",
  "nodes": [{"id": "db-1", "kind": "cloud_db", "zone": "prod", "class": "data_store",
             "tags": ["crown-jewel"],
             "coverage": [
               {"direction": "in",   "tier": "configured", "observed_at": "2026-12-01T08:30:00Z", "source": "aws_sg"},
               {"direction": "both", "tier": "observed",   "observed_at": "2026-12-01T08:45:00Z", "source": "sentry"}]}],
  "edges": [{"src": "app-1", "dst": "db-1", "proto": "tcp", "ports": "5432", "basis": "observed"}] }
```

`coverage` may also be the P0 object `{"tier", "observed_at", "source"}` (= `both`), a list, or
absent (blind). At most 32 facts per node.

`examples/gen_estates.py` regenerates the two sample estates (clean, and one with a planted
guest to POS path, an exposed database and SSH open to the internet).

## Input limits (what is rejected, and why)

- Invariant YAML: at most 64 KiB, no aliases, at most 12 levels deep. A flow collection (`[`/`{`)
  nests without indentation and PyYAML is superlinear on it, so bracket depth is bounded by a
  linear character scan *before* parsing; any parser failure (including `RecursionError`) is a
  `ParseError`, nothing else escapes.
- Invariant ids must fully match `^[a-z][a-z0-9]{0,31}:[a-z0-9][a-z0-9-]{0,63}$` (a trailing
  newline no longer slips through) and must not contain a CVE or GHSA identifier
  (`CVE-2021-44228`, `GHSA-xxxx-xxxx-xxxx`): the platform derives a finding's identity from such
  tokens in its rule id and would merge every finding of that invariant.
- Graph documents: `version` must be the integer 1; ids, endpoints, zones, classes and timestamps
  are type-checked and anything malformed (including an out-of-range timestamp) is a `GraphError`.

## What this library is not

Not built here: the persistent graph and edge builders, findings and the API (the orchestrator,
P1), agent v2 and signed host posture (P2), attestation, signing and the open verifier (P3),
enforcement with confirm-or-revert (P4), in-zone confirmation probes (P5), the dashboard (P6).
NACLs, route tables, egress rules and peering are not modelled: a source that does not read them
must not claim `out` coverage. `evidence.confirm` is accepted and recorded but nothing is
actively confirmed yet.

## Changes from 0.1

- Node `coverage` is a list of directional facts (`Node.coverage` is a tuple of `Coverage`); the
  old single object still loads and means `both`. The old clique rule for unknown edges is gone
  (it would let an inbound-only source rule out outbound edges).
- New assertion `covered`, `PlanKind.COVERED`, `std:coverage-complete`, `Result.assertion`,
  `BlindSpot.direction`.
- `evidence_tier` / `valid_until` now also account for covered nodes that merely keep an unknown
  edge out (0.1 ignored them, which could over-state how long a `HOLDS` lasts).

## Coverage floor (P1.5)

`coverage.require` is measured over the nodes the verdict is about (sources, targets and everything the
augmented search could reach, excluding the internet and CIDR pseudo-nodes), counting a node as covered when
it has qualifying evidence in at least one direction. Soundness does **not** depend on the floor: the
unknown-edge rule is applied regardless, and a floor of 0 cannot let a possible unknown edge through. Results
report both the relevant figures (`relevant_*`) and the tenant-wide both-direction figures. The std
reach/exposure invariants use `min_tier: configured`; the tier a `HOLDS` rests on is always in the result.
