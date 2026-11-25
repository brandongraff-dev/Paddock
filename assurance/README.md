# paddock-assurance (0.3)

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

paddock-invariants std                      # the six shipped invariants
paddock-invariants fields                   # the host fields a host-config predicate may read
paddock-invariants lint std:no-internet-to-datastore
paddock-invariants test std:no-internet-to-datastore std:guest-cannot-reach-pos \
    std:public-ports-allowlist --graph examples/estate-violated.json     # exit 1, with witnesses
paddock-invariants test std:guest-cannot-reach-pos --graph examples/estate-clean.json   # exit 0
paddock-invariants explain std:guest-cannot-reach-pos --graph examples/estate-violated.json
pytest -q
```

Exit codes for `test`: `0` all hold, `1` any violated, `2` none violated but some `UNKNOWN`
or `EXPIRED`, `3` bad input.

## The six invariants

| id | Says |
|---|---|
| `std:no-internet-to-datastore` | From the internet, no data store is reachable (up to 6 hops), reaching but not passing through nodes labelled `app-tier`. |
| `std:guest-cannot-reach-pos` | Nothing in zone `guest` can reach anything in zone `pos`, through any chain of devices. |
| `std:public-ports-allowlist` | Everything the internet can connect to is limited to 80 and 443, unless an expiring, reasoned exception says otherwise. |
| `std:coverage-complete` | Every host, cloud instance, database, load balancer and device is covered **both inbound and outbound** by fresh evidence of at least `configured` strength. Each gap is named with its direction and reason. |
| `std:server-ssh-hardened` | (host-config) Every server tagged `agent` or `server` has no SSH server, or no password login, no root login, no empty passwords, public keys on and at most 4 attempts, judged from signed agent facts. |
| `std:server-default-deny-inbound` | (host-config) Every such server's host firewall drops or rejects inbound by default in **every enabled address family** (IPv6 included), from an exact firewall model. |

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

## Host-config invariants (0.3)

`assert:` is one of the three literals above, **or** a predicate over the signed facts an agent
reports about a host: a string, or a mapping `{all|any|not: ...}`. `subjects.to` selects the hosts
(same `Selector`); `from`, `ports`, `allow` and `via` are not allowed. The result's `assertion` is
`host-config` and `PlanKind` is `HOSTCONFIG`.

```yaml
id: std:server-ssh-hardened
subjects: { to: { tag: [agent, server] } }       # a declared `server` without an agent is UNKNOWN (no_agent)
assert:
  any:
    - host.sshd.installed == false
    - all:
        - host.sshd.password_login_possible == false
        - host.sshd.root_login_possible == false
        - host.sshd.permitemptypasswords == "no"
        - host.sshd.pubkeyauthentication == "yes"
        - host.sshd.maxauthtries <= 4
evidence: { min_tier: configured, max_age: 6h }
coverage: { require: 1.0 }
```

**Predicate grammar** (hand-written tokenizer and parser, no `eval`, no regular expressions;
at most 200 characters per predicate, 120 tokens, depth 6, 64 leaves, lists of 64):

```
pred := path OP literal | path 'in' list | path 'subset_of' list | 'count(' path ')' CMP INT
path := ident ('.' ident | '(' INT ')')*            host.listener(22).exists
OP   := == != < <= > >=        literal := "text" | 'text' | INT | true | false
```

Types: `str` (case-insensitive, closed vocabulary where the field has one), `int`, `bool`,
`set<str>` (case-sensitive names), `set<cidr>`. `==`/`!=` work on every type, `<` `<=` `>` `>=` on
`int`, `in` on `int` and `str` (membership in a list), `subset_of` on sets, `count(set)` compares
with an integer. Anything outside the grammar is a parse error; an unknown field, a bad parameter
(ports 1-65535), an operator the type does not allow or a literal outside a field's vocabulary is
too. `paddock-invariants fields` lists the registry. **Registry** (closed; every row has a name,
parameters, type, collector, `max_tier`, and what a missing value means):

| field | type | collector | notes |
|---|---|---|---|
| `host.sshd.installed` | bool | sshd | `false` needs the sshd fact to say tool_missing **and** a usable, complete, fully attributed listener table with no listener on 22 or named like an SSH server |
| `host.sshd.password_login_possible` | bool | sshd | derived: `passwordauthentication yes`, or `kbdinteractiveauthentication yes` with `usepam yes` and no public-key-only `authenticationmethods`; **any** Match probe delta counts |
| `host.sshd.root_login_possible` | bool | sshd | derived: `permitrootlogin yes` in the base config or any probe delta (key-only `prohibit-password` is not counted) |
| `host.sshd.{passwordauthentication, kbdinteractiveauthentication, permitemptypasswords, pubkeyauthentication, usepam}` | str | sshd | `yes`/`no`; a key a Match block changes has no single value (`match_override`) |
| `host.sshd.permitrootlogin` | str | sshd | `without-password` reads as `prohibit-password` |
| `host.sshd.authenticationmethods`, `host.sshd.maxauthtries` | str, int | sshd | |
| `host.sshd.{allowusers, allowgroups}` | set<str> | sshd | absent in an exact `sshd -T` fact = empty set |
| `host.fw.default_inbound_all_families` | str | firewall | derived: `deny` only if the model is `exact` and **every enabled family** has an effective default of drop/reject; `allow` if an enabled family accepts (ip6 accepting while IPv6 is on is `allow`); otherwise no value |
| `host.fw.engine`, `host.fw.ipv6_enabled` | str, bool | firewall | |
| `host.listener(PORT).{exists, wildcard}`, `.process` | bool, set<str> | listeners | a positive survives a partial table, a negative needs a complete one; `.process` needs full attribution |
| `host.listeners.count`, `host.listeners.addresses` | int, set<cidr> | listeners | complete table only |
| `host.patch.{security_updates_pending, reboot_required}` | int, bool | patch | |

Every field's `max_tier` is `configured`: an agent-signed fact is never lifted, so `min_tier:
observed` on a host-config invariant is a **compile error** (it could never hold).

**Canonical form and digest.** The parser returns a canonical tree: `all`/`any` children sorted by
their canonical JSON, single-child `all`/`any` collapsed, set literals sorted and de-duplicated,
case-folded strings lower-cased. The digest covers that structure (`parse.canonical_json` puts it
under `assert`), so it ignores whitespace, quoting, key order and sibling order and changes with any
field, parameter, operator, literal, `not` or combinator. The shipped std digests are pinned in
`tests/test_stdlib_host.py`: changing a std invariant is a new id.

**Facts in the graph document.** `nodes[].facts.<collector>` (at most 16 collectors per node, lists
of at most 5000 rows, no floats, strict types, `GraphError` on anything malformed):

```json
{"id": "web-1", "kind": "host", "tags": ["agent", "server"],
 "facts": {"sshd": {"status": "ok", "tier": "configured", "observed_at": "2026-12-01T08:30:00Z",
                    "signed": true, "source": "agent", "key_id": "0f3a...", "seq": 7,
                    "evidence_ref": "posture:7", "conf": "exact", "partial": false,
                    "conflict": null, "reason": "", "data": {"...": "the collector section value"}}}}
```

`status` is `ok | error | unavailable` (`reason` says why when it is not `ok`); `conf` and `partial`
default to the weak answer (`approximate`, `true`) when absent; `conflict` is absent/false, `true`,
or a non-empty object/list (any other value, and a misspelt `conflicts` key, is rejected). The
library never verifies a signature (the server did at ingest): it trusts `signed: true` and carries
`key_id`, `seq` and `evidence_ref` into witnesses so a verifier can find the evidence again. The
`data` shapes the accessors read are the collectors' section values (`sshd`: `installed`, `config`,
`probes.deltas[].delta`, `match.unprobed`, `source`; `firewall`: `backend`, `ipv6_enabled`,
`families.{ip4,ip6}.{read,effective_default}`, `flat_view.confidence`, `dataplane`,
`opaque_features`; `listeners`: `count`, `listeners[]`, `attribution.status`; `patch`:
`pending.{state,security}`, `reboot.{state,required}`).

**Three-valued logic (Kleene strong).** `all`: a false dominates, else an unknown, else true.
`any`: a true dominates, else an unknown, else false. `not` swaps true and false and leaves unknown
alone. A **leaf is unknown unless its collector fact is usable**: `status == ok`, `signed`, tier
(capped at the field's `max_tier`) at least `min_tier`, fresh (`now - observed_at <= max_age`, not
more than 5 minutes in the future), no `conflict`, `conf == exact` and complete where the field
needs it, and the accessor produced a value. **An unusable fact is never false**: a stale violating
value is unknown, so the open finding stays open and nothing is closed on silence. A repeated leaf
is unknown wherever it is unknown (`A or not A` is unknown, never true).

**Per host, then the estate.** `VIOLATED` if any host is false; else `UNKNOWN`
(`hosts_unknown:<n>`) if any host is unknown; else `HOLDS`. A violating host always beats an
unknown one. An empty selection is `UNKNOWN` (`empty_selector:to`). A host invariant that does not
state `coverage.require` gets **1.0**; an explicit lower floor lets a `HOLDS` stand when
passing/selected reaches it (at least one host must pass; the unknown hosts are blind spots and in
`unproven_targets`; the reasons are `no_counterexample, hosts_unknown:<n>`).

**What a result carries.**

- `witnesses`: hop-less, `weakest_basis` = the fact's tier, `confirmed: false`, and a `detail` with
  exactly these all-string keys: `node, field, clause, predicate, op, expected, observed, tier,
  observed_at, source, signed, key_id, seq, evidence_ref` (`clause` is the position in the canonical
  tree, `0` for a lone predicate, `0.1` for the second child; `predicate` is the canonical text,
  wrapped in `not(...)` for a clause under `not`; `op` is `count<=` etc. for `count()`). At most 3
  per host and 50 overall (one clause per host first, so many violating hosts all show up);
  `violating_targets` lists every violating host.
- `blind_spots`: one row per undecided host and collector, `direction: "host"`, `collector` set
  (omitted for P1 rows), `relevant: true`, `reason` the most fundamental one (`no_agent`,
  `no_sensor`, `unavailable`, `collector_error`, `unsigned`, `evidence_conflict`, `approximate`,
  `partial`, `match_override`, `no_value`, `tier_below_min`, `future_timestamp`, `stale`).
- `hosts`: `{selected, holds, violated, unknown}` (only for host-config results).
- `unproven_targets`: the unknown hosts (never read "absent from `violating_targets`" as safe).
- `evidence_tier` = the weakest tier among the facts the `HOLDS` relied on; `valid_until` =
  `min(observed_at) + max_age` over them (an `any` relies on its single best true branch; a
  `host.sshd.installed == false` also relies on the listener table that corroborated it).

```bash
paddock-invariants test std:server-ssh-hardened std:server-default-deny-inbound \
    --graph examples/estate-hosts-violated.json          # exit 1: web-2 allows passwords, app-2 accepts inbound
paddock-invariants test std:server-ssh-hardened --graph examples/estate-hosts-clean.json   # exit 0
```

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

## Changes from 0.2

- Host-config assertions (above): `PlanKind.HOSTCONFIG`, `Invariant.expr`, `Plan.expr`,
  `Plan.collectors`, `Node.host` (`HostFacts`), `Result.hosts`, `BlindSpot.collector`,
  `BlindSpot.direction == "host"`, `ReachGraph` loads `nodes[].facts`. All additive: P1
  invariants keep their digests and `Result.to_dict()` keeps its keys.
- The invariant document may now nest 14 levels (an `all`/`any`/`not` costs two).

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
