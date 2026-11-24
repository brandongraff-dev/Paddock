# paddock-assurance (P0)

**Provable containment, first slice.** Declare what must never be reachable, then search for a
counterexample. Scope and design: [`docs/PROVABLE_CONTAINMENT_MVP.md`](../docs/PROVABLE_CONTAINMENT_MVP.md).

This is a pure library and CLI: no database, no network, no clock except the one you pass in.
It is **not wired into the platform yet** (no findings, no API, no attestations); see
*What P0 is not*.

```bash
cd assurance
pip install -e '.[test]'

paddock-invariants std                      # the three shipped invariants
paddock-invariants lint std:no-internet-to-datastore
paddock-invariants test std:no-internet-to-datastore std:guest-cannot-reach-pos \
    std:public-ports-allowlist --graph examples/estate-violated.json     # exit 1, with witnesses
paddock-invariants test std:guest-cannot-reach-pos --graph examples/estate-clean.json   # exit 0
paddock-invariants explain std:guest-cannot-reach-pos --graph examples/estate-violated.json
pytest -q
```

Exit codes for `test`: `0` all hold, `1` any violated, `2` none violated but some `UNKNOWN`
or `EXPIRED`, `3` bad input.

## The three invariants

| id | Says |
|---|---|
| `std:no-internet-to-datastore` | From the internet, no data store is reachable (up to 6 hops), reaching but not passing through nodes labelled `app-tier`. |
| `std:guest-cannot-reach-pos` | Nothing in zone `guest` can reach anything in zone `pos`, through any chain of devices. |
| `std:public-ports-allowlist` | Everything the internet can connect to is limited to 80 and 443, unless an expiring, reasoned exception says otherwise. |

## How a verdict is reached

- **Directed graph.** `A -> B` means A may open connections to B on a protocol and ports, each
  edge tagged with the strength of its evidence: `declared < configured < observed < tested`.
- **Coverage lives on nodes.** A node is *covered* when it has fresh evidence of at least the
  required tier. A connection needs both ends to allow it, so one covered end rules an edge out;
  unknown edges can only exist between two *blind* nodes.
- **Verdicts:** `VIOLATED` (a witness path exists, always wins), `UNKNOWN` (a possible path
  through unknown edges, a selector that matches nothing, or coverage below the floor),
  `HOLDS` (no counterexample at this coverage), then `EXPIRED` once the stalest evidence used
  ages past `max_age`. `HOLDS` means **no counterexample found**, never "secure".
- **Application boundary (`via.stop_at`).** A normal web, app, database stack always links the
  internet to its database through the app. A boundary lets the search reach a node without
  passing through it. It is part of the invariant's digest and is reported in every result.
- **Exceptions** (`allow`) must carry a reason and an expiry; expired ones are ignored and
  reported.
- Output is deterministic (sorted adjacency, no hidden clock) and every invariant has a
  content-addressed digest that is stable under key order and defaulted fields.

## Reach-graph file

```json
{ "version": 1, "now": "2026-12-01T09:00:00Z",
  "nodes": [{"id": "db-1", "zone": "prod", "class": "data_store", "tags": ["crown-jewel"],
             "coverage": {"tier": "observed", "observed_at": "2026-12-01T08:30:00Z", "source": "agent"}}],
  "edges": [{"src": "app-1", "dst": "db-1", "proto": "tcp", "ports": "5432", "basis": "observed"}] }
```

`examples/gen_estates.py` regenerates the two sample estates (clean, and one with a planted
guest to POS path, an exposed database and SSH open to the internet).

## What P0 is not

Not yet built, in order: the persistent reach graph and edge builders (P1), agent v2 and signed
host posture (P2), attestation, signing and the open verifier (P3), enforcement with
confirm-or-revert (P4), in-zone confirmation probes (P5), the dashboard (P6). Findings with
`rule_source = 'invariant'` need a schema change (the `findings_rule_source_check` constraint,
`app/constants.py`, `test_rule_source_sync.py`, then OpenAPI/SDK regeneration) and are left for P1.
`evidence.confirm` is accepted and recorded but nothing is actively confirmed yet.
