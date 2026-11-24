# Provable Containment, P1: persistent reach graph, builders, evaluation

> Status: design contract + implementation notes for P1. Companion to
> [PROVABLE_CONTAINMENT_MVP.md](PROVABLE_CONTAINMENT_MVP.md) (the whole MVP) and
> [`../assurance/README.md`](../assurance/README.md) (the pure P0 library). Where this file and
> the MVP doc disagree, **this file wins for P1**.

## 0. Decisions (and why)

| # | Decision | Why |
|---|---|---|
| D1 | **Evaluation runs inside the orchestrator** (`orchestrator/app/assurance/`), not in a new service. | The orchestrator already owns tenancy, `findings`, the audit chain, licensing and the event stream. A new service needs its own DB role, a grants migration, compose/lite/helm/CI/release entries and a tenancy-helper copy. `docs/ARCHITECTURE.md`'s "no compute service holds Postgres credentials" is stale versus `docker-compose.yml`, so it is not the argument; the argument is fewer moving parts and in-process tenant context. |
| D2 | The pure library `paddock_assurance` (repo `assurance/`) is a dependency of the orchestrator, bundled in the image (repo-root build context: `COPY assurance`). Modules that only describe routes import it **lazily**. | `scripts/export_openapi.py` and SDK checks install only the orchestrator. A module-level import would break them. |
| D3 | **Coverage is directional and multi-source.** | A security group's ingress rules tell us what can reach an instance and nothing about what it connects *out* to. P0's "covered node rules the edge out" was unsound for that. An unknown edge `u -> v` is possible only if `u` is blind **outbound** and `v` is blind **inbound**. |
| D4 | A source asserts coverage **only when its evidence is complete for that direction**. A top-100 port scan is not complete. | Otherwise a scan of 100 ports would let `HOLDS` claim the other 65,435 are closed. |
| D5 | Findings are written **in-process** through the existing upsert (`routers/findings.py::bulk_upsert`), `rule_source='invariant'`, stable `rule_id='invariant:<invariant_id>'`. `UNKNOWN` creates no finding. | Reuses dedupe, lifecycle, SLA, ticketing, SIEM events. |
| D6 | Over-approximate when a fact is unknown, and **record the assumption** in the edge's `evidence`. | A false `HOLDS` is the worst failure. A noisy `VIOLATED` is recoverable. |
| D7 | P1 does **not** model NACLs, route tables, egress rules, peering, host firewalls (P2), or IPv6 on Sentry. They are listed as blind spots, never silently treated as "closed". | Honesty. |

Out of scope for P1: attestations/verifier (P3), agent v2 (P2), enforcement (P4), active confirmation
probes (P5), dashboard pages (P6; only a `RuleSource` type addition).

## 1. Data model (`schema/039_assurance.sql`, already written)

`reach_nodes`, `reach_edges`, `reach_coverage`, `reach_flow_obs`, `zones`, `asset_labels`,
`invariants`, `invariant_versions` (append-only), `invariant_runs` (transitions), `assurance_state`
(graph version + evaluation lease). Plus `findings.rule_source += 'invariant'` and
`constants.RULE_SOURCES`. All are tenant tables: **never filter or insert `tenant_id` in SQL**; the
pool sets it from the tenant context (`tenancy.tenant_context(tid)` *before* `pool.acquire()`).
`ON CONFLICT` targets include `tenant_id`.

## 2. Node references and kinds (`app/assurance/refs.py`, written)

`internet` | `asset:<uuid>` | `ip:<addr>` | `cidr:<net>` (canonical strings; use the helpers).
Node `kind` in `refs.KINDS`: `internet, host, cloud_instance, cloud_db, cloud_lb, device, ip, cidr`.

Identity merging: an AWS instance and the `ipv4` asset for its public IP are the **same machine**.
Builders resolve an IP to `asset:<uuid>` of the cloud resource whose `metadata.public_ips` or
`metadata.private_ips` contains it; otherwise `ip:<addr>`. A shared helper
`app/assurance/builders/_ipmap.py` (owned by the external-exposure work package, imported by the
others) builds that map from asset rows.

## 3. The library delta (`assurance/`, work package LIB)

Graph document (superset of P0, P0 documents stay valid):

```json
{ "version": 1, "now": "...",
  "nodes": [{"id": "asset:..", "kind": "cloud_db", "zone": "prod", "class": "data_store",
             "tags": ["crown-jewel"],
             "coverage": [ {"direction": "in", "tier": "configured", "observed_at": "...", "source": "aws_sg"},
                           {"direction": "both", "tier": "observed", "observed_at": "...", "source": "sentry"} ]}],
  "edges": [{"src": "internet", "dst": "asset:..", "proto": "tcp", "ports": "5432",
             "basis": "configured", "source": "aws_sg"}] }
```

* `coverage` accepts a **list** of facts, or the P0 single object (= `direction: both`).
  `direction` in `in | out | both`.
* A node is **covered inbound** if some fact with direction in/both is fresh (`now - observed_at <= max_age`,
  not in the future beyond 5 min) and `tier >= evidence.min_tier`; likewise outbound.
* **Unknown edge rule (replaces P0's clique):** a possible unknown edge `u -> v` exists iff
  `u` is **not covered outbound** and `v` is **not covered inbound** (`u != v`). The augmented search adds
  exactly those edges. For `exposes-only`, unknown `s -> t` iff `s` not covered outbound and `t` not
  covered inbound.
* `Result.evidence_tier` = min over the relevant node-directions actually relied on of the **best
  qualifying** fact's tier; `valid_until` = min over them of `observed_at + max_age`.
* `BlindSpot` gains `direction` (`in | out | both`); `Result.to_dict()['blind_spots'][i]['direction']`.
* `coverage_covered / coverage_universe` count a node as covered only if covered in **both** directions
  (conservative, and simple to explain).
* New assertion **`covered`** (`assert: covered`, `subjects.to` required, `subjects.from` forbidden):
  `HOLDS` iff every selected node is covered both directions and fresh at `min_tier`; otherwise
  `VIOLATED` with one **hop-less** witness per uncovered node (`Witness.hops == ()`,
  `detail = {"node": ..., "reason": ..., "direction": ...}`), root causes first. Empty selector is `UNKNOWN`.
* New std invariant **`std:coverage-complete`** (severity medium; selects
  `kind: [host, cloud_instance, cloud_db, cloud_lb, device]`; `min_tier: configured`, `max_age: 24h`).
* All P0 tests keep passing; the oracle test is extended with directional coverage (bipartite unknown edges).
  Mutation check: removing the directional rule must fail a test.

## 4. Builders (`app/assurance/builders/`)

A builder module exposes: `SOURCE: str`; `async def load(conn, now, **opts) -> rows` (tenant-bound
connection, read-only SQL); `def build(rows, now, **opts) -> BuildOutput` (**pure**: no DB, no clock, no
network; deterministic; sorted output). Types in `app/assurance/types.py`.

### 4.1 `aws_sg` (work package AWS)

Connector change (`integrations/connectors/aws.py`): add pure
`normalize_ingress(sg) -> list[dict]` and persist it as `ingress_rules` in the **security-group asset
metadata** (cap the list; keep existing keys). Rule shape:
`{"proto": "tcp|udp|icmp|any", "from": int, "to": int, "sources": [{"type": "cidr|cidr6|sg|prefix_list", "value": "..."}]}`.
`ingress_rules` present (even `[]`) means "rules synced". SG ids are only unique per `(account_id, region)`.

Builder semantics:
* Nodes: EC2 instance → `cloud_instance`, RDS → `cloud_db`, load balancer → `cloud_lb`, as `asset:<uuid>`.
* A rule source `0.0.0.0/0` or `::/0` yields `internet -> node` **only if the node is internet-addressable**
  (instance has `public_ips`; LB scheme internet-facing; RDS publicly accessible). If addressability is
  unknown, emit it and set `evidence.assumed_public = true` (D6). A world-open rule on a node that is
  *not* addressable yields `cidr:0.0.0.0/0 -> node` instead.
* Other CIDR sources yield `cidr:<net> -> node`. An SG source yields an edge from **every member node of
  that SG** to the node. Prefix lists: emit `cidr:0.0.0.0/0`-style over-approximation with an
  `evidence.prefix_list` marker and a note (D6).
* Ports = the rule's range (not the DB's default port). Proto `-1`/`all`/`6`/`17`/`1` normalised.
  `basis = configured`; `source = aws_sg`; `evidence = {sg: [...], instance/asset ids, rule index}`.
* **Coverage**, direction `in`, tier `configured`, source `aws_sg`: only for a node **all** of whose SGs
  have `ingress_rules` present; `observed_at` = oldest `last_seen` among the node and its SGs. Nodes with any
  SG lacking `ingress_rules` get **no** coverage (blind) and a note. Never direction `out`.
* Mode `replace`.

### 4.2 `external_exposure` (work package EXT)

* Edges `internet -> host:port` from `assets` `kind='port'` rows (SQL in the scouting report, kept in the
  module), `basis = observed`. `source` is `external_scan` for `port_scan` assets and `shodan_internetdb`
  for shodan (confidence 60, **never** gives coverage). Parse ports from the canonical (right-anchored);
  IPv6 hosts may be labelled `ipv4`: parse, do not trust the kind. Keep only hosts inside an active,
  unexpired, **public** scope CIDR (Python-side filter) and observations younger than
  `assurance_external_max_age_h`.
* Host identity via `_ipmap` (IP -> `asset:<uuid>` of a cloud resource, else `ip:<addr>`).
* **Coverage** direction `in`, tier `observed`, source `external_scan`, `observed_at = scans.finished_at`,
  only for hosts whose latest completed `port_scan` covered **all ports 1-65535** (scan `config.ports`
  parsed with the library's port parser; anything narrower, e.g. top-100, asserts nothing) and whose scan
  has no recorded tool failure for that target. Counts of partial-scan hosts go in `notes`.
* The `internet` node never gets coverage. Mode `window`.

### 4.3 `sentry_flows` (work package SEN)

* Pipeline: `otdiscovery/app/pipeline.py::_project` posts compact aggregated flows
  `{src_ip,dst_ip,proto,dst_port,sensor_id,first_seen,last_seen,packets,bytes,oriented}` to the new
  `POST /v1/reach/flows/bulk` (`routers/reach_flows.py`, service key, `write`, listed in
  `service_routes.COMPUTE_ROUTES`, `auth.py` rule already added). Upsert into `reach_flow_obs`
  (`ON CONFLICT (tenant_id, src_ip, dst_ip, proto, dst_port, sensor_id)`: `first_seen=LEAST`,
  `last_seen=GREATEST`, counters add), clamp timestamps to `now + 5 min`, cap the batch (1000), validate
  IPs and ports, return counts. `otdiscovery` must stamp `sensor_id` from the claim and follow the
  existing error-key convention so a failed post makes `_ingest_managed` return 503 (the sensor retries).
* Builder: edges `src -> dst` per flow, `basis = observed`, `source = sentry_flow`, `port_lo = port_hi =
  dst_port`, `oriented='heuristic'` lowers `confidence` to 50. Nodes: an IP that is a known device asset
  (`assets.metadata->'ips'`) becomes `asset:<uuid>` (`device`), else `ip:<addr>`.
* **Coverage** (directions `in` and `out`, tier `observed`, source `sentry_flow`): only for node IPs **seen**
  in flows of an **online, active sensor** (`sensors.online AND status='active'`), with
  `observed_at = sensors.last_upload_at`. A silent/offline sensor leaves its nodes blind. Nothing is inferred
  for IPs never seen.
* Retention: delete `reach_flow_obs` older than `assurance_edge_window_h * 3` in the builder's store step.
  Mode `window` with `window = assurance_edge_window_h`.

## 5. Store, graph loader (work package STORE)

* `store.persist_build(conn, out: BuildOutput, now) -> BuildReport(changed: bool, edges_added, edges_removed,
  coverage_changed, nodes_upserted)`: upsert nodes; upsert edges keyed by the unique key (refresh
  `last_seen`, `confidence`, `evidence`; keep `first_seen`); mode `replace` deletes this source's rows not
  re-emitted, mode `window` deletes this source's edges with `last_seen < now - window`; **replace** this
  source's coverage rows. `changed` is true iff the **set** of `(src,dst,proto,lo,hi,basis)` or of
  `(node,direction,tier)` changed (a mere `last_seen`/`observed_at` refresh is not a change).
  If changed: `bump_graph_version`. Single transaction; per-source advisory lock; never raises on one bad
  row (skip + count + note).
* `store.get_state / bump_graph_version / claim_eval / release_eval` over `assurance_state`
  (`INSERT ... ON CONFLICT (tenant_id)`; lease via `UPDATE ... WHERE lease_until IS NULL OR lease_until < now
  RETURNING`).
* `graph_loader.load_graph_doc(conn, now) -> dict` (the document in section 3). Zone of a node, in order:
  declared `asset_labels(tag='zone')` > a declared `zones.cidrs` CIDR that contains the node's IP/CIDR >
  `internet` for the internet node > none. Labels: `class`, `kind`, plain tags from `asset_labels`; defaults
  from asset metadata with source `metadata` (`crown_jewel` -> tag `crown-jewel`, `cloud_db` -> class
  `data_store`), **declared labels override**. A node appears if it is in `reach_nodes`, an edge endpoint, or
  `internet`. Coverage facts from `reach_coverage`. Deterministic ordering.
* Label provenance: every `asset_labels` row records `set_by`, `justification`, `set_at`; changing a
  `app-tier` or `zone` label bumps `graph_version` (it changes verdicts) and is audited.

## 6. Runner and findings (work package RUN)

* `runner.assurance_loop(app)`: every `assurance_tick_s`; for each tenant (`tenancy.list_tenant_ids`) inside
  `tenancy.tenant_context(tid)`:
  1. if `now - last_build_at >= assurance_rebuild_min`: run every builder (`load` -> `build` -> `persist_build`),
     isolating failures per builder (log, note, continue).
  2. evaluate enabled invariants if `graph_version != last_eval_version` **or** `now - last_eval_at >=
     assurance_backstop_min` **or** any `valid_until <= now`. Lease via `claim_eval` so N replicas never
     double-evaluate. Budget per tenant per tick; no tenant can starve others.
  3. record results: update `invariants.last_*`; insert `invariant_runs` only on a verdict/digest change or if
     the last row is older than a day.
* `runner.evaluate_tenant(pool, tenant_id, *, force=False, only=None)` is the function the API calls.
* Invariant definitions: stored YAML is re-compiled on each evaluation (library `compile_text`); a stored
  invariant that no longer compiles is marked `UNKNOWN` with reason `invalid_definition`, never skipped
  silently. `std:*` rows are copies refreshed from the shipped library when the shipped digest changes (a new
  `invariant_versions` row; the row's `version` increments).
* `findings_sync`:
  * `VIOLATED`: one finding per **root-cause target** (`witness.hops[-1].dst`). Asset = the target's asset when
    `asset:<uuid>`; otherwise a per-tenant estate asset (`kind='org'`, value `paddock-assurance`) is
    upserted. `rule_id = 'invariant:<invariant_id>'`, `rule_source='invariant'`, severity = invariant severity,
    title/description describe the witness in words, `evidence = {invariant, digest, verdict, target_ref,
    witness, coverage, graph_version}` with a **constant key set**, no `url`/`matched_at`/`target_url` keys,
    no CVE-looking strings. Respect suppression/`accepted`/`false_positive` (do not reopen those).
  * Recurrence on a `fixed` finding: reopen (`lifecycle.record_history`, reason `invariant violated again`,
    actor `system:assurance`) and publish `finding_reopened`.
  * `HOLDS` (not `UNKNOWN`): close open findings of that invariant whose target no longer violates:
    `status='fixed'`, `fix_verified_at = now` **iff** `Result.evidence_tier >= observed` (the re-evaluation is
    the verification), history actor `system:assurance`. `UNKNOWN` never opens or closes anything.
  * `verification` of an invariant finding stays `unsupported` (must not raise).

## 7. API (work package API; `routers/assurance.py`)

All JSON; mutating routes are **admin** (the deny-closed default) except where noted; every mutation calls
`audit.record` with semantic detail; errors for foreign ids are the **same** 404 body as unknown ids;
path params are typed UUIDs where an id is used. Mutations gated with `billing_gate.require_paid("assurance")`
(no-op on self-hosted unless enforcement is on); reads are never gated.

| Method | Path | Notes |
|---|---|---|
| GET | `/v1/invariants` | list with last verdict, freshness (`status_at(now)` => `EXPIRED`), coverage ratio |
| GET | `/v1/invariants/std` | shipped std invariants and whether each is enabled |
| POST | `/v1/invariants` | `{yaml}`: parse+compile, 422 with the library's problem list, new `invariant_versions` row |
| PUT | `/v1/invariants/{inv_uuid}` | new definition => new digest/version; `enabled` toggle |
| DELETE | `/v1/invariants/{inv_uuid}` | disables and archives (rows kept); never deletes versions/runs |
| POST | `/v1/invariants/std/{std_id}/enable` | copy from the shipped library |
| GET | `/v1/invariants/{inv_uuid}/runs` | transition ledger, paged |
| POST | `/v1/assurance/evaluate` | `{invariant_ids?, rebuild?: bool}`; runs now; 200 with `{ok, ...}` even if degraded |
| GET | `/v1/assurance/coverage` | per-source and per-node coverage, blind spots by reason, stale sensors |
| GET | `/v1/assurance/state` | graph version, last build/eval, builders' last notes |
| GET | `/v1/reach/nodes`, `/v1/reach/edges` | paged, filterable by source/basis/node |
| GET/POST/PUT/DELETE | `/v1/zones[...]` | zone CRUD, CIDRs validated, names `^[a-z][a-z0-9-]{0,31}$` |
| GET/PUT/DELETE | `/v1/labels[...]` | `PUT {node_ref, tag, value, justification}` requires a non-empty justification; bumps `graph_version` |

ABAC: reach tables carry no classification; findings keep theirs. Service-key callers: none in P1 except
`/v1/reach/flows/bulk`.

## 8. Work packages and file ownership

Each package edits **only** its files. Shared wiring (main.py, auth.py, service_routes.py, config.py,
licensing.py, constants.py, schema/039, `app/assurance/{refs,types}.py`, `builders/__init__.py`) is done and
frozen; request changes through the lead.

| WP | Owns |
|---|---|
| LIB | `assurance/**` |
| AWS | `integrations/connectors/aws.py` (the ingress-rules addition only), `app/assurance/builders/aws_sg.py`, `tests/test_assurance_aws.py`, additions to `tests/test_aws_connector.py` |
| EXT | `app/assurance/builders/external_exposure.py`, `builders/_ipmap.py`, `tests/test_assurance_external.py` |
| SEN | `app/assurance/builders/sentry_flows.py`, `app/routers/reach_flows.py`, `tests/test_assurance_sentry.py`, `otdiscovery/app/{pipeline,orchestrator,main}.py` + its tests |
| STORE | `app/assurance/store.py`, `graph_loader.py`, `tests/test_assurance_store.py` |
| RUN | `app/assurance/runner.py`, `findings_sync.py`, `tests/test_assurance_runner.py`, `tests/test_assurance_findings.py` |
| API | `app/routers/assurance.py`, `tests/test_assurance_api.py` |

## 9. Verification gates (all must be green before P1 is done)

* `assurance/`: `pytest -q`, `ruff check .`.
* Orchestrator: `tests/test_rule_source_sync.py test_migrate.py test_isolation_sweep.py test_tenancy.py
  test_service_tenancy.py test_api_isolation_sweep.py test_licensing.py test_finding_lifecycle.py
  test_aws_connector.py test_sensors.py test_devices.py` + every new `test_assurance_*.py`, run with
  `ORCH_TEST_PG=localhost:5432:asm` (and the RLS-role run: `ORCH_TEST_APP_ROLE=1`).
* `otdiscovery`: its suite. `ruff check .` at repo root.
* Generated files: `python scripts/export_openapi.py && python sdk/python/codegen.py && node
  sdk/typescript/scripts/codegen.mjs` then the same with `--check`; `docs/api/openapi.json` and both SDKs committed.
* `dashboard`: `RuleSource` union gains `"invariant"` (types only, no styling).
* An end-to-end test: seed assets that mimic the AWS connector + a port scan + flows; run the loop once;
  assert the verdicts, the findings, close-on-fix and reopen-on-recurrence, and that tenant B sees nothing.

## 10. Known gaps after P1 (stated, not hidden)

NACLs, route tables, IGW/NAT, peering and egress are not read (nodes are blind **outbound** from AWS
data). Host firewalls arrive with agent v2 (P2). Sentry coverage is `observed` only: it proves "no such
traffic seen", not "impossible". IPv6 is not parsed by the sensor. `worker-active` posts
`{"assets": ...}`/`{"findings": ...}` bodies the orchestrator rejects (422), so real active port-scan results
do not land today; `external_exposure` therefore sees only what passive/Shodan and manual ingest provide until
that is fixed (tracked separately).

## 11. P1.5 amendments (after independent verification)

The verifier fixed seven defects (three could produce a false `HOLDS`) and surfaced two design problems
that made the std invariants unusable for AWS-only tenants. Both are resolved here; they supersede the
wording above.

* **D8 - the coverage floor is scoped to what the verdict is about.** `coverage.require` is measured over the
  *relevant* non-pseudo nodes (sources, targets and everything the augmented search could reach), and a node
  counts as covered when it has qualifying evidence in **at least one** direction. The old tenant-wide,
  both-direction ratio sat near zero for any estate with AWS nodes (security groups can only ever cover
  *inbound*), so every std invariant ended `UNKNOWN: coverage_below_required` however well the relevant nodes
  were covered. The floor is a disclosed policy overlay, **not** the soundness mechanism: the unknown-edge rule
  (an edge `u -> v` is possible iff `u` is not covered outbound and `v` is not covered inbound) is applied
  regardless of the floor, and a test proves a floor of 0 cannot let a possible unknown edge through.
  `Result.to_dict()['coverage']` keeps `universe/covered/ratio` (tenant-wide, both directions) and adds
  `relevant_universe/relevant_covered/relevant_ratio`.
* **D9 - the std reach/exposure invariants accept `configured` evidence.** A security group's or firewall's
  configuration is an upper bound on reachability, so absence of an allowed path under it is real evidence.
  `std:no-internet-to-datastore`, `std:guest-cannot-reach-pos` and `std:public-ports-allowlist` now use
  `min_tier: configured`. The tier of the evidence a `HOLDS` rests on is recorded in every result, and a
  consumer (an insurer's acceptance policy, P3) can still require `observed`. Findings are marked
  `fix_verified` only when the closing `HOLDS` rests on `observed` or `tested` evidence.
* **Still `UNKNOWN`, correctly.** A host known only from a TCP port scan cannot rule out a UDP service, and the
  internet is blind outbound, so a std internet invariant over such a host stays `UNKNOWN:
  possible_via_unknown_edges` until the host is covered inbound (security group, agent firewall) or the scan
  is extended. This is the soundness rule working, not a defect.
