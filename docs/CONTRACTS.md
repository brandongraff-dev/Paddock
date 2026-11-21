# Contracts

Shared interfaces between services. If you change these, update every service.

## Services

| Service | Role | Depends on |
|---|---|---|
| `orchestrator` | HTTP API, scope service, job dispatch, audit sink | postgres, redis |
| `workers/passive` | passive recon (CT logs, DNS, GitHub search, Shodan, Wayback) | orchestrator |
| `workers/active` | authorized probing (httpx, naabu, katana, nuclei, tlsx, playwright) | orchestrator |
| `intel` | NVD/EPSS/KEV ingestion, CVE↔asset matching | postgres |
| `correlation` | policies-as-code, chain detection, blast-radius scoring | orchestrator |
| `dashboard` | React UI | orchestrator |

## Postgres

Schema in `/schema`. Everyone connects via `DATABASE_URL`, a PostgreSQL async DSN (asyncpg). Services should use the ORM-free async helper in `orchestrator/app/db.py` as a reference (or roll their own; schema is the contract). Postgres initializes schema files in alphabetical filename order, so `006_patches.sql` applies after the main tables.

Key tables:

- `scope_entries` / `scope_decisions` — the allowlist and its audit log. `scope_entries.metadata` (JSONB) carries opaque per-entry config, e.g. `{"politeness": {"concurrency": 1, "delay_ms": 500}}`.
- `assets` / `asset_edges` / `asset_snapshots` — the graph
- `findings` / `finding_chains` — issues and composites
- `outbound_log` / `scans` / `schedules` — audit + job state. `scans.parent_scan_id` references the parent scan for sub-steps of an orchestration (e.g. `full_recon`).
- `cves` / `cve_matches` / `intel_cursors` — threat intel

## Redis queues

- `queue:passive` — passive discovery jobs
- `queue:active` — active probing jobs
- `queue:correlate` — correlation / chain-detection jobs
- `stream:events` — fan-out events; see **Event stream** below for the full list

Job format (JSON, in a single `job` field of the stream entry):

```json
{
  "scan_id": "uuid",
  "kind": "passive_subdomains | active_http_probe | nuclei_scan | ...",
  "target": "normalized.host.name",
  "config": {},
  "scope_matched_entry": 42,
  "parent_scan_id": "uuid-or-null"
}
```

`target` is **already normalized** by the orchestrator before enqueue (scheme / port / path stripped, lowercased, trailing dot gone).

## Orchestrator HTTP API

Base URL: `http://orchestrator:8080` (inside compose), `http://localhost:8080` (dev).

### Scope

- `GET  /v1/scope` — list entries (each row carries `metadata`).
- `POST /v1/scope` — add entry. Body: `{kind, value, added_by, auth_doc_ref?, expires_at?, notes?, metadata?}`. `metadata.politeness` may carry `{concurrency?, delay_ms?}`, which the active worker applies via `PolitenessLimiter.configure_host(...)` after a scope-check match. Emits `scope_added` on success.
- `DELETE /v1/scope/{id}` — deactivate entry. Emits `scope_removed`.
- `POST /v1/scope/check` — `{target}` → `{allow, matched_entry?, matched_entry_metadata, normalized, reason}`.
  - `matched_entry_metadata` is the matched entry's `scope_entries.metadata` JSONB (empty object on no match or no metadata). The active worker's `scope_guard` uses this to configure politeness.
  - **Every worker MUST call this before touching a target.** Decisions are audit-logged.
- `GET  /v1/scope/{id}/decisions?limit=10&offset=0` — recent `scope_decisions` rows for a given scope entry, newest first. Default `limit=10`.

Scope mutations (`POST`, `DELETE`) go through the `require_scope_admin` dependency (no-op in the MVP; wire real auth before external exposure).

### Scans

- `POST /v1/scans` — `{kind, target, config?, priority?, parent_scan_id?}` → returns a full `ScanOut`.
  - Scope-checked before enqueue when `parent_scan_id` is absent or references an unknown scan.
  - When `parent_scan_id` references an existing scan, the child **inherits** the parent's scope decision (no new `scope_decisions` row written) and the target is still normalized for storage.
  - Scan kinds in the Do-not-build list below are refused with 400 before any scope-check runs.
- `GET  /v1/scans/{id}` — status + result_summary.
- `GET  /v1/scans?target=&status=&parent_scan_id=&limit=&offset=` — list.
- `PATCH /v1/scans/{id}` — body `{status?, result_summary?, error?, worker_id?}`.
  - `started_at = NOW()` on first transition to `running`; `finished_at = NOW()` on first transition to a terminal state (`completed`, `failed`, `cancelled`).
  - `result_summary` merges (`||`) into the stored JSONB.
  - Idempotent: re-posting the same status is a no-op on timestamps and emits no event.
  - 404 on unknown scan id.
  - Emits one of `scan_started` / `scan_completed` / `scan_failed` only on an actual status transition.
- `POST /v1/scans/{id}/start`     — `{worker_id?}` → PATCH `{status: running, worker_id}`.
- `POST /v1/scans/{id}/complete`  — `{result_summary?}` → PATCH `{status: completed, result_summary}`.
- `POST /v1/scans/{id}/fail`      — `{error?}` → PATCH `{status: failed, error}`.

### Assets

- `GET  /v1/assets?kind=&value=&canonical=&limit=&offset=` — list.
- `GET  /v1/assets/{id}` — asset + depth-1 neighbourhood.
- `GET  /v1/assets/{id}/graph?depth=2` — BFS subgraph.
- `GET  /v1/assets/graph?limit=500` — **whole-surface** top-N most-connected assets + the edges among them. `limit` is capped at 2000; the server rejects larger values. Each node carries `degree` and `open_high_crit_count` (open findings with severity ∈ {high, critical}).
- `POST /v1/assets/bulk` — upsert from workers. Body: `{items: [{kind, value, source, canonical?, confidence?, metadata?}]}`. The orchestrator canonicalizes.
  - **Edge sentinel:** an item with `kind == "_edge"` is routed to `asset_edges` instead of `assets`. The item's `metadata` must carry `{src_kind, src_canonical, dst_kind, dst_canonical, edge_kind, edge_metadata?}`; the older `{src_value, dst_value, kind}` shape is also accepted. Both endpoints must already exist in `assets`; if either is missing, the edge is skipped and counted in `edges_skipped_missing_endpoint`.
  - Response adds the counters `edges_inserted`, `edges_updated`, `edges_skipped_missing_endpoint`.
  - Emits `asset_added` per inserted asset and `edge_added` per inserted edge.
- `POST /v1/edges/bulk` — dedicated edges endpoint for callers that don't need the sentinel. Body: `{edges: [{src_id?, dst_id?, src_kind?, src_canonical?, dst_kind?, dst_canonical?, kind, metadata?}]}`. Either id-based or (kind, canonical)-based references work. Returns `{edges_inserted, edges_updated, edges_skipped_missing_endpoint}`. Emits `edge_added` per inserted edge.

### Findings

- `GET  /v1/findings?severity=&status=&asset_id=&rule_source=&kev=&q=&limit=&offset=` — paged envelope `{items, total, limit, offset}`. Defaults: `limit=50`, `offset=0`. `kev=true` keeps only findings with `metadata.kev=true` OR an asset that has at least one `cve_matches` row to a KEV CVE. `q` is a case-insensitive substring match against `title || description`.
- `GET  /v1/findings/list?...` — legacy bare-list response for pre-pagination callers (same filters).
- `GET  /v1/findings/{id}` — returns `{finding, asset, chains: [...]}`. `chains` are any `finding_chains` rows whose `finding_ids` array contains this id.
- `PATCH /v1/findings/{id}` — `{status, assigned_to, notes}`. Publishes `finding_closed` on transition to any terminal status (`fixed`, `wontfix`, `false_positive`, `accepted_risk`).
- `POST /v1/findings/bulk` — upsert from workers / correlation / intel. Body: `{items: [FindingIn]}`.
  - Each item provides **either** `asset_id` (preferred) **or** `asset_value` (plus optional `asset_kind`; defaults to `endpoint`). With `asset_value`, the orchestrator upserts the asset by (kind, canonical(value)) before attaching the finding.
  - 422 if neither `asset_id` nor `asset_value` is supplied.
  - Emits `finding_opened` per inserted finding. Updates don't re-emit.
- `GET  /v1/chains?severity=&anchor_asset_id=&limit=&offset=` — correlated finding chains. Each row includes the anchor asset summary (`anchor_asset`) and the matched findings' severities (`finding_severities`).
- `POST /v1/chains` — upsert from correlation. Body: `{chain_rule_id, severity, title, description, impact_narrative?, blast_radius_score?, finding_ids: [uuid], anchor_asset_id?: uuid, metadata?}`.
  - If `anchor_asset_id` is present: upsert by `(chain_rule_id, anchor_asset_id)`.
  - Otherwise: upsert by `(chain_rule_id, metadata.fingerprint)`. The correlator should set `metadata.fingerprint`; if missing, the orchestrator computes a stable fingerprint from sorted `finding_ids` so re-posts still upsert cleanly.
  - 400 if any `finding_id` doesn't exist.
  - Emits `chain_detected` on insert only.

### Outbound audit

- `POST /v1/outbound/bulk` — `{entries: [...]}`. Each entry maps 1:1 to an `outbound_log` row (`worker`, `target`, `tool`, `method?`, `request_summary?`, `response_code?`, `scope_matched`, `scope_entry_id?`, `started_at`, `duration_ms?`, `bytes_in?`, `bytes_out?`, `error?`). `started_at` may be a float epoch (what `workers/active` sends) or an ISO 8601 / datetime value. Bulk inserted via `executemany`. Returns `{inserted}`.

### Timeline

- `GET /v1/timeline?from=&to=&sample=` — asset diffs + new findings per day.

### SSE event mirror

- `GET /v1/events?since=<stream-id-or-$>` — SSE tail of `stream:events`.

## Scope enforcement (the rule nobody breaks)

Every outbound request from every worker goes through this check:

1. Normalize the target (strip scheme, port, path; lowercase; resolve hostname to IP if IP match requested).
2. `POST /v1/scope/check` to the orchestrator. If `allow=false`, the worker **MUST** abort and log.
3. On allow, emit the request, then write an `outbound_log` row (individually or via `POST /v1/outbound/bulk`).
4. Second-line defense: egress HTTP client is wrapped so it also calls `scope_check` locally from cached entries, fail-closed if cache is stale beyond 60s.

Per-host politeness is configurable on the matching scope entry (`scope_entries.metadata.politeness.{concurrency, delay_ms}`); the active worker reads it from `matched_entry_metadata` on the scope-check response.

## Event stream

Workers and services publish to Redis stream `stream:events`. Current events:

| event | emitted by | fields |
|---|---|---|
| `asset_added` | `POST /v1/assets/bulk`, `POST /v1/findings/bulk` (when asset_value upserts a new row) | `asset_id, kind, value, canonical, source, ts` |
| `asset_updated` | (reserved; not emitted on update today) | — |
| `edge_added` | `POST /v1/assets/bulk` (`_edge` items), `POST /v1/edges/bulk` | `edge_id, src_id, dst_id, kind` |
| `finding_opened` | `POST /v1/findings/bulk` (insert only) | `finding_id, asset_id, severity, rule_id, rule_source, ts` |
| `finding_closed` | `PATCH /v1/findings/{id}` on terminal status transition | `finding_id, status` |
| `chain_detected` | `POST /v1/chains` (insert only) | `chain_id, chain_rule_id, severity, anchor_asset_id, finding_count` |
| `scan_started` | `PATCH /v1/scans/{id}` (status→running), `POST /v1/scans/{id}/start` | `scan_id, kind, target, worker_id` |
| `scan_completed` | PATCH or `POST /v1/scans/{id}/complete` | `scan_id, kind, target` |
| `scan_failed` | PATCH or `POST /v1/scans/{id}/fail` | `scan_id, kind, target, error` |
| `scope_added` | `POST /v1/scope` | `scope_entry_id, kind, value, added_by` |
| `scope_removed` | `DELETE /v1/scope/{id}` | `scope_entry_id, kind, value` |
| `cve_published` | intel service | `cve_id, cvss, affected` |

Correlation and dashboard subscribe to this stream.

## Do-not-build list (hard rules)

The following are **out of scope** for every service in this repo. Do not add them, do not add hooks for them, do not add configuration flags that enable them:

- Auto-exploitation of discovered vulnerabilities
- Credential stuffing, password spraying, brute force
- Rate-limit evasion, timing-based evasion, header manipulation to bypass WAFs
- Stealth / low-and-slow / fragmentation scanning modes
- Session hijacking, token theft, anti-forensics
- Data exfiltration tooling
- Anything aimed at targets not represented in `scope_entries`

`POST /v1/scans` refuses `kind` values in the orchestrator's `_REFUSED_KINDS` list with 400 **before** scope-check, so no audit row is written for attack-aid intents.

This tool is a **defensive asset intelligence platform**. Workers probe politely and transparently. The point is visibility, not access.
