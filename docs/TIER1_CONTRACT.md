# Tier 1 contract — attack paths + change intelligence

Shared spec for the four services that implement Tier 1. Schema is `schema/007_tier1.sql`.

## Ownership

| Service | Owns | Writes | Reads |
|---|---|---|---|
| `correlation` (attack-path engine) | `engine/attackpath.py` + wiring | `attack_paths` table (direct asyncpg) | assets, asset_edges, findings |
| `changewatch` (NEW service) | whole `changewatch/` dir | `surface_changes`, `alert_deliveries` | assets, findings, `alert_rules`, `intel_cursors` |
| `orchestrator` | new routers | `alert_rules`, `surface_changes.acknowledged` | `attack_paths`, `surface_changes`, `alert_rules`, `alert_deliveries` |
| `dashboard` | 2 new pages | — | the orchestrator endpoints below |

Compute services write their own tables directly; the orchestrator owns reads + the mutations below. This decouples them.

## Attack-path engine (correlation service)

Algorithm: **node-weighted shortest path on the (undirected) asset graph** from any internet-facing source to any crown-jewel target.

**Sources (internet-facing):**
- every `endpoint` asset
- any asset with `metadata.public = true`
- any `port` asset for a well-known port (80,443,8080,8443,22,3389,5432,27017,9200,6379) whose parent ip is inside a public scope CIDR

**Targets (crown jewels):**
- every `secret_candidate` asset
- any asset with `metadata.sensitive = true` or `metadata.crown_jewel = true`
- `technology` assets that are data stores (mongodb, elasticsearch, redis, postgres, mysql, postgresql)
- any `endpoint` with `metadata.env = 'prod'` AND `metadata.sensitive = true`

**Node entry cost** (cost to "step onto" a node):
- base 10
- minus exploitability bonus from the node's open findings: KEV −8, else critical −6, high −4; plus exposed_file/secret_scan finding −5 (stackable, cap total bonus at 9)
- `entry_cost = max(1, 10 − bonus)`; sources cost 0

**Path cost** = sum of entry costs of all nodes after the source. Use Dijkstra (heapq) from each source over the undirected edge set; keep the cheapest path to each reachable target. Cap: paths ≤ 8 hops, keep top 50 by score.

**exploitability** (0–100) = `round(100 * (1 − total_cost / (10 * length)), 2)` clamped 0–100 (shorter + more-exploitable ⇒ higher).

**severity** of a path = max finding severity on any hop; `kev_on_path` = any hop has a KEV finding.

**title/narrative**: generated, describing the route (`internet → staging .git → leaked key`). NARRATIVE RULE (same as chains): describe the route and impact, never exploitation commands/payloads. Reject/skip any narrative containing shell/payload/exploit tokens.

**fingerprint** = stable hash of the ordered hop `asset_id`s; upsert on conflict (recompute replaces).

Run on a periodic sweep (env `ATTACKPATH_INTERVAL_MIN`, default 20) and expose `POST /compute-paths` on the correlation service's existing HTTP port (8091). Publish a `attack_path_found` event to `stream:events` on new/changed paths.

## changewatch service (NEW)

New service at `/home/user/palantir-asm/changewatch/`, same shape as `intel/` (Dockerfile, pyproject, app/main.py, config, db, HTTP on port 8092 with /healthz /readyz /stats + POST /run). Add it to `docker-compose.yml`.

**Detection loop** (env `CHANGEWATCH_INTERVAL_MIN`, default 10; also react to `stream:events`):
- cursor in `intel_cursors` where source='changewatch' (`last_synced`)
- find assets with `first_seen > cursor` → emit a `surface_change` typed by kind:
  - subdomain→`subdomain_discovered`, endpoint→`endpoint_discovered`, ipv4/ipv6→`ip_discovered`, port→`port_opened`, technology→`tech_detected`, certificate→`cert_added`, secret_candidate→`secret_found` (sev high), repository→`repository_found`
- findings with `first_seen > cursor` → `finding_opened` (severity = finding severity)
- findings moved to status fixed/false_positive since cursor → `finding_resolved`
- assets with `last_seen < NOW() - INTERVAL '7 days'` not already flagged → `asset_removed`
- certificate assets whose `metadata.not_after` < NOW()+30d → `cert_expiring` (dedupe)
- a host (subdomain/ip) that gained a new open port OR a new public endpoint since cursor → `exposure_increased` (sev medium+)
- advance cursor to the run start time at the end

**Change severity** = the natural notability: secret_found/exposure_increased ≥ high; port_opened/tech_detected medium; discovery events low/info; finding_opened inherits finding severity.

**Alerting**: after writing changes, load enabled `alert_rules`, match each new change (match = AND of `change_types` ∈, `min_severity` ≤, `kinds` ∈ — any absent key = wildcard). For each match deliver to the rule's channel:
- `log` → structured log line, record delivery `sent`
- `webhook` / `slack` → POST JSON `{change, rule, ts}` to `rule.target` (slack uses `{"text": "..."}` shape). Timeout 5s; record `sent`/`failed` + response snippet. **Only POST to the user-configured target URL — never anywhere else.** No other outbound calls.
- write an `alert_deliveries` row per attempt; set `alert_rules.last_fired`.

Safety: changewatch sends packets to NOTHING except user-configured alert webhook targets. It does not probe assets. No exploitation, no scope targets.

## Orchestrator endpoints (new routers)

### Attack paths
- `GET /v1/attack-paths?severity=&kev=&limit=&offset=` → `{items, total, limit, offset}`; each item includes source/target asset summaries (value+kind), length, total_cost, exploitability, severity, kev_on_path, title, narrative, hops (each hop enriched with asset value/kind + max_severity).
- `GET /v1/attack-paths/{id}` → full path with every hop's asset + finding summaries.
- `POST /v1/attack-paths/recompute` → proxies/enqueues a compute request (publish `correlate:` job or call correlation's `/compute-paths`); returns `{queued:true}`.

### Changes
- `GET /v1/changes?type=&severity=&since=&acknowledged=&limit=&offset=` → `{items,total,limit,offset}`, newest first.
- `POST /v1/changes/{id}/ack` → `{acknowledged:true}`, sets ack_by/ack_at, publishes nothing.
- `GET /v1/changes/summary?window_days=7` → counts by type + by day (feeds the dashboard).

### Alert rules
- `GET /v1/alert-rules`, `POST /v1/alert-rules` (`{name, match, channel, target, enabled?}`), `PATCH /v1/alert-rules/{id}`, `DELETE /v1/alert-rules/{id}`.
- `GET /v1/alert-rules/{id}/deliveries?limit=` → recent deliveries.

All additive; keep REFUSED_KINDS + scope rules intact. No endpoint aids exploitation.

## Dashboard

Two new pages + nav-rail icons.

### Attack Paths (`/attack-paths`)
- Ranked list by exploitability. Each path rendered as a horizontal react-flow strip (reuse the chain mini-graph pattern): source asset → hop nodes (colored by max severity, KEV hops flagged) → crown-jewel target, with exploitability + severity badges and the narrative below. A KEV filter + severity filter. Clicking a hop opens it in the DetailDrawer.
- A small header stat row: total paths, paths with KEV, shortest path length, highest exploitability.

### Changes (`/changes`)
- A live feed (newest first) of surface changes: type icon, severity chip, asset value, summary, relative time, ack button. Filter by type/severity/acknowledged. Uses the existing SSE stream to prepend new ones.
- A compact "change velocity" area chart (changes/day by severity) from `/v1/changes/summary`.
- An "Alert rules" panel: list + create form (name, channel [log/webhook/slack], target URL, match: change types multiselect + min severity), enable/disable, and recent deliveries. Creating a webhook rule shows a note that the target URL is stored server-side.

Types to add to `src/api/types.ts`: `AttackPath`, `AttackPathHop`, `SurfaceChange`, `AlertRule`, `AlertDelivery`, `ChangeSummary`. New api modules `src/api/attackpaths.ts`, `src/api/changes.ts`. New nav entries in Shell. Match the existing dark/dense aesthetic — no slop.
