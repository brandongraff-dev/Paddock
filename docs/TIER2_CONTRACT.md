# Tier 2 contract — posture grading, takeover detection, ownership/ticketing, continuous monitoring

Schema: `schema/008_tier2.sql`. Four work streams, scoped by service tree so they don't collide.

| Service | Owns | Writes | Reads |
|---|---|---|---|
| `workers/active` | new modules `takeover_check.py`, `tls_grade.py` (+fingerprints) | findings (`takeover`,`tls_grade` sources) via orchestrator; `tls_grades` via orchestrator | assets |
| `triage` (NEW service) | whole `triage/` dir | `tickets`; reads/evaluates `asset_owners`, `sla_policies` | findings, assets, chains, attack_paths |
| `orchestrator` | new routers + scheduler loop | `schedules`, `tickets.status`, `asset_owners`, `sla_policies`, `tls_grades` (bulk) | all Tier2 tables |
| `dashboard` | new pages | — | the endpoints below |

Everything additive. Keep REFUSED_KINDS + scope + all existing tests green. No exploitation/evasion. All outbound stays either scope-gated (active worker) or user-configured target URLs (triage tickets/webhooks).

## 1. Subdomain-takeover detection (active worker)

`workers/active/app/modules/takeover_check.py` + `workers/active/app/data/takeover_fingerprints.json`.
- Input: a subdomain asset. Resolve its CNAME chain (dnspython). If the CNAME points at a known third-party host suffix (S3, GitHub Pages, Heroku, Azure *.azurewebsites.net / *.cloudapp.net, Fastly, Shopify, Netlify, Cloudfront, Readthedocs, Tumblr, Zendesk, …), fetch the target over HTTPS (scope-gated, polite, UA = scanner) and match the service's "unclaimed" body/status fingerprint.
- On a match → a finding: `rule_source='takeover'`, severity `high` (critical if the subdomain is prod/sensitive), title `Dangling DNS — possible subdomain takeover (<service>)`, with the CNAME target + matched fingerprint in evidence. Impact/remediation describe reclaiming or removing the record. NO exploitation — detection only (we never claim the resource).
- Fingerprint file: service → {cname_suffixes:[], fingerprint_text:"", http_status:int?}. Ship ~15 well-known services. Cite the community source (can-i-take-over-xyz style) in a comment.
- Job kind `takeover_scan` (single subdomain) and folded into `full_recon`. Scope-check before any DNS/HTTP. Drop out-of-scope.

## 2. TLS grading (active worker)

`workers/active/app/modules/tls_grade.py` (builds on the existing `tls_inspect.py` output).
- From a host's TLS data (protocols, ciphers, cert validity/chain), compute a letter grade A+..F (and `T` for a trust/validation failure) with a 0–100 score. Grading rules (SSL-Labs-flavored, simplified, documented in-module):
  - start 100; TLS1.1 enabled −20, TLS1.0 −30, SSLv3 −40; no TLS1.3 −5; weak cipher present −20; cert expired → grade `T`; self-signed/untrusted in prod → `T`; cert expiring <15d −15, <30d −5; missing forward secrecy −10.
  - score→grade: ≥95 A+, ≥80 A, ≥65 B, ≥50 C, ≥35 D, ≥20 E, else F.
- Write via orchestrator `POST /v1/tls-grades/bulk` (see endpoints). Also emit a `tls_grade` finding when grade ≤ C (severity: C→low, D/E→medium, F/T→high).
- Job kind `tls_grade` (host) and folded into `full_recon` after `tls_inspect`.

## 3. Triage service (NEW) — ownership + ticketing + SLA

New service `/home/user/paddock/triage/` mirroring `intel/` shape. HTTP port 8093 (`/healthz`,`/readyz`,`/stats`,`POST /run`,`POST /resolve-owners`). Add a `triage` block to `docker-compose.yml`.

- **Owner resolution**: for an asset, evaluate enabled `asset_owners` rules in `priority` ASC; first match wins. Match = AND of present keys: `kinds` (asset.kind ∈), `value_regex` (re.search on asset.value), `cidr` (asset ip ∈), `metadata_env` (asset.metadata.env ==), `tag` (in asset.metadata.tags). Returns {team, contact} or null.
- **Ticket creation**: periodic pass (env `TRIAGE_INTERVAL_MIN`, default 10) + react to `finding_opened` events. For each open finding with severity ≥ `TRIAGE_MIN_SEVERITY` (default `medium`) and no existing ticket: resolve owner from the finding's asset, look up `sla_policies[severity].hours`, set `sla_due = opened_at + hours`, create a `tickets` row. `system` from the matched owner rule or default `internal`.
  - `internal` → DB only. `webhook`/`github`/`jira` → POST JSON to a configured target URL (the owner rule's contact if it's a URL, or a service-level `TRIAGE_WEBHOOK_URL`); record external_url/external_id from the response if present. 5s timeout, failures are logged and the ticket stays `system='internal'` with a note. **Only POST to the configured target — nowhere else. No asset probing.**
- **SLA sweep**: each pass, mark `breached=true` for open (status ∉ resolved/closed/wontfix) tickets past `sla_due`. Publish `ticket_breached` events.
- Publish `ticket_opened` / `ticket_breached` to `stream:events`.

## 4. Orchestrator endpoints + scheduler

New routers + a scheduler loop. (httpx imported lazily as elsewhere.)

### Scheduler loop (continuous monitoring)
- Background task: every minute, read enabled `schedules` whose `next_run_at <= now` (or compute from `cron` with `croniter`), enqueue the scan(s) for the schedule's `target_scope` by publishing jobs to the right `queue:*` (reuse the scans dispatch logic / `POST /v1/scans` internals), set `last_run_at`, `last_scan_id`, `last_status`, and compute the next `next_run_at`. If `croniter` isn't available, support a simple `every_n_minutes` field in `schedules.config`. Never probe anything itself — it only enqueues.

### Endpoints (all additive, paged where lists)
- Schedules: `GET/POST /v1/schedules`, `PATCH/DELETE /v1/schedules/{id}`, `POST /v1/schedules/{id}/run-now`.
- TLS grades: `GET /v1/tls-grades?grade=&limit=&offset=` (paged), `GET /v1/tls-grades/summary` (counts per grade), `POST /v1/tls-grades/bulk` (upsert from the active worker, by asset_id).
- Tickets: `GET /v1/tickets?status=&team=&severity=&breached=&limit=&offset=` (paged, include finding+asset summary), `GET /v1/tickets/{id}`, `PATCH /v1/tickets/{id}` (status, owner_team, contact → sets closed_at when status∈resolved/closed/wontfix), `GET /v1/tickets/summary` (open/breached counts by team + by severity).
- Owners: `GET/POST /v1/alert... no` → `GET/POST /v1/owners`, `PATCH/DELETE /v1/owners/{id}`.
- SLA: `GET /v1/sla-policies`, `PATCH /v1/sla-policies/{severity}`.

Response field names the dashboard will rely on:
- TlsGrade: `{id, asset_id, host, grade, score, protocols[], weak_ciphers[], issues[], cert_expires, graded_at}`
- Ticket: `{id, finding_id, title, severity, owner_team, contact, system, external_url, status, sla_hours, sla_due, breached, opened_at, closed_at, asset:{value,kind}|null, finding:{title,rule_source}|null}`
- Owner: `{id, name, match, team, contact, priority, enabled, created_at}`
- Schedule: `{id, name, scan_kind, target_scope, cron, enabled, last_run_at, next_run_at, last_status, config}`

## 5. Dashboard

Three new nav destinations (reuse existing components, dark/dense, no slop):

- **Posture** (`/posture`): TLS report-card. A grade-distribution strip (A+→F counts, colored), then a table/cards of hosts with grade badge (big letter, color: A/A+ green, B teal, C amber, D/E orange, F/T red), score meter, issues list, cert-expiry countdown. A second section "Takeover risk" listing `takeover` findings as cards (subdomain → dangling CNAME target → service), severity-flagged. Clicking a host/subdomain opens the DetailDrawer.
- **Tickets** (`/tickets`): a queue table — severity chip, title, owner team, SLA countdown (green→amber→red, "BREACHED" pill when past due), status dropdown (PATCH on change), system badge, opened-ago. Header stat tiles: open / breached / resolved-this-week / by-team. Filters: status, team, severity, breached-only. An "Ownership rules" panel: list + create (name, team, contact, match builder: kinds multiselect + value regex + env + tag, priority) + enable toggle; and an SLA-policy mini-editor (severity → hours).
- **Monitoring** (`/monitoring`): schedule list (name, scan kind, target scope, cron, next run, last status) + create form (name, scan_kind select, target_scope, cron string or "every N minutes") + enable toggle + "Run now". Explain in a one-liner that schedules feed the Change feed + alerts.

Add `src/api/posture.ts`, `src/api/tickets.ts`, `src/api/monitoring.ts`; types `TlsGrade`, `TakeoverFinding` (reuse Finding), `Ticket`, `Owner`, `SlaPolicy`, `Schedule`. New nav icons in Shell (shield/grade, ticket, clock). Wire routes in App.tsx. Match the token system exactly.
