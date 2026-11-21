# Operations

How to run Paddock in production: install, upgrade, back up and restore,
monitor, size, and keep data bounded. The docker-compose stack (`make up`)
is still the quickest way to evaluate Paddock. For anything long-lived, use
the Helm chart, or the hardened compose profile on a single host.

| Artefact | Where |
|---|---|
| Migration runner | `orchestrator/app/migrate.py`, run as `python -m app.migrate up\|status\|verify\|wait` |
| Helm chart | `deploy/helm/paddock/` (checked by `bash deploy/helm/ci-check.sh`) |
| Backup / restore | `scripts/backup.sh`, `scripts/restore.sh`, `make backup`, `make restore FILE=…` |
| Metrics | `GET /metrics` on the orchestrator (and otdiscovery), `orchestrator/app/metrics.py` |
| Grafana dashboard | `deploy/grafana/paddock-overview.json` |
| Alert rules | `deploy/prometheus/paddock-alerts.yml` (+ `paddock-alerts.test.yml`) |
| Retention job | `orchestrator/app/retention.py`, run from the scheduler loop |
| Scale test | `hardening/scale_test.py`, `make scale-test`, nightly `.github/workflows/scale.yml` |

---

## 1. Install with Helm

Prerequisites: Kubernetes ≥ 1.25, an ingress controller, cert-manager or a
TLS secret, PostgreSQL 16 (managed service or an operator such as
CloudNativePG), and Redis 7. You also need the Paddock images in a registry
you can pull from: build them with `docker compose build`, then tag and push
`paddock/<service>:<version>`.

```bash
kubectl create namespace paddock
# Connection strings + app secrets. Prefer sealed-secrets / external-secrets.
kubectl -n paddock create secret generic paddock-prod \
  --from-literal=DATABASE_URL='postgresql://paddock:…@db.internal:5432/paddock?sslmode=require' \
  --from-literal=REDIS_URL='rediss://:…@redis.internal:6379/0' \
  --from-literal=JWT_SECRET="$(openssl rand -base64 48)" \
  --from-literal=METRICS_TOKEN="$(openssl rand -hex 24)" \
  --from-literal=ADMIN_BOOTSTRAP_PASSWORD="$(openssl rand -base64 18)" \
  --from-literal=PADDOCK_SECRET_KEY="$(python3 -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"

helm install paddock deploy/helm/paddock -n paddock \
  --set secrets.existingSecret=paddock-prod \
  --set global.imageRegistry=registry.example.com \
  --set ingress.host=paddock.example.com --set ingress.className=nginx
```

What gets deployed:

| Component | Kind | Notes |
|---|---|---|
| orchestrator | Deployment + HPA (2–8) + PDB | API on `/v1` via the Ingress. `/metrics`, `/docs` and the health endpoints are **not** routed. |
| dashboard | Deployment + PDB | nginx config injected from a ConfigMap, so the upstream is this release's Service. |
| worker-passive / worker-active | Deployment + PDB | No Service, no inbound traffic. worker-active is the **only** pod with an added capability (`NET_RAW`). |
| intel, correlation | Deployment + Service | Internal only. |
| otdiscovery | Deployment + Service (+ optional Ingress) | `otdiscovery.ingress.enabled=true` publishes **only** `POST /ingest` for Paddock Sentry sensors. Keep `replicas: 1`, because the observation store is in memory. |
| integrations-worker | Deployment | Same image as the orchestrator, `python -m app.integrations.worker`. Set `integrationsWorker.enabled=false` if your build does not ship that module yet. |
| migrate | Job (`pre-install,pre-upgrade` hook) | See §2. |
| postgresql / redis | StatefulSet / Deployment | Only with `postgresql.enabled` / `redis.enabled`. Meant for evaluation, not HA. |

**Hardening, on every pod:** `runAsNonRoot` (uid 10001; 101 for nginx; 70
and 999 for the bundled data stores), `readOnlyRootFilesystem`, `drop: [ALL]`,
`allowPrivilegeEscalation: false`, the `RuntimeDefault` seccomp profile, no
ServiceAccount token, and resource requests and limits. Writable paths are
`emptyDir` volumes: `/tmp`, `$HOME` for the scanners, `/data` for
screenshots. `ci-check.sh` fails the build if a rendered workload breaks any
of these rules.

> `NET_RAW` and naabu: the chart adds `NET_RAW` to worker-active only, as
> compose does. With a non-root user and `allowPrivilegeEscalation: false`,
> the kernel does not pass the capability to the `naabu` binary, so naabu
> falls back to CONNECT scans. Both deployment paths behave the same way.
> Enabling SYN scans would require a root container, and the chart
> deliberately does not offer one.

**NetworkPolicies** (`networkPolicy.enabled`, on by default) mirror the
compose network tiers:

* *default deny*: all ingress and egress is denied for every Paddock pod.
* *base egress*: every pod may reach DNS, Postgres (5432), Redis (6379) and
  the orchestrator API. Set `networkPolicy.databaseCIDRs` /
  `networkPolicy.redisCIDRs` to restrict these to your managed endpoints.
* *edge*: only the ingress controller namespace may reach the dashboard,
  the orchestrator, and otdiscovery `/ingest`. Prometheus (the
  `monitoring` namespace) may reach the orchestrator, intel, correlation and
  otdiscovery.
* *internet egress*: only worker-passive, worker-active, intel and the
  integrations worker may reach `0.0.0.0/0` / `::/0`, and even they cannot
  reach the cloud metadata endpoint (`networkPolicy.egressExcept`). RFC 1918
  ranges are not blocked, because authorised scope can include internal
  ranges. The scope allowlist controls what workers may touch.

Adjust `networkPolicy.ingressControllerNamespaceSelector` and
`monitoringNamespaceSelector` to match your cluster.

**Bundled datastores (evaluation):**
`--set postgresql.enabled=true --set redis.enabled=true`. The Postgres password
is generated once, kept across upgrades (`helm.sh/resource-policy: keep`), and
stored only in the `<release>-postgresql` Secret. Pods build `DATABASE_URL`
from that Secret with `$(POSTGRES_PASSWORD)` interpolation.

---

## 2. Upgrades and schema migrations

### How migrations work

* `schema/NNN_<name>.sql` files are migrations, applied in filename order.
  New files are picked up automatically.
* `schema_migrations` records each applied file: filename, sha256 checksum,
  `applied_at`, `duration_ms`, `baselined`, `applied_by` and `notes`. The
  runner creates this table itself.
* Each file runs in **its own transaction**. A failure rolls that file back
  and stops the run. Files before it stay applied; nothing after it runs. Fix
  the file and run again.
* The whole run holds a **Postgres advisory lock**. Any number of
  orchestrator replicas, Jobs or compose one-shots can start at once: one
  migrates, the others wait (`MIGRATE_LOCK_TIMEOUT_SEC`, default 300) and then
  find nothing pending.
* A file whose first lines contain `-- migrate: no-transaction` runs outside
  a transaction, one statement at a time, which `CREATE INDEX CONCURRENTLY`
  requires. Such a file is not atomic, so write it to be re-runnable
  (`IF NOT EXISTS`).
* Out-of-order files: a file merged after a higher number was already
  applied (common with parallel branches) is applied with a warning. Pass
  `--strict-order` to refuse instead.

### Where migrations run

| Deployment | Who migrates |
|---|---|
| docker compose | The `migrate` one-shot service. Every service that reads Postgres waits on `service_completed_successfully`. The orchestrator also runs `up` on startup (`MIGRATE_ON_STARTUP=true`), which is a no-op under the same lock. Postgres no longer applies `schema/` through initdb. |
| Helm, external DB | The `migrate` Job runs as a **`pre-install,pre-upgrade` hook**, so the upgrade stops before any new pod starts if a migration fails. Pods also run a `migrate` init container, which is a no-op afterwards. |
| Helm, bundled Postgres | A fresh install is migrated by the pods' init container, because the database does not exist at `pre-install` and this keeps `helm install --wait` from deadlocking. Upgrades use the `pre-upgrade` Job. |

```bash
python -m app.migrate status     # STATE / FILE / APPLIED_AT / MS table
python -m app.migrate verify     # exit 1 if anything is pending, drifted, missing or un-baselined
python -m app.migrate up         # apply pending (also: make migrate)
python -m app.migrate wait --until 022_ops.sql --wait 300   # block until a file is applied
```

### Policy: applied files are immutable

**Never edit a file that has been applied anywhere. Put every change in a
new numbered file.** Applied files are checksummed. If one changes on disk,
`up` refuses to run (exit code 2) and `verify` fails, because the change
would never reach databases that already ran the file, and the schema would
fork silently.

*Checksum drift escape hatch:* `--allow-checksum-drift=FILE[,FILE]` (or
`MIGRATE_ALLOW_CHECKSUM_DRIFT`, or Helm `migrations.allowChecksumDrift`)
re-stamps the recorded checksum **without re-running the file** and appends a
note to `schema_migrations.notes`. Use it only for an edit you have shown to
be harmless, such as a comment or whitespace change in one of the historical
`IF NOT EXISTS`-idempotent files 001–014. Never use it for a semantic change.

### Baselining databases created before the runner

Deployments from before this release applied `schema/` through Postgres'
initdb hook and have no `schema_migrations` rows. On its first run the
runner baselines such a database automatically:

1. It finds the last file whose `CREATE TABLE`s all exist (the frontier).
2. It marks every file up to the frontier whose tables exist, or which
   creates no table, as applied with `baselined = TRUE`.
3. Everything else runs normally: files with missing tables (added after the
   volume was created) and table-less patch files after the frontier, such as
   `022_ops.sql`. The historical files are idempotent, so this is safe.

To upgrade an existing compose install, `git pull && make up`. The `migrate`
one-shot baselines and then applies the new files. Run `make migrate-status`
to see the result.

### Upgrade checklist

1. Take a backup (`make backup` or your managed snapshot). See §3.
2. Read the release notes for new `schema/` files. `022_ops.sql` adds
   indexes and briefly blocks writes per table while it builds: seconds at
   100k findings.
3. Upgrade: `helm upgrade paddock deploy/helm/paddock -n paddock -f values.prod.yaml`,
   or `git pull && make up`.
4. Check: `kubectl logs job/paddock-migrate` / `make migrate-status`, then
   confirm `paddock_schema_migrations_pending == 0` and that the
   `/v1/audit/verify` chain is OK.

Rolling back code to a release older than the schema is not supported:
migrations only move forward. To roll back, restore the pre-upgrade backup.

---

## 3. Backups and restore

### Backups

`scripts/backup.sh` (`make backup`) runs `pg_dump --format=custom`, then:

* checks that the dump is readable (`pg_restore --list`) **before** trusting it;
* optionally encrypts it: `BACKUP_ENCRYPT=age` with `AGE_RECIPIENT` or
  `AGE_RECIPIENTS_FILE`, or `BACKUP_ENCRYPT=gpg` with `GPG_RECIPIENT`. No
  plaintext copy is left on disk;
* writes `<file>.sha256` (compatible with `sha256sum -c`) and `<file>.meta`
  (time, server and pg_dump versions, last applied migration, audit row
  count);
* prunes artefacts older than `BACKUP_RETENTION_DAYS` (default 14) but always
  keeps the newest `BACKUP_MIN_KEEP` (default 3).

The source is `BACKUP_VIA=local` (`pg_dump` against `DATABASE_URL`, for
managed Postgres or a Kubernetes CronJob) or `compose` (`docker compose exec
postgres pg_dump`). The default `auto` picks `local` when `DATABASE_URL` or
`PGHOST` is set. Files are mode 0600 in a 0700 directory. Copy them off the
host, for example to object storage with versioning and object lock.

```bash
# nightly on a compose host (crontab)
17 2 * * * cd /opt/paddock && BACKUP_ENCRYPT=age AGE_RECIPIENT=age1… make backup >>/var/log/paddock-backup.log 2>&1
```

On managed Postgres, also keep the provider's point-in-time recovery
enabled. The logical dump is the portable, verifiable copy, and PITR covers
the gap between dumps.

### Restore

```bash
make restore FILE=backups/paddock-asm-20261121T020000Z.dump.age   # AGE_IDENTITY=key.txt
```

`scripts/restore.sh`:

1. verifies the `.sha256`; a mismatch is refused (`RESTORE_SKIP_VERIFY=1` overrides);
2. decrypts `.age` (`AGE_IDENTITY`) or `.gpg` (your keyring) into a private
   temp dir;
3. **refuses to overwrite a non-empty database** unless you pass
   `RESTORE_CONFIRM=yes` or `--yes`;
4. restores with `pg_restore --clean --if-exists --no-owner --no-privileges
   --single-transaction --exit-on-error`: it either fully succeeds or leaves
   the target untouched.

Then run `make migrate` / `python -m app.migrate up`, which brings an older
backup forward to the running code's schema, start the stack, and call
`GET /v1/audit/verify`. The orchestrator re-applies the audit-table
`REVOKE UPDATE/DELETE` on startup (`--no-privileges` drops grants).

### Restore drill (do this quarterly)

1. Pick yesterday's backup and verify `sha256sum -c` on the storage copy.
2. Restore into a **scratch** database or cluster, never production:
   `RESTORE_DATABASE_URL=postgresql://…/paddock_drill scripts/restore.sh <file>`.
3. Run `DATABASE_URL=…/paddock_drill python -m app.migrate verify`. It should
   report `verify: OK` (or only newer pending files).
4. Compare row counts for `assets`, `findings`, `scope_decisions` and
   `audit_log` against `<file>.meta` and production, and check that the audit
   chain verifies: point an orchestrator at the drill DB and call
   `GET /v1/audit/verify`, or run `audit.verify()`.
5. Record the time taken and the result. Drop the scratch database.

Measured drill: a 396 MB database (10k assets / 100k findings / 1M scope
decisions) produced a **20 MB** age-encrypted dump in **5.3 s**. The restore
took **11.4 s**. Row counts, all 182 indexes and `migrate verify` matched.
`orchestrator/tests/test_backup_restore.py` runs this round trip in CI, both
plain and age-encrypted, including the audit chain, the non-empty-target
guard and a tampered-file refusal.

---

## 4. Monitoring

### `/metrics` access (decision)

`/metrics` is served by an outermost ASGI middleware, **before** the user
auth, RBAC and audit middleware. A scraper is not a user, and scrapes must not
fill the audit log. Instead it is protected by a dedicated bearer token:

| `METRICS_TOKEN` | `AUTH_MODE` | `/metrics` |
|---|---|---|
| set | any | requires `Authorization: Bearer <token>` (constant-time compare), else 401 |
| unset | `dev` | open (local development) |
| unset | `enforce` | **404**: closed until an operator opts in |

The endpoint is also never routed by the Helm Ingress, and the NetworkPolicy
admits only the monitoring namespace. otdiscovery's `/metrics` follows the
same rule (it is open only when `REQUIRE_SENTRY_TOKEN` is off).

Prometheus scrape config (non-operator):

```yaml
- job_name: paddock-orchestrator
  authorization: {type: Bearer, credentials_file: /etc/prometheus/paddock-metrics-token}
  static_configs: [{targets: ["orchestrator:8080"]}]
- job_name: paddock-otdiscovery
  authorization: {type: Bearer, credentials_file: /etc/prometheus/paddock-metrics-token}
  static_configs: [{targets: ["otdiscovery:8101"]}]
```

With the Prometheus Operator, set `metrics.serviceMonitor.enabled=true` and
`metrics.prometheusRule.enabled=true`.

### Metrics

| Metric | Meaning |
|---|---|
| `paddock_http_requests_total{method,route,status}` | Requests by **route template** (`/v1/assets/{asset_id}`). Unknown paths are counted as `<unmatched>`, so cardinality stays bounded. |
| `paddock_http_request_duration_seconds{method,route}` | Latency histogram, including auth and audit time. |
| `paddock_scope_decisions_total{decision}` | allow/deny decisions recorded by the scope service. |
| `paddock_audit_append_failures_total` | Audit hash-chain appends that raised. The request was still served, so this should always be 0. |
| `paddock_queue_depth` / `_pending` / `_lag {queue}` | Redis job streams: XLEN, unacked, and not-yet-delivered. |
| `paddock_scans{status}`, `paddock_scan_oldest_queued_age_seconds` | Scan backlog. |
| `paddock_db_pool_connections{state=size\|idle\|in_use\|max}` | asyncpg pool. |
| `paddock_integration_deliveries{status}` | Rows in `integration_deliveries` by status (when the table exists). |
| `paddock_asset_source_last_seen_timestamp_seconds{source}` | Ingest freshness per discovery source. |
| `paddock_schema_migrations_pending` | Files on disk not yet applied (only where the schema dir is mounted). |
| `paddock_retention_purged_rows_total{table}`, `paddock_retention_last_run_timestamp_seconds` | Retention job. |
| `paddock_sentry_last_ingest_timestamp_seconds{sensor,site}` | (otdiscovery) last batch per Sentry sensor. |

DB-derived gauges are refreshed at most every `METRICS_DB_CACHE_SEC` (15 s),
so frequent scrapes cannot load the database.

### Alerts (`deploy/prometheus/paddock-alerts.yml`)

| Alert | Fires when |
|---|---|
| `PaddockOrchestratorDown` | scrape target down 5 min |
| `PaddockAPIErrorRateHigh` / `…Critical` | 5xx above 5 % for 10 min / above 25 % for 5 min |
| `PaddockAPILatencyHigh` | p95 above 2 s for 15 min (SSE excluded) |
| `PaddockDBPoolSaturated` | pool more than 90 % in use for 10 min |
| `PaddockAuditAppendFailures` | **any** audit append failure (critical) |
| `PaddockSchemaMigrationsPending` | pending migrations for 30 min |
| `PaddockRetentionNotRunning` | no completed purge in 24 h |
| `PaddockScanQueueBacklog` | oldest queued scan older than 30 min |
| `PaddockQueueLagHigh` | more than 1000 undelivered or unacked jobs on a queue |
| `PaddockIntegrationDeliveriesDead` | new dead-lettered deliveries in the last hour |
| `PaddockSentrySilent` | a Sentry sensor silent for **more than 15 min** |
| `PaddockSentryAllSilent` | no sensor has reported since otdiscovery restarted (more than 15 min) |

`promtool test rules deploy/prometheus/paddock-alerts.test.yml` unit-tests the
Sentry-silent, audit-failure, error-rate and backlog alerts, and CI runs it.

### Grafana

Import `deploy/grafana/paddock-overview.json` and pick your Prometheus data
source. It has rows for overview stats, the API (status mix, p50/p95/p99,
slowest routes, 5xx by route), scope and governance (decisions, audit
failures, retention), the pipeline (queues, scans, integration deliveries),
and capacity plus Sentry (DB pool, seconds since each sensor's last batch,
ingest freshness).

---

## 5. Sizing

Starting points, assuming one active scan wave per hour. Tune using the
`paddock_db_pool_connections` and latency panels.

| Estate | Assets / findings | Orchestrator | Workers (passive / active) | Postgres | Redis |
|---|---|---|---|---|---|
| Small (lab, single team) | ≤ 2k / ≤ 20k | 2 × (0.25 CPU, 384 Mi) | 1 / 1 | 2 vCPU, 4 GB, 20 GB disk | 256 Mi |
| Medium | ≤ 10k / ≤ 100k, 1M scope decisions | 2–4 × (0.5 CPU, 512 Mi), HPA | 2 / 2 | 4 vCPU, 8 GB, 50 GB SSD | 512 Mi |
| Large | ≤ 100k / ≤ 1M | 4–8 × (1 CPU, 1 Gi), HPA | 4 / 4+ | 8 vCPU, 32 GB, 200 GB SSD, read replica for reporting | 1–2 Gi |

The DB connection budget is `replicas × DB_POOL_MAX` (default 10) plus the
other services. Keep it below `max_connections` minus 20 % headroom, or put
PgBouncer in front of the app. Migrations need a **direct** connection
(`MIGRATE_DATABASE_URL`), because the advisory lock is session-scoped and
transaction-pooling breaks it.

Disk: at the medium size, the database was 396 MB, of which `scope_decisions`
is about 60 %. Retention bounds it (§6).

### Scale test

`hardening/scale_test.py` seeds 10k assets, about 30k edges, 100k findings, 1M
scope decisions and 10k scans into a scratch database. It migrates with the
runner, drives the real FastAPI app in-process (`AUTH_MODE=dev`, httpx ASGI),
and reports p50/p95 for 30 requests per endpoint after 3 warm-ups.
`--without-ops-indexes` drops the `022_ops.sql` indexes for comparison.
It is not part of PR CI: it runs nightly in `.github/workflows/scale.yml`, or
manually with `make scale-test SCALE_ADMIN_DSN=postgresql://postgres@host/postgres`.

Results: PostgreSQL 16, 4 vCPU / 15 GB shared dev VM with other workloads
running, so treat ±30 % as noise. Seeding took about 30 s. All times are
milliseconds. The two runs were back-to-back on the same machine.

| Endpoint | p50 without 022 | p95 without 022 | p50 with 022 | p95 with 022 |
|---|---:|---:|---:|---:|
| findings: default page (`?limit=50`) | 39.3 | 49.5 | 34.1 | 41.9 |
| findings: severity + status | 9.7 | 12.3 | 10.0 | 12.8 |
| findings: status, offset 5000 | 44.5 | 94.0 | 37.9 | 82.9 |
| findings: rule_source | 26.8 | 43.4 | 35.6 | 37.0 |
| findings: text search `q=` (common term) | 44.0 | 57.2 | 29.3 | 39.7 |
| findings: text search `q=` (rare term) | 64.2 | 77.3 | **17.2** | **21.2** |
| findings: one asset | 3.1 | 4.0 | 2.4 | 3.3 |
| findings: `kev=true` | 97.4 | 112.0 | 77.1 | 114.4 |
| assets: list | 3.8 | 6.6 | 3.9 | 5.2 |
| assets: kind filter | 3.3 | 3.8 | 3.7 | 4.3 |
| assets: surface graph (500 nodes) | 43.1 | 60.2 | 57.7 | 64.9 |
| assets: neighbourhood graph | 6.9 | 11.4 | 9.5 | 12.5 |
| timeline: 14 days | 71.6 | 102.5 | **53.9** | **74.7** |
| timeline: 90 days | 228.9 | 324.7 | 239.5 | 324.6 |
| scope decisions: busy entry | 3.4 | 5.6 | 2.2 | 2.7 |
| scope decisions: quiet entry | 42.3 | 97.4 | **1.7** | **2.1** |

Every read is under 100 ms p95 at this size except the 90-day timeline.

What `022_ops.sql` adds, and why:

* `scope_decisions (matched_entry, decided_at DESC)`: decisions for an entry
  with few or no rows used to walk the entire `decided_at` index. Measured
  with EXPLAIN: 314 ms → under 1 ms at 1M rows.
* `pg_trgm` GIN indexes on `findings.title` / `description`: rare-term `q=`
  search goes from a full scan to an index lookup (64 → 17 ms p50). The
  extension is created only when permitted; otherwise the migration skips
  these two indexes with a NOTICE.
* `findings (first_seen)`, `assets (first_seen)`, `scans (queued_at)`:
  timeline buckets.
* `findings (status, last_seen DESC)` and `(severity, status, last_seen DESC)`:
  filtered list pages stay in sort order.
* Partial `findings (asset_id) WHERE open AND high/critical`: the surface
  graph's per-asset counts.
* `assets (kind, last_seen DESC)` and `assets (source, last_seen DESC)`: kind
  filtering and the ingest-freshness metric.
* Partial `integration_deliveries (updated_at)` on terminal statuses: the
  retention purge.

Known remaining hotspots. These are left as they are because they are
query-shape issues, not missing indexes:

* **`COUNT(*)` on `/v1/findings`.** The paged envelope's `total` costs about
  25 ms of the 34 ms at 100k findings and grows linearly. Options: an
  estimated count above a threshold, or keyset pagination.
* **Timeline, 90 days.** The `ROW_NUMBER()` sample query sorts every finding
  in the window. A per-day `LATERAL … LIMIT n` rewrite would bound it.
* **`kev=true`.** An `OR EXISTS (cve_matches…)` predicate defeats indexes. A
  materialised `kev` flag on findings would fix it.

---

## 6. Data retention

The orchestrator's scheduler loop runs `app/retention.py` every
`RETENTION_INTERVAL_SEC` (6 h; the first run is on the first tick after
startup). It takes an advisory lock, so with N replicas exactly one replica
purges. Deletes run in batches of `RETENTION_BATCH_SIZE` (5000), which keeps
lock time short.

| Table | Horizon column | Default | Variable |
|---|---|---|---|
| `scope_decisions` | `decided_at` | 180 days | `RETENTION_SCOPE_DECISIONS_DAYS` |
| `outbound_log` | `started_at` | 180 days | `RETENTION_OUTBOUND_LOG_DAYS` |
| `integration_deliveries` (only `sent`/`dead`/`skipped`) | `updated_at` | 90 days | `RETENTION_INTEGRATION_DELIVERIES_DAYS` |
| observation tables, auto-detected: `observations`, `sentry_observations`, `device_observations`, … | `observed_at` / `last_seen` / `ts` / `created_at` | 30 days | `RETENTION_OBSERVATIONS_DAYS` |
| anything else | as given | as given | `RETENTION_EXTRA="table:column:days,…"` |

A value of `0` disables a policy, and tables that do not exist are skipped.
**`audit_log` is never purged.** A policy naming it, or `schema_migrations`,
is refused in code, whatever the configuration says. Every purge that deletes
rows appends one `retention_purge` entry to the audit log with per-table
counts, so retention itself is auditable. To turn it off, set
`RETENTION_ENABLED=false`. It also stops when `SCHEDULER_ENABLED=false`.

Long-term audit storage: the audit log grows by about one row per mutating or
denied request. Archive it with the backups. Do not delete it, because the
hash chain detects deletions.

---

## 7. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `migrate: ERROR: applied migration(s) changed on disk: 0xx_….sql` | Someone edited an applied file. Revert the edit and put it in a new file. If the edit is provably cosmetic, use `--allow-checksum-drift=0xx_….sql` (§2). |
| `could not acquire migration lock within …s` | Another runner is mid-migration (a long index build?) or a crashed session still holds the lock. Check `SELECT pid, state, query FROM pg_stat_activity WHERE pid IN (SELECT pid FROM pg_locks WHERE locktype='advisory')`. |
| compose: services stuck in `Created` | `migrate` failed. Run `docker compose logs migrate`. |
| Helm upgrade fails at `pre-upgrade` | The Job failed: run `kubectl logs job/<release>-paddock-migrate`. Nothing was rolled out. Fix it and re-run `helm upgrade`. |
| Pods stuck in `Init:0/1` | The `migrate` init container cannot reach the DB, or is waiting for the lock. Check its logs and the NetworkPolicy `databaseCIDRs`. |
| `/metrics` returns 404 | `AUTH_MODE=enforce` without `METRICS_TOKEN`. Set the token. |
| `/metrics` returns 401 | Prometheus is not sending `Authorization: Bearer $METRICS_TOKEN`. |
| `PaddockAuditAppendFailures` | Check Postgres disk and permissions and `audit_record_failed` in the orchestrator logs, then `GET /v1/audit/verify`. |
| `PaddockSentrySilent` | The sensor host is down, the mirror port was reconfigured, or the token was rotated. Check `paddock-sentry` logs on the sensor (docs/SENTRY.md). |
| Restore refused: `checksum mismatch` | The file is corrupt or tampered with. Use another copy. Do not bypass the check. |
| Dashboard 502 on `/v1` | The orchestrator Service is not ready. Check `kubectl get endpoints <release>-paddock-orchestrator`. |
| Slow findings list at large scale | Check that `022_ops.sql` is applied (`make migrate-status`), then see the scale-test hotspots above. |
