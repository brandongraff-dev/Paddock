# Tenancy model (Postgres row-level security)

Status: implemented in `schema/099_tenancy.sql`, `orchestrator/app/tenancy.py`,
`orchestrator/app/db.py`, `orchestrator/app/auth.py`. Tested in
`orchestrator/tests/test_tenancy.py`. Single-tenant installs keep working
unchanged: everything lives in the **default tenant**
(`00000000-0000-0000-0000-000000000001`).

## How it works

| Layer | Mechanism |
|---|---|
| Data | Every table in schema `public` (except the global catalogues below) gets `tenant_id UUID NOT NULL DEFAULT COALESCE(paddock_current_tenant(), paddock_default_tenant())`, an index, a FK to `tenants`, `ENABLE` + `FORCE ROW LEVEL SECURITY`, and policy `tenant_isolation`: `USING/WITH CHECK (tenant_id = paddock_current_tenant())`. `paddock_current_tenant()` reads the session GUC `app.tenant_id`. |
| Coverage | The migration is a **dynamic DO-block over `pg_class`**, so tables added by other migrations (015–098) are covered automatically. It is idempotent; re-apply it after adding tables (the test harness and `docker-entrypoint-initdb.d` always apply it last). A test (`test_every_public_table_has_rls`) fails if any public table lacks RLS. |
| Global catalogues | `tenants`, `cves`, `intel_cursors`, `attack_technique_map`, `ontology_object_types`, `ontology_link_types`, `ti_feeds`, `ti_indicators`, `sla_policies`, plus any table whose `COMMENT` contains `@paddock:global`. RLS is enabled with `global_read` (everyone reads) and `global_platform_write` (writes only from the default/platform tenant or the owner). |
| Per-tenant natural keys | `UNIQUE(kind,value)` on `scope_entries`, `UNIQUE(kind,canonical)` on `assets`, `UNIQUE(kind,name)` on `integrations`, `UNIQUE(hostname)` on `fleet_agents` are rebuilt as `UNIQUE(tenant_id, …)`. The orchestrator's `ON CONFLICT` targets on those tables were updated to `(tenant_id, …)`. **Any new `ON CONFLICT` on these four tables must name `tenant_id` too.** |
| DB role | `paddock_app`: `NOSUPERUSER NOBYPASSRLS`, owns nothing, cannot create objects, `SELECT/INSERT/UPDATE/DELETE` on tenant tables, `SELECT` on `tenants`, `INSERT/SELECT` only on `audit_log`. Migrations keep running as the owner. The orchestrator logs a loud banner at startup if it is connected as a superuser or BYPASSRLS role (`db.warn_if_privileged`). |
| Connection scoping | `db.create_pool` installs `tenancy.setup_connection` as asyncpg's `setup` hook: **every `pool.acquire()`** runs `set_config('app.tenant_id', <tenant>, false)` from a `ContextVar`. asyncpg's release-time `RESET ALL` clears it, so pooled connections never carry a previous request's tenant. No query had to be rewritten. |
| Request → tenant | `GovernanceMiddleware` binds the resolved principal's tenant to the context. Users and API keys carry `tenant_id` (row column); JWTs carry a `tid` claim that must match the live user row. The shared `SERVICE_API_KEY` acts in the tenant named by the `X-Paddock-Tenant` header (id or slug), else the default tenant. Suspended tenants get 401. |
| Credential lookup | The tenant is unknown until the key/user row is read, so `app_users`/`api_keys` have a second policy arm `current_setting('app.auth_lookup') = 'on'`, set only inside `tenancy.auth_lookup()` (credential resolution and login). No other table honours it. Usernames are therefore **globally** unique. |
| Background work | The scheduler sweeps each active tenant inside `tenant_context(tid)`. Queued scan jobs carry `tenant_id`. The audit anchor loop anchors each tenant's chain. With no tenant in context, code runs in the default tenant — or, with `TENANCY_STRICT=true`, in **no** tenant (reads return nothing, writes fail WITH CHECK). |
| In-process caches | The scope allowlist cache is keyed per tenant (a shared slot would let one tenant's scope authorise another's scans). |
| Audit | Each tenant has its own hash chain (see `audit.py`). |

## Creating a tenant

```bash
OWNER_DATABASE_URL=postgresql://asm:...@postgres:5432/asm \
  python -m app.tenancy create acme "Acme Corp" --admin acme-admin   # prints a one-time password
python -m app.tenancy list
```

The app role cannot write `tenants`; tenant creation is an operator action.

## Deploying / upgrading

* Fresh compose volume: `099_tenancy.sql` runs automatically, then
  `100_app_role.sh` gives `paddock_app` a password (`PADDOCK_APP_DB_PASSWORD`,
  falling back to `POSTGRES_PASSWORD`) and the orchestrator connects as it.
* Existing volume (initdb hooks do not re-run):
  ```bash
  docker compose exec postgres psql -U asm -d asm -f /docker-entrypoint-initdb.d/098_audit_keyed.sql
  docker compose exec postgres psql -U asm -d asm -f /docker-entrypoint-initdb.d/099_tenancy.sql
  docker compose exec postgres sh /docker-entrypoint-initdb.d/100_app_role.sh
  ```
  Then restart the orchestrator.

## Limits (read before selling this as multi-tenant SaaS)

1. **Only the orchestrator runs as `paddock_app`.** The compute services that
   hold `DATABASE_URL` (intel, brain, mlrisk, changewatch, triage, correlation,
   sca, codeanalysis, graphsync, ontology, threatintel, otdiscovery,
   remediation, worker-*) still connect as the owner/superuser in
   `docker-compose.yml`, bypass RLS, and write into the default tenant. They are
   **not tenant-aware**. In particular `brain` executes LLM-generated SQL over
   the `ask_*` views and `graphsync` mirrors everything into a single Neo4j
   graph — both would leak across tenants. Multi-tenant mode requires making
   each of them tenant-aware (or disabling them) first.
2. **Workers do not yet echo `tenant_id`** from the job payload as
   `X-Paddock-Tenant`, so worker callbacks for a non-default tenant's scans land
   in the default tenant (and 404). The API-level isolation is complete; the
   scanning pipeline for tenant ≠ default is not.
3. **Foreign keys bypass RLS.** A tenant that knows another tenant's row UUID
   could reference it from its own row (e.g. a finding pointing at a foreign
   `asset_id`) — it still cannot read it. Composite `(tenant_id, id)` FKs would
   close this; not done.
4. **Some natural keys remain global** because non-orchestrator services
   upsert on them (`sca_projects(name)`, `attack_paths(fingerprint)`,
   `anomalies(...)`, `ml_models(kind,version)`, `code_findings(...)`,
   `ti_*`, `app_users(username)`, `sla_policies(severity)`): a collision across
   tenants is an error or (for globals) shared data, and reveals existence.
5. **RLS protects against query bugs, not a compromised app process.** The
   app sets its own `app.tenant_id`; code execution inside the orchestrator can
   set any tenant. Defence against that is process isolation per tenant
   (separate deployments / databases), which this model does not provide.
6. Sequences (`BIGSERIAL` ids) are shared, so ids leak approximate global
   volumes. Per-tenant encryption keys for evidence blobs (roadmap P5) are not
   implemented.
7. Tables created after the last run of `099_tenancy.sql` have **no** RLS
   until it is re-applied.

---

# Compute services and workers (schema 029)

The orchestrator was the only component that enforced tenancy. This section
records how **every other component** now gets its data, with which database
role, and where its tenant comes from. Everything below is covered by tests
(`<service>/tests/test_tenancy.py`, `orchestrator/tests/test_service_tenancy.py`,
`scripts/tests/test_tenancy_helper.py`).

## The rules

1. **Every unit of work names its tenant.** Stream events carry `tenant_id`
   (`queue.publish_event` stamps the request's tenant); queued scan jobs carry it
   (`queue.enqueue_scan`, which refuses to enqueue a job with no tenant under
   `TENANCY_STRICT`); HTTP calls from the orchestrator to a service carry
   `X-Paddock-Tenant` + the service key (`service_client.service_headers`).
   Periodic sweeps iterate the active tenants (`tenants` catalogue), each in its
   own context, one tenant's failure never stopping the others.
2. **The tenant is bound per unit of work** in a `ContextVar`
   (`shared/paddock_tenancy.py`, copied verbatim to `<svc>/app/tenancy.py` by
   `python scripts/sync_tenancy_helper.py`; a test fails if a copy drifts).
3. **The database enforces it.** Each service connects as its own
   `paddock_svc_<name>` role (`NOSUPERUSER NOBYPASSRLS`, explicit table
   allow-list, no role-level default tenant: an unscoped session sees nothing).
   `Database.acquire()` opens a transaction and runs
   `set_config('app.tenant_id', <tenant>, true)` -- `SET LOCAL` semantics, so the
   value dies with the transaction and a pooled connection can never carry it to
   the next user. `REQUIRE_RLS_ROLE=true` (set in compose) makes a service refuse
   to start if it is connected as a superuser / BYPASSRLS role.
4. **With no tenant bound** a service runs in the default tenant (single-tenant
   installs unchanged) -- or in *no* tenant with `TENANCY_STRICT=true`: reads
   return nothing, writes fail the RLS check, and an event/job that names no
   tenant is dropped.
5. **Global catalogues stay global and platform-written.** `cves`,
   `intel_cursors`, `attack_technique_map`, `ontology_*_types`, `ti_feeds`,
   `ti_indicators`, `sla_policies` have no tenant column and are writable only
   from the platform (default) tenant; services write them inside
   `platform_context()` (`Database.acquire_platform()`), whichever tenant's job
   triggered the write, and never put tenant data in them. Tenant-specific
   state that used to live in `intel_cursors` (changewatch, graphsync cursors)
   moved to the tenant-scoped **`service_cursors`**. Per-tenant models and
   scores (`ml_models`, `ml_risk_scores`, `anomalies`) are tenant rows: a tenant's
   model is never trained on, or served to, another tenant.
6. **Per-tenant natural keys** (schema 029): `sca_projects(name)`,
   `attack_paths(fingerprint)`, `ml_models(kind,version)`,
   `anomalies(subject_type,subject_label,detected_at)` and the attack-path
   ledger's open-episode index are now `(tenant_id, ...)`. Services' `ON CONFLICT`
   targets were updated; **any new upsert on those tables must name `tenant_id`**.
7. **A rejected statement aborts the service's transaction.** Because each
   `acquire()` is one transaction, code that catches a database error and keeps
   using the connection must wrap the risky statement in `conn.transaction()` (a
   savepoint) -- threatintel's indicator upsert does.

## Service inventory

| Component | Reaches data via | DB role | Tenant comes from |
|---|---|---|---|
| orchestrator | asyncpg pool | `paddock_app` | principal (user/key/JWT); service key + `X-Paddock-Tenant` |
| integrations worker (orchestrator image) | Redis `stream:events` + DB | `paddock_app` (was owner) | event `tenant_id`; delivery loop sweeps each tenant |
| intel | DB (`cves`, `cve_matches`) + orchestrator API | `paddock_svc_intel` | `asset_added` event / tenant sweep / `X-Paddock-Tenant`; NVD/EPSS/KEV sync = platform |
| correlation | DB + orchestrator API + `stream:events` | `paddock_svc_correlation` | event `tenant_id`; sweeps per tenant; per-tenant debounce state |
| mlrisk | DB | `paddock_svc_mlrisk` | per-tenant scheduled pass / `X-Paddock-Tenant` |
| triage | DB + `stream:events` | `paddock_svc_triage` | event `tenant_id` / per-tenant sweep |
| changewatch | DB + `stream:events` | `paddock_svc_changewatch` | event `tenant_id` / per-tenant sweep + cursor |
| ontology | DB | `paddock_svc_ontology` | per-tenant projection; type catalogue = platform |
| threatintel | DB + orchestrator API | `paddock_svc_threatintel` | matching per tenant; feeds/indicators are global and **platform-only** |
| otdiscovery | HTTP ingest + DB (`cves`) + orchestrator API | `paddock_svc_otdiscovery` | sensor token bound to a tenant (`SENTRY_TOKENS=<tenant-uuid>=<token>`); one in-memory engine per tenant |
| brain | DB (LLM-written SQL!) | `paddock_svc_brain` | `X-Paddock-Tenant`; NL-SQL runs in one top-level READ ONLY transaction carrying the tenant, with a post-check that the tenant GUC did not move |
| remediation | DB | `paddock_svc_remediation` | `X-Paddock-Tenant` |
| sca | DB + orchestrator API | `paddock_svc_sca` | `X-Paddock-Tenant`; `/scan-dir` (host filesystem) is platform-tenant only |
| codeanalysis | DB + orchestrator API | `paddock_svc_codeanalysis` | `X-Paddock-Tenant` |
| graphsync | DB -> one Neo4j graph | `paddock_svc_graphsync` | **single-tenant by design**, see below |
| worker-passive / worker-active | Redis queues + orchestrator API only (no DB; the DB credential was removed from compose) | none | job `tenant_id`, echoed on every callback |
| agent (fleet) | orchestrator `/v1/fleet` | none | see "Not converted" |
| sentry | HTTP `/ingest` on otdiscovery | none | bearer token bound to a tenant |

## Workers: tenant echo and verification

A worker binds the job's `tenant_id` + `scan_id` for the whole job
(`tenancy.bind_job`). Every orchestrator call it makes -- scope checks, asset /
finding / edge bulk writes, scan status -- carries `X-Paddock-Tenant` and
`X-Paddock-Scan`. A job with no tenant is dropped in strict mode. The workers'
scope-decision caches are keyed by tenant (a cached "allow" for tenant A never
authorises tenant B's scan of the same name).

The orchestrator (`job_binding.py`, called from the governance middleware for
service principals) verifies that the job the callback names was **issued to the
tenant it claims** -- `scans` is RLS'd, so the lookup runs inside the claimed
tenant and only finds a job that tenant owns. A mismatch (job from another
tenant, unknown job, or an echoed scan id that differs from the URL's) is
rejected with `409 job_tenant_mismatch` and audited. Under `TENANCY_STRICT`,
scan-lifecycle callbacks must echo their job.

## The service key

`SERVICE_API_KEY` is a fleet credential, not a tenant. Under `TENANCY_STRICT`
a service-key request without `X-Paddock-Tenant` is refused (401). The header is
honoured **only** for service principals, the tenant must exist and be active
(unknown / suspended -> 401), and every service-key request is audited in the
acting tenant's chain with `via=service_key`, `acting_tenant` and the job id.
The compute services apply the same rule to their own HTTP surface: naming a
tenant requires the service key (403 otherwise, and always in strict mode).
*Remaining limit:* the key itself is still shared, so a compromised holder can
name any tenant; per-job bound tokens are the next step.

## Deploying

* Fresh volume: `029_service_tenancy.sql` creates the roles NOLOGIN; the
  `migrate` one-shot then runs `python -m app.tenancy provision-roles`, which
  gives `paddock_app` and every `paddock_svc_*` role LOGIN + a password
  (`PADDOCK_SVC_<NAME>_DB_PASSWORD` -> `PADDOCK_SERVICES_DB_PASSWORD` ->
  `PADDOCK_APP_DB_PASSWORD` -> `POSTGRES_PASSWORD`; **set a distinct
  `PADDOCK_SERVICES_DB_PASSWORD`** so a compromised service never learns the owner
  password). `docker-compose.lite.yml` (initdb mount) does the same through
  `schema/101_service_roles.sh`. (The base compose file mounts no initdb
  directory, so `100_app_role.sh` never ran there; `provision-roles` also covers
  `paddock_app`.)
* Existing volume: the migration runner applies 029 on the next `migrate`; then
  restart the services. A new table is invisible to every service role until it
  is added to the allow-list in `paddock_apply_service_grants()` and
  `SELECT paddock_apply_service_grants();` is re-run.
* Helm: set `secrets.serviceRoles=true` and provide `DATABASE_URL_INTEL` /
  `_CORRELATION` / `_OTDISCOVERY` (`secrets.serviceDatabaseUrls`). The chart
  template change could not be rendered in this environment (no `helm`); the
  chart's worker pods still receive the shared `DATABASE_URL` env (unused).
* Multi-tenant installs should set `TENANCY_STRICT=true` on **every** component.

## Not converted / known limits (read before selling this as multi-tenant)

1. **graphsync is platform-tenant only.** Neo4j Community has no per-tenant
   isolation and the Cypher (`queries.py`) is not tenant-filtered (crown-jewel
   and stats queries are global aggregates). Converting it safely needs tenant
   properties on every node/edge and a Cypher rewrite tested against a real
   Neo4j, which is not available here. So: it mirrors only the default
   tenant's Postgres rows (every DB access is pinned to it by construction) and
   answers every other tenant with the documented `{"available": false}` degrade.
2. **Threat-intel feeds / indicators are global.** A non-platform tenant cannot
   register feeds or ingest indicators (403); there is no tenant-scoped IOC
   store. Matching against the global IOCs is per tenant.
3. **Agent (fleet).** Agents authenticate with their own `X-Agent-Token`, which
   is looked up inside the default tenant context; the enforce-mode agent routes
   are not in the governance allow-list upstream of tenancy, so an agent
   enrolled into a non-default tenant is not supported yet. Unchanged in this pass.
4. **remediation** opens PRs with one platform GitHub credential; per-tenant
   credentials are not modelled.
5. **dev auth mode** gives every caller the default tenant; multi-tenant needs
   `AUTH_MODE=enforce`.
6. Foreign keys still bypass RLS (limit 3 above); `sca` `/scan-dir` and the
   NVD/KEV/EPSS sync are platform-operator facilities by design.
7. In-process, per-service stats (`last_run`, ...) describe the last tenant
   processed, not an aggregate.
