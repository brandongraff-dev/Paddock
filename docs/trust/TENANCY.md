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
