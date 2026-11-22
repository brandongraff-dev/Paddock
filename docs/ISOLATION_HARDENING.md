# Isolation & load hardening

A stress pass over multi-tenancy after the billing, verification, ingest,
service-tenancy, SSO, cloud-connector, growth, MSP and sensor workstreams
landed. Everything below is a test that runs in CI, plus one manual load script.

## What is checked

| Test | What it proves |
|---|---|
| `tests/test_isolation_sweep.py` | Enumerates **every relation in schema `public`** at runtime. A table must be tenant-scoped (`tenant_id` + ENABLE/FORCE RLS + `tenant_isolation` keyed on `paddock_current_tenant()`, no `OR` arm) or an explicitly allow-listed global catalogue; extra policies must be on a reviewed list and be narrow `SELECT` lookups; views must be `security_invoker`. Then, as `paddock_app`, one generated row per tenant table inserted in tenant A is invisible to B, cannot be updated or deleted by B, and B cannot insert a row for A. |
| `tests/test_isolation_keys.py` | Two tenants can hold a row with the **same natural key** in every tenant table (a global UNIQUE/PK collides across tenants and either fails or, with `ON CONFLICT DO NOTHING`, silently drops the write). Deliberately global keys (credential lookup handles) are listed with a reason. |
| `tests/test_api_isolation_sweep.py` | Reads the **live OpenAPI spec** and calls every GET/PATCH/PUT/DELETE as five attackers (tenant key, MSP user session, MSP switch token into a customer, service key + `X-Paddock-Tenant`) with every id of every victim tenant: no victim marker in any response, a foreign id is answered exactly like a random id (no existence oracle), no victim row or global catalogue changes. Skipped routes (public by design, SSE, SCIM) carry a reason. |
| `tests/test_scim_cross_tenant.py` | SCIM tokens are bound to their tenant. |
| `tests/test_tenancy_stress.py` | 900 interleaved requests from six identities against a 4-connection pool, with the tenant-iterating background loops running at the same time: every response only holds the caller's data, every row lands in the writer's tenant, pooled connections come back clean (also under `TENANCY_STRICT`). Regressions for the scheduler loops (source sync, retention, weekly digest). |
| `tests/test_event_stream_isolation.py`, `test_license_tenant_cache.py`, `test_lifecycle_sweep_tenant.py` | Regressions for the SSE stream, the license cache and the on-read sweep throttle. |

## Adding a table

Nothing to do: `099_tenancy.sql` gives it `tenant_id` + RLS. If it must be
global, mark it `COMMENT ... '@paddock:global'` **and** add it to
`GLOBAL_ALLOWLIST` in `test_isolation_sweep.py` with the reason. If a natural key
is looked up before the tenant is known (a token, a slug), list it in
`GLOBAL_UNIQUE_OK` in `test_isolation_keys.py`; otherwise make it
`UNIQUE (tenant_id, ...)` and name `tenant_id` in every `ON CONFLICT`.

## Load test

```bash
python hardening/tenant_load_test.py --admin-dsn postgresql://postgres@127.0.0.1:5432/postgres
```

Seeds 5 tenants (10k assets, 100k findings) plus an MSP with 50 customers into a
scratch database, serves the real app as the non-superuser `paddock_app` with
API-key auth, and reports p50/p95 for the findings list (severity, status,
exploitability, fix_verified, SLA, KEV, asset, text, deep offset), the executive
and compliance reports, the MSP rollup (cold and cached) and a 20k-result SARIF
ingest. `--skip-ingest`, `--keep`, `--markdown FILE` are available.

Findings and fixes are in the hardening commit message; schema changes are in
`schema/036_isolation_fixes.sql`.
