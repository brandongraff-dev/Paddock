#!/usr/bin/env python3
"""Multi-tenant load test: 5 tenants, 100k findings, 10k assets, a 50-customer MSP.

Creates a scratch database, applies the schema through the migration runner,
seeds (as the schema owner, with explicit tenant ids)

* 5 tenants sharing 10k assets and 100k findings,
* an MSP tenant with 50 customer tenants (each a small data set),

then serves the real FastAPI app in-process (httpx ASGI transport) through the
NON-superuser ``paddock_app`` role with API-key auth, i.e. the production path
(auth lookup, RLS, governance middleware, audit) and reports p50/p95/max for
the hot endpoints:

* findings list with filters (severity/status/exploitability/asset/q/KEV/SLA)
* executive report (JSON) and the posture-heavy reads
* MSP customer rollup over 50 customers (cold and cached)
* ingest of a 20k-result SARIF file

    python hardening/tenant_load_test.py --admin-dsn postgresql://postgres@127.0.0.1:55470/postgres \
        [--findings 100000 --assets 10000 --iterations 20] [--markdown out.md]
        [--without-036-indexes]   # drop the indexes schema/036 adds (before/after numbers)

Never point --admin-dsn at a production server.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "orchestrator"))
os.environ.setdefault("MIGRATE_ON_STARTUP", "false")
os.environ.setdefault("SCHEDULER_ENABLED", "false")

import asyncpg  # noqa: E402

N_TENANTS = 5
N_CUSTOMERS = 50
TENANT_IDS = [f"00000000-0000-0000-0000-0000000001{i:02d}" for i in range(N_TENANTS)]
MSP_ID = "00000000-0000-0000-0000-000000000200"


def pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


SEED_ASSETS = """
INSERT INTO assets (kind, value, canonical, source, first_seen, last_seen, metadata, tenant_id)
SELECT (ARRAY['subdomain','domain','ipv4','service','port','technology','certificate','endpoint'])[1 + (g % 8)],
       'host' || g || '.t' || ($2::int) || '.example', 'host' || g || '.t' || ($2::int) || '.example',
       (ARRAY['passive','active','intel','otdiscovery','sca'])[1 + (g % 5)],
       NOW() - make_interval(days => (g % 90), mins => (g % 1440)),
       NOW() - make_interval(mins => (g % 10080)),
       jsonb_build_object('blast_score', (g % 100)::float / 10), $3::uuid
  FROM generate_series(1, $1::int) g
"""

SEED_FINDINGS = """
WITH a AS (SELECT id, row_number() OVER (ORDER BY id) - 1 AS rn FROM assets WHERE tenant_id = $2::uuid),
     n AS (SELECT count(*) AS c FROM assets WHERE tenant_id = $2::uuid)
INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description, status,
                      first_seen, last_seen, evidence, metadata, exploitability, status_reason, tenant_id)
SELECT a.id, 'rule-' || (g / n.c) || '-' || (g % 53),
       (ARRAY['nuclei','cve_match','policy','header_check','tls_check','exposed_file'])[1 + (g % 6)],
       (ARRAY['info','low','low','medium','medium','medium','high','critical'])[1 + (g % 8)],
       (ARRAY['Outdated TLS configuration','Missing security header','Exposed .git directory',
              'SQL error disclosure','Open admin panel','Known exploited CVE'])[1 + (g % 6)] || ' #' || g,
       'Synthetic finding ' || g || ' for load testing',
       (ARRAY['open','open','open','triaged','fixed','false_positive','accepted'])[1 + (g % 7)],
       NOW() - make_interval(days => (g % 90), mins => (g % 997)),
       NOW() - make_interval(mins => (g % 20000)),
       jsonb_build_object('url', 'https://host' || g || '.example/'),
       jsonb_build_object('blast_score', (g % 100)::float / 10, 'kev', (g % 97 = 0)),
       (ARRAY['unverified','unverified','unverified','confirmed','not_reproducible','inconclusive'])[1 + (g % 6)],
       'load test', $2::uuid
  FROM generate_series(0, $1::int - 1) g CROSS JOIN n JOIN a ON a.rn = g % n.c
"""


async def seed(dsn: str, args) -> dict:
    from app import auth as auth_svc

    con = await asyncpg.connect(dsn, command_timeout=None)
    keys: dict[str, str] = {}
    try:
        t0 = time.perf_counter()
        for i, tid in enumerate(TENANT_IDS):
            await con.execute("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)", tid, f"load-{i}")
        await con.execute("INSERT INTO tenants (id, slug, name) VALUES ($1, 'load-msp', 'load msp')", MSP_ID)
        for i, tid in enumerate(TENANT_IDS + [MSP_ID]):
            full, prefix, key_hash = auth_svc.generate_api_key()
            uid = await con.fetchval(
                "INSERT INTO app_users (username, role, clearance, pw_hash, tenant_id) "
                "VALUES ($1, 'admin', 'restricted', 'x', $2) RETURNING id", f"load-admin-{i}", tid)
            await con.execute(
                "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes, tenant_id) "
                "VALUES ($1, 'k', $2, $3, $4::text[], $5)",
                uid, prefix, key_hash, sorted(auth_svc.ROLE_CAPABILITIES["admin"]), tid)
            keys[tid] = full
        per_assets, per_findings = args.assets // N_TENANTS, args.findings // N_TENANTS
        for i, tid in enumerate(TENANT_IDS):
            await con.execute("INSERT INTO scope_entries (kind, value, added_by, tenant_id) "
                              "VALUES ('domain', $1, 'load', $2)", f"t{i}.example", tid)
            await con.execute(SEED_ASSETS, per_assets, i, tid)
            await con.execute(SEED_FINDINGS, per_findings, tid)
            print(f"  tenant {i}: {per_assets} assets, {per_findings} findings", flush=True)
        # MSP + customers
        await con.execute("INSERT INTO msp_orgs (tenant_id, name, created_by) VALUES ($1, 'Load MSP', 'load')", MSP_ID)
        msp_user = await con.fetchval("SELECT id FROM app_users WHERE tenant_id = $1", MSP_ID)
        for c in range(N_CUSTOMERS):
            cid = str(uuid.UUID(int=0x3000 + c))
            await con.execute("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)", cid, f"load-cust-{c}", f"Customer {c}")
            await con.execute("INSERT INTO msp_children (tenant_id, child_tenant_id, slug, name, created_by) "
                              "VALUES ($1, $2, $3, $4, 'load')", MSP_ID, cid, f"load-cust-{c}", f"Customer {c}")
            await con.execute(SEED_ASSETS, 40, 100 + c, cid)
            await con.execute(SEED_FINDINGS, 400, cid)
            await con.execute("INSERT INTO scans (kind, target, status, finished_at, tenant_id) "
                              "VALUES ('nuclei_scan', 'x.example', 'completed', NOW(), $1)", cid)
        await con.execute("INSERT INTO msp_grants (user_id, child_tenant_id, role, clearance, tenant_id, granted_by) "
                          "VALUES ($1, NULL, 'admin', 'restricted', $2, 'load')", msp_user, MSP_ID)
        await con.execute("ANALYZE")
        counts = {t: await con.fetchval(f"SELECT count(*) FROM {t}") for t in ("assets", "findings", "tenants")}
        print(f"  seeded in {time.perf_counter() - t0:.1f}s; rows: {counts}", flush=True)
    finally:
        await con.close()
    return keys


def sarif(n: int) -> bytes:
    rules = [{"id": f"LOAD{i:03d}", "shortDescription": {"text": f"load rule {i}"},
              "defaultConfiguration": {"level": ["note", "warning", "error"][i % 3]}} for i in range(60)]
    results = [{
        "ruleId": f"LOAD{i % 60:03d}", "level": ["note", "warning", "error"][i % 3],
        "message": {"text": f"synthetic result {i}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"src/mod{i % 700}/file{i % 97}.py"},
                                            "region": {"startLine": 1 + (i % 400)}}}],
    } for i in range(n)]
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "loadscan", "rules": rules}}, "results": results}]}
    return json.dumps(doc).encode()


async def measure(dsn: str, keys: dict[str, str], args) -> list[dict]:
    from httpx import ASGITransport, AsyncClient

    from app import main as main_mod
    from app.config import settings
    from app.db import create_pool

    settings.auth_mode = "enforce"

    @asynccontextmanager
    async def _noop(app):
        yield

    main_mod.lifespan = _noop
    app = main_mod.create_app()
    su = await asyncpg.connect(dsn)
    await su.execute("ALTER ROLE paddock_app LOGIN")
    base = dsn.rsplit("/", 1)
    pool = await create_pool(f"{base[0].replace('postgres@', 'paddock_app@')}/{base[1]}", min_size=2, max_size=8)
    app.state.pool = pool
    import fakeredis.aioredis

    app.state.redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    t0id = TENANT_IDS[0]
    hdr = {"Authorization": f"Bearer {keys[t0id]}"}
    msp_hdr = {"Authorization": f"Bearer {keys[MSP_ID]}"}
    asset = await su.fetchval("SELECT asset_id FROM findings WHERE tenant_id = $1 GROUP BY asset_id "
                              "ORDER BY count(*) DESC LIMIT 1", t0id)
    await su.close()

    probes = [
        ("findings: default page", "GET", "/v1/findings?limit=50", hdr),
        ("findings: severity+status", "GET", "/v1/findings?severity=critical&status=open&limit=50", hdr),
        ("findings: exploitability=confirmed", "GET", "/v1/findings?exploitability=confirmed&limit=50", hdr),
        ("findings: exploitability+severity+open", "GET",
         "/v1/findings?exploitability=confirmed&severity=high&status=open&limit=50", hdr),
        ("findings: fix_verified", "GET", "/v1/findings?fix_verified=true&limit=50", hdr),
        ("findings: sla_breached", "GET", "/v1/findings?sla_breached=true&limit=50", hdr),
        ("findings: kev=true", "GET", "/v1/findings?kev=true&limit=50", hdr),
        ("findings: one asset", "GET", f"/v1/findings?asset_id={asset}&limit=50", hdr),
        ("findings: text search q=", "GET", "/v1/findings?q=admin%20panel&limit=50", hdr),
        ("findings: deep offset", "GET", "/v1/findings?status=open&limit=50&offset=5000", hdr),
        ("reports: executive json (30d)", "GET", "/v1/reports/executive?format=json", hdr),
        ("reports: executive json (90d)", "GET", "/v1/reports/executive?format=json&period=90d", hdr),
        ("reports: compliance", "GET", "/v1/reports/compliance", hdr),
        ("assets: list", "GET", "/v1/assets?limit=100", hdr),
        ("status/posture", "GET", "/status", hdr),
        ("msp: customers (50, cached)", "GET", "/v1/msp/customers?limit=50", msp_hdr),
        ("msp: summary", "GET", "/v1/msp/summary", msp_hdr),
    ]
    results = []
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://load", timeout=300) as client:
        # MSP cold rollup (first computation over all 50 customers) is measured once, explicitly.
        for label, url in (("msp: customers REFRESH (50 cold)", "/v1/msp/customers?limit=50&refresh=true"),):
            samples = []
            for _ in range(max(3, args.iterations // 4)):
                t = time.perf_counter()
                r = await client.get(url, headers=msp_hdr)
                samples.append((time.perf_counter() - t) * 1000)
            results.append(_row(label, r.status_code, samples))
        for label, method, url, h in probes:
            for _ in range(2):
                r = await client.request(method, url, headers=h)
            if r.status_code != 200:
                print(f"  !! {label}: HTTP {r.status_code} {r.text[:160]}")
            samples = []
            for _ in range(args.iterations):
                t = time.perf_counter()
                r = await client.request(method, url, headers=h)
                samples.append((time.perf_counter() - t) * 1000)
            results.append(_row(label, r.status_code, samples))
        # SARIF ingest, 20k results
        if args.skip_ingest:
            await pool.close()
            for r in results:
                print(f"  {r['label']:<46} p50 {r['p50']:9.1f} ms  p95 {r['p95']:9.1f} ms  [{r['status']}]", flush=True)
            return results
        body = sarif(args.sarif_results)
        samples = []
        status = 0
        for k in range(args.ingest_runs):
            t = time.perf_counter()
            r = await client.post(f"/v1/ingest?format=sarif&project=load{k}", content=body,
                                  headers={**hdr, "Content-Type": "application/json"})
            samples.append((time.perf_counter() - t) * 1000)
            status = r.status_code
            if status not in (200, 201, 202):
                print(f"  !! ingest: HTTP {status} {r.text[:200]}")
        results.append(_row(f"ingest: SARIF {args.sarif_results:,} results ({len(body) / 1e6:.1f} MB)", status, samples))
    await pool.close()
    for r in results:
        print(f"  {r['label']:<46} p50 {r['p50']:9.1f} ms  p95 {r['p95']:9.1f} ms  [{r['status']}]", flush=True)
    return results


def _row(label, status, samples) -> dict:
    return {"label": label, "status": status, "p50": statistics.median(samples),
            "p95": pct(samples, 0.95), "max": max(samples), "n": len(samples)}


def markdown(results, args) -> str:
    lines = [
        f"Dataset: {N_TENANTS} tenants, {args.assets:,} assets, {args.findings:,} findings, "
        f"{N_CUSTOMERS}-customer MSP; {args.iterations} timed requests per endpoint; "
        f"served as `paddock_app` with API-key auth (RLS on).",
        "", "| Endpoint | p50 (ms) | p95 (ms) | max (ms) |", "|---|---:|---:|---:|",
    ]
    lines += [f"| {r['label']} | {r['p50']:.1f} | {r['p95']:.1f} | {r['max']:.1f} |" for r in results]
    return "\n".join(lines) + "\n"


async def amain(args) -> int:
    from app import migrate

    base = args.admin_dsn.rsplit("/", 1)[0]
    name = f"tload_{uuid.uuid4().hex[:8]}"
    admin = await asyncpg.connect(args.admin_dsn)
    await admin.execute(f'CREATE DATABASE "{name}"')
    await admin.close()
    dsn = f"{base}/{name}"
    print(f"database {name}", flush=True)
    try:
        con = await asyncpg.connect(dsn)
        from tests.conftest import _schema_transform  # noqa: E402

        await migrate.migrate_up(con, schema_dir=ROOT / "schema", transform=_schema_transform)
        if args.without_036_indexes:
            for ix in args.drop_index:
                await con.execute(f'DROP INDEX IF EXISTS "{ix}"')
        await con.close()
        keys = await seed(dsn, args)
        results = await measure(dsn, keys, args)
        if args.markdown:
            Path(args.markdown).write_text(markdown(results, args))
        return 0
    finally:
        if not args.keep:
            admin = await asyncpg.connect(args.admin_dsn)
            await admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
                name)
            await admin.execute(f'DROP DATABASE IF EXISTS "{name}"')
            await admin.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--admin-dsn", default="postgresql://postgres@127.0.0.1:5432/postgres")
    ap.add_argument("--assets", type=int, default=10_000)
    ap.add_argument("--findings", type=int, default=100_000)
    ap.add_argument("--iterations", type=int, default=20)
    ap.add_argument("--sarif-results", type=int, default=20_000)
    ap.add_argument("--ingest-runs", type=int, default=3)
    ap.add_argument("--without-036-indexes", action="store_true",
                    help="drop the indexes added by the hardening migration (see --drop-index)")
    ap.add_argument("--drop-index", action="append", default=[])
    ap.add_argument("--skip-ingest", action="store_true")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--markdown")
    args = ap.parse_args()
    return asyncio.run(amain(args))


if __name__ == "__main__":
    raise SystemExit(main())
