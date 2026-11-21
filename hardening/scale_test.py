#!/usr/bin/env python3
"""Scale test: seed a large dataset and measure the main API reads.

Seeds (defaults) 10k assets, ~30k edges, 100k findings, 1M scope decisions,
10k scans into a FRESH database (created and dropped by this script), applies
the schema through the versioned migration runner, then drives the real
FastAPI app in-process (httpx ASGI transport, AUTH_MODE=dev) and reports
p50/p95/max latency per endpoint.

NOT part of normal CI (seeding 1M rows takes a minute or two). Run manually
or from the nightly `scale` workflow job:

    pip install -e "orchestrator[dev]"
    python hardening/scale_test.py --admin-dsn postgresql://postgres@127.0.0.1:5432/postgres

Options:
    --assets N --findings N --decisions N --scans N   dataset size
    --iterations N            timed requests per endpoint (after 3 warm-ups)
    --without-ops-indexes     drop the indexes schema/022_ops.sql adds before
                              measuring (to see what they buy)
    --explain                 print EXPLAIN (ANALYZE, BUFFERS) for each SQL probe
    --keep                    keep the database afterwards (name is printed)
    --markdown FILE           also write the results table as Markdown

Never point --admin-dsn at a production server: the script creates and drops
its own database there, but it does generate heavy load.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import statistics
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "orchestrator"))
os.environ.setdefault("AUTH_MODE", "dev")
os.environ.setdefault("MIGRATE_ON_STARTUP", "false")
os.environ.setdefault("SCHEDULER_ENABLED", "false")

import asyncpg  # noqa: E402

# Indexes schema/022_ops.sql adds; --without-ops-indexes drops them.
OPS_INDEXES = [
    "idx_findings_status_last_seen",
    "idx_findings_sev_status_last_seen",
    "idx_findings_first_seen",
    "idx_findings_open_hi_asset",
    "idx_findings_title_trgm",
    "idx_findings_description_trgm",
    "idx_assets_first_seen",
    "idx_assets_source_last_seen",
    "idx_assets_kind_last_seen",
    "idx_scope_decisions_entry_ts",
    "idx_scans_queued_at",
    "idx_integration_deliveries_updated",
]


SEED_SQL = [
    # ---- scope entries (100) -------------------------------------------
    """
    INSERT INTO scope_entries (kind, value, added_by, auth_doc_ref)
    SELECT 'domain', 'scale' || g || '.example', 'scale', 'scale-test'
      FROM generate_series(1, 100) g
    """,
    # ---- assets ---------------------------------------------------------
    """
    INSERT INTO assets (kind, value, canonical, source, first_seen, last_seen, metadata)
    SELECT (ARRAY['subdomain','domain','ipv4','service','port','technology',
                  'certificate','endpoint'])[1 + (g % 8)],
           'host' || g || '.scale' || (g % 100) || '.example',
           'host' || g || '.scale' || (g % 100) || '.example',
           (ARRAY['passive','active','intel','otdiscovery','sca'])[1 + (g % 5)],
           NOW() - make_interval(days => (g % 90), mins => (g % 1440)),
           NOW() - make_interval(mins => (g % 10080)),
           jsonb_build_object('blast_score', (g % 100)::float / 10)
      FROM generate_series(1, $1::int) g
    """,
    # ---- edges: ~3 per asset, to nearby ids ----------------------------
    """
    WITH a AS (SELECT id, row_number() OVER (ORDER BY id) AS rn FROM assets),
         n AS (SELECT count(*) AS c FROM assets)
    INSERT INTO asset_edges (src_id, dst_id, kind)
    SELECT s.id, d.id, (ARRAY['resolves_to','hosts','runs'])[k]
      FROM a s
      CROSS JOIN generate_series(1, 3) k
      CROSS JOIN n
      JOIN a d ON d.rn = 1 + ((s.rn * 7 + k * 131) % n.c)
     WHERE s.id <> d.id
    ON CONFLICT DO NOTHING
    """,
    # ---- findings: N spread over assets, unique (asset, rule, source) ---
    """
    WITH a AS (SELECT id, row_number() OVER (ORDER BY id) - 1 AS rn FROM assets),
         n AS (SELECT count(*) AS c FROM assets)
    INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description,
                          status, first_seen, last_seen, evidence, metadata)
    SELECT a.id,
           'rule-' || (g / n.c) || '-' || (g % 53),
           (ARRAY['nuclei','cve_match','policy','header_check','tls_check',
                  'exposed_file'])[1 + (g % 6)],
           (ARRAY['info','low','low','medium','medium','medium','high','critical'])[1 + (g % 8)],
           (ARRAY['Outdated TLS configuration','Missing security header',
                  'Exposed .git directory','SQL error disclosure','Open admin panel',
                  'Known exploited CVE'])[1 + (g % 6)] || ' #' || g,
           'Synthetic finding ' || g || ' for scale testing; remediation guidance follows.',
           (ARRAY['open','open','open','triaged','fixed','false_positive',
                  'accepted_risk'])[1 + (g % 7)],
           NOW() - make_interval(days => (g % 90), mins => (g % 997)),
           NOW() - make_interval(mins => (g % 20000)),
           jsonb_build_object('url', 'https://host' || g || '.example/'),
           jsonb_build_object('blast_score', (g % 100)::float / 10, 'kev', (g % 97 = 0))
      FROM generate_series(0, $1::int - 1) g
      CROSS JOIN n
      JOIN a ON a.rn = g % n.c
    """,
    # ---- scope decisions (the big one) ---------------------------------
    """
    INSERT INTO scope_decisions (target, normalized, decision, matched_entry, worker, reason, decided_at)
    SELECT 'host' || (g % 10000) || '.scale' || (g % 100) || '.example',
           'host' || (g % 10000) || '.scale' || (g % 100) || '.example',
           CASE WHEN g % 5 = 0 THEN 'deny' ELSE 'allow' END,
           CASE WHEN g % 5 = 0 THEN NULL ELSE (SELECT min(id) FROM scope_entries) + (g % 100) END,
           (ARRAY['worker-passive','worker-active','orchestrator.dispatch'])[1 + (g % 3)],
           'scale',
           NOW() - make_interval(secs => (g % (200 * 86400)))
      FROM generate_series(1, $1::int) g
    """,
    # ---- scans ----------------------------------------------------------
    """
    INSERT INTO scans (kind, target, status, queued_at)
    SELECT (ARRAY['passive_subdomains','active_http_probe','nuclei_scan'])[1 + (g % 3)],
           'scale' || (g % 100) || '.example',
           (ARRAY['completed','completed','completed','failed','queued','running'])[1 + (g % 6)],
           NOW() - make_interval(mins => (g % 129600))
      FROM generate_series(1, $1::int) g
    """,
]


def pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


async def seed(dsn: str, args: argparse.Namespace) -> dict[str, float]:
    con = await asyncpg.connect(dsn, command_timeout=None)
    timings: dict[str, float] = {}
    try:
        sizes = [None, args.assets, None, args.findings, args.decisions, args.scans]
        names = ["scope_entries", "assets", "asset_edges", "findings", "scope_decisions", "scans"]
        for name, sql, n in zip(names, SEED_SQL, sizes):
            t0 = time.perf_counter()
            if n is None:
                await con.execute(sql)
            else:
                await con.execute(sql, n)
            timings[name] = time.perf_counter() - t0
            print(f"  seeded {name:<16} in {timings[name]:6.1f}s", flush=True)
        t0 = time.perf_counter()
        await con.execute("ANALYZE")
        timings["analyze"] = time.perf_counter() - t0
        counts = {}
        for t in names:
            counts[t] = await con.fetchval(f"SELECT count(*) FROM {t}")
        print("  row counts:", counts, flush=True)
    finally:
        await con.close()
    return timings


async def measure(dsn: str, args: argparse.Namespace) -> list[dict]:
    from httpx import ASGITransport, AsyncClient

    from app import main as main_mod
    from app.config import settings

    settings.auth_mode = "dev"

    @asynccontextmanager
    async def _noop(app):
        yield

    main_mod.lifespan = _noop
    app = main_mod.create_app()
    pool = await asyncpg.create_pool(dsn, min_size=2, max_size=8)
    app.state.pool = pool
    try:
        import fakeredis.aioredis

        app.state.redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    except ImportError:  # pragma: no cover
        app.state.redis = None

    async with pool.acquire() as con:
        some_asset = await con.fetchval(
            "SELECT asset_id FROM findings GROUP BY asset_id ORDER BY count(*) DESC LIMIT 1"
        )
        hub_asset = await con.fetchval(
            "SELECT src_id FROM asset_edges GROUP BY src_id ORDER BY count(*) DESC LIMIT 1"
        )
        entry = await con.fetchval(
            "SELECT matched_entry FROM scope_decisions WHERE matched_entry IS NOT NULL LIMIT 1"
        )
        # An entry with no decisions at all (the worst case without an index).
        quiet_entry = await con.fetchval(
            "INSERT INTO scope_entries (kind, value, added_by) "
            "VALUES ('domain', 'quiet.example', 'scale') RETURNING id"
        )

    probes = [
        ("findings: default page", "/v1/findings?limit=50"),
        ("findings: severity+status", "/v1/findings?severity=critical&status=open&limit=50"),
        ("findings: status, deep offset", "/v1/findings?status=open&limit=50&offset=5000"),
        ("findings: rule_source", "/v1/findings?rule_source=nuclei&limit=50"),
        ("findings: text search q=", "/v1/findings?q=admin%20panel&limit=50"),
        ("findings: text search (rare)", "/v1/findings?q=zz-no-such-term&limit=50"),
        ("findings: one asset", f"/v1/findings?asset_id={some_asset}&limit=50"),
        ("findings: kev=true", "/v1/findings?kev=true&limit=50"),
        ("assets: list", "/v1/assets?limit=100"),
        ("assets: kind filter", "/v1/assets?kind=subdomain&limit=100"),
        ("assets: surface graph (500)", "/v1/assets/graph?limit=500"),
        ("assets: neighbourhood graph", f"/v1/assets/{hub_asset}/graph"),
        ("timeline: 14 days", "/v1/timeline"),
        ("timeline: 90 days", "/v1/timeline?from="
         + time.strftime("%Y-%m-%d", time.gmtime(time.time() - 89 * 86400))),
        ("scope: decisions, busy entry", f"/v1/scope/{entry}/decisions?limit=50"),
        ("scope: decisions, quiet entry", f"/v1/scope/{quiet_entry}/decisions?limit=50"),
    ]
    results = []
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://scale") as client:
        for label, url in probes:
            for _ in range(3):  # warm-up (plan cache, buffer cache)
                r = await client.get(url)
            if r.status_code != 200:
                print(f"  !! {label}: HTTP {r.status_code} {r.text[:200]}")
            samples = []
            for _ in range(args.iterations):
                t0 = time.perf_counter()
                r = await client.get(url)
                samples.append((time.perf_counter() - t0) * 1000)
            row = {
                "label": label,
                "url": url,
                "status": r.status_code,
                "p50": statistics.median(samples),
                "p95": pct(samples, 0.95),
                "max": max(samples),
            }
            results.append(row)
            print(f"  {label:<32} p50 {row['p50']:8.1f} ms   p95 {row['p95']:8.1f} ms", flush=True)
    await pool.close()
    return results


EXPLAIN_SQL = {
    "findings default": (
        "SELECT f.id FROM findings f LEFT JOIN assets a ON a.id=f.asset_id "
        "ORDER BY f.last_seen DESC LIMIT 50"
    ),
    "findings sev+status": (
        "SELECT f.id FROM findings f WHERE f.severity='critical' AND f.status='open' "
        "ORDER BY f.last_seen DESC LIMIT 50"
    ),
    "findings q": (
        "SELECT f.id FROM findings f WHERE f.title ILIKE '%admin panel%' "
        "OR f.description ILIKE '%admin panel%' ORDER BY f.last_seen DESC LIMIT 50"
    ),
    "scope decisions": (
        "SELECT id FROM scope_decisions WHERE matched_entry = "
        "(SELECT min(id) FROM scope_entries) ORDER BY decided_at DESC LIMIT 50"
    ),
    "timeline findings": (
        "SELECT (first_seen AT TIME ZONE 'UTC')::date, severity, count(*) FROM findings "
        "WHERE first_seen >= NOW() - interval '14 days' GROUP BY 1, 2"
    ),
}


async def explain(dsn: str) -> None:
    con = await asyncpg.connect(dsn)
    try:
        for name, sql in EXPLAIN_SQL.items():
            plan = await con.fetch("EXPLAIN (ANALYZE, BUFFERS) " + sql)
            print(f"\n--- {name}")
            for r in plan:
                print("   ", r[0])
    finally:
        await con.close()


def markdown(results: list[dict], args: argparse.Namespace, seed_t: dict[str, float]) -> str:
    lines = [
        f"Dataset: {args.assets:,} assets, {args.findings:,} findings, "
        f"{args.decisions:,} scope decisions, {args.scans:,} scans; "
        f"{args.iterations} timed requests per endpoint after 3 warm-ups; "
        f"ops indexes: {'dropped' if args.without_ops_indexes else 'present'}.",
        "",
        "| Endpoint | p50 (ms) | p95 (ms) | max (ms) |",
        "|---|---:|---:|---:|",
    ]
    for r in results:
        lines.append(f"| {r['label']} | {r['p50']:.1f} | {r['p95']:.1f} | {r['max']:.1f} |")
    lines.append("")
    lines.append("Seeding: " + ", ".join(f"{k} {v:.1f}s" for k, v in seed_t.items()))
    return "\n".join(lines) + "\n"


async def amain(args: argparse.Namespace) -> int:
    from app import migrate

    base = args.admin_dsn.rsplit("/", 1)[0]
    name = f"scale_{uuid.uuid4().hex[:8]}"
    admin = await asyncpg.connect(args.admin_dsn)
    await admin.execute(f'CREATE DATABASE "{name}"')
    await admin.close()
    dsn = f"{base}/{name}"
    print(f"database {name}", flush=True)
    try:
        con = await asyncpg.connect(dsn, command_timeout=None)
        try:
            res = await migrate.migrate_up(con, schema_dir=ROOT / "schema")
            print(f"  migrated {len(res.applied)} files", flush=True)
            if args.without_ops_indexes:
                for ix in OPS_INDEXES:
                    await con.execute(f"DROP INDEX IF EXISTS {ix}")
                print("  dropped schema/022_ops.sql indexes", flush=True)
        finally:
            await con.close()
        seed_t = await seed(dsn, args)
        if args.explain:
            await explain(dsn)
        results = await measure(dsn, args)
        md = markdown(results, args, seed_t)
        print("\n" + md)
        if args.markdown:
            Path(args.markdown).write_text(md)
        slow = [r for r in results if r["p95"] > args.budget_ms]
        if slow:
            print(f"over budget ({args.budget_ms} ms p95): " + ", ".join(r["label"] for r in slow))
            return 1 if args.fail_over_budget else 0
        return 0
    finally:
        if args.keep:
            print(f"kept database {name}")
        else:
            admin = await asyncpg.connect(args.admin_dsn)
            await admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = $1 AND pid <> pg_backend_pid()", name,
            )
            await admin.execute(f'DROP DATABASE "{name}"')
            await admin.close()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--admin-dsn", default=os.environ.get(
        "SCALE_ADMIN_DSN", "postgresql://postgres@127.0.0.1:5432/postgres"))
    p.add_argument("--assets", type=int, default=10_000)
    p.add_argument("--findings", type=int, default=100_000)
    p.add_argument("--decisions", type=int, default=1_000_000)
    p.add_argument("--scans", type=int, default=10_000)
    p.add_argument("--iterations", type=int, default=30)
    p.add_argument("--without-ops-indexes", action="store_true")
    p.add_argument("--explain", action="store_true")
    p.add_argument("--keep", action="store_true")
    p.add_argument("--markdown", default=None)
    p.add_argument("--budget-ms", type=float, default=500.0)
    p.add_argument("--fail-over-budget", action="store_true")
    return asyncio.run(amain(p.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
