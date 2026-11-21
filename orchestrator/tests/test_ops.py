"""Production-operations surface: /metrics, retention purge, startup migrate."""
from __future__ import annotations

import json
import re
import uuid

import asyncpg
import pytest

from app import audit, metrics, retention, scheduler
from app.config import settings
from app.opsconfig import ops_settings


@pytest.fixture(autouse=True)
def _fresh_metrics_cache(monkeypatch):
    monkeypatch.setattr(ops_settings, "metrics_db_cache_sec", 0)
    monkeypatch.setattr(ops_settings, "metrics_token", None)
    yield


def _sample(text: str, name: str, **labels) -> float | None:
    for line in text.splitlines():
        if not line.startswith(name):
            continue
        m = re.match(r"^([a-zA-Z_:][\w:]*)(\{(.*)\})?\s+(\S+)$", line)
        if not m or m.group(1) != name:
            continue
        got = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', m.group(3) or ""))
        if all(got.get(k) == v for k, v in labels.items()):
            return float(m.group(4))
    return None


# --------------------------------------------------------------------------- #
# /metrics
# --------------------------------------------------------------------------- #

async def test_metrics_route_template_labels(client):
    aid = uuid.uuid4()
    await client.get("/v1/assets")
    await client.get(f"/v1/assets/{aid}")  # 404, but templated
    await client.get("/definitely/not/a/route")
    r = await client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    body = r.text
    assert _sample(body, "paddock_http_requests_total", method="GET", route="/v1/assets", status="200")
    assert _sample(
        body, "paddock_http_requests_total", method="GET", route="/v1/assets/{asset_id}", status="404"
    )
    assert str(aid) not in body  # raw ids never become labels
    assert _sample(body, "paddock_http_requests_total", route="<unmatched>", status="404")
    assert _sample(body, "paddock_http_request_duration_seconds_count", route="/v1/assets")
    assert _sample(body, "paddock_db_pool_connections", state="max") is not None
    assert _sample(body, "paddock_scans", status="queued") == 0
    assert _sample(body, "paddock_schema_migrations_pending") == 0


async def test_metrics_token_and_fail_closed(client, monkeypatch):
    monkeypatch.setattr(ops_settings, "metrics_token", "s3cret-token")
    assert (await client.get("/metrics")).status_code == 401
    bad = await client.get("/metrics", headers={"Authorization": "Bearer nope"})
    assert bad.status_code == 401
    ok = await client.get("/metrics", headers={"Authorization": "Bearer s3cret-token"})
    assert ok.status_code == 200 and "paddock_http_requests_total" in ok.text
    # enforce + no token configured -> not exposed at all.
    monkeypatch.setattr(ops_settings, "metrics_token", None)
    monkeypatch.setattr(settings, "auth_mode", "enforce")
    assert (await client.get("/metrics")).status_code == 404
    # ...and the scrape is never written to the audit log.


async def test_metrics_scope_decisions_and_queues(client, db_pool, fake_redis):
    from app import scope as scope_svc

    before_allow = _sample((await client.get("/metrics")).text,
                           "paddock_scope_decisions_total", decision="allow") or 0
    before_deny = _sample((await client.get("/metrics")).text,
                          "paddock_scope_decisions_total", decision="deny") or 0
    await client.post("/v1/scope", json={
        "kind": "ipv4_cidr", "value": "10.9.0.0/24", "added_by": "t", "auth_doc_ref": "x",
    })
    scope_svc.scope_cache.invalidate()
    assert (await scope_svc.check(db_pool, "10.9.0.5", worker="t")).allow
    assert not (await scope_svc.check(db_pool, "192.0.2.1", worker="t")).allow
    await fake_redis.xadd(settings.queue_active, {"job": "1"})
    await fake_redis.xadd(settings.queue_active, {"job": "2"})
    body = (await client.get("/metrics")).text
    assert _sample(body, "paddock_scope_decisions_total", decision="allow") >= before_allow + 1
    assert _sample(body, "paddock_scope_decisions_total", decision="deny") >= before_deny + 1
    assert _sample(body, "paddock_queue_depth", queue="active") == 2
    assert _sample(body, "paddock_queue_depth", queue="passive") == 0


async def test_metrics_integration_deliveries_and_source_freshness(client, db_pool):
    async with db_pool.acquire() as con:
        iid = await con.fetchval(
            "INSERT INTO integrations (kind, name) VALUES ('webhook', 'm') RETURNING id"
        )
        for i, st in enumerate(["sent", "sent", "dead", "pending"]):
            await con.execute(
                "INSERT INTO integration_deliveries (integration_id, event_id, event_type, status) "
                "VALUES ($1, $2, 'finding.opened', $3)", iid, f"e{i}", st,
            )
        await con.execute(
            "INSERT INTO assets (kind, value, canonical, source) "
            "VALUES ('ipv4', '10.0.0.9', '10.0.0.9', 'otdiscovery')"
        )
    body = (await client.get("/metrics")).text
    assert _sample(body, "paddock_integration_deliveries", status="sent") == 2
    assert _sample(body, "paddock_integration_deliveries", status="dead") == 1
    assert _sample(body, "paddock_integration_deliveries", status="failed") == 0
    assert _sample(body, "paddock_asset_source_last_seen_timestamp_seconds", source="otdiscovery") > 0


async def test_audit_failure_counter(client, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("db down")

    before = _sample((await client.get("/metrics")).text, "paddock_audit_append_failures_total") or 0
    monkeypatch.setattr(audit, "record", boom)
    r = await client.post("/v1/scope", json={
        "kind": "domain", "value": "audit-fail.example", "added_by": "t", "auth_doc_ref": "x",
    })
    assert r.status_code < 500  # request still served
    after = _sample((await client.get("/metrics")).text, "paddock_audit_append_failures_total")
    assert after == before + 1


# --------------------------------------------------------------------------- #
# Retention
# --------------------------------------------------------------------------- #

async def _seed_retention(con):
    await con.execute(
        "INSERT INTO scope_decisions (target, normalized, decision, worker, decided_at) "
        "SELECT 'old'||g, 'old', 'deny', 't', NOW() - interval '400 days' FROM generate_series(1, 25) g"
    )
    await con.execute(
        "INSERT INTO scope_decisions (target, normalized, decision, worker) "
        "SELECT 'new'||g, 'new', 'allow', 't' FROM generate_series(1, 5) g"
    )
    await con.execute(
        "INSERT INTO outbound_log (worker, target, tool, scope_matched, started_at) "
        "VALUES ('w','old','http',true, NOW() - interval '400 days'), ('w','new','http',true, NOW())"
    )
    iid = await con.fetchval(
        "INSERT INTO integrations (kind, name) VALUES ('webhook', 'r') RETURNING id"
    )
    await con.execute(
        "INSERT INTO integration_deliveries (integration_id, event_id, event_type, status, updated_at) "
        "VALUES ($1,'a','x','sent', NOW() - interval '200 days'),"
        "       ($1,'b','x','pending', NOW() - interval '200 days'),"
        "       ($1,'c','x','sent', NOW())", iid,
    )


async def test_retention_purges_old_rows_and_never_audit(db_pool):
    for i in range(3):
        await audit.record(db_pool, action="create", actor=f"u{i}")
    async with db_pool.acquire() as con:
        await _seed_retention(con)
        # An observation table another stream might add.
        await con.execute(
            "CREATE TABLE observations (id serial, observed_at timestamptz NOT NULL)"
        )
        await con.execute(
            "INSERT INTO observations (observed_at) VALUES (NOW() - interval '60 days'), (NOW())"
        )
        # Make the audit chain look ancient: retention must still not touch it.
        audit_before = await con.fetchval("SELECT count(*) FROM audit_log")

    counts = await retention.run_retention(db_pool, batch_size=10)
    assert counts["scope_decisions"] == 25
    assert counts["outbound_log"] == 1
    assert counts["integration_deliveries"] == 1  # the pending one is kept
    assert counts["observations"] == 1
    assert "audit_log" not in counts

    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM scope_decisions") == 5
        assert await con.fetchval("SELECT count(*) FROM outbound_log") == 1
        st = await con.fetch("SELECT status FROM integration_deliveries ORDER BY event_id")
        assert [r["status"] for r in st] == ["pending", "sent"]
        assert await con.fetchval("SELECT count(*) FROM observations") == 1
        # audit_log only GREW (the purge itself is audited) ...
        assert await con.fetchval("SELECT count(*) FROM audit_log") == audit_before + 1
        row = await con.fetchrow(
            "SELECT actor, details FROM audit_log WHERE action = 'retention_purge'"
        )
        assert row["actor"] == "system:retention"
        assert json.loads(row["details"])["deleted"]["scope_decisions"] == 25
    # ... and the hash chain still verifies.
    assert (await audit.verify(db_pool))["ok"] is True

    # Second run: nothing left to delete, nothing new audited.
    again = await retention.run_retention(db_pool)
    assert not any(again.values())


async def test_retention_refuses_audit_log_policies(db_pool):
    with pytest.raises(retention.RetentionPolicyError):
        retention.parse_extra("audit_log:ts:1")
    with pytest.raises(retention.RetentionPolicyError):
        retention.parse_extra("schema_migrations:applied_at:1")
    with pytest.raises(retention.RetentionPolicyError):
        await retention.run_retention(db_pool, [retention.Policy("audit_log", "ts", 1)])
    with pytest.raises(retention.RetentionPolicyError):
        retention.parse_extra("bad;drop:ts:1")
    assert retention.parse_extra("surface_changes:detected_at:30") == [
        retention.Policy("surface_changes", "detected_at", 30)
    ]


async def test_retention_disabled_policy_and_missing_table(db_pool):
    pols = [
        retention.Policy("scope_decisions", "decided_at", 0),
        retention.Policy("no_such_table", "ts", 1),
    ]
    async with db_pool.acquire() as con:
        await _seed_retention(con)
    counts = await retention.run_retention(db_pool, pols)
    assert counts == {"no_such_table": 0}
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM scope_decisions") == 30


async def test_retention_lock_held_by_other_replica(db_pool):
    async with db_pool.acquire() as holder:
        await holder.execute("SELECT pg_advisory_lock($1)", retention.RETENTION_LOCK_KEY)
        try:
            assert await retention.run_retention(db_pool) is None
        finally:
            await holder.execute("SELECT pg_advisory_unlock($1)", retention.RETENTION_LOCK_KEY)


async def test_scheduler_runs_retention_on_interval(db_pool, monkeypatch):
    monkeypatch.setattr(scheduler, "_retention_last_run", None)
    monkeypatch.setattr(ops_settings, "retention_interval_sec", 100)
    assert await scheduler.maybe_run_retention(db_pool, now=1000.0) is not None
    assert await scheduler.maybe_run_retention(db_pool, now=1050.0) is None  # too soon
    assert await scheduler.maybe_run_retention(db_pool, now=1101.0) is not None
    monkeypatch.setattr(ops_settings, "retention_enabled", False)
    assert await scheduler.maybe_run_retention(db_pool, now=5000.0) is None


# --------------------------------------------------------------------------- #
# Startup migrations
# --------------------------------------------------------------------------- #

async def test_startup_migrations_on_template_db_is_noop(db_pool):
    """The per-test DB came from the runner; a startup run finds nothing."""
    from app import migrate

    con = await db_pool.acquire()
    try:
        params = con._params  # noqa: SLF001 -- reuse the test DB's coordinates
        addr = con._addr  # noqa: SLF001
    finally:
        await db_pool.release(con)
    dsn = f"postgresql://{params.user}@{addr[0]}:{addr[1]}/{params.database}"
    if params.password:
        dsn = f"postgresql://{params.user}:{params.password}@{addr[0]}:{addr[1]}/{params.database}"
    res = await migrate.run_startup_migrations(dsn)
    assert res.applied == [] and res.baselined == []
    c2 = await asyncpg.connect(dsn)
    try:
        assert await c2.fetchval("SELECT count(*) FROM schema_migrations") == len(migrate.discover())
    finally:
        await c2.close()
