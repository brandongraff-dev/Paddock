"""invariant_runs compaction (docs/ASSURANCE_P2_1.md 6.2, D34).

The run ledger carries the full stored result (witnesses, up to 200 blind spots, up to 5000+5000 target refs, up to
5000 passing targets): megabytes per row. After ``assurance_runs_compact_days`` (30) the heavy parts are dropped and the
decision-relevant ones are kept; the DELETE policy (retention.py, WP0) is pinned here end to end as well, because the
property "the newest row of each invariant survives" is only worth something when compaction and purge are tried together.

Rules pinned here:
  * a row is compacted only when it is older than the horizon, not ``pinned`` and not compacted yet;
  * compaction keeps the verdict, the digest, the reasons, the coverage, the first 5 witnesses and the blind-spot summary,
    and drops every target list, the blind spots, the boundaries and the exception detail;
  * it never deletes a row, never touches another tenant, never touches the columns the runner reads (``verdict``,
    ``digest``, ``evaluated_at``: the heartbeat and the "since when" anchor);
  * it is bounded (``batch``) and idempotent; one audit row per tenant per run, only when something was compacted;
  * the scheduler runs it under an advisory lock and not when retention is switched off.
"""
from __future__ import annotations

import datetime as dt
import json
import uuid

import pytest

from app import retention, tenancy
from app.assurance import housekeeping

from .test_isolation_sweep import TENANT_A, TENANT_B

NOW = dt.datetime.now(dt.timezone.utc)


def ago(days: float) -> dt.datetime:
    return NOW - dt.timedelta(days=days)


def heavy_result(n_witnesses: int = 9, n_targets: int = 40) -> dict:
    """The shape ``runner.compact_result`` stores, with every heavy list filled."""
    return {
        "invariant": "acme:x", "digest": "sha256:abc", "severity": "high", "assertion": "unreachable",
        "verdict": "VIOLATED", "reasons": ["violated"], "evaluated_at": "2026-01-01T00:00:00Z",
        "valid_until": "2026-01-02T00:00:00Z", "evidence_tier": "configured",
        "coverage": {"universe": 4, "covered": 3, "ratio": 0.75, "required": 0.5},
        "violation_count": n_witnesses,
        "witnesses": [{"hops": [{"src": "internet", "dst": f"asset:{i}"}], "weakest_basis": "configured", "i": i}
                      for i in range(n_witnesses)],
        "blind_spots": [{"node": f"asset:b{i}", "direction": "in", "reason": "no_sensor", "relevant": True}
                        for i in range(30)],
        "blind_spot_summary": {"total": 30, "stored": 30, "by_reason": {"no_sensor": 30}},
        "violating_targets": [f"asset:v{i}" for i in range(n_targets)],
        "unproven_targets": [f"asset:u{i}" for i in range(n_targets)],
        "passing_targets": [f"asset:p{i}" for i in range(n_targets)],
        "boundaries_reached": ["internet"], "exceptions_used": [{"to": "x", "reason": "because"}],
        "expired_exceptions": [{"to": "y"}], "confirmation": "not_run", "graph_version": 7, "doc_sha": "d0c",
    }


async def seed_run(db_pool, tenant, inv, age_days, *, pinned=False, result=None, verdict="VIOLATED"):
    res = heavy_result() if result is None else result
    return await db_pool.fetchval(
        "INSERT INTO invariant_runs (tenant_id, invariant_id, digest, verdict, reasons, result, graph_version, "
        "violation_count, coverage_covered, coverage_universe, evaluated_at, valid_until, pinned) "
        "VALUES ($1,$2,'sha256:abc',$3,'[\"violated\"]'::jsonb,$4::jsonb,7,9,3,4,$5,$6,$7) RETURNING id",
        uuid.UUID(tenant), inv, verdict, json.dumps(res), ago(age_days), ago(age_days) + dt.timedelta(days=1), pinned)


async def run_row(db_pool, rid):
    r = await db_pool.fetchrow("SELECT * FROM invariant_runs WHERE id = $1", rid)
    d = dict(r)
    d["result"] = json.loads(d["result"]) if isinstance(d["result"], str) else d["result"]
    return d


async def make_tenants(db_pool):
    for slug, tid in (("hk-a", TENANT_A), ("hk-b", TENANT_B)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)


async def compact_in(app_pool, tenant, days=30, batch=1000):
    with tenancy.tenant_context(tenant):
        async with app_pool.acquire() as con:
            return await housekeeping.compact_runs(con, days, batch)


# --------------------------------------------------------------------------- #
# compact_runs: what is kept, what is dropped
# --------------------------------------------------------------------------- #

async def test_an_old_run_keeps_its_decision_and_loses_its_heavy_parts(db_pool, app_pool):
    old = await seed_run(db_pool, tenant=tenancy.DEFAULT_TENANT_ID, inv="acme:x", age_days=45)
    before = await run_row(db_pool, old)
    assert await compact_in(app_pool, tenancy.DEFAULT_TENANT_ID) == 1
    after = await run_row(db_pool, old)

    assert after["compacted_at"] is not None
    res = after["result"]
    for gone in ("violating_targets", "unproven_targets", "passing_targets", "blind_spots", "boundaries_reached",
                 "exceptions_used", "expired_exceptions"):
        assert gone not in res, gone
    for kept in ("invariant", "digest", "assertion", "verdict", "reasons", "evaluated_at", "valid_until",
                 "evidence_tier", "coverage", "violation_count", "graph_version", "doc_sha", "blind_spot_summary"):
        assert res[kept] == before["result"][kept], kept
    assert res["witnesses"] == before["result"]["witnesses"][:5] and len(res["witnesses"]) == 5
    assert res["compacted"] is True
    # the real columns the runner and the API read are untouched
    for col in ("verdict", "digest", "reasons", "graph_version", "violation_count", "coverage_covered",
                "coverage_universe", "evaluated_at", "valid_until", "pinned", "invariant_id"):
        assert after[col] == before[col], col
    assert len(json.dumps(res)) < len(json.dumps(before["result"])) / 3


async def test_a_young_a_pinned_and_an_already_compacted_run_are_not_touched(db_pool, app_pool):
    t = tenancy.DEFAULT_TENANT_ID
    young = await seed_run(db_pool, t, "acme:x", 29.5)
    pinned = await seed_run(db_pool, t, "acme:x", 200, pinned=True)
    old = await seed_run(db_pool, t, "acme:x", 31)
    assert await compact_in(app_pool, t) == 1
    assert (await run_row(db_pool, young))["compacted_at"] is None
    assert (await run_row(db_pool, pinned))["compacted_at"] is None
    assert "violating_targets" in (await run_row(db_pool, pinned))["result"]
    stamp = (await run_row(db_pool, old))["compacted_at"]
    assert stamp is not None
    # idempotent: nothing left to do, and the stamp does not move
    assert await compact_in(app_pool, t) == 0
    assert (await run_row(db_pool, old))["compacted_at"] == stamp


async def test_the_horizon_is_the_argument_not_a_constant(db_pool, app_pool):
    t = tenancy.DEFAULT_TENANT_ID
    r = await seed_run(db_pool, t, "acme:x", 10)
    assert await compact_in(app_pool, t, days=30) == 0
    assert await compact_in(app_pool, t, days=7) == 1
    assert (await run_row(db_pool, r))["compacted_at"] is not None


async def test_compaction_is_bounded_per_call(db_pool, app_pool):
    t = tenancy.DEFAULT_TENANT_ID
    ids = [await seed_run(db_pool, t, "acme:x", 40 + i) for i in range(7)]
    assert [await compact_in(app_pool, t, batch=3) for _ in range(4)] == [3, 3, 1, 0]
    for i in ids:
        assert (await run_row(db_pool, i))["compacted_at"] is not None


async def test_compaction_never_deletes_a_row(db_pool, app_pool):
    t = tenancy.DEFAULT_TENANT_ID
    for i in range(5):
        await seed_run(db_pool, t, "acme:x", 100 + i)
    await compact_in(app_pool, t)
    assert await db_pool.fetchval("SELECT count(*) FROM invariant_runs") == 5


@pytest.mark.parametrize("res", [{}, {"witnesses": None}, {"witnesses": "nope"}, {"witnesses": [], "coverage": None},
                                 {"verdict": "HOLDS", "witnesses": [{"a": 1}]}])
async def test_odd_stored_results_compact_without_error(db_pool, app_pool, res):
    t = tenancy.DEFAULT_TENANT_ID
    r = await seed_run(db_pool, t, "acme:x", 50, result=res)
    assert await compact_in(app_pool, t) == 1
    got = (await run_row(db_pool, r))["result"]
    assert got["compacted"] is True and isinstance(got["witnesses"], list) and len(got["witnesses"]) <= 5
    assert set(got) <= set(housekeeping.RUN_KEEP_KEYS) | {"witnesses", "compacted"}


async def test_a_non_object_result_is_left_alone_but_stamped_so_it_is_not_retried_forever(db_pool, app_pool):
    t = tenancy.DEFAULT_TENANT_ID
    r = await db_pool.fetchval(
        "INSERT INTO invariant_runs (tenant_id, invariant_id, evaluated_at, result) VALUES ($1,'acme:x',$2,'[1,2,3]'::jsonb) "
        "RETURNING id", uuid.UUID(t), ago(60))
    assert await compact_in(app_pool, t) == 1
    assert (await run_row(db_pool, r))["compacted_at"] is not None
    assert await compact_in(app_pool, t) == 0


# --------------------------------------------------------------------------- #
# tenants
# --------------------------------------------------------------------------- #

async def test_compaction_in_one_tenant_never_touches_another(db_pool, app_pool):
    await make_tenants(db_pool)
    a = await seed_run(db_pool, TENANT_A, "acme:x", 60)
    b = await seed_run(db_pool, TENANT_B, "acme:x", 60)
    assert await compact_in(app_pool, TENANT_A) == 1
    assert (await run_row(db_pool, a))["compacted_at"] is not None
    assert (await run_row(db_pool, b))["compacted_at"] is None
    assert "violating_targets" in (await run_row(db_pool, b))["result"]


async def test_run_compaction_visits_every_tenant_and_audits_each_that_changed(db_pool, app_pool):
    await make_tenants(db_pool)
    await seed_run(db_pool, TENANT_A, "acme:x", 60)
    await seed_run(db_pool, TENANT_A, "acme:y", 61)
    await seed_run(db_pool, TENANT_B, "acme:x", 5)               # nothing to do for B
    counts = await housekeeping.run_compaction(app_pool, days=30, batch=1000)
    assert counts == {TENANT_A: 2}
    rows = await db_pool.fetch("SELECT tenant_id, actor, details FROM audit_log WHERE action = 'assurance_runs_compact'")
    assert [str(r["tenant_id"]) for r in rows] == [TENANT_A]
    d = rows[0]["details"]
    d = json.loads(d) if isinstance(d, str) else d
    assert d["compacted"] == 2 and d["days"] == 30
    # a second run changes nothing and writes no audit row
    assert await housekeeping.run_compaction(app_pool, days=30, batch=1000) == {}
    assert await db_pool.fetchval("SELECT count(*) FROM audit_log WHERE action = 'assurance_runs_compact'") == 1


async def test_run_compaction_uses_the_configured_days_and_batches_until_done(db_pool, app_pool, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "assurance_runs_compact_days", 3)
    for i in range(5):
        await seed_run(db_pool, tenancy.DEFAULT_TENANT_ID, "acme:x", 4 + i)
    await seed_run(db_pool, tenancy.DEFAULT_TENANT_ID, "acme:x", 1)
    assert await housekeeping.run_compaction(app_pool, batch=2) == {tenancy.DEFAULT_TENANT_ID: 5}


async def test_run_compaction_returns_none_when_another_replica_holds_the_lock(db_pool, app_pool):
    await seed_run(db_pool, tenancy.DEFAULT_TENANT_ID, "acme:x", 60)
    async with db_pool.acquire() as other:
        assert await other.fetchval("SELECT pg_try_advisory_lock($1)", housekeeping.COMPACT_LOCK_KEY)
        try:
            assert await housekeeping.run_compaction(app_pool, days=30) is None
        finally:
            await other.execute("SELECT pg_advisory_unlock($1)", housekeeping.COMPACT_LOCK_KEY)
    assert (await housekeeping.run_compaction(app_pool, days=30)) == {tenancy.DEFAULT_TENANT_ID: 1}


async def test_a_failing_tenant_does_not_stop_the_others(db_pool, app_pool, monkeypatch):
    await make_tenants(db_pool)
    await seed_run(db_pool, TENANT_A, "acme:x", 60)
    await seed_run(db_pool, TENANT_B, "acme:x", 60)
    real = housekeeping.compact_runs

    async def flaky(con, days, batch, **kw):
        if str(tenancy.current_tenant_id()) == TENANT_A:
            raise RuntimeError("boom")
        return await real(con, days, batch, **kw)

    monkeypatch.setattr(housekeeping, "compact_runs", flaky)
    counts = await housekeeping.run_compaction(app_pool, days=30)
    assert counts == {TENANT_B: 1}


# --------------------------------------------------------------------------- #
# compaction + purge together: "since when" always has an anchor
# --------------------------------------------------------------------------- #

async def test_compact_then_purge_keeps_the_newest_row_of_each_invariant_and_every_pinned_row(db_pool, app_pool):
    await make_tenants(db_pool)
    keep_a = await seed_run(db_pool, TENANT_A, "acme:x", 500)       # the ONLY row of acme:x, ancient
    x_old = [await seed_run(db_pool, TENANT_A, "acme:y", d) for d in (600, 500)]
    y_newest = await seed_run(db_pool, TENANT_A, "acme:y", 400)     # newest of acme:y: older than 365 d, must stay
    pinned = await seed_run(db_pool, TENANT_A, "acme:z", 700, pinned=True)
    z_newest = await seed_run(db_pool, TENANT_A, "acme:z", 10)
    other_tenant = await seed_run(db_pool, TENANT_B, "acme:x", 800)
    await housekeeping.run_compaction(app_pool, days=30)
    await retention.run_retention(app_pool, [retention.Policy(
        "invariant_runs", "evaluated_at", 365,
        where=next(p for p in retention.configured_policies() if p.table == "invariant_runs").where)])
    alive = {r["id"] for r in await db_pool.fetch("SELECT id FROM invariant_runs")}
    assert keep_a in alive and y_newest in alive and pinned in alive and z_newest in alive and other_tenant in alive
    assert not set(x_old) & alive
    # the survivors that were old are compacted (except the pinned one, which is whole)
    assert (await run_row(db_pool, y_newest))["compacted_at"] is not None
    assert (await run_row(db_pool, pinned))["compacted_at"] is None


# --------------------------------------------------------------------------- #
# the scheduler step
# --------------------------------------------------------------------------- #

@pytest.fixture
def fresh_scheduler(monkeypatch):
    from app import scheduler
    monkeypatch.setattr(scheduler, "_compaction_last_run", None)
    return scheduler


async def test_the_scheduler_compacts_once_per_interval(db_pool, app_pool, fresh_scheduler, monkeypatch):
    from app.opsconfig import ops_settings
    monkeypatch.setattr(ops_settings, "retention_enabled", True)
    monkeypatch.setattr(ops_settings, "retention_interval_sec", 3600)
    r = await seed_run(db_pool, tenancy.DEFAULT_TENANT_ID, "acme:x", 60)
    out = await fresh_scheduler.maybe_run_compaction(app_pool, now=1000.0)
    assert out == {tenancy.DEFAULT_TENANT_ID: 1}
    assert (await run_row(db_pool, r))["compacted_at"] is not None
    r2 = await seed_run(db_pool, tenancy.DEFAULT_TENANT_ID, "acme:x", 70)
    assert await fresh_scheduler.maybe_run_compaction(app_pool, now=1010.0) is None       # inside the interval
    assert (await run_row(db_pool, r2))["compacted_at"] is None
    assert await fresh_scheduler.maybe_run_compaction(app_pool, now=1000.0 + 3601) == {tenancy.DEFAULT_TENANT_ID: 1}


async def test_the_scheduler_does_not_compact_when_retention_is_switched_off(db_pool, app_pool, fresh_scheduler,
                                                                            monkeypatch):
    from app.opsconfig import ops_settings
    monkeypatch.setattr(ops_settings, "retention_enabled", False)
    r = await seed_run(db_pool, tenancy.DEFAULT_TENANT_ID, "acme:x", 60)
    assert await fresh_scheduler.maybe_run_compaction(app_pool, now=1.0) is None
    assert (await run_row(db_pool, r))["compacted_at"] is None


async def test_the_scheduler_never_raises_on_a_compaction_failure(app_pool, fresh_scheduler, monkeypatch):
    from app.opsconfig import ops_settings
    monkeypatch.setattr(ops_settings, "retention_enabled", True)

    async def boom(*a, **k):
        raise RuntimeError("down")

    monkeypatch.setattr(housekeeping, "run_compaction", boom)
    assert await fresh_scheduler.maybe_run_compaction(app_pool, now=5.0) is None


def test_the_loop_calls_compaction_next_to_retention():
    import inspect
    from app import scheduler
    src = inspect.getsource(scheduler.scheduler_loop)
    assert src.index("maybe_run_retention") < src.index("maybe_run_compaction")


# --------------------------------------------------------------------------- #
# the API shows what was compacted
# --------------------------------------------------------------------------- #

async def test_the_runs_api_marks_compacted_rows(client, db_pool, app_pool):
    r = await client.post("/v1/invariants", json={"yaml": (
        "apiVersion: paddock.dev/invariant/v1\nid: acme:x\ntitle: Guests cannot reach the POS\nseverity: high\n"
        "subjects:\n  from: { zone: guest }\n  to: { zone: pos }\nassert: unreachable\n")})
    assert r.status_code == 201, r.text
    row_id = r.json()["invariant"]["id"]
    old = await seed_run(db_pool, tenancy.DEFAULT_TENANT_ID, "acme:x", 60)
    fresh = await seed_run(db_pool, tenancy.DEFAULT_TENANT_ID, "acme:x", 1)
    await compact_in(app_pool, tenancy.DEFAULT_TENANT_ID)
    page = (await client.get(f"/v1/invariants/{row_id}/runs?include_result=true")).json()
    by = {x["id"]: x for x in page["items"]}
    assert by[str(old)]["compacted_at"] is not None and by[str(old)]["result"]["compacted"] is True
    assert by[str(fresh)]["compacted_at"] is None and "violating_targets" in by[str(fresh)]["result"]
    assert by[str(old)]["verdict"] == "VIOLATED"
