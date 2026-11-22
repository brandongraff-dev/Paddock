"""Twin evidence persistence (schema 044): tenant isolation, the rolling
window / row caps, the probe age rule on load, and standing certificates.

Needs ``TEST_DATABASE_URL`` pointing at a NON-superuser role (RLS does not
apply to superusers) and two tenants (created via ``TEST_ADMIN_DATABASE_URL``
when given), exactly like ``test_twin_store_db.py``; skips otherwise.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest
import pytest_asyncio

from app import tenancy
from app.config import _asyncpg_dsn
from app.engine.wargame import evidence as ev, store
from app.engine.wargame.model import Flow, Proto

T1 = "00000000-0000-0000-0000-0000000000e1"
T2 = "00000000-0000-0000-0000-0000000000e2"
_TABLES = ("wargame_observed_flows", "wargame_probe_results", "wargame_segments",
           "wargame_assessments")


@pytest_asyncio.fixture
async def tdb(db):
    try:
        await db.execute("SELECT 1 FROM wargame_probe_results LIMIT 1")
    except Exception as e:
        pytest.skip(f"wargame evidence tables unavailable: {e}")
    row = await db.fetchrow(
        "SELECT rolsuper OR rolbypassrls AS bypass FROM pg_roles WHERE rolname = current_user")
    if row["bypass"]:
        pytest.skip("test role bypasses RLS; use a NOBYPASSRLS role (paddock_svc_correlation)")
    yield db


@pytest_asyncio.fixture
async def two_tenants(tdb):
    admin = os.environ.get("TEST_ADMIN_DATABASE_URL")
    if admin:
        con = await asyncpg.connect(_asyncpg_dsn(admin))
        try:
            for t, slug in ((T1, "wg-ev-e1"), (T2, "wg-ev-e2")):
                await con.execute(
                    "INSERT INTO tenants (id, slug, name) VALUES ($1::uuid, $2, $2) "
                    "ON CONFLICT (id) DO NOTHING", t, slug)
        finally:
            await con.close()
    have = await tdb.fetch("SELECT id::text FROM tenants WHERE id = ANY($1::uuid[])", [T1, T2])
    if len(have) != 2:
        pytest.skip("two test tenants unavailable (set TEST_ADMIN_DATABASE_URL)")

    async def _clean():
        for t in (T1, T2):
            with tenancy.tenant_context(t):
                for tbl in _TABLES:
                    await tdb.execute(f"DELETE FROM {tbl}")
    await _clean()
    yield
    await _clean()


NOW = datetime.now(timezone.utc)


def _row(i: int, age: timedelta = timedelta(hours=1), src="10.9.0.5"):
    f = Flow(src, "10.1.0.9", Proto.TCP, 5432 + i, handshake_completed=True, ts=f"t{i}")
    return ev.flow_to_row(f, observed_at=NOW - age, source="fw")


def _probe(result="blocked", age_h=1.0, src="guest", dst="db", port=5432):
    return ev.ProbeResult(src, dst, "tcp", port, result, NOW - timedelta(hours=age_h), "s1")


async def test_flows_round_trip_window_and_isolation(two_tenants, tdb):
    with tenancy.tenant_context(T1):
        res = await ev.persist_flows(tdb, [_row(0), _row(1, timedelta(days=31))], now=NOW)
        assert res == {"stored": 1, "pruned": 1}
        flows, window = await ev.load_flows(tdb, now=NOW)
        assert flows == [ev.row_to_flow(_row(0))] and window == 1
    with tenancy.tenant_context(T2):
        assert await ev.load_flows(tdb, now=NOW) == ([], 0)
        await ev.persist_flows(tdb, [_row(9, src="10.9.0.99")], now=NOW)
    with tenancy.tenant_context(T1):
        flows, _ = await ev.load_flows(tdb, now=NOW)
        assert [f.src_ip for f in flows] == ["10.9.0.5"]


async def test_flows_old_rows_pruned_on_later_ingest(two_tenants, tdb):
    with tenancy.tenant_context(T1):
        await ev.persist_flows(tdb, [_row(0, timedelta(days=35))], now=NOW - timedelta(days=10))
        assert await tdb.fetchval("SELECT COUNT(*) FROM wargame_observed_flows") == 1
        res = await ev.persist_flows(tdb, [_row(1)], now=NOW)
        assert res["pruned"] == 1
        assert await tdb.fetchval("SELECT COUNT(*) FROM wargame_observed_flows") == 1


async def test_flow_row_cap_keeps_newest(two_tenants, tdb, monkeypatch):
    monkeypatch.setattr(ev, "MAX_FLOWS_PER_TENANT", 3)
    with tenancy.tenant_context(T1):
        rows = [_row(i, timedelta(hours=i + 1)) for i in range(5)]
        await ev.persist_flows(tdb, rows[:2], now=NOW)
        await ev.persist_flows(tdb, rows[2:], now=NOW)
        flows, _ = await ev.load_flows(tdb, now=NOW)
        assert sorted(f.dst_port for f in flows) == [5432, 5433, 5434]


async def test_probes_age_rule_on_load_and_isolation(two_tenants, tdb):
    with tenancy.tenant_context(T1):
        res = await ev.persist_probes(tdb, [
            _probe(), _probe("crossed", age_h=30), _probe("error"),
            _probe(age_h=24 * 40),                     # beyond retention: not kept
        ], now=NOW)
        assert res == {"stored": 3, "pruned": 1}
        loaded = await ev.load_probes(tdb, now=NOW)
        assert [(p.result, p.src, p.dst) for p in loaded] == [("blocked", "guest", "db")]
        assert ev.pair_probes(loaded, now=NOW) == {("guest", "db"): False}
    with tenancy.tenant_context(T2):
        assert await ev.load_probes(tdb, now=NOW) == []


async def test_segment_keys_and_standing_certificates(two_tenants, tdb):
    from tests.wargame.test_store import _bundle
    with tenancy.tenant_context(T1):
        await tdb.execute("INSERT INTO wargame_segments (seg_key) VALUES ('guest'), ('db')")
        assert await ev.segment_keys(tdb) == {"guest", "db"}
        assert await ev.standing_certificates(tdb, now=NOW) == []
        b = _bundle()
        b.assessment["label"] = "twin"
        for c in b.certificates:
            c["expires_at"] = (NOW + timedelta(hours=1)).isoformat()
        await store.persist(tdb, b)
        got = await ev.standing_certificates(tdb, now=NOW)
        assert {c["fingerprint"] for c in got} == {c["fingerprint"] for c in b.certificates}
        assert got  # the fixture bundle carries at least one certificate
        assert await ev.standing_certificates(tdb, now=NOW + timedelta(hours=2)) == []
    with tenancy.tenant_context(T2):
        assert await ev.segment_keys(tdb) == set()
        assert await ev.standing_certificates(tdb, now=NOW) == []


async def test_e2e_against_postgres(two_tenants, tdb, monkeypatch):
    """Real tables end to end: twin -> stored evidence -> _wargame_tenant ->
    persisted verdict. No evidence: proved_config; a stored blocked probe from
    entry to jewel: pass; a stored real crossing flow: fail_open + an
    impossible-traffic alert naming the earlier certificate. Tenant T2's
    evidence never touches T1's verdict."""
    from app import main as main_mod
    from app.engine.wargame import twin_store as ts
    from app.engine.wargame.fabric import EdgeSpec, SegmentSpec
    from app.engine.wargame.model import Action, NodeRole, PortRange, RuleSet

    monkeypatch.setattr(main_mod.service, "db", tdb)
    T = main_mod.IngestProbesRequest
    F = main_mod.IngestFlowsRequest
    pg = PortRange.single(Proto.TCP, 5432)

    async def verdict():
        await main_mod.service._wargame_tenant()
        latest = await store.latest(tdb)
        (b,) = latest["boundaries"]
        return b["verdict"], latest

    async def twin():
        await ts.persist_rulesets(tdb, {"sg-db": RuleSet("sg-db", [], default_action=Action.DENY)},
                                  replace=True)
        await ts.persist_topology(tdb, [
            SegmentSpec("guest", ("10.9.0.0/24",), NodeRole.ENTRY),
            SegmentSpec("db", ("10.1.0.0/24",), NodeRole.CROWN_JEWEL),
        ], [EdgeSpec("guest", "db", "sg-db", pg)])

    probe = {"src": "guest", "dst": "db", "port": 5432, "result": "blocked",
             "observed_at": datetime.now(timezone.utc).isoformat(), "source": "s"}
    with tenancy.tenant_context(T2):
        await twin()
        await main_mod.do_ingest_probes(T.model_validate({"results": [{**probe, "result": "crossed"}]}))
    with tenancy.tenant_context(T1):
        await twin()
        v, first = await verdict()
        assert v == "proved_config"
        (cert,) = first["certificates"]

        await main_mod.do_ingest_probes(T.model_validate({"results": [probe]}))
        v, latest = await verdict()
        assert v == "pass"
        (pass_cert,) = latest["certificates"]
        assert pass_cert["corroboration"]["probe_tested"] is True
        assert cert["fingerprint"] != pass_cert["fingerprint"]

        raw = ('[{"src": "10.9.0.5", "dst": "10.1.0.9", "proto": "tcp", "dport": 5432, '
               '"state": "established"}]')
        out = await main_mod.do_ingest_flows(F.model_validate({"raw": raw, "format": "generic"}))
        assert out["flows_stored"] == 1
        v, latest = await verdict()
        assert v == "fail_open" and latest["certificates"] == []
        md = latest["metadata"]
        assert md["impossible_traffic_alerts"] == 1
        # the probe-backed certificate of the previous run is the one contradicted
        assert md["impossible_traffic_sample"][0]["contradicts_certificate"] == \
            pass_cert["fingerprint"]
