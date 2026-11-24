"""Store + graph loader (docs/ASSURANCE_P1.md section 5).

DB-backed and RLS-realistic: all store calls go through ``app_pool`` (the non-superuser
``paddock_app`` role, tenant stamped on acquire from ``tenancy.tenant_context``). ``db_pool``
(superuser) is only used to seed foreign rows and to tamper with the database underneath.
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import json
import random
import uuid

import pytest

from app import tenancy
from app.assurance import graph_loader, refs, store
from app.assurance.types import BuildOutput, CoverageOut, EdgeOut, NodeOut

TENANT_A = tenancy.DEFAULT_TENANT_ID
TENANT_B = "00000000-0000-0000-0000-0000000000b2"
T0 = dt.datetime(2026, 12, 1, 9, 0, tzinfo=dt.timezone.utc)
H = dt.timedelta(hours=1)


@contextlib.asynccontextmanager
async def conn_for(pool, tid=TENANT_A):
    """A connection stamped with ``tid`` (tenancy is set BEFORE acquire, as in production)."""
    with tenancy.tenant_context(tid):
        async with pool.acquire() as con:
            yield con


@pytest.fixture
async def tenant_b(db_pool):
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo Corp", tenant_id=TENANT_B)
    return TENANT_B


def aid() -> str:
    return refs.asset_ref(uuid.uuid4())


def edge(src, dst, *, lo=5432, hi=None, proto="tcp", basis="configured", source="aws_sg",
         last=T0, **kw) -> EdgeOut:
    return EdgeOut(src_ref=src, dst_ref=dst, proto=proto, port_lo=lo, port_hi=lo if hi is None else hi,
                   basis=basis, source=source, last_seen=last, **kw)


def cov(ref, *, direction="in", tier="configured", source="aws_sg", at=T0) -> CoverageOut:
    return CoverageOut(node_ref=ref, direction=direction, tier=tier, observed_at=at, source=source)


def build(source="aws_sg", *, edges=(), coverage=(), nodes=(), mode="replace", window=None, notes=()):
    return BuildOutput(source=source, mode=mode, nodes=list(nodes), edges=list(edges),
                       coverage=list(coverage), window=window, notes=list(notes))


async def persist(pool, out, now=T0, tid=TENANT_A):
    async with conn_for(pool, tid) as con:
        return await store.persist_build(con, out, now)


async def version(pool, tid=TENANT_A) -> int:
    async with conn_for(pool, tid) as con:
        return (await store.get_state(con)).graph_version


async def edge_rows(pool, tid=TENANT_A, source=None):
    async with conn_for(pool, tid) as con:
        return await con.fetch(
            "SELECT * FROM reach_edges WHERE ($1::text IS NULL OR source = $1) "
            "ORDER BY src_ref, dst_ref, port_lo", source)


DB = aid()
APP = aid()


# --------------------------------------------------------------------------- #
# Change detection and graph_version
# --------------------------------------------------------------------------- #

async def test_first_persist_bumps_then_pure_refresh_does_not(app_pool):
    out1 = build(edges=[edge("internet", DB)], coverage=[cov(DB)],
                 nodes=[NodeOut(DB, "cloud_db"), NodeOut("internet", "internet")])
    r1 = await persist(app_pool, out1, T0)
    assert r1.changed and r1.edges_added == 1 and r1.coverage_changed == 1
    assert r1.graph_version == 1 == await version(app_pool)

    # Later run: only last_seen / observed_at moved forward.
    later = T0 + H
    out2 = build(edges=[edge("internet", DB, last=later)], coverage=[cov(DB, at=later)],
                 nodes=[NodeOut(DB, "cloud_db"), NodeOut("internet", "internet")])
    r2 = await persist(app_pool, out2, later)
    assert not r2.changed and (r2.edges_added, r2.edges_removed, r2.coverage_changed) == (0, 0, 0)
    assert await version(app_pool) == 1               # no bump -> the runner does not re-evaluate

    (row,) = await edge_rows(app_pool)
    assert row["last_seen"] == later and row["first_seen"] == T0   # refreshed, first_seen kept
    async with conn_for(app_pool) as con:
        assert await con.fetchval("SELECT observed_at FROM reach_coverage") == later


@pytest.mark.parametrize("mutate", [
    lambda e: edge("internet", DB, lo=5433),                       # port moved
    lambda e: edge("internet", DB, basis="observed"),              # evidence tier changed
    lambda e: edge("internet", DB, proto="udp"),
    lambda e: edge("internet", APP),                               # target changed
], ids=["port", "basis", "proto", "dst"])
async def test_edge_set_change_bumps(app_pool, mutate):
    await persist(app_pool, build(edges=[edge("internet", DB)]))
    r = await persist(app_pool, build(edges=[mutate(None)]), T0 + H)
    assert r.changed and r.edges_added == 1 and r.edges_removed == 1
    assert await version(app_pool) == 2


async def test_added_edge_and_removed_edge_bump(app_pool):
    await persist(app_pool, build(edges=[edge("internet", DB)]))
    r = await persist(app_pool, build(edges=[edge("internet", DB), edge("internet", APP, lo=22)]), T0 + H)
    assert (r.edges_added, r.edges_removed, r.changed) == (1, 0, True)
    r = await persist(app_pool, build(edges=[edge("internet", DB)]), T0 + 2 * H)
    assert (r.edges_added, r.edges_removed, r.changed) == (0, 1, True)
    assert await version(app_pool) == 3


async def test_coverage_change_bumps_but_refresh_does_not(app_pool):
    await persist(app_pool, build(coverage=[cov(DB, tier="configured")]))
    assert await version(app_pool) == 1
    r = await persist(app_pool, build(coverage=[cov(DB, tier="configured", at=T0 + H)]), T0 + H)
    assert not r.changed
    r = await persist(app_pool, build(coverage=[cov(DB, tier="observed", at=T0 + H)]), T0 + H)
    assert r.changed and r.coverage_changed == 1                  # tier change is a change
    r = await persist(app_pool, build(coverage=[cov(DB, tier="observed", direction="out", at=T0 + H)]), T0 + H)
    assert r.changed and r.coverage_changed == 2                  # in removed, out added
    r = await persist(app_pool, build(coverage=[]), T0 + 2 * H)
    assert r.changed and r.coverage_changed == 1                  # coverage withdrawn
    async with conn_for(app_pool) as con:
        assert await con.fetchval("SELECT count(*) FROM reach_coverage") == 0


async def test_confidence_and_evidence_refresh_is_stored_but_not_a_change(app_pool):
    await persist(app_pool, build(edges=[edge("internet", DB, confidence=60, evidence={"a": 1})]))
    r = await persist(app_pool, build(edges=[edge("internet", DB, confidence=90, evidence={"a": 2})]), T0 + H)
    assert not r.changed
    (row,) = await edge_rows(app_pool)
    assert row["confidence"] == 90 and json.loads(row["evidence"]) == {"a": 2}


async def test_node_kind_is_never_downgraded_so_two_builders_do_not_flap(app_pool):
    await persist(app_pool, build("aws_sg", nodes=[NodeOut(DB, "cloud_db")]))
    v = await version(app_pool)
    r = await persist(app_pool, build("external_exposure", mode="window", window=H,
                                      nodes=[NodeOut(DB, "host")]), T0)
    assert not r.changed and await version(app_pool) == v
    async with conn_for(app_pool) as con:
        assert await con.fetchval("SELECT kind FROM reach_nodes WHERE node_ref = $1", DB) == "cloud_db"
    # ... but a node that genuinely becomes more specific does change the universe.
    ip = refs.ip_ref("10.0.0.5")
    await persist(app_pool, build("sentry_flow", mode="window", window=H, nodes=[NodeOut(ip, "ip")]))
    r = await persist(app_pool, build("sentry_flow", mode="window", window=H, nodes=[NodeOut(ip, "device")]))
    assert r.changed


# --------------------------------------------------------------------------- #
# Replace vs window
# --------------------------------------------------------------------------- #

async def test_replace_deletes_stale_rows_of_that_source_only(app_pool):
    await persist(app_pool, build("aws_sg", edges=[edge("internet", DB, source="aws_sg"),
                                                   edge("internet", APP, source="aws_sg", lo=22)],
                                  coverage=[cov(DB), cov(APP)]))
    await persist(app_pool, build("sentry_flow", mode="window", window=24 * H,
                                  edges=[edge(APP, DB, source="sentry_flow", basis="observed")],
                                  coverage=[cov(DB, source="sentry_flow", direction="out", tier="observed")]))
    # aws_sg now only asserts one edge and no coverage for APP.
    r = await persist(app_pool, build("aws_sg", edges=[edge("internet", DB, source="aws_sg")],
                                      coverage=[cov(DB)]), T0 + H)
    assert r.edges_removed == 1 and r.coverage_changed == 1
    assert [x["dst_ref"] for x in await edge_rows(app_pool, source="aws_sg")] == [DB]
    assert len(await edge_rows(app_pool, source="sentry_flow")) == 1      # untouched
    async with conn_for(app_pool) as con:
        left = await con.fetch("SELECT node_ref, source FROM reach_coverage ORDER BY source, node_ref")
    assert sorted((r_["source"], r_["node_ref"]) for r_ in left) == sorted(
        [("aws_sg", DB), ("sentry_flow", DB)])


async def test_replace_with_empty_output_clears_only_that_source(app_pool):
    await persist(app_pool, build("aws_sg", edges=[edge("internet", DB)]))
    await persist(app_pool, build("external_exposure", mode="window", window=H,
                                  edges=[edge("internet", APP, source="external_scan", basis="observed")
                                         if False else edge("internet", APP, source="external_exposure",
                                                            basis="observed")]))
    r = await persist(app_pool, build("aws_sg"), T0 + H)
    assert r.changed and r.edges_removed == 1
    assert [x["source"] for x in await edge_rows(app_pool)] == ["external_exposure"]


async def test_window_mode_ages_out_unrefreshed_edges(app_pool):
    w = 24 * H
    keep, drop = refs.ip_ref("10.0.0.1"), refs.ip_ref("10.0.0.2")
    await persist(app_pool, build("sentry_flow", mode="window", window=w, edges=[
        edge(keep, DB, source="sentry_flow", basis="observed", lo=443),
        edge(drop, DB, source="sentry_flow", basis="observed", lo=443)]))
    # 20h later: only `keep` is seen again. `drop` is 20h old: still inside the window.
    t1 = T0 + 20 * H
    r = await persist(app_pool, build("sentry_flow", mode="window", window=w, edges=[
        edge(keep, DB, source="sentry_flow", basis="observed", lo=443, last=t1)]), t1)
    assert not r.changed and len(await edge_rows(app_pool)) == 2
    # 30h after the start: `drop` (last seen at T0) is outside the window, `keep` is not.
    t2 = T0 + 30 * H
    r = await persist(app_pool, build("sentry_flow", mode="window", window=w, edges=[]), t2)
    assert r.changed and r.edges_removed == 1
    assert [x["src_ref"] for x in await edge_rows(app_pool)] == [keep]


async def test_window_mode_does_not_resurrect_expired_observations(app_pool):
    w = 24 * H
    old = edge(refs.ip_ref("10.0.0.9"), DB, source="sentry_flow", basis="observed", last=T0 - 48 * H)
    r = await persist(app_pool, build("sentry_flow", mode="window", window=w, edges=[old]), T0)
    assert not r.changed and r.skipped == 0 and await edge_rows(app_pool) == []
    assert any("older than the window" in n for n in r.notes)


async def test_future_last_seen_is_clamped_so_a_bad_clock_cannot_keep_an_edge_alive(app_pool):
    e = edge(refs.ip_ref("10.0.0.9"), DB, source="sentry_flow", basis="observed", last=T0 + 30 * 24 * H)
    await persist(app_pool, build("sentry_flow", mode="window", window=H, edges=[e]), T0)
    (row,) = await edge_rows(app_pool)
    assert row["last_seen"] == T0
    r = await persist(app_pool, build("sentry_flow", mode="window", window=H), T0 + 2 * H)
    assert r.edges_removed == 1


async def test_window_mode_requires_a_window(app_pool):
    with pytest.raises(ValueError):
        await persist(app_pool, build("sentry_flow", mode="window", window=None))
    with pytest.raises(ValueError):
        await persist(app_pool, build("sentry_flow", mode="window", window=dt.timedelta(0)))
    with pytest.raises(ValueError):
        await persist(app_pool, build("", mode="replace"))
    assert await version(app_pool) == 0


# --------------------------------------------------------------------------- #
# Nodes
# --------------------------------------------------------------------------- #

async def test_unreferenced_stale_nodes_are_pruned_after_a_grace_period(app_pool):
    gone, kept = aid(), aid()
    await persist(app_pool, build(nodes=[NodeOut(gone, "cloud_instance"), NodeOut(kept, "cloud_instance")]))
    # Not emitted any more, but inside the grace period (another builder may still emit it).
    r = await persist(app_pool, build(nodes=[NodeOut(kept, "cloud_instance")]), T0 + store.NODE_GRACE / 2)
    assert r.nodes_removed == 0
    r = await persist(app_pool, build(nodes=[NodeOut(kept, "cloud_instance")]), T0 + 2 * H)
    assert r.nodes_removed == 1 and r.changed
    async with conn_for(app_pool) as con:
        assert [x["node_ref"] for x in await con.fetch("SELECT node_ref FROM reach_nodes")] == [kept]


async def test_node_referenced_by_an_edge_or_coverage_is_not_pruned(app_pool):
    n1, n2 = aid(), aid()
    await persist(app_pool, build(nodes=[NodeOut(n1, "cloud_instance"), NodeOut(n2, "cloud_instance")],
                                  edges=[edge("internet", n1)], coverage=[cov(n2)]))
    r = await persist(app_pool, build(nodes=[], edges=[edge("internet", n1)], coverage=[cov(n2)]), T0 + 5 * H)
    assert r.nodes_removed == 0


# --------------------------------------------------------------------------- #
# Bad rows
# --------------------------------------------------------------------------- #

async def test_bad_rows_are_skipped_and_counted_never_raised(app_pool):
    good = edge("internet", DB)
    naive = dt.datetime(2026, 12, 1, 9, 0)
    bad = [
        edge("not-a-ref", DB),
        edge("internet", "asset:not-a-uuid"),
        edge("ip:010.1.1.1", DB),                                   # non-canonical
        edge("internet", DB, lo=0, hi=10),                          # tcp port 0
        edge("internet", DB, lo=100, hi=10),
        edge("internet", DB, lo=1, hi=70000),
        edge("internet", DB, proto="sctp"),                         # type: ignore[arg-type]
        edge("internet", DB, basis="guessed"),                      # type: ignore[arg-type]
        edge("internet", DB, source="someone_else"),                # foreign source
        edge("internet", DB, last=naive),
        edge("internet", DB, lo=True),                              # type: ignore[arg-type]
    ]
    bad_cov = [
        cov("nonsense"),
        cov(DB, direction="both"),                                  # type: ignore[arg-type]
        cov(DB, tier="vibes"),                                      # type: ignore[arg-type]
        cov(DB, source="someone_else"),
        cov("internet"),                                            # the internet is never covered
        cov(DB, at=naive),
    ]
    bad_nodes = [NodeOut("zzz", "host"), NodeOut(DB, "spaceship"), NodeOut("internet", "host"),
                 NodeOut(DB, "host", asset_id="nope")]
    r = await persist(app_pool, build(edges=[*bad, good], coverage=[*bad_cov, cov(APP)],
                                      nodes=[*bad_nodes, NodeOut(DB, "cloud_db")]))
    assert r.skipped == len(bad) + len(bad_cov) + len(bad_nodes)
    assert r.edges_added == 1 and r.coverage_changed == 1 and r.nodes_upserted == 1
    assert len(r.notes) >= r.skipped
    assert [x["dst_ref"] for x in await edge_rows(app_pool)] == [DB]


async def test_icmp_ports_may_be_zero_but_tcp_ports_may_not(app_pool):
    r = await persist(app_pool, build(edges=[edge("internet", DB, proto="icmp", lo=0, hi=0),
                                             edge("internet", DB, proto="tcp", lo=0, hi=0)]))
    assert r.edges_added == 1 and r.skipped == 1


async def test_oversized_evidence_keeps_the_edge_and_drops_the_detail(app_pool):
    r = await persist(app_pool, build(edges=[edge("internet", DB, evidence={"blob": "x" * 100_000})]))
    assert r.skipped == 0 and r.edges_added == 1                  # dropping the edge would under-approximate
    (row,) = await edge_rows(app_pool)
    assert json.loads(row["evidence"])["truncated"] is True


async def test_duplicate_keys_in_one_build_merge_to_the_stronger_edge_and_weaker_coverage(app_pool):
    r = await persist(app_pool, build(
        edges=[edge("internet", DB, basis="configured"), edge("internet", DB, basis="observed")],
        coverage=[cov(DB, tier="observed", at=T0), cov(DB, tier="configured", at=T0 - H)]))
    assert r.edges_added == 1
    (row,) = await edge_rows(app_pool)
    assert row["basis"] == "observed"
    async with conn_for(app_pool) as con:
        c = await con.fetchrow("SELECT tier, observed_at FROM reach_coverage")
    assert (c["tier"], c["observed_at"]) == ("configured", T0 - H)


# --------------------------------------------------------------------------- #
# Tenant isolation
# --------------------------------------------------------------------------- #

async def test_tenants_cannot_see_or_affect_each_other(app_pool, tenant_b):
    out = build(edges=[edge("internet", DB)], coverage=[cov(DB)], nodes=[NodeOut(DB, "cloud_db")])
    await persist(app_pool, out, T0, TENANT_A)
    assert await version(app_pool, TENANT_A) == 1 and await version(app_pool, TENANT_B) == 0
    async with conn_for(app_pool, TENANT_A) as con:
        await store.set_label(con, DB, "app-tier", "web", set_by="alice", justification="front door")
        await store.upsert_zone(con, "prod", ["10.0.0.0/8"], set_by="alice", justification="prod nets")
    va = await version(app_pool, TENANT_A)

    # B sees nothing of A, in any table the store owns.
    async with conn_for(app_pool, TENANT_B) as con:
        for t in ("reach_nodes", "reach_edges", "reach_coverage", "asset_labels", "zones", "assurance_state"):
            assert await con.fetchval(f"SELECT count(*) FROM {t}") == 0, t
        doc = await graph_loader.load_graph_doc(con, T0)
    assert [n["id"] for n in doc["nodes"]] == ["internet"] and doc["edges"] == []

    # B builds the SAME keys: independent rows, independent version, A untouched.
    rb = await persist(app_pool, out, T0, TENANT_B)
    assert rb.changed and rb.graph_version == 1
    # B's replace-with-nothing removes B's rows only.
    await persist(app_pool, build("aws_sg"), T0 + H, TENANT_B)
    assert await edge_rows(app_pool, TENANT_B) == []
    assert len(await edge_rows(app_pool, TENANT_A)) == 1
    assert await version(app_pool, TENANT_A) == va

    # B cannot delete A's label/zone (invisible), and a no-op does not bump anything.
    async with conn_for(app_pool, TENANT_B) as con:
        ch = await store.delete_label(con, DB, "app-tier", set_by="bob", justification="try")
        assert not ch.changed
        assert await store.delete_zone(con, "prod", set_by="bob", justification="try") is None
    assert await version(app_pool, TENANT_A) == va
    async with conn_for(app_pool, TENANT_A) as con:
        assert [x["tag"] for x in await store.list_labels(con)] == ["app-tier"]
        assert [z.name for z in await store.list_zones(con)] == ["prod"]


async def test_leases_are_per_tenant(app_pool, tenant_b):
    now = T0
    async with conn_for(app_pool, TENANT_A) as a, conn_for(app_pool, TENANT_B) as b:
        assert await store.claim_eval(a, "pod-1", now) is not None
        assert await store.claim_eval(b, "pod-2", now) is not None     # not blocked by A's lease
        assert await store.claim_eval(a, "pod-2", now) is None


# --------------------------------------------------------------------------- #
# Lease
# --------------------------------------------------------------------------- #

async def test_concurrent_claimers_get_exactly_one_winner(app_pool):
    async def claim(i):
        async with conn_for(app_pool) as con:
            return await store.claim_eval(con, f"pod-{i}", T0, 300)

    # With no assurance_state row yet (insert race) ...
    results = await asyncio.gather(*(claim(i) for i in range(4)))
    assert sum(r is not None for r in results) == 1
    # ... and again after the lease is released and the row exists (update race).
    winner = next(i for i, r in enumerate(results) if r is not None)
    async with conn_for(app_pool) as con:
        assert await store.release_eval(con, f"pod-{winner}", T0, evaluated_version=0)
    results = await asyncio.gather(*(claim(i) for i in range(4)))
    assert sum(r is not None for r in results) == 1


async def test_lease_expiry_release_and_watermark(app_pool):
    async with conn_for(app_pool) as con:
        await store.bump_graph_version(con)
        st = await store.claim_eval(con, "pod-1", T0, 60)
        assert st is not None and st.graph_version == 1 and st.last_eval_version == -1
        assert await store.claim_eval(con, "pod-2", T0 + dt.timedelta(seconds=30)) is None
        assert await store.extend_eval(con, "pod-1", T0 + dt.timedelta(seconds=30), 600)
        assert await store.claim_eval(con, "pod-2", T0 + dt.timedelta(seconds=300)) is None  # extended
        # expiry: pod-2 may take over, and pod-1's late release must not clobber it.
        assert await store.claim_eval(con, "pod-2", T0 + dt.timedelta(seconds=700)) is not None
        assert not await store.release_eval(con, "pod-1", T0, evaluated_version=1)
        assert (await store.get_state(con)).lease_owner == "pod-2"
        assert not await store.extend_eval(con, "pod-1", T0 + dt.timedelta(seconds=701))
        # a failed run releases without moving the watermark ...
        assert await store.release_eval(con, "pod-2", T0)
        s = await store.get_state(con)
        assert s.lease_owner is None and s.last_eval_version == -1 and s.last_eval_at is None
        # ... a successful one records it.
        await store.claim_eval(con, "pod-3", T0 + 800 * dt.timedelta(seconds=1))
        assert await store.release_eval(con, "pod-3", T0 + H, evaluated_version=1)
        s = await store.get_state(con)
        assert (s.last_eval_version, s.last_eval_at, s.lease_until) == (1, T0 + H, None)


async def test_get_state_of_a_new_tenant_does_not_write(app_pool):
    async with conn_for(app_pool) as con:
        s = await store.get_state(con)
        assert (s.graph_version, s.last_eval_version, s.lease_owner) == (0, -1, None)
        assert await con.fetchval("SELECT count(*) FROM assurance_state") == 0
        await store.touch_build(con, T0)
        assert (await store.get_state(con)).last_build_at == T0


async def test_concurrent_persists_of_one_source_serialise(app_pool):
    outs = [build(edges=[edge("internet", DB, lo=1000 + i)]) for i in range(4)]
    reports = await asyncio.gather(*(persist(app_pool, o, T0 + i * H) for i, o in enumerate(outs)))
    assert all(isinstance(r, store.BuildReport) for r in reports)
    # Whatever the interleaving, the source ends with exactly ONE edge (replace semantics held
    # under the advisory lock) and every bump was counted.
    assert len(await edge_rows(app_pool, source="aws_sg")) == 1
    assert await version(app_pool) == sum(r.changed for r in reports)


# --------------------------------------------------------------------------- #
# Labels and zones (store helpers)
# --------------------------------------------------------------------------- #

async def test_label_changes_bump_the_version_and_keep_provenance(app_pool):
    async with conn_for(app_pool) as con:
        c1 = await store.set_label(con, DB, "zone", "prod", set_by="alice", justification="per CMDB", now=T0)
        assert c1.changed and c1.previous is None and c1.graph_version == 1
        same = await store.set_label(con, DB, "zone", "prod", set_by="bob", justification="re-checked", now=T0 + H)
        assert not same.changed and same.graph_version is None
        moved = await store.set_label(con, DB, "zone", "guest", set_by="bob", justification="moved", now=T0 + H)
        assert moved.changed and moved.previous == "prod" and moved.graph_version == 2
        row = (await store.list_labels(con, DB))[0]
        assert (row["set_by"], row["justification"], row["set_at"], row["source"]) == (
            "bob", "moved", T0 + H, "declared")
        gone = await store.delete_label(con, DB, "zone", set_by="bob", justification="cleanup")
        assert gone.changed and gone.previous == "guest" and gone.graph_version == 3
        again = await store.delete_label(con, DB, "zone", set_by="bob", justification="cleanup")
        assert not again.changed and (await store.get_state(con)).graph_version == 3


@pytest.mark.parametrize("args", [
    dict(node_ref="internet", tag="zone", value="prod"),
    dict(node_ref="bogus", tag="zone", value="prod"),
    dict(node_ref=DB, tag="Zone", value="prod"),
    dict(node_ref=DB, tag="zone", value="Not A Zone"),
    dict(node_ref=DB, tag="zone", value="internet"),
    dict(node_ref=DB, tag="kind", value="spaceship"),
    dict(node_ref=DB, tag="class", value="x" * 500),
])
async def test_invalid_labels_are_rejected_without_a_bump(app_pool, args):
    async with conn_for(app_pool) as con:
        with pytest.raises(ValueError):
            await store.set_label(con, set_by="a", justification="why", **args)
        assert (await store.get_state(con)).graph_version == 0


async def test_labels_and_zones_require_who_and_why(app_pool):
    async with conn_for(app_pool) as con:
        with pytest.raises(ValueError):
            await store.set_label(con, DB, "app-tier", "web", set_by="a", justification="  ")
        with pytest.raises(ValueError):
            await store.set_label(con, DB, "app-tier", "web", set_by="", justification="because")
        with pytest.raises(ValueError):
            await store.upsert_zone(con, "guest", ["10.9.0.0/16"], set_by="a", justification="")
        with pytest.raises(ValueError):
            await store.delete_zone(con, "guest", set_by="a", justification="")
        assert await store.list_labels(con) == [] and await store.list_zones(con) == []


def test_zone_cidr_validation_and_membership():
    assert store.validate_zone_cidrs(["10.0.0.5/24", "10.0.0.0/24", "2001:DB8::/32"]) == (
        "10.0.0.0/24", "2001:db8::/32")
    for bad in (["10.0.0.1"], ["0.0.0.0/0"], ["::/0"], ["nope/8"], [], [""], ["10.0.0.0/33"]):
        with pytest.raises(ValueError):
            store.validate_zone_cidrs(bad)
    for bad in ("Guest", "9guest", "internet", "", "a" * 33):
        with pytest.raises(ValueError):
            store.validate_zone_name(bad)
    zones = [store.Zone("1", "corp", "custom", ("10.0.0.0/8",)),
             store.Zone("2", "guest", "custom", ("10.1.0.0/16", "192.168.5.0/24"))]
    assert store.zone_matches(zones, "10.1.2.3") == [("guest", 16), ("corp", 8)]   # most specific first
    assert store.zone_matches(zones, "10.1.0.0/20") == [("guest", 16), ("corp", 8)]
    assert store.zone_matches(zones, "10.0.0.0/7") == []            # bigger than the zone is not inside it
    assert store.zone_matches(zones, "2001:db8::1") == []           # v6 vs v4 never matches
    assert store.zone_matches(zones, "garbage") == []
    assert store.resolve_zone(zones, ["10.1.2.3"]) == ("guest", [])
    assert store.resolve_zone(zones, ["10.2.2.3", "192.168.5.9"]) == ("guest", ["corp", "guest"])  # conflict: most specific wins
    assert store.resolve_zone(zones, []) == (None, [])


async def test_zone_upsert_and_delete_bump_only_on_real_change(app_pool):
    async with conn_for(app_pool) as con:
        z = await store.upsert_zone(con, "corp", ["10.0.0.0/8"], set_by="a", justification="lan")
        assert z.created and z.changed and z.graph_version == 1 and z.overlaps == ()
        z = await store.upsert_zone(con, "corp", ["10.0.0.0/8"], description="d", set_by="a", justification="x")
        assert not z.changed and z.graph_version is None            # description only
        z = await store.upsert_zone(con, "guest", ["10.1.0.0/16"], kind="guest", set_by="a", justification="g")
        assert z.created and z.overlaps == ("corp",) and z.graph_version == 2
        z = await store.upsert_zone(con, "guest", ["10.1.0.0/16", "10.7.0.0/16"], set_by="a", justification="g2")
        assert z.changed and not z.created and z.graph_version == 3
        assert await store.delete_zone(con, "guest", set_by="a", justification="gone") == 4
        assert await store.delete_zone(con, "guest", set_by="a", justification="gone") is None
        assert [x.name for x in await store.list_zones(con)] == ["corp"]


async def test_prune_flow_obs(app_pool, db_pool):
    async with db_pool.acquire() as su:
        for i, days in enumerate((1, 5, 10)):
            await su.execute(
                "INSERT INTO reach_flow_obs (src_ip, dst_ip, dst_port, last_seen, first_seen) "
                "VALUES ('10.0.0.1', $1, 443, $2, $2)", f"10.0.0.{i + 2}", T0 - dt.timedelta(days=days))
    async with conn_for(app_pool) as con:
        assert await store.prune_flow_obs(con, T0 - dt.timedelta(days=3)) == 2
        assert await con.fetchval("SELECT count(*) FROM reach_flow_obs") == 1
        assert await store.prune_flow_obs(con, T0 - dt.timedelta(days=3)) == 0
        with pytest.raises(ValueError):
            await store.prune_flow_obs(con, dt.datetime(2026, 1, 1))


# --------------------------------------------------------------------------- #
# Graph document
# --------------------------------------------------------------------------- #

async def _seed_asset(db_pool, kind, value, md) -> str:
    async with db_pool.acquire() as su:
        return str(await su.fetchval(
            "INSERT INTO assets (kind, value, canonical, source, metadata) "
            "VALUES ($1, $2, $2, 'test', $3::jsonb) RETURNING id", kind, value, json.dumps(md)))


async def _estate(app_pool, db_pool):
    """A small estate: internet -> LB -> app -> db, a guest laptop, a POS terminal."""
    ids = {k: await _seed_asset(db_pool, "cloud_resource", f"arn:{k}", md) for k, md in {
        "lb": {}, "app": {}, "db": {"crown_jewel": True, "private_ips": ["10.0.5.5"]},
        "laptop": {"ips": ["10.20.0.7"]}, "pos": {"ip": "10.30.0.4"}}.items()}
    ref = {k: refs.asset_ref(v) for k, v in ids.items()}
    out = build("aws_sg", nodes=[
        NodeOut(ref["lb"], "cloud_lb"), NodeOut(ref["app"], "cloud_instance"),
        NodeOut(ref["db"], "cloud_db", asset_id=ids["db"]), NodeOut(ref["laptop"], "device"),
        NodeOut(ref["pos"], "device", attrs={"ips": ["10.30.0.4"]}), NodeOut("internet", "internet")],
        edges=[edge("internet", ref["lb"], lo=443), edge(ref["lb"], ref["app"], lo=8080),
               edge(ref["app"], ref["db"], lo=5432), edge(ref["laptop"], ref["pos"], lo=1, hi=1024),
               edge(ref["laptop"], ref["pos"], proto="icmp", lo=0, hi=0),
               edge(refs.cidr_ref("10.20.0.0/24"), ref["pos"], proto="any", lo=1, hi=65535)],
        coverage=[cov(ref["db"]), cov(ref["lb"], direction="out", tier="observed", source="aws_sg")])
    await persist(app_pool, out)
    return ref


async def test_load_graph_doc_shape_zones_labels_and_coverage(app_pool, db_pool):
    ref = await _estate(app_pool, db_pool)
    async with conn_for(app_pool) as con:
        await store.upsert_zone(con, "guest", ["10.20.0.0/16"], set_by="a", justification="wifi")
        await store.upsert_zone(con, "pos", ["10.30.0.0/16"], set_by="a", justification="tills")
        await store.upsert_zone(con, "prod", ["10.0.0.0/16"], set_by="a", justification="dc")
        await store.set_label(con, ref["app"], "app-tier", "", set_by="a", justification="boundary")
        await store.set_label(con, ref["app"], "zone", "prod", set_by="a", justification="declared")
        await store.set_label(con, ref["pos"], "zone", "guest", set_by="a", justification="mislabelled on purpose")
        doc = await graph_loader.load_graph_doc(con, T0)
    n = {x["id"]: x for x in doc["nodes"]}

    assert doc["version"] == 1 and doc["now"] == "2026-12-01T09:00:00+00:00"
    # nodes = reach_nodes + edge endpoints (the cidr) + internet
    assert set(n) == {"internet", refs.cidr_ref("10.20.0.0/24"), *ref.values()}
    assert n["internet"]["zone"] == "internet" and "coverage" not in n["internet"]
    assert n[ref["db"]]["tags"] == ["crown-jewel"] and n[ref["db"]]["class"] == "data_store"   # metadata defaults
    assert n[ref["db"]]["zone"] == "prod"                       # from metadata private_ips via CIDR
    assert n[ref["laptop"]]["zone"] == "guest"                  # from metadata 'ips'
    assert n[ref["pos"]]["zone"] == "guest"                     # declared label beats the pos CIDR
    assert n[ref["app"]]["tags"] == ["app-tier"] and n[ref["app"]]["zone"] == "prod"
    assert "zone" not in n[ref["lb"]]                           # no label, no ips, no CIDR: none
    assert n[refs.cidr_ref("10.20.0.0/24")]["kind"] == "cidr" and n[refs.cidr_ref("10.20.0.0/24")]["zone"] == "guest"
    assert n[ref["db"]]["coverage"] == [
        {"direction": "in", "tier": "configured", "observed_at": "2026-12-01T09:00:00+00:00", "source": "aws_sg"}]
    assert n[ref["lb"]]["coverage"][0]["direction"] == "out"

    by = {(e["src"], e["dst"], e["proto"]): e for e in doc["edges"]}
    assert by[("internet", ref["lb"], "tcp")]["ports"] == "443-443"
    assert by[(ref["laptop"], ref["pos"], "tcp")]["ports"] == "1-1024"
    assert "ports" not in by[(ref["laptop"], ref["pos"], "icmp")]
    assert by[(refs.cidr_ref("10.20.0.0/24"), ref["pos"], "any")]["ports"] == "1-65535"
    assert all(set(e) == {"src", "dst", "proto", "ports", "basis", "source"} or e["proto"] == "icmp"
               for e in doc["edges"])


async def test_declared_labels_override_metadata_defaults(app_pool, db_pool):
    ref = await _estate(app_pool, db_pool)
    async with conn_for(app_pool) as con:
        await store.set_label(con, ref["db"], "crown-jewel", "false", set_by="a", justification="decommissioned")
        await store.set_label(con, ref["db"], "class", "cache", set_by="a", justification="really a cache")
        await store.set_label(con, ref["app"], "kind", "cloud_db", set_by="a", justification="runs the DB")
        doc = await graph_loader.load_graph_doc(con, T0)
    n = {x["id"]: x for x in doc["nodes"]}
    assert n[ref["db"]]["tags"] == [] and n[ref["db"]]["class"] == "cache"
    assert n[ref["app"]]["kind"] == "cloud_db"
    # the metadata-derived default for the OTHER direction: undeclared => defaults stay
    assert n[ref["lb"]]["tags"] == [] and "class" not in n[ref["lb"]]


async def test_zone_resolution_order_label_then_cidr_then_none(app_pool):
    ip_a, ip_b, ip_c = refs.ip_ref("10.50.0.1"), refs.ip_ref("10.50.0.2"), refs.ip_ref("172.31.0.1")
    await persist(app_pool, build(nodes=[NodeOut(ip_a, "ip"), NodeOut(ip_b, "ip"), NodeOut(ip_c, "ip")]))
    async with conn_for(app_pool) as con:
        await store.upsert_zone(con, "corp", ["10.0.0.0/8"], set_by="a", justification="lan")
        await store.upsert_zone(con, "iot", ["10.50.0.0/24"], set_by="a", justification="cameras")
        await store.set_label(con, ip_b, "zone", "dmz", set_by="a", justification="pinned")
        doc, diag = await graph_loader.load_graph_doc_with_diagnostics(con, T0)
    z = {x["id"]: x.get("zone") for x in doc["nodes"]}
    assert z[ip_a] == "iot"            # most specific CIDR
    assert z[ip_b] == "dmz"            # declared label beats CIDR
    assert z[ip_c] is None             # nothing says
    assert z["internet"] == "internet"
    assert diag.graph_version >= 1 and diag.zone_conflicts == {}


async def test_multihomed_node_in_two_zones_is_reported(app_pool, db_pool):
    a = await _seed_asset(db_pool, "cloud_resource", "arn:bridge", {"private_ips": ["10.1.0.5", "10.2.0.5"]})
    ref = refs.asset_ref(a)
    await persist(app_pool, build(nodes=[NodeOut(ref, "cloud_instance", asset_id=a)]))
    async with conn_for(app_pool) as con:
        await store.upsert_zone(con, "guest", ["10.1.0.0/16"], set_by="a", justification="g")
        await store.upsert_zone(con, "pos", ["10.2.0.0/16"], set_by="a", justification="p")
        doc, diag = await graph_loader.load_graph_doc_with_diagnostics(con, T0)
    assert diag.zone_conflicts == {ref: ["guest", "pos"]}
    assert {x["id"]: x.get("zone") for x in doc["nodes"]}[ref] == "guest"     # deterministic, not random


async def test_edge_port_zero_is_widened_never_narrowed(app_pool, db_pool):
    """Rows another writer put in the table that the library could not parse must not vanish."""
    async with db_pool.acquire() as su:
        await su.execute(
            "INSERT INTO reach_edges (src_ref, dst_ref, proto, port_lo, port_hi, source) VALUES "
            "('ip:10.0.0.1', 'ip:10.0.0.2', 'tcp', 0, 0, 'x'), ('ip:10.0.0.1', 'ip:10.0.0.3', 'udp', 0, 53, 'x')")
    async with conn_for(app_pool) as con:
        doc = await graph_loader.load_graph_doc(con, T0)
    ports = {e["dst"]: e["ports"] for e in doc["edges"]}
    assert ports == {"ip:10.0.0.2": "1-65535", "ip:10.0.0.3": "1-53"}


async def test_internet_never_gets_coverage_even_if_a_row_is_forced_in(app_pool, db_pool):
    async with db_pool.acquire() as su:
        await su.execute("INSERT INTO reach_coverage (node_ref, direction, source, tier) "
                         "VALUES ('internet', 'out', 'x', 'tested')")
    async with conn_for(app_pool) as con:
        doc = await graph_loader.load_graph_doc(con, T0)
    (inet,) = [n for n in doc["nodes"] if n["id"] == "internet"]
    assert "coverage" not in inet


async def test_load_graph_doc_is_deterministic_regardless_of_insert_order(app_pool, db_pool):
    ref = await _estate(app_pool, db_pool)
    async with conn_for(app_pool) as con:
        first = await graph_loader.load_graph_doc(con, T0)
    # Rebuild a second tenant's identical graph with every list shuffled.
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo Corp", tenant_id=TENANT_B)
    async with conn_for(app_pool) as con:
        edges_a = await con.fetch("SELECT * FROM reach_edges")
        nodes_a = await con.fetch("SELECT * FROM reach_nodes")
        cov_a = await con.fetch("SELECT * FROM reach_coverage")
    rnd = random.Random(7)
    ed = [edge(r["src_ref"], r["dst_ref"], lo=r["port_lo"], hi=r["port_hi"], proto=r["proto"], basis=r["basis"])
          for r in edges_a]
    nd = [NodeOut(r["node_ref"], r["kind"], asset_id=str(r["asset_id"]) if r["asset_id"] else None,
                  attrs=json.loads(r["attrs"])) for r in nodes_a]
    cv = [cov(r["node_ref"], direction=r["direction"], tier=r["tier"], at=r["observed_at"]) for r in cov_a]
    for lst in (ed, nd, cv):
        rnd.shuffle(lst)
    await persist(app_pool, build(edges=ed, nodes=nd, coverage=cv), T0, TENANT_B)
    async with conn_for(app_pool, TENANT_B) as con:
        second = await graph_loader.load_graph_doc(con, T0)
    # same estate => same document (assets table is shared across tenants only by the superuser seed;
    # metadata defaults need the asset rows, which B cannot see, so compare the structural parts).
    strip = lambda d: {  # noqa: E731
        "edges": d["edges"],
        "nodes": [{k: v for k, v in n.items() if k in ("id", "kind", "coverage")} for n in d["nodes"]]}
    assert strip(first) == strip(second)
    # and repeated loads are byte-identical
    async with conn_for(app_pool) as con:
        again = await graph_loader.load_graph_doc(con, T0)
    assert json.dumps(first, sort_keys=False) == json.dumps(again, sort_keys=False)
    ids = [n["id"] for n in first["nodes"]]
    assert ids == sorted(ids)
    keys = [(e["src"], e["dst"], e["proto"], e.get("ports", "")) for e in first["edges"]]
    assert keys == sorted(keys)
    assert ref  # estate seeded


def _lib_supports_directional_coverage() -> bool:
    try:
        from paddock_assurance.graph import ReachGraph
        g = ReachGraph.from_dict({"version": 1, "nodes": [{"id": "a", "coverage": [
            {"direction": "in", "tier": "configured", "observed_at": "2026-12-01T09:00:00+00:00"}]}]})
        return g.nodes["a"].coverage is not None
    except Exception:  # noqa: BLE001
        return False


async def test_document_without_coverage_loads_in_the_library(app_pool, db_pool):
    pytest.importorskip("paddock_assurance")
    from paddock_assurance.graph import ReachGraph
    ref = await _estate(app_pool, db_pool)
    async with conn_for(app_pool) as con:
        await con.execute("DELETE FROM reach_coverage")
        doc = await graph_loader.load_graph_doc(con, T0)
    g = ReachGraph.from_dict(doc)
    assert set(g.nodes) >= set(ref.values()) | {"internet"}
    assert len(g.edges) == len(doc["edges"])
    assert g.nodes["internet"].zone == "internet"


async def test_document_with_directional_coverage_loads_in_the_library(app_pool, db_pool):
    pytest.importorskip("paddock_assurance")
    if not _lib_supports_directional_coverage():
        pytest.skip("installed paddock_assurance only supports the legacy single-object coverage")
    from paddock_assurance.graph import ReachGraph
    ref = await _estate(app_pool, db_pool)
    async with conn_for(app_pool) as con:
        doc = await graph_loader.load_graph_doc(con, T0)
    g = ReachGraph.from_dict(doc)
    assert g.nodes[ref["db"]].coverage is not None
    assert g.nodes["internet"].coverage is None or not g.nodes["internet"].coverage
