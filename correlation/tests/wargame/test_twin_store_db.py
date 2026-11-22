"""Twin / assessment persistence: tenant isolation, replace-vs-append,
atomicity, and exact ser/de round trips.

The round-trip tests are pure. The DB tests need ``TEST_DATABASE_URL`` pointing
at a NON-superuser role (row-level security does not apply to superusers); the
two-tenant tests additionally need two tenants to exist: they are created via
``TEST_ADMIN_DATABASE_URL`` (a superuser DSN) when given, else the tests skip.
"""
from __future__ import annotations

import os
import uuid

import asyncpg
import pytest
import pytest_asyncio

from app import tenancy
from app.config import _asyncpg_dsn
from app.engine.wargame import store, twin_store as ts
from app.engine.wargame.fabric import EdgeSpec, SegmentSpec
from app.engine.wargame.model import (
    Action, EvidenceLabel as L, NodeRole, PortRange, Proto, Rule, RuleSet,
)

T1 = "00000000-0000-0000-0000-0000000000a1"
T2 = "00000000-0000-0000-0000-0000000000a2"


# -- pure round trips --------------------------------------------------------

def _rich_ruleset() -> RuleSet:
    return RuleSet(
        id="sg-rich",
        vendor="aws",
        default_action=Action.DENY,
        rules=[
            Rule("r1", Action.ALLOW, 10, ("10.0.0.0/8", "2001:db8::/32"),
                 ("::/0",), (PortRange.single(Proto.TCP, 443),
                             PortRange(Proto.UDP, 1000, 2000)),
                 vendor="aws", conditional=True, raw_ref="line 12",
                 cost_class="cloud_policy"),
            Rule("r2", Action.DENY, 20, ("0.0.0.0/0",), ("fd00::/8",),
                 (PortRange.any(),), vendor="aws", conditional=False,
                 raw_ref="", cost_class="network_rule"),
            Rule("r0", Action.ALLOW, 5, ("192.168.0.0/16",), ("10.1.0.0/24",),
                 (), vendor="aws"),
        ],
    )


def test_ruleset_roundtrip_exact_incl_ipv6_ports_conditional_cost_order():
    rs = _rich_ruleset()
    rs_row, rule_rows = ts.ruleset_to_rows(rs)
    # Shuffle the stored rows: order must come back from `ord`, not from the DB.
    back = ts.rows_to_ruleset(rs_row, list(reversed(rule_rows)))
    assert [r.id for r in back.rules] == ["r0", "r1", "r2"]
    by = {r.id: r for r in back.rules}
    orig = {r.id: r for r in rs.rules}
    assert by == orig                       # frozen dataclass equality, field by field
    assert by["r1"].conditional is True and by["r2"].conditional is False
    assert by["r1"].cost_class == "cloud_policy"
    assert by["r1"].src_cidrs == ("10.0.0.0/8", "2001:db8::/32")
    assert by["r0"].ports == ()
    assert back.default_action is Action.DENY and back.vendor == "aws"


def test_edge_and_segment_roundtrip_exact():
    seg = SegmentSpec("s", ("2001:db8::/48", "10.0.0.0/24"), NodeRole.CROWN_JEWEL,
                      "why", "pci", {"k": [1, 2]})
    assert ts.row_to_segment(ts.segment_to_row(seg)) == seg
    e = EdgeSpec("a", "b", "rs", PortRange(Proto.TCP, 1, 1024),
                 frozenset({L.OBSERVED, L.PROVED_CONFIG}), "fix:1", {"x": 1})
    assert ts.row_to_edge(ts.edge_to_row(e)) == e
    bare = EdgeSpec("a", "b")
    assert ts.row_to_edge(ts.edge_to_row(bare)) == bare


# -- DB ------------------------------------------------------------------------

def _dsn() -> str | None:
    raw = os.environ.get("TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
    return _asyncpg_dsn(raw) if raw else None


@pytest_asyncio.fixture
async def tdb(db):
    """The shared ``db`` fixture, skipped unless the twin tables exist and the
    role is subject to RLS (a superuser would make isolation tests vacuous)."""
    try:
        await db.execute("SELECT 1 FROM wargame_rulesets LIMIT 1")
    except Exception as e:
        pytest.skip(f"wargame twin tables unavailable: {e}")
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
            for t, slug in ((T1, "wg-iso-a1"), (T2, "wg-iso-a2")):
                await con.execute(
                    "INSERT INTO tenants (id, slug, name) VALUES ($1::uuid, $2, $2) "
                    "ON CONFLICT (id) DO NOTHING", t, slug)
        finally:
            await con.close()
    have = await tdb.fetch("SELECT id::text FROM tenants WHERE id = ANY($1::uuid[])", [T1, T2])
    if len(have) != 2:
        pytest.skip("two test tenants unavailable (set TEST_ADMIN_DATABASE_URL)")
    for t in (T1, T2):
        with tenancy.tenant_context(t):
            for tbl in ("wargame_edges", "wargame_segments", "wargame_rules",
                        "wargame_rulesets", "wargame_config_snapshots",
                        "wargame_assessments"):
                await tdb.execute(f"DELETE FROM {tbl}")
    yield
    for t in (T1, T2):
        with tenancy.tenant_context(t):
            for tbl in ("wargame_edges", "wargame_segments", "wargame_rules",
                        "wargame_rulesets", "wargame_config_snapshots",
                        "wargame_assessments"):
                await tdb.execute(f"DELETE FROM {tbl}")


def _rs(key: str, n: int = 2, port: int = 5432) -> RuleSet:
    return RuleSet(key, [
        Rule(f"{key}-{i}", Action.ALLOW, i, ("10.0.0.0/8",), ("10.1.0.0/24",),
             (PortRange.single(Proto.TCP, port),), vendor="aws")
        for i in range(n)], default_action=Action.DENY, vendor="aws")


async def _counts(db):
    return (await db.fetchval("SELECT COUNT(*) FROM wargame_rulesets"),
            await db.fetchval("SELECT COUNT(*) FROM wargame_rules"),
            await db.fetchval("SELECT COUNT(*) FROM wargame_config_snapshots"))


async def test_reingest_same_device_replaces_not_duplicates(two_tenants, tdb):
    with tenancy.tenant_context(T1):
        snap = [{"vendor": "aws", "source": "acct-1", "sha256": "h1"}]
        await ts.persist_rulesets(tdb, {"sg-a": _rs("sg-a"), "sg-b": _rs("sg-b")},
                                  replace=False, snapshots=snap, source="acct-1")
        # Same device again, byte-identical config.
        await ts.persist_rulesets(tdb, {"sg-a": _rs("sg-a"), "sg-b": _rs("sg-b")},
                                  replace=False, snapshots=snap, source="acct-1")
        assert await _counts(tdb) == (2, 4, 1)
        rulesets, _ = await ts.load_twin(tdb)
        assert [r.id for r in rulesets["sg-a"].rules] == ["sg-a-0", "sg-a-1"]

        # The device's config changed: sg-b is gone, sg-a has one rule, new hash.
        snap2 = [{"vendor": "aws", "source": "acct-1", "sha256": "h2"}]
        await ts.persist_rulesets(tdb, {"sg-a": _rs("sg-a", n=1)},
                                  replace=False, snapshots=snap2, source="acct-1")
        assert await _counts(tdb) == (1, 1, 1)
        assert await ts.config_hashes(tdb) == ["h2"]       # no stale provenance

        # A different source is left alone.
        await ts.persist_rulesets(tdb, {"sg-z": _rs("sg-z")}, replace=False,
                                  snapshots=[{"vendor": "aws", "source": "acct-2", "sha256": "h3"}],
                                  source="acct-2")
        await ts.persist_rulesets(tdb, {"sg-a": _rs("sg-a", n=3)}, replace=False,
                                  snapshots=snap2, source="acct-1")
        assert await _counts(tdb) == (2, 5, 2)


async def test_ingest_without_source_still_replaces_same_key(two_tenants, tdb):
    with tenancy.tenant_context(T1):
        for _ in range(3):
            await ts.persist_rulesets(tdb, {"sg-a": _rs("sg-a")}, replace=False,
                                      snapshots=[{"vendor": "aws", "source": "", "sha256": "h"}])
        assert await _counts(tdb) == (1, 2, 1)


async def test_twin_is_tenant_isolated(two_tenants, tdb):
    with tenancy.tenant_context(T1):
        await ts.persist_rulesets(tdb, {"sg-a": _rs("sg-a")}, replace=False, source="x",
                                  snapshots=[{"vendor": "aws", "source": "x", "sha256": "t1"}])
        await ts.persist_topology(tdb, [SegmentSpec("seg", ("10.0.0.0/24",))], [])
    with tenancy.tenant_context(T2):
        # T2 sees nothing, and the SAME keys do not collide across tenants.
        assert await ts.has_twin(tdb) is False
        assert await _counts(tdb) == (0, 0, 0)
        await ts.persist_rulesets(tdb, {"sg-a": _rs("sg-a", port=22)}, replace=False, source="x",
                                  snapshots=[{"vendor": "aws", "source": "x", "sha256": "t2"}])
        await ts.persist_topology(tdb, [SegmentSpec("seg", ("10.5.0.0/24",))], [])
        rs, spec = await ts.load_twin(tdb)
        assert rs["sg-a"].rules[0].ports == (PortRange.single(Proto.TCP, 22),)
        assert await ts.config_hashes(tdb) == ["t2"]
        # T2 replacing/deleting never touches T1.
        await ts.persist_rulesets(tdb, {}, replace=True)
        await ts.persist_topology(tdb, [], [], replace=True)
    with tenancy.tenant_context(T1):
        rs, spec = await ts.load_twin(tdb)
        assert set(rs) == {"sg-a"} and [s.id for s in spec.segments] == ["seg"]
        assert await ts.config_hashes(tdb) == ["t1"]
        assert rs["sg-a"].rules[0].ports == (PortRange.single(Proto.TCP, 5432),)


async def test_assessments_are_tenant_isolated(two_tenants, tdb):
    from tests.wargame.test_store import _bundle
    with tenancy.tenant_context(T1):
        aid = await store.persist(tdb, _bundle())
        assert (await store.load(tdb, aid)) is not None
    with tenancy.tenant_context(T2):
        assert await store.load(tdb, aid) is None
        assert await store.latest(tdb) is None
        # nor can T2 reach T1's children by id
        assert await tdb.fetchval("SELECT COUNT(*) FROM wargame_routes") == 0
        # nor write a child row under another tenant's id
        with pytest.raises(Exception):
            await tdb.execute(
                "INSERT INTO wargame_routes (assessment_id, entry, jewel, tenant_id) "
                "VALUES ($1::uuid, 'a', 'b', $2::uuid)", aid, T1)


async def test_persist_is_atomic(two_tenants, tdb):
    from tests.wargame.test_store import _bundle
    b = _bundle()
    b.evidence[0]["status"] = "bogus"            # violates the CHECK in the LAST insert
    with tenancy.tenant_context(T1):
        with pytest.raises(Exception):
            await store.persist(tdb, b)
        assert await tdb.fetchval("SELECT COUNT(*) FROM wargame_assessments") == 0
        assert await tdb.fetchval("SELECT COUNT(*) FROM wargame_routes") == 0


async def test_failed_ingest_rolls_back_the_replace(two_tenants, tdb):
    with tenancy.tenant_context(T1):
        await ts.persist_rulesets(tdb, {"sg-a": _rs("sg-a")}, replace=False, source="s")
        bad = _rs("sg-a")
        bad.rules[1] = Rule("sg-a-1", Action.ALLOW, 1, ("1.1.1.1/32",), ("2.2.2.2/32",),
                            (PortRange.any(),), cost_class=None)       # NOT NULL violation
        with pytest.raises(Exception):
            await ts.persist_rulesets(tdb, {"sg-a": bad}, replace=False, source="s")
        # The old copy of sg-a survived (delete + insert are one transaction).
        assert await _counts(tdb) == (1, 2, 0)
