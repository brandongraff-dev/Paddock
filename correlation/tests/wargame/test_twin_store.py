"""Tests for the Wargame twin store (ser/de is pure; persistence needs a DB).

The pure round-trip tests always run. The DB-backed tests skip cleanly when
no ``TEST_DATABASE_URL`` / ``DATABASE_URL`` is set (via the conftest ``db``
fixture) or when the ``wargame_*`` twin tables (schema 040) are absent.
"""
from __future__ import annotations

import pytest

from app.engine.wargame.fabric import EdgeSpec, SegmentSpec, TopologySpec
from app.engine.wargame.model import (
    Action,
    EvidenceLabel as L,
    NodeRole,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)
from app.engine.wargame.topology import build_topology
from app.engine.wargame import twin_store as ts


# ---------------------------------------------------------------------------
# hand-built fixtures
# ---------------------------------------------------------------------------

def _ruleset() -> RuleSet:
    """A rule set whose rules are deliberately NOT in ``order`` sequence, so a
    round-trip exercises the re-sort by ``ord``."""
    r_hi = Rule(
        id="fw1:r20",
        action=Action.DENY,
        order=20,
        src_cidrs=("0.0.0.0/0",),
        dst_cidrs=("10.2.0.0/16",),
        ports=(PortRange.any(),),
        vendor="panos",
        raw_ref="rulebase/r20",
    )
    r_lo = Rule(
        id="fw1:r10",
        action=Action.ALLOW,
        order=10,
        src_cidrs=("10.0.0.0/24", "10.0.1.0/24"),
        dst_cidrs=("10.2.0.5/32",),
        ports=(
            PortRange.single(Proto.TCP, 5432),
            PortRange(Proto.UDP, 1000, 2000),
        ),
        vendor="panos",
        conditional=True,
        raw_ref="rulebase/r10",
        cost_class="cloud_policy",
    )
    # built high-order-first on purpose
    return RuleSet("fw1", [r_hi, r_lo], default_action=Action.DENY, vendor="panos")


def _segments() -> list[SegmentSpec]:
    return [
        SegmentSpec("entry", ("10.0.0.0/24",), NodeRole.ENTRY,
                    reason="internet edge", metadata={"zone": "untrust"}),
        SegmentSpec("mid", ("10.1.0.0/24",), NodeRole.INTERMEDIATE),
        SegmentSpec("jewel", ("10.2.0.0/24",), NodeRole.CROWN_JEWEL,
                    jewel_kind="database"),
    ]


def _edges() -> list[EdgeSpec]:
    return [
        EdgeSpec("entry", "mid", rule_set_id="fw1",
                 port=PortRange.single(Proto.TCP, 443),
                 base_labels=frozenset({L.OBSERVED, L.PROVED_CONFIG}),
                 fix_candidate_id="edge:entry-mid",
                 metadata={"note": "north-south"}),
        EdgeSpec("mid", "jewel", rule_set_id="fw2"),
    ]


def _allow_all(rid: str) -> RuleSet:
    return RuleSet(
        rid,
        [Rule(f"{rid}:allow", Action.ALLOW, 1,
              ("0.0.0.0/0",), ("0.0.0.0/0",), (PortRange.any(),))],
        default_action=Action.DENY,
    )


# ---------------------------------------------------------------------------
# pure: PortRange
# ---------------------------------------------------------------------------

def test_portrange_roundtrip_none():
    assert ts.portrange_to_json(None) is None
    assert ts.portrange_from_json(None) is None


def test_portrange_roundtrip_values():
    for pr in [
        PortRange.any(),
        PortRange.single(Proto.TCP, 5432),
        PortRange(Proto.UDP, 1000, 2000),
        PortRange(Proto.ICMP, 0, 0),
        PortRange.single(Proto.ANY, 53),
    ]:
        d = ts.portrange_to_json(pr)
        assert set(d) == {"proto", "low", "high"}
        assert ts.portrange_from_json(d) == pr


# ---------------------------------------------------------------------------
# pure: Rule
# ---------------------------------------------------------------------------

def test_rule_roundtrip_exact():
    r = _ruleset().rules[1]  # the conditional, multi-port rule
    row = ts.rule_to_row(r)
    assert row["rule_id"] == "fw1:r10"
    assert row["ord"] == 10
    assert row["action"] == "allow"
    assert row["src_cidrs"] == ["10.0.0.0/24", "10.0.1.0/24"]
    assert row["conditional"] is True
    assert row["cost_class"] == "cloud_policy"
    assert len(row["ports"]) == 2
    assert ts.row_to_rule(row) == r


def test_rule_roundtrip_defaults():
    r = Rule("r", Action.DENY, 0, ("1.2.3.4/32",), ("5.6.7.8/32",))
    assert ts.row_to_rule(ts.rule_to_row(r)) == r


# ---------------------------------------------------------------------------
# pure: RuleSet
# ---------------------------------------------------------------------------

def test_ruleset_roundtrip_resorts_by_ord():
    rs = _ruleset()
    ruleset_row, rule_rows = ts.ruleset_to_rows(rs)
    assert ruleset_row == {
        "ruleset_key": "fw1", "vendor": "panos",
        "default_action": "deny", "name": "fw1",
    }
    assert all(r["ruleset_key"] == "fw1" for r in rule_rows)

    rebuilt = ts.rows_to_ruleset(ruleset_row, rule_rows)
    # Rebuilt rules are sorted by ord (r10 before r20).
    assert [r.id for r in rebuilt.rules] == ["fw1:r10", "fw1:r20"]
    # And the whole thing equals a RuleSet with rules already in ord order.
    expected = RuleSet("fw1", sorted(rs.rules, key=lambda x: x.order),
                       default_action=Action.DENY, vendor="panos")
    assert rebuilt == expected


# ---------------------------------------------------------------------------
# pure: SegmentSpec / EdgeSpec
# ---------------------------------------------------------------------------

def test_segment_roundtrip_exact():
    for seg in _segments():
        assert ts.row_to_segment(ts.segment_to_row(seg)) == seg


def test_edge_roundtrip_exact():
    for e in _edges():
        row = ts.edge_to_row(e)
        assert ts.row_to_edge(row) == e


def test_edge_roundtrip_labels_and_port():
    e = _edges()[0]
    row = ts.edge_to_row(e)
    assert row["base_labels"] == ["observed", "proved_config"]  # sorted
    assert row["port"] == {"proto": "tcp", "low": 443, "high": 443}
    assert row["fix_candidate_id"] == "edge:entry-mid"
    back = ts.row_to_edge(row)
    assert back.base_labels == frozenset({L.OBSERVED, L.PROVED_CONFIG})
    assert back.port == PortRange.single(Proto.TCP, 443)


# ---------------------------------------------------------------------------
# DB-backed (skip cleanly without a DB or without the 040 twin tables)
# ---------------------------------------------------------------------------

async def _require_tables(db):
    try:
        await db.execute("SELECT 1 FROM wargame_segments LIMIT 1")
        await db.execute("SELECT 1 FROM wargame_rulesets LIMIT 1")
    except Exception as e:  # schema 040 not applied
        pytest.skip(f"wargame twin tables unavailable: {e}")


async def _clear(db):
    for tbl in (
        "wargame_edges", "wargame_segments", "wargame_rules",
        "wargame_rulesets", "wargame_config_snapshots",
    ):
        await db.execute(f"DELETE FROM {tbl}")


def _topology_env():
    """The environment the in-memory build would give for our fixtures."""
    rulesets = {"fw1": _allow_all("fw1"), "fw2": _allow_all("fw2")}
    spec = TopologySpec(segments=_segments(), edges=_edges())
    return build_topology(spec, rulesets).environment


async def test_db_persist_and_load_roundtrip(db):
    await _require_tables(db)
    await _clear(db)
    try:
        rulesets = {"fw1": _allow_all("fw1"), "fw2": _allow_all("fw2")}
        await ts.persist_rulesets(
            db, rulesets,
            snapshots=[{"vendor": "panos", "source": "cfg.xml", "sha256": "deadbeef"}],
        )
        await ts.persist_topology(db, _segments(), _edges())

        assert await ts.has_twin(db) is True
        assert await ts.config_hashes(db) == ["deadbeef"]

        loaded_rulesets, spec = await ts.load_twin(db)
        assert set(loaded_rulesets) == {"fw1", "fw2"}
        assert loaded_rulesets["fw1"] == _allow_all("fw1")
        assert [s.id for s in spec.segments] == ["entry", "jewel", "mid"]
        assert ts.row_to_edge(ts.edge_to_row(_edges()[0]))  # sanity
        # Edge with labels/port survived.
        e0 = next(e for e in spec.edges if e.src == "entry")
        assert e0.base_labels == frozenset({L.OBSERVED, L.PROVED_CONFIG})
        assert e0.port == PortRange.single(Proto.TCP, 443)

        # The loaded environment reaches the same crown jewel as the
        # in-memory build.
        env = await ts.load_environment(db)
        assert env is not None
        expected = _topology_env().reachability().open_pairs
        assert env.reachability().open_pairs == expected
        assert ("entry", "jewel") in env.reachability().open_pairs
    finally:
        await _clear(db)


async def test_db_replace_wipes_prior_rows(db):
    await _require_tables(db)
    await _clear(db)
    try:
        await ts.persist_rulesets(db, {"old": _allow_all("old")})
        await ts.persist_topology(
            db, [SegmentSpec("a", ("10.9.0.0/24",), NodeRole.ENTRY)], [])

        # replace=True should drop the old twin entirely.
        await ts.persist_rulesets(db, {"fw1": _allow_all("fw1")}, replace=True)
        await ts.persist_topology(db, _segments(), _edges(), replace=True)

        rulesets, spec = await ts.load_twin(db)
        assert set(rulesets) == {"fw1"}
        assert "old" not in rulesets
        assert {s.id for s in spec.segments} == {"entry", "mid", "jewel"}
        assert "a" not in {s.id for s in spec.segments}
    finally:
        await _clear(db)


async def test_db_empty_twin(db):
    await _require_tables(db)
    await _clear(db)
    try:
        assert await ts.has_twin(db) is False
        assert await ts.load_environment(db) is None
        assert await ts.config_hashes(db) == []
        rulesets, spec = await ts.load_twin(db)
        assert rulesets == {}
        assert spec.segments == [] and spec.edges == []
    finally:
        await _clear(db)
