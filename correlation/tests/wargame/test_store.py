"""Tests for the Wargame persistence layer (assembler is pure; writer needs a DB)."""
from __future__ import annotations

import pytest

from app.engine.wargame.agreement import AgreementReport
from app.engine.wargame.compliance import (
    EvidenceItem,
    EvidencePack,
    EvidenceStatus,
    chain,
)
from app.engine.wargame.model import (
    Assumption,
    Certificate,
    Corroboration,
    FixCandidate,
    FixSet,
    Hop,
    PortRange,
    Proto,
    ReachabilityResult,
    Route,
)
from app.engine.wargame.model import EvidenceLabel as L
from app.engine.wargame.report import build_scorecard
from app.engine.wargame import store
from app.engine.wargame.store import assemble_bundle, format_port


# -- fixtures -----------------------------------------------------------------

PG = PortRange.single(Proto.TCP, 5432)


def _reach() -> ReachabilityResult:
    r1 = Route("inet", "ehr", [
        Hop("inet", "dmz", frozenset({L.OBSERVED, L.PROVED_CONFIG}),
            PortRange.single(Proto.TCP, 443), "fw1:r1", frozenset({"fw1:r1"})),
        Hop("dmz", "ehr", frozenset({L.PROVED_CONFIG}), PG, "fw2:r7",
            frozenset({"fw2:r7", "edge:dmz-ehr"})),
    ])
    r2 = Route("guest", "pci", [
        Hop("guest", "pci", frozenset({L.INFERRED}), None),
    ])
    return ReachabilityResult(
        routes=[r2, r1],  # deliberately unsorted
        open_pairs={("inet", "ehr"), ("guest", "pci")},
        closed_pairs={("vpn", "ehr"), ("vpn", "pci")},
        conditional_pairs={("vpn", "pci")},
    )


def _bundle(coverage=None, **kw):
    reach = _reach()
    report = AgreementReport("a", "b", PG, "fail_open", False,
                             ["probe says open", "config says open"], "note")
    cert = Certificate(
        claim="no route from a to b on tcp/5432",
        boundary_src="a", boundary_dst="b", port=PG,
        config_hashes=("h2", "h1"),
        assumptions=[Assumption("k1", "t1")],
        corroboration=Corroboration(0, 30, True),
        issued_at="2026-01-01T00:00:00+00:00",
        expires_at="2026-02-01T00:00:00+00:00",
        fingerprint="fp1",
    )
    cands = {
        "fw2:r7": FixCandidate("fw2:r7", "rule", "network_rule", "tighten r7", 1.0),
        "fw1:r1": FixCandidate("fw1:r1", "rule", "network_rule", "tighten r1", 1.0),
    }
    fix = FixSet(selected=["fw2:r7"], total_cost=1.0, cuts_all=True)
    items = [
        EvidenceItem("1.3.1", "t", EvidenceStatus.MET, "s1", {"x": 1}),
        EvidenceItem("1.3.2", "t", EvidenceStatus.EXCEPTION, "s2", {"y": 2}),
    ]
    chain(items)
    pack = EvidencePack("PCI DSS 4.0", items, "2026-01-01T00:00:00Z", "sum")
    sc = build_scorecard(reach, agreement_reports=[report],
                         coverage_pct=coverage, blind_spots=["z", "a"])
    return assemble_bundle(
        reachability=reach, scorecard=sc, agreement_reports=[report],
        certificates=[cert], fix_set=fix, fix_candidates=cands,
        evidence_packs=[pack], label="nightly", **kw,
    )


# -- pure assembler -----------------------------------------------------------

def test_format_port():
    assert format_port(PG) == "tcp/5432"
    assert format_port(PortRange.any()) == "any"
    assert format_port(None) == "any"
    assert format_port(PortRange(Proto.TCP, 1000, 2000)) == "tcp/1000-2000"
    assert format_port(PortRange(Proto.UDP, 0, 65535)) == "udp/any"
    assert format_port(PortRange.single(Proto.ANY, 53)) == "any/53"


def test_assessment_row():
    a = _bundle(coverage=None).assessment
    assert a["label"] == "nightly"
    assert (a["crownjewel_total"], a["crownjewel_open"],
            a["crownjewel_closed"], a["crownjewel_conditional"]) == (4, 2, 2, 1)
    assert a["closure_pct"] == 50.0
    assert a["coverage_pct"] is None
    assert a["false_closed_rate"] is None
    assert a["blind_spots"] == ["a", "z"]
    assert "not yet measured" in a["board_line"]
    assert a["metadata"] == {}


def test_coverage_and_false_closed_passthrough():
    b = _bundle(coverage=80.0, false_closed_rate=0.0123, metadata={"k": "v"})
    assert b.assessment["coverage_pct"] == 80.0
    assert b.assessment["false_closed_rate"] == 0.0123
    assert b.assessment["metadata"] == {"k": "v"}


def test_routes_serialised_sorted():
    routes = _bundle().routes
    assert [(r["entry"], r["jewel"]) for r in routes] == [("guest", "pci"), ("inet", "ehr")]
    inet = routes[1]
    assert inet["length"] == 2
    assert inet["weakest_label"] == "proved_config"
    assert inet["fingerprint"]
    h0, h1 = inet["hops"]
    assert h0["labels"] == ["observed", "proved_config"]  # sorted
    assert h0["port"] == "tcp/443"
    assert h1["port"] == "tcp/5432"
    assert h1["rule_ref"] == "fw2:r7"
    assert h1["fix_candidate_ids"] == ["edge:dmz-ehr", "fw2:r7"]
    guest = routes[0]
    assert guest["weakest_label"] == "inferred"
    assert guest["hops"][0]["port"] == "any"


def test_boundaries_and_certificates():
    b = _bundle()
    assert b.boundaries == [{
        "boundary_src": "a", "boundary_dst": "b", "port": "tcp/5432",
        "verdict": "fail_open",
        "disagreements": ["config says open", "probe says open"],
        "note": "note",
    }]
    (c,) = b.certificates
    assert c["port"] == "tcp/5432"
    assert c["assumptions"] == [{"key": "k1", "text": "t1"}]
    assert c["config_hashes"] == ["h1", "h2"]
    assert c["status"] == "valid"
    assert c["issued_at"] == "2026-01-01T00:00:00+00:00"
    assert c["fingerprint"] == "fp1"


def test_fix_set_enriched():
    fs = _bundle().fix_set
    assert fs == {
        "total_cost": 1.0, "optimality": "exact", "cuts_all": True,
        "selected": [{"id": "fw2:r7", "kind": "rule", "cost_class": "network_rule",
                      "description": "tighten r7", "cost": 1.0}],
    }


def test_fix_set_none_and_unknown_candidate():
    b = assemble_bundle(
        reachability=_reach(),
        scorecard=build_scorecard(_reach()),
        fix_set=FixSet(selected=["ghost"], total_cost=2.0, cuts_all=False,
                       optimality="greedy"),
    )
    assert b.fix_set["selected"][0]["id"] == "ghost"
    assert b.fix_set["optimality"] == "greedy"
    none = assemble_bundle(reachability=_reach(), scorecard=build_scorecard(_reach()))
    assert none.fix_set is None
    assert none.boundaries == none.certificates == none.evidence == []


def test_evidence_flattened_with_ordinals():
    ev = _bundle().evidence
    assert [(e["framework"], e["control_id"], e["status"], e["ordinal"]) for e in ev] == [
        ("PCI DSS 4.0", "1.3.1", "met", 0),
        ("PCI DSS 4.0", "1.3.2", "exception", 1),
    ]
    assert ev[0]["evidence"] == {"x": 1}
    assert ev[0]["item_hash"] and ev[1]["item_hash"] != ev[0]["item_hash"]


def test_deterministic():
    assert _bundle() == _bundle()


# -- DB-backed (skip cleanly without TEST_DATABASE_URL / DATABASE_URL) -------

async def _require_tables(db):
    try:
        await db.execute("SELECT 1 FROM wargame_assessments LIMIT 1")
    except Exception as e:  # schema 039 not applied
        pytest.skip(f"wargame tables unavailable: {e}")


async def test_db_persist_and_load(db):
    await _require_tables(db)
    aid = await store.persist(db, _bundle(coverage=75.5, false_closed_rate=0.05))
    try:
        got = await store.load(db, aid)
        assert got is not None and got["id"] == aid
        assert got["label"] == "nightly"
        assert got["crownjewel_open"] == 2
        assert got["closure_pct"] == 50.0
        assert got["coverage_pct"] == 75.5
        assert got["false_closed_rate"] == 0.05
        assert got["blind_spots"] == ["a", "z"]
        assert len(got["routes"]) == 2
        assert len(got["boundaries"]) == 1
        assert len(got["certificates"]) == 1
        assert got["certificates"][0]["status"] == "valid"
        assert got["fix_set"]["cuts_all"] is True
        assert got["fix_set"]["selected"][0]["id"] == "fw2:r7"
        assert [e["ordinal"] for e in got["evidence"]] == [0, 1]
        latest = await store.latest(db)
        assert latest is not None and latest["id"] == aid
    finally:
        await db.execute("DELETE FROM wargame_assessments WHERE id = $1::uuid", aid)


async def test_db_null_coverage_and_no_fix(db):
    await _require_tables(db)
    b = assemble_bundle(reachability=_reach(), scorecard=build_scorecard(_reach()))
    aid = await store.persist(db, b)
    try:
        got = await store.load(db, aid)
        assert got["coverage_pct"] is None
        assert got["fix_set"] is None
        assert len(got["routes"]) == 2
    finally:
        await db.execute("DELETE FROM wargame_assessments WHERE id = $1::uuid", aid)


async def test_db_load_missing(db):
    await _require_tables(db)
    assert await store.load(db, "00000000-0000-0000-0000-000000000000") is None


def test_certificate_row_carries_key_id_and_corroboration():
    (c,) = _bundle().certificates
    assert c["key_id"] == ""                    # legacy object: no key id
    assert set(c["corroboration"]) == {
        "observed_flows", "window_days", "sensor_on_protected_side", "probe_tested",
    }


def test_proved_config_verdict_serialises_and_unknown_verdict_is_refused():
    import pytest

    from app.engine.wargame.agreement import AgreementReport
    from app.engine.wargame.report import build_scorecard
    from app.engine.wargame.store import assemble_bundle

    rr = _reach()
    ok = AgreementReport("a", "b", None, "proved_config", False, [], "n")
    b = assemble_bundle(reachability=rr, scorecard=build_scorecard(rr), agreement_reports=[ok])
    assert b.boundaries[0]["verdict"] == "proved_config"
    bad = AgreementReport("a", "b", None, "closed-ish", False, [], "n")
    with pytest.raises(ValueError):
        assemble_bundle(reachability=rr, scorecard=build_scorecard(rr), agreement_reports=[bad])
