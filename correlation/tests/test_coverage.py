"""Coverage engine tests. Pure classification needs no DB; one DB-backed test
exercises the snapshot write (skips without TEST_DATABASE_URL)."""
from __future__ import annotations

import uuid

import pytest

from app.engine.coverage import (
    CoverageEngine,
    classify_path,
    label_hop_evidence,
    path_has_proven_hop,
    summarize,
)

from .conftest import mk_asset, mk_edge, mk_finding


def _path(*finding_sets, tripwired=False):
    """A path whose hops carry the given finding-id lists."""
    hops = [{"asset_id": str(uuid.uuid4()), "finding_ids": list(fs)} for fs in finding_sets]
    return {"id": str(uuid.uuid4()), "hops": hops, "tripwired": tripwired}


# ----------------------------------------------------------------------------
# Pure classification
# ----------------------------------------------------------------------------

def test_open_when_no_findings():
    assert classify_path(_path([], []), {}) == "open"


def test_open_when_unverified():
    f = {"a": {"status": "open", "exploitability": "unverified"}}
    assert classify_path(_path(["a"]), f) == "open"


def test_proven_closed_when_all_not_reproducible():
    f = {
        "a": {"status": "open", "exploitability": "not_reproducible"},
        "b": {"status": "open", "exploitability": "not_reproducible"},
    }
    assert classify_path(_path(["a"], ["b"]), f) == "proven_closed"


def test_not_closed_when_one_hop_still_confirmed():
    f = {
        "a": {"status": "open", "exploitability": "not_reproducible"},
        "b": {"status": "open", "exploitability": "confirmed"},
    }
    assert classify_path(_path(["a"], ["b"]), f) == "open"


def test_risk_accepted_when_all_suppressed():
    f = {
        "a": {"status": "accepted_risk", "exploitability": "unverified"},
        "b": {"status": "false_positive", "exploitability": "unverified"},
    }
    assert classify_path(_path(["a"], ["b"]), f) == "risk_accepted"


def test_proven_closed_beats_risk_accepted():
    # all not_reproducible AND accepted -> proven_closed wins (door is shut).
    f = {"a": {"status": "accepted", "exploitability": "not_reproducible"}}
    assert classify_path(_path(["a"]), f) == "proven_closed"


def test_tripwired_hook():
    assert classify_path(_path(["a"], tripwired=True), {}) == "tripwired"


def test_proven_hop_detection():
    f = {"a": {"status": "open", "exploitability": "confirmed"}}
    assert path_has_proven_hop(_path(["a"]), f) is True
    assert path_has_proven_hop(_path([]), f) is False


def test_hop_evidence_labels():
    f = {
        "c": {"status": "open", "exploitability": "confirmed"},
        "n": {"status": "open", "exploitability": "not_reproducible"},
        "u": {"status": "open", "exploitability": "unverified"},
    }
    assert label_hop_evidence({"finding_ids": ["c"]}, f)["evidence"] == "proven"
    assert label_hop_evidence({"finding_ids": ["n"]}, f)["evidence"] == "proven"
    assert label_hop_evidence({"finding_ids": ["u"]}, f)["evidence"] == "inferred"
    assert label_hop_evidence({"finding_ids": []}, f)["evidence"] == "inferred"


def test_summarize_counts_and_pct():
    f = {
        "closed": {"status": "open", "exploitability": "not_reproducible"},
        "acc": {"status": "accepted", "exploitability": "unverified"},
        "conf": {"status": "open", "exploitability": "confirmed"},
    }
    paths = [
        _path(["closed"]),        # proven_closed
        _path(["acc"]),           # risk_accepted
        _path(["conf"]),          # open, proven hop
        _path([]),                # open, no proven hop
    ]
    s = summarize(paths, f, crown_jewels_total=3, crown_jewels_exposed=2, choke_point_count=5)
    assert s["total_paths"] == 4
    assert s["proven_closed_paths"] == 1
    assert s["risk_accepted_paths"] == 1
    assert s["open_paths"] == 2
    assert s["proven_hop_paths"] == 1
    assert s["coverage_pct"] == 50.0  # (1 closed + 1 accepted) / 4
    assert s["choke_point_count"] == 5


def test_summarize_empty():
    s = summarize([], {})
    assert s["total_paths"] == 0 and s["coverage_pct"] == 0.0


# ----------------------------------------------------------------------------
# DB-backed snapshot write
# ----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_writes_snapshot(clean_db):
    db = clean_db
    # One source -> one jewel path with a not_reproducible finding => proven_closed.
    src = await mk_asset(db, "endpoint", "https://app.example.com", {"public": True})
    mid = await mk_asset(db, "ipv4", "10.0.0.9")
    jewel = await mk_asset(db, "technology", "PostgreSQL 14", {"sensitive": True})
    await mk_edge(db, src, mid, "resolves_to")
    await mk_edge(db, mid, jewel, "runs")
    fid = await mk_finding(db, mid, "CVE-2021-1", rule_source="sca", severity="high")
    await db.execute(
        "UPDATE findings SET exploitability = 'not_reproducible' WHERE id = $1::uuid", fid
    )
    # Seed a matching attack_path row directly (coverage reads attack_paths).
    await db.execute(
        """
        INSERT INTO attack_paths (source_asset_id, target_asset_id, hops, length,
          total_cost, exploitability, severity, title, fingerprint)
        VALUES ($1::uuid,$2::uuid,$3::jsonb,2,5,40,'high','p','fp-cov-1')
        """,
        src, jewel,
        [
            {"asset_id": src, "finding_ids": []},
            {"asset_id": mid, "finding_ids": [fid]},
            {"asset_id": jewel, "finding_ids": []},
        ],
    )
    eng = CoverageEngine(db)
    res = await eng.run()
    assert res["total_paths"] == 1
    assert res["proven_closed_paths"] == 1
    assert res["coverage_pct"] == 100.0
    latest = await eng.latest()
    assert latest is not None and latest["coverage_pct"] == 100.0
