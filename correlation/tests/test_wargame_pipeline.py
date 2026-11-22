"""Integration: the Part-1 pipeline composes (attack paths -> reachability ->
choke points -> coverage) and coverage reads the other engines' tables.
DB-backed; skips without TEST_DATABASE_URL."""
from __future__ import annotations

import pytest

from app.engine.attackpath import AttackPathEngine
from app.engine.chokepoint import ChokePointEngine
from app.engine.coverage import CoverageEngine
from app.engine.reachability import ReachabilityEngine

from .conftest import mk_asset, mk_edge, mk_finding


async def _seed_corridor(db):
    """internet endpoint -> ip -> jewel datastore, with a KEV finding on the ip."""
    src = await mk_asset(db, "endpoint", "https://app.example.com", {"public": True})
    # The intermediate is a private host (NOT public) so it is a genuine
    # mid-corridor node the min-cut can recommend cutting -- not itself a source.
    ip = await mk_asset(db, "ipv4", "10.0.0.9")
    jewel = await mk_asset(db, "technology", "PostgreSQL 14", {"sensitive": True})
    await mk_edge(db, src, ip, "resolves_to")
    await mk_edge(db, ip, jewel, "runs")
    await mk_finding(db, ip, "CVE-2021-44228", rule_source="nuclei",
                     severity="critical", metadata={"kev": True})
    return src, ip, jewel


@pytest.mark.asyncio
async def test_full_pipeline_populates_all_tables(clean_db):
    db = clean_db
    src, ip, jewel = await _seed_corridor(db)

    # Order mirrors run_pathcompute: paths, then reachability + choke points,
    # then coverage (which reads crown_jewel_exposure + choke_points).
    ap = await AttackPathEngine(db).run()
    assert ap["computed"] >= 1

    reach = await ReachabilityEngine(db).run()
    assert reach["crown_jewels"] >= 1

    choke = await ChokePointEngine(db).run()
    # The single intermediate ip is the one node that cuts the corridor.
    assert choke["choke_points"] >= 1

    cov = await CoverageEngine(db).run()
    assert cov["total_paths"] >= 1
    # The path's hop finding is unverified -> the path is still open.
    assert cov["open_paths"] >= 1
    # coverage picked up the choke-point count from the choke_points table.
    assert cov["choke_point_count"] >= 1
    # crown-jewel totals came from crown_jewel_exposure.
    assert cov["crown_jewels_total"] >= 1

    # The exposed jewel is reachable (not proven closed).
    row = await db.fetchrow(
        "SELECT proven_closed, reachable_source_count FROM crown_jewel_exposure "
        "WHERE asset_id = $1::uuid", jewel
    )
    assert row is not None and row["proven_closed"] is False
    assert row["reachable_source_count"] >= 1

    # The choke point is the intermediate ip, not the source or the jewel.
    choke_assets = [r["asset_id"] for r in await db.fetch(
        "SELECT asset_id::text AS asset_id FROM choke_points WHERE in_min_cut IS TRUE")]
    assert ip in choke_assets
    assert src not in choke_assets and jewel not in choke_assets


@pytest.mark.asyncio
async def test_coverage_reflects_verified_fix(clean_db):
    db = clean_db
    src, ip, jewel = await _seed_corridor(db)
    await AttackPathEngine(db).run()
    await ReachabilityEngine(db).run()
    await ChokePointEngine(db).run()

    # Mark the on-path finding not_reproducible => the path is proven_closed.
    await db.execute(
        "UPDATE findings SET exploitability = 'not_reproducible' WHERE asset_id = $1::uuid", ip
    )
    cov = await CoverageEngine(db).run()
    assert cov["proven_closed_paths"] >= 1
    assert cov["coverage_pct"] > 0
