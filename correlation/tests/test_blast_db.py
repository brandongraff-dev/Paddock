"""Blast-radius scoring tests."""
from __future__ import annotations

import pytest

from app.engine.blast import SEVERITY_BASE, BlastScorer

from .conftest import mk_asset, mk_edge, mk_finding


pytestmark = pytest.mark.asyncio


async def test_blast_base_severity(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.2.0.1")
    f = await mk_finding(
        clean_db, asset_id=host, rule_id="x", rule_source="nuclei",
        severity="medium",
    )
    scorer = BlastScorer(clean_db)
    r = await scorer.score_and_persist(f)
    assert r["components"]["severity_base"] == SEVERITY_BASE["medium"]
    assert 0 <= r["score"] <= 100


async def test_blast_neighbor_bonus(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.2.0.2")
    # 5 neighbors
    for i in range(5):
        svc = await mk_asset(clean_db, "service", f"svc-{i}-blast")
        await mk_edge(clean_db, host, svc, "hosts")
    f = await mk_finding(
        clean_db, asset_id=host, rule_id="x2", rule_source="nuclei",
        severity="low",
    )
    scorer = BlastScorer(clean_db)
    r = await scorer.score_and_persist(f)
    assert r["components"]["neighbor_bonus"] == 5


async def test_blast_kev_bonus(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.2.0.3")
    f = await mk_finding(
        clean_db, asset_id=host, rule_id="cve-kev-b", rule_source="cve_match",
        severity="high", metadata={"kev": True},
    )
    scorer = BlastScorer(clean_db)
    r = await scorer.score_and_persist(f)
    assert r["components"]["kev_bonus"] == 10


async def test_blast_public_bonus(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.2.0.4")
    ep = await mk_asset(clean_db, "endpoint", "https://pb/")
    await mk_edge(clean_db, ep, host, "resolves_to", metadata={"public": True})
    f = await mk_finding(
        clean_db, asset_id=host, rule_id="header-x", rule_source="header_check",
        severity="medium",
    )
    scorer = BlastScorer(clean_db)
    r = await scorer.score_and_persist(f)
    assert r["components"]["public_bonus"] == 10


async def test_blast_clamped_to_100(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.2.0.5")
    ep = await mk_asset(clean_db, "endpoint", "https://big/")
    await mk_edge(clean_db, ep, host, "resolves_to", metadata={"public": True})
    for i in range(30):
        s = await mk_asset(clean_db, "service", f"big-{i}")
        await mk_edge(clean_db, host, s, "hosts")
    f = await mk_finding(
        clean_db, asset_id=host, rule_id="cve-big", rule_source="cve_match",
        severity="critical", cvss=9.9, epss=0.95, metadata={"kev": True},
    )
    scorer = BlastScorer(clean_db)
    r = await scorer.score_and_persist(f)
    assert r["score"] == 100


async def test_recompute_all_open_counts(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.2.0.6")
    for i in range(3):
        await mk_finding(
            clean_db, asset_id=host, rule_id=f"r-{i}", rule_source="nuclei",
            severity="medium",
        )
    scorer = BlastScorer(clean_db)
    n = await scorer.recompute_all_open(limit=10)
    assert n == 3
