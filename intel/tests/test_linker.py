from __future__ import annotations

import pytest

from app.matchers import linker


@pytest.mark.asyncio
async def test_match_one_asset_emits_match_and_finding(fake_db, fake_orch):
    await fake_db.upsert_cve({
        "id": "CVE-2024-1234",
        "cvss_v3": 7.5,
        "cvss_v3_vector": "CVSS:3.1/AV:N",
        "description": "d",
        "refs": [],
        "cwe_ids": ["CWE-120"],
        "known_exploited": False,
        "cpe_affected": [
            {
                "vendor": "example", "product": "example-lib",
                "versionStartIncluding": "1.0.0",
                "versionEndExcluding": "1.4.2",
                "vulnerable": True,
            },
        ],
    })
    asset = {
        "id": "bbbbbbbb-0000-0000-0000-000000000000",
        "kind": "technology",
        "value": "example-lib@host",
        "metadata": {"vendor": "example", "product": "example-lib", "version": "1.3.9"},
    }
    res = await linker.match_one_asset(fake_db, fake_orch, asset,
                                       min_finding_confidence=60)
    assert res["matches"] == 1
    assert res["findings"] == 1
    assert len(fake_db.matches) == 1
    assert fake_db.matches[0]["confidence"] == 85
    assert len(fake_orch.posted_findings) == 1
    assert fake_orch.posted_findings[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_match_below_threshold_does_not_create_finding(fake_db, fake_orch):
    await fake_db.upsert_cve({
        "id": "CVE-X",
        "cvss_v3": 5.0,
        "description": "d",
        "refs": [],
        "cwe_ids": [],
        "cpe_affected": [
            {"vendor": "", "product": "nginx", "version": "*", "vulnerable": True},
        ],
    })
    asset = {
        "id": "a1",
        "kind": "technology",
        "value": "nginx@h",
        # No vendor -> heuristic 40 tier
        "metadata": {"product": "nginx", "version": "1.18.0"},
    }
    res = await linker.match_one_asset(fake_db, fake_orch, asset,
                                       min_finding_confidence=60)
    assert res["matches"] == 1
    assert res["findings"] == 0
    assert fake_orch.posted_findings == []


@pytest.mark.asyncio
async def test_linker_run_all_walks_assets(fake_db, fake_orch):
    await fake_db.upsert_cve({
        "id": "CVE-1",
        "cvss_v3": 9.5,
        "description": "d",
        "refs": [],
        "cwe_ids": [],
        "known_exploited": True,
        "cpe_affected": [
            {"vendor": "apache", "product": "httpd", "version": "*", "vulnerable": True},
        ],
    })
    fake_orch._assets = [
        {
            "id": "a-1", "kind": "technology", "value": "httpd@h1",
            "metadata": {"vendor": "apache", "product": "httpd", "version": "2.4.0"},
        },
        {
            "id": "a-2", "kind": "technology", "value": "httpd@h2",
            "metadata": {"vendor": "apache", "product": "httpd", "version": "2.4.58"},
        },
    ]
    res = await linker.run_all(fake_db, fake_orch, min_finding_confidence=60)
    assert res["assets"] == 2
    assert res["findings"] == 2
    # Both findings should be critical because the CVE is KEV.
    assert all(f["severity"] == "critical" for f in fake_orch.posted_findings)


@pytest.mark.asyncio
async def test_asset_without_product_is_skipped(fake_db, fake_orch):
    asset = {"id": "x", "kind": "technology", "value": "?", "metadata": {}}
    res = await linker.match_one_asset(fake_db, fake_orch, asset)
    assert res["candidates"] == 0
    assert res["matches"] == 0
