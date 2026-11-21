from __future__ import annotations

import pytest

from app.sources import kev
from tests.conftest import load_fixture


def test_parse_extracts_cve_and_date() -> None:
    payload = load_fixture("kev_sample.json")
    entries = kev.parse(payload)
    assert len(entries) == 2
    ids = [e[0] for e in entries]
    assert "CVE-2024-1234" in ids
    assert "CVE-2023-9999" in ids
    for cid, dt in entries:
        assert dt is not None
        assert dt.tzinfo is not None


def test_parse_tolerates_bad_shapes() -> None:
    assert kev.parse({}) == []
    assert kev.parse({"vulnerabilities": [None, {"not_cve": 1}, {"cveID": ""}]}) == []


@pytest.mark.asyncio
async def test_sync_marks_known_cves(fake_db) -> None:
    await fake_db.upsert_cve({
        "id": "CVE-2024-1234", "cpe_affected": [], "refs": [], "cwe_ids": [],
    })
    # second one is not in the DB - should be silently skipped.

    async def fake_fetch(_session, url=kev.KEV_URL):
        return load_fixture("kev_sample.json")

    import app.sources.kev as kev_mod
    original = kev_mod.fetch
    kev_mod.fetch = fake_fetch
    try:
        res = await kev.sync(fake_db, None)
    finally:
        kev_mod.fetch = original

    assert res["entries"] == 2
    assert res["marked"] == 1
    assert fake_db.cves["CVE-2024-1234"]["known_exploited"] is True
    assert fake_db.cves["CVE-2024-1234"]["kev_added_at"] is not None
