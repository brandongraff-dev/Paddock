from __future__ import annotations

import gzip
import pathlib

import pytest

from app.sources import epss
from tests.conftest import FIXTURES


def test_parses_csv_with_leading_comment() -> None:
    text = (FIXTURES / "epss_sample.csv").read_text()
    rows = epss.parse_csv(text)
    assert len(rows) == 3
    rows_by_id = {cve: (score, pct) for cve, score, pct in rows}
    assert rows_by_id["CVE-2024-1234"] == (0.845, 0.987)
    assert rows_by_id["CVE-2023-0001"] == (0.004, 0.102)


def test_decompress_handles_plain_or_gzip() -> None:
    text = "cve,epss,percentile\nCVE-X,0.1,0.5\n"
    assert epss.decompress(text.encode()) == text
    gz = gzip.compress(text.encode())
    assert epss.decompress(gz) == text


def test_malformed_rows_are_skipped() -> None:
    body = "#comment\ncve,epss,percentile\nCVE-A,0.5,0.7\nMISSING,ROW\nCVE-B,notanumber,0.3\nCVE-C,0.6,0.9\n"
    rows = epss.parse_csv(body)
    cves = [r[0] for r in rows]
    assert "CVE-A" in cves
    assert "CVE-C" in cves
    assert "MISSING" not in cves
    assert "CVE-B" not in cves


@pytest.mark.asyncio
async def test_sync_updates_only_known_cves(fake_db) -> None:
    # Pre-insert one of the three
    await fake_db.upsert_cve({
        "id": "CVE-2024-1234", "modified_at": None, "cpe_affected": [], "refs": [], "cwe_ids": [],
    })

    class FakeSession:
        async def get(self, url):
            return self

        async def __aenter__(self): return self
        async def __aexit__(self, *_): return False

        def raise_for_status(self): pass

        async def read(self):
            return (FIXTURES / "epss_sample.csv").read_bytes()

    # Monkeypatch fetch to just pull from fixture; easier than mocking aiohttp.
    async def fake_fetch(_session, url=epss.EPSS_URL):
        return (FIXTURES / "epss_sample.csv").read_bytes()

    import app.sources.epss as epss_mod
    original = epss_mod.fetch
    epss_mod.fetch = fake_fetch
    try:
        res = await epss.sync(fake_db, None)
    finally:
        epss_mod.fetch = original

    assert res["rows_seen"] == 3
    assert res["updated"] == 1
    assert fake_db.cves["CVE-2024-1234"]["epss"] == 0.845
    assert fake_db.cves["CVE-2024-1234"]["epss_percentile"] == 0.987
