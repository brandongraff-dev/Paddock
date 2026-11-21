"""EPSS daily-score adapter.

Downloads the gzip'd CSV, parses it, and *updates* EPSS fields on CVEs
we already know about. Deliberately UPDATE-only: EPSS is an enrichment,
not an authoritative CVE source.
"""
from __future__ import annotations

import csv
import gzip
import io
import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Iterable

import aiohttp

log = logging.getLogger(__name__)

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def parse_csv(text: str) -> list[tuple[str, float, float]]:
    """Parse the EPSS CSV body into (cve_id, epss, percentile) tuples.

    The header line (``#model_version:v...``) is present on every row so
    we skip leading comments and resolve column names from the header row.
    """
    rows: list[tuple[str, float, float]] = []
    reader = csv.reader(io.StringIO(text))
    header: list[str] | None = None
    for row in reader:
        if not row:
            continue
        first = row[0]
        if first.startswith("#"):
            continue
        if header is None:
            header = [c.strip().lower() for c in row]
            continue
        try:
            idx_cve = header.index("cve")
            idx_epss = header.index("epss")
            idx_pct = header.index("percentile")
        except ValueError:
            continue
        try:
            cve_id = row[idx_cve].strip()
            epss = float(row[idx_epss])
            pct = float(row[idx_pct])
        except (IndexError, ValueError):
            continue
        if cve_id:
            rows.append((cve_id, round(epss, 3), round(pct, 3)))
    return rows


def decompress(body: bytes) -> str:
    """Decompress the EPSS payload. Accepts gzip or plain text transparently."""
    if body[:2] == b"\x1f\x8b":
        return gzip.decompress(body).decode("utf-8", errors="replace")
    return body.decode("utf-8", errors="replace")


async def fetch(session: aiohttp.ClientSession, url: str = EPSS_URL) -> bytes:
    async with session.get(url) as resp:
        resp.raise_for_status()
        return await resp.read()


async def sync(
    db: Any,
    session: aiohttp.ClientSession,
    *,
    url: str = EPSS_URL,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    body = await fetch(session, url)
    text = decompress(body)
    rows = parse_csv(text)
    updated = 0
    # UPDATE-only — missing rows mean "CVE not yet ingested from NVD"; ignore.
    for cve_id, epss, pct in rows:
        if await db.update_epss(cve_id, epss, pct):
            updated += 1

    await db.set_cursor(
        "epss",
        last_synced=now,
        stats={"rows_seen": len(rows), "updated": updated,
               "last_run_ts": now.isoformat()},
    )
    log.info("epss: sync complete rows=%d updated=%d", len(rows), updated)
    return {"rows_seen": len(rows), "updated": updated}
