"""CISA KEV (Known Exploited Vulnerabilities) adapter.

Marks known-exploited CVEs as such. Like EPSS, this is enrichment —
we never INSERT new CVE rows here, only flip the flag and store the
date it was added to KEV.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from typing import Any

import aiohttp

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def parse(payload: dict[str, Any]) -> list[tuple[str, datetime | None]]:
    """Extract (cve_id, date_added) tuples from a KEV payload."""
    out: list[tuple[str, datetime | None]] = []
    for item in (payload or {}).get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID") or item.get("cve_id")
        if not cve_id:
            continue
        out.append((cve_id, _parse_date(item.get("dateAdded"))))
    return out


async def fetch(session: aiohttp.ClientSession, url: str = KEV_URL) -> dict[str, Any]:
    async with session.get(url) as resp:
        resp.raise_for_status()
        return await resp.json(content_type=None)


async def sync(
    db: Any,
    session: aiohttp.ClientSession,
    *,
    url: str = KEV_URL,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    payload = await fetch(session, url)
    entries = parse(payload)
    marked = 0
    for cve_id, added_at in entries:
        if await db.mark_kev(cve_id, added_at):
            marked += 1
    await db.set_cursor(
        "kev",
        last_synced=now,
        stats={"entries": len(entries), "marked": marked,
               "last_run_ts": now.isoformat()},
    )
    log.info("kev: sync complete entries=%d marked=%d", len(entries), marked)
    return {"entries": len(entries), "marked": marked}
