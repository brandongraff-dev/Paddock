"""TAXII 2.1 / STIX-URL polling.

Given a ``ti_feeds`` row the owner configured, fetch STIX objects and ingest
them. Two feed kinds reach the network here:

  * ``taxii``    -- poll a TAXII 2.1 collection's ``objects`` endpoint, paging
                    through via the ``more`` / ``next`` cursor, with the
                    ``application/taxii+json;version=2.1`` media type.
  * ``stix_url`` -- GET a single STIX 2.1 bundle document.

SAFETY: the ONLY URL contacted is the one stored on the feed (user-configured).
An indicator's value is never dereferenced. A 10s timeout caps each request;
any failure is recorded on the feed (``last_status``) and never crashes the
service.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import aiohttp

from . import stix

log = logging.getLogger(__name__)

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"
DEFAULT_PAGE_LIMIT = 100


def build_objects_url(feed: dict[str, Any]) -> str:
    """Resolve the objects endpoint for a TAXII feed row."""
    base = (feed.get("url") or "").strip()
    base = base.rstrip("/")
    collection = feed.get("collection")
    if base.endswith("/objects"):
        return base + "/"
    if collection:
        return f"{base}/collections/{collection}/objects/"
    return base + "/"


async def _get_json(
    session: aiohttp.ClientSession,
    url: str,
    *,
    accept: str,
    params: dict[str, Any] | None = None,
    timeout_s: int = 10,
) -> dict[str, Any]:
    timeout = aiohttp.ClientTimeout(total=timeout_s)
    async with session.get(
        url, headers={"Accept": accept}, params=params or {}, timeout=timeout
    ) as resp:
        resp.raise_for_status()
        # Feeds are sloppy about content-type; don't let aiohttp reject it.
        return await resp.json(content_type=None)


async def poll_feed(
    db: Any,
    session: aiohttp.ClientSession,
    feed: dict[str, Any],
    *,
    timeout_s: int = 10,
    max_pages: int = 20,
    page_limit: int = DEFAULT_PAGE_LIMIT,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Poll a feed, ingest every indicator found, and record the outcome.

    Returns {"feed_id", "status", "pages", "ingested", "inserted"}. On any
    HTTP/parse error the feed's ``last_status`` is set to the error and the
    summary carries ``status="error"`` -- it never raises.
    """
    now = now or datetime.now(timezone.utc)
    feed_id = feed.get("id")
    kind = feed.get("kind")
    ingested = 0
    inserted = 0
    pages = 0
    status = "ok"

    try:
        if kind == "stix_url":
            bundle = await _get_json(
                session, (feed.get("url") or "").strip(),
                accept=STIX_MEDIA_TYPE, timeout_s=timeout_s,
            )
            pages = 1
            ing, ins = await _ingest_objects(db, bundle, feed)
            ingested += ing
            inserted += ins
        elif kind == "taxii":
            url = build_objects_url(feed)
            cursor: str | None = None
            while pages < max_pages:
                params: dict[str, Any] = {"limit": page_limit}
                if cursor:
                    params["next"] = cursor
                envelope = await _get_json(
                    session, url, accept=TAXII_MEDIA_TYPE,
                    params=params, timeout_s=timeout_s,
                )
                pages += 1
                ing, ins = await _ingest_objects(db, envelope, feed)
                ingested += ing
                inserted += ins
                if not envelope.get("more"):
                    break
                cursor = envelope.get("next")
                if not cursor:
                    break
        else:
            status = f"unsupported feed kind: {kind}"
            await db.record_feed_poll(feed_id, status=status, ingested=0, last_poll=now)
            return {"feed_id": feed_id, "status": status, "pages": 0,
                    "ingested": 0, "inserted": 0}
    except aiohttp.ClientError as exc:
        status = f"error: {exc!s}"[:480]
        log.warning("taxii poll %s failed: %s", feed_id, exc)
    except Exception as exc:  # noqa: BLE001 - never crash the poll loop
        status = f"error: {exc!s}"[:480]
        log.warning("taxii poll %s failed: %s", feed_id, exc)
    else:
        status = f"ok: {inserted} new / {ingested} seen"

    await db.record_feed_poll(feed_id, status=status, ingested=inserted, last_poll=now)
    return {
        "feed_id": feed_id,
        "status": status,
        "pages": pages,
        "ingested": ingested,
        "inserted": inserted,
    }


async def _ingest_objects(
    db: Any, envelope: dict[str, Any], feed: dict[str, Any]
) -> tuple[int, int]:
    """Parse a bundle/TAXII envelope and upsert its indicators."""
    records = stix.parse_bundle(envelope, source=feed.get("name"))
    seen = 0
    new = 0
    for rec in records:
        seen += 1
        res = await db.upsert_indicator(rec, feed_id=feed.get("id"))
        if res.get("inserted"):
            new += 1
    return seen, new
