"""Apply a SOURCE connector's ``SourceBatch`` to the asset graph.

Writes go through the orchestrator's OWN bulk handlers (``/v1/assets/bulk``,
``/v1/edges/bulk``, ``/v1/findings/bulk``) called in-process, so canonical
forms, upsert semantics and ``asset_added``/``finding_opened`` events are
exactly what every other producer gets. Two additions live here:

* **merge hints** -- an asset/finding item may carry
  ``merge_on = {"ips", "hostnames", "macs"}``. Its metadata is merged onto
  EVERY existing asset that matches (capped), and only when nothing matches is
  the item's own ``kind``/``value`` created -- unless the item is
  ``merge_only``, in which case it is dropped. ``tags`` are unioned, not
  replaced, on merged assets.
* **owner rules** -- ``batch.owners`` entries are upserted into
  ``asset_owners`` by ``name`` (an admin's ``enabled`` flag is never touched).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Mapping
from uuid import UUID

from .base import SourceBatch

log = logging.getLogger(__name__)

_CHUNK = 500
_MAX_MERGE_TARGETS = 20
_MERGE_KEYS = ("merge_on", "merge_only")

_MATCH_SQL = """
SELECT id FROM assets
 WHERE (kind IN ('ipv4','ipv6') AND canonical = ANY($1::text[]))
    OR (kind IN ('iot_device','ot_device')
        AND (canonical = ANY($1::text[]) OR metadata->'ips' ?| $1::text[]))
    OR (kind = 'cloud_resource' AND metadata->'private_ips' ?| $1::text[])
    OR (kind IN ('domain','subdomain') AND canonical = ANY($2::text[]))
    OR (cardinality($2::text[]) > 0 AND lower(metadata->>'hostname') = ANY($2::text[]))
    OR (cardinality($3::text[]) > 0 AND lower(metadata->>'mac') = ANY($3::text[]))
 ORDER BY CASE kind WHEN 'iot_device' THEN 0 WHEN 'ot_device' THEN 0
                    WHEN 'cloud_resource' THEN 1 ELSE 2 END, first_seen
 LIMIT $4
"""

_MERGE_SQL = """
UPDATE assets
   SET last_seen = NOW(),
       metadata = (assets.metadata || $2::jsonb)
                  || CASE WHEN $3::jsonb IS NULL THEN '{}'::jsonb ELSE jsonb_build_object(
                       'tags',
                       (SELECT COALESCE(jsonb_agg(DISTINCT t), '[]'::jsonb)
                          FROM jsonb_array_elements(
                               COALESCE(CASE WHEN jsonb_typeof(assets.metadata->'tags') = 'array'
                                             THEN assets.metadata->'tags' END, '[]'::jsonb)
                               || $3::jsonb) AS t)) END
 WHERE id = ANY($1::uuid[])
"""


def _hint_key(hint: Mapping[str, Any]) -> str:
    return json.dumps({k: sorted(hint.get(k) or []) for k in ("ips", "hostnames", "macs")},
                      sort_keys=True)


def _strip(item: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in item.items() if k not in _MERGE_KEYS}


async def _match(con, hint: Mapping[str, Any]) -> list[UUID]:
    ips = [str(i) for i in hint.get("ips") or []]
    hosts = [str(h).lower() for h in hint.get("hostnames") or []]
    macs = [str(m).lower() for m in hint.get("macs") or []]
    if not (ips or hosts or macs):
        return []
    rows = await con.fetch(_MATCH_SQL, ips, hosts, macs, _MAX_MERGE_TARGETS)
    return [r["id"] for r in rows]


async def apply_source_batch(pool, redis, batch: SourceBatch, *, source: str) -> dict[str, int]:
    """Write a batch; return counters for the sync-run record."""
    from ..models import AssetBulkIn, EdgeBulkIn, FindingBulkIn
    from ..routers import assets as assets_router
    from ..routers import findings as findings_router

    counts = {
        "assets_inserted": 0, "assets_updated": 0, "assets_merged": 0, "merge_targets": 0,
        "assets_dropped": 0, "edges_inserted": 0, "edges_updated": 0, "edges_skipped": 0,
        "findings_inserted": 0, "findings_updated": 0, "findings_dropped": 0,
        "owners_upserted": 0,
    }

    # 1) merge items onto existing assets ------------------------------------ #
    plain: list[dict[str, Any]] = []
    matched: dict[str, list[UUID]] = {}
    async with pool.acquire() as con:
        async with con.transaction():
            for item in batch.assets:
                hint = item.get("merge_on")
                if not hint:
                    plain.append(_strip(item))
                    continue
                ids = await _match(con, hint)
                matched[_hint_key(hint)] = ids
                if ids:
                    md = dict(item.get("metadata") or {})
                    tags = md.pop("tags", None)
                    await con.execute(_MERGE_SQL, ids, json.dumps(md),
                                      json.dumps(tags) if isinstance(tags, list) else None)
                    counts["assets_merged"] += 1
                    counts["merge_targets"] += len(ids)
                elif item.get("merge_only"):
                    counts["assets_dropped"] += 1
                else:
                    plain.append(_strip(item))

    # 2) plain assets through the bulk handler -------------------------------- #
    for i in range(0, len(plain), _CHUNK):
        out = await assets_router.bulk_upsert(AssetBulkIn(items=plain[i:i + _CHUNK]),
                                              pool=pool, r=redis)
        counts["assets_inserted"] += out.inserted
        counts["assets_updated"] += out.updated

    # 3) edges ------------------------------------------------------------- #
    for i in range(0, len(batch.edges), _CHUNK):
        out = await assets_router.bulk_edges(EdgeBulkIn(edges=batch.edges[i:i + _CHUNK]),
                                             pool=pool, r=redis)
        counts["edges_inserted"] += out.edges_inserted
        counts["edges_updated"] += out.edges_updated
        counts["edges_skipped"] += out.edges_skipped_missing_endpoint

    # 4) findings: merged findings fan out to every matched asset ------------- #
    items: list[dict[str, Any]] = []
    for f in batch.findings:
        hint = f.get("merge_on")
        if hint:
            ids = matched.get(_hint_key(hint))
            if ids is None:
                async with pool.acquire() as con:
                    ids = await _match(con, hint)
            if ids:
                for aid in ids:
                    g = _strip(f)
                    g.pop("asset_value", None)
                    g.pop("asset_kind", None)
                    g["asset_id"] = aid
                    items.append(g)
                continue
            if f.get("merge_only"):
                counts["findings_dropped"] += 1
                continue
        items.append(_strip(f))
    for i in range(0, len(items), _CHUNK):
        out = await findings_router.bulk_upsert(FindingBulkIn(items=items[i:i + _CHUNK]),
                                                pool=pool, r=redis)
        counts["findings_inserted"] += out.inserted
        counts["findings_updated"] += out.updated

    # 5) owner rules ---------------------------------------------------------- #
    if batch.owners:
        async with pool.acquire() as con:
            async with con.transaction():
                for o in batch.owners:
                    name = str(o.get("name") or "")[:200]
                    team = str(o.get("team") or "")
                    if not name or not team:
                        continue
                    match = json.dumps(o.get("match") or {})
                    prio = int(o.get("priority") or 100)
                    done = await con.fetchval(
                        "UPDATE asset_owners SET match = $2::jsonb, team = $3, "
                        "contact = COALESCE($4, contact), priority = $5 "
                        "WHERE name = $1 RETURNING id",
                        name, match, team, o.get("contact"), prio,
                    )
                    if done is None:
                        await con.execute(
                            "INSERT INTO asset_owners (name, match, team, contact, priority) "
                            "VALUES ($1, $2::jsonb, $3, $4, $5)",
                            name, match, team, o.get("contact"), prio,
                        )
                    counts["owners_upserted"] += 1

    log.info("source_batch_applied", extra={"source": source, **counts})
    return counts
