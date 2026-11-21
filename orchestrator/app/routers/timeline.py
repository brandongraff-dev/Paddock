"""Timeline: per-day counts of new assets and new findings in a window,
plus a small sample of items for each day so the dashboard has something
to render without a second round-trip.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query

from ..db import get_pool
from ..models import TimelineDay, TimelineOut

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1", tags=["timeline"])


@router.get("/timeline", response_model=TimelineOut)
async def timeline(
    from_: date | None = Query(None, alias="from"),
    to: date | None = None,
    sample: int = Query(5, ge=0, le=25),
    pool=Depends(get_pool),
):
    today = datetime.now(timezone.utc).date()
    if to is None:
        to = today
    if from_ is None:
        from_ = to - timedelta(days=13)  # 14-day window default

    # Window as timestamptz: [from 00:00 UTC, to 24:00 UTC)
    start = datetime.combine(from_, time.min, tzinfo=timezone.utc)
    end = datetime.combine(to + timedelta(days=1), time.min, tzinfo=timezone.utc)

    async with pool.acquire() as con:
        asset_counts = await con.fetch(
            """
            SELECT (first_seen AT TIME ZONE 'UTC')::date AS day,
                   COUNT(*) AS c
              FROM assets
             WHERE first_seen >= $1 AND first_seen < $2
             GROUP BY 1
            """,
            start,
            end,
        )
        finding_counts = await con.fetch(
            """
            SELECT (first_seen AT TIME ZONE 'UTC')::date AS day,
                   COUNT(*) AS c
              FROM findings
             WHERE first_seen >= $1 AND first_seen < $2
             GROUP BY 1
            """,
            start,
            end,
        )
        asset_samples = []
        finding_samples = []
        if sample > 0:
            asset_samples = await con.fetch(
                """
                SELECT (first_seen AT TIME ZONE 'UTC')::date AS day,
                       id, kind, value, canonical, source, first_seen
                  FROM (
                    SELECT *,
                      ROW_NUMBER() OVER (
                        PARTITION BY (first_seen AT TIME ZONE 'UTC')::date
                        ORDER BY first_seen
                      ) AS rn
                      FROM assets
                     WHERE first_seen >= $1 AND first_seen < $2
                  ) t
                 WHERE rn <= $3
                """,
                start,
                end,
                sample,
            )
            finding_samples = await con.fetch(
                """
                SELECT (first_seen AT TIME ZONE 'UTC')::date AS day,
                       id, asset_id, rule_id, severity, title, first_seen
                  FROM (
                    SELECT *,
                      ROW_NUMBER() OVER (
                        PARTITION BY (first_seen AT TIME ZONE 'UTC')::date
                        ORDER BY severity DESC, first_seen
                      ) AS rn
                      FROM findings
                     WHERE first_seen >= $1 AND first_seen < $2
                  ) t
                 WHERE rn <= $3
                """,
                start,
                end,
                sample,
            )

    a_counts = {r["day"]: r["c"] for r in asset_counts}
    f_counts = {r["day"]: r["c"] for r in finding_counts}
    a_samples: dict[date, list[dict[str, Any]]] = {}
    for r in asset_samples:
        a_samples.setdefault(r["day"], []).append(
            {
                "id": str(r["id"]),
                "kind": r["kind"],
                "value": r["value"],
                "canonical": r["canonical"],
                "source": r["source"],
                "first_seen": r["first_seen"].isoformat(),
            }
        )
    f_samples: dict[date, list[dict[str, Any]]] = {}
    for r in finding_samples:
        f_samples.setdefault(r["day"], []).append(
            {
                "id": str(r["id"]),
                "asset_id": str(r["asset_id"]),
                "rule_id": r["rule_id"],
                "severity": r["severity"],
                "title": r["title"],
                "first_seen": r["first_seen"].isoformat(),
            }
        )

    days: list[TimelineDay] = []
    cur = from_
    while cur <= to:
        days.append(
            TimelineDay(
                day=cur,
                asset_count=int(a_counts.get(cur, 0)),
                finding_count=int(f_counts.get(cur, 0)),
                sample_assets=a_samples.get(cur, []),
                sample_findings=f_samples.get(cur, []),
            )
        )
        cur = cur + timedelta(days=1)

    return TimelineOut(**{"from": from_, "to": to, "days": days})
