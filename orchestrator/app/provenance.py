"""Provenance / lineage: how the platform came to believe each fact.

A ``provenance`` row records, per produced fact (asset/finding/...), which
service produced it, by what method, with what evidence and confidence. This
module provides the append + bulk helpers used by ingest endpoints and the
``/v1/provenance`` lookup + one-time ``backfill`` from existing ``source``
columns.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Iterable
from uuid import UUID

logger = logging.getLogger(__name__)

SUBJECT_TYPES = ("asset", "finding", "attack_path", "sbom_component", "ticket", "anomaly")

# Map a subject_type to (table, source_column) for the one-time backfill.
_BACKFILL_SOURCES: dict[str, tuple[str, str]] = {
    "asset": ("assets", "source"),
    "finding": ("findings", "rule_source"),
}


async def record_one(
    con,
    *,
    subject_type: str,
    subject_id: UUID | str,
    source_service: str,
    source_detail: str | None = None,
    method: str | None = None,
    evidence: dict[str, Any] | None = None,
    confidence: int = 100,
) -> Any:
    """Insert a single provenance row on an existing connection/transaction."""
    return await con.fetchrow(
        """
        INSERT INTO provenance (
            subject_type, subject_id, source_service, source_detail, method,
            evidence, confidence
        ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)
        RETURNING id, subject_type, subject_id, source_service, source_detail,
                  method, evidence, confidence, recorded_at
        """,
        subject_type,
        subject_id if isinstance(subject_id, UUID) else UUID(str(subject_id)),
        source_service,
        source_detail,
        method,
        json.dumps(evidence or {}, default=str),
        int(confidence),
    )


async def record_bulk(pool, items: Iterable[dict[str, Any]]) -> int:
    """Insert many provenance rows (own transaction). Returns the count."""
    rows = list(items)
    if not rows:
        return 0
    async with pool.acquire() as con:
        async with con.transaction():
            for it in rows:
                await record_one(
                    con,
                    subject_type=it["subject_type"],
                    subject_id=it["subject_id"],
                    source_service=it.get("source_service", "unknown"),
                    source_detail=it.get("source_detail"),
                    method=it.get("method"),
                    evidence=it.get("evidence"),
                    confidence=it.get("confidence", 100),
                )
    return len(rows)


async def fetch_for_subject(
    pool, subject_type: str, subject_id: UUID | str
) -> list[dict[str, Any]]:
    sid = subject_id if isinstance(subject_id, UUID) else UUID(str(subject_id))
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, subject_type, subject_id, source_service, source_detail,
                   method, evidence, confidence, recorded_at
              FROM provenance
             WHERE subject_type = $1 AND subject_id = $2
             ORDER BY recorded_at ASC
            """,
            subject_type,
            sid,
        )
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get("evidence"), str):
            d["evidence"] = json.loads(d["evidence"])
        out.append(d)
    return out


async def backfill(pool) -> dict[str, int]:
    """One-time: synthesise provenance rows from existing ``source`` columns.

    Idempotent: only inserts a backfill row for a subject that has no existing
    ``import``/backfill provenance yet, so re-running does not duplicate.
    """
    created: dict[str, int] = {}
    async with pool.acquire() as con:
        async with con.transaction():
            for subject_type, (table, src_col) in _BACKFILL_SOURCES.items():
                rows = await con.fetch(
                    f"""
                    SELECT t.id AS sid, t.{src_col} AS src
                      FROM {table} t
                     WHERE NOT EXISTS (
                        SELECT 1 FROM provenance p
                         WHERE p.subject_type = $1
                           AND p.subject_id = t.id
                           AND p.method = 'import'
                     )
                    """,
                    subject_type,
                )
                n = 0
                for r in rows:
                    await record_one(
                        con,
                        subject_type=subject_type,
                        subject_id=r["sid"],
                        source_service=str(r["src"] or "unknown"),
                        source_detail="backfilled from source column",
                        method="import",
                        evidence={"backfill": True, "source_column": src_col},
                        confidence=100,
                    )
                    n += 1
                created[subject_type] = n
    return created
