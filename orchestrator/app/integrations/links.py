"""Persistence for two-way ticket sync: which external object mirrors which finding.

Thin helpers over ``integration_links`` (schema 015). Every function takes
either an asyncpg ``Pool`` or an already-acquired ``Connection`` so callers
can run them inside their own transaction.

The table has two uniqueness rules -- one external object per (integration,
finding) and one finding per (integration, external id) -- so ``upsert`` is
"last writer wins": re-pointing an external id at a different finding moves
the link instead of failing.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, AsyncIterator, Optional
from uuid import UUID

__all__ = [
    "Link",
    "get_by_finding",
    "get_by_external",
    "upsert",
    "set_external_status",
    "delete",
]

_COLS = (
    "id, integration_id, finding_id, external_id, external_url, "
    "external_status, created_at, updated_at"
)


@dataclass(frozen=True)
class Link:
    id: int
    integration_id: str
    finding_id: str
    external_id: str
    external_url: Optional[str]
    external_status: Optional[str]
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_row(cls, row: Any) -> "Link":
        return cls(
            id=int(row["id"]),
            integration_id=str(row["integration_id"]),
            finding_id=str(row["finding_id"]),
            external_id=row["external_id"],
            external_url=row["external_url"],
            external_status=row["external_status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


@asynccontextmanager
async def _conn(db: Any) -> AsyncIterator[Any]:
    """Yield a connection from a pool, or pass a connection straight through."""
    if hasattr(db, "acquire"):
        async with db.acquire() as con:
            yield con
    else:
        yield db


def _uuid(value: Any) -> UUID:
    return value if isinstance(value, UUID) else UUID(str(value))


async def get_by_finding(db: Any, integration_id: Any, finding_id: Any) -> Optional[Link]:
    async with _conn(db) as con:
        row = await con.fetchrow(
            f"SELECT {_COLS} FROM integration_links WHERE integration_id = $1 AND finding_id = $2",
            _uuid(integration_id), _uuid(finding_id),
        )
    return Link.from_row(row) if row else None


async def get_by_external(db: Any, integration_id: Any, external_id: str) -> Optional[Link]:
    async with _conn(db) as con:
        row = await con.fetchrow(
            f"SELECT {_COLS} FROM integration_links WHERE integration_id = $1 AND external_id = $2",
            _uuid(integration_id), str(external_id),
        )
    return Link.from_row(row) if row else None


async def upsert(
    db: Any,
    integration_id: Any,
    finding_id: Any,
    external_id: str,
    external_url: Optional[str] = None,
    external_status: Optional[str] = None,
) -> Link:
    """Create or update the link for (integration, finding).

    ``external_url`` / ``external_status`` are only overwritten when given
    (``None`` keeps what is stored).
    """
    iid, fid, ext = _uuid(integration_id), _uuid(finding_id), str(external_id)
    async with _conn(db) as con:
        async with con.transaction():
            # The external object may currently point at another finding
            # (e.g. a ticket re-linked by hand): move it.
            await con.execute(
                "DELETE FROM integration_links "
                "WHERE integration_id = $1 AND external_id = $2 AND finding_id <> $3",
                iid, ext, fid,
            )
            row = await con.fetchrow(
                f"""
                INSERT INTO integration_links
                       (integration_id, finding_id, external_id, external_url, external_status)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (integration_id, finding_id) DO UPDATE
                   SET external_id     = EXCLUDED.external_id,
                       external_url    = COALESCE(EXCLUDED.external_url, integration_links.external_url),
                       external_status = COALESCE(EXCLUDED.external_status, integration_links.external_status),
                       updated_at      = NOW()
                RETURNING {_COLS}
                """,
                iid, fid, ext, external_url, external_status,
            )
    return Link.from_row(row)


async def set_external_status(
    db: Any, integration_id: Any, external_id: str, external_status: Optional[str]
) -> bool:
    """Record the external system's current status. Returns False if no link."""
    async with _conn(db) as con:
        res = await con.execute(
            "UPDATE integration_links SET external_status = $3, updated_at = NOW() "
            "WHERE integration_id = $1 AND external_id = $2",
            _uuid(integration_id), str(external_id), external_status,
        )
    return res.endswith(" 1")


async def delete(db: Any, integration_id: Any, finding_id: Any) -> bool:
    async with _conn(db) as con:
        res = await con.execute(
            "DELETE FROM integration_links WHERE integration_id = $1 AND finding_id = $2",
            _uuid(integration_id), _uuid(finding_id),
        )
    return res.endswith(" 1")
