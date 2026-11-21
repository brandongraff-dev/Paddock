"""Asyncpg connection pool + helpers for the SCA tables.

SCA owns writes to ``sca_projects``, ``sbom_components``,
``sbom_component_vulns`` and ``supply_chain_risks``. Everything else (findings,
assets) goes through the orchestrator HTTP API. All queries use one pool.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Optional
from uuid import UUID

import asyncpg

log = logging.getLogger("sca.db")


async def _init_connection(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec(
        "jsonb",
        encoder=lambda v: json.dumps(v, default=str),
        decoder=json.loads,
        schema="pg_catalog",
    )
    await conn.set_type_codec(
        "json",
        encoder=lambda v: json.dumps(v, default=str),
        decoder=json.loads,
        schema="pg_catalog",
    )


def _clean(row: Optional[asyncpg.Record]) -> Optional[dict[str, Any]]:
    if row is None:
        return None
    d = dict(row)
    for k, v in list(d.items()):
        if isinstance(v, UUID):
            d[k] = str(v)
    return d


class Database:
    """Thin wrapper around an asyncpg pool."""

    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 8) -> None:
        self.dsn = dsn
        self._min = min_size
        self._max = max_size
        self._pool: Optional[asyncpg.Pool] = None

    async def connect(self, min_size: int | None = None, max_size: int | None = None) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            dsn=self.dsn,
            min_size=min_size or self._min,
            max_size=max_size or self._max,
            init=_init_connection,
            command_timeout=60,
        )
        log.info("db: pool connected")

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("db pool not initialised; call connect()")
        return self._pool

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[asyncpg.Connection]:
        async with self.pool.acquire() as conn:
            yield conn

    async def fetch(self, sql: str, *args: Any) -> list[asyncpg.Record]:
        async with self.acquire() as conn:
            return await conn.fetch(sql, *args)

    async def fetchrow(self, sql: str, *args: Any) -> Optional[asyncpg.Record]:
        async with self.acquire() as conn:
            return await conn.fetchrow(sql, *args)

    async def fetchval(self, sql: str, *args: Any) -> Any:
        async with self.acquire() as conn:
            return await conn.fetchval(sql, *args)

    async def execute(self, sql: str, *args: Any) -> str:
        async with self.acquire() as conn:
            return await conn.execute(sql, *args)

    async def ping(self) -> bool:
        try:
            async with self.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("db ping failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # sca_projects
    # ------------------------------------------------------------------
    async def upsert_project(
        self,
        name: str,
        source_ref: Optional[str],
        ecosystems: list[str],
        asset_id: Optional[str] = None,
    ) -> dict[str, Any]:
        row = await self.fetchrow(
            """
            INSERT INTO sca_projects (name, source_ref, ecosystems, asset_id, last_scanned)
            VALUES ($1, $2, $3::text[], $4::uuid, NOW())
            ON CONFLICT (name) DO UPDATE SET
                source_ref   = COALESCE(EXCLUDED.source_ref, sca_projects.source_ref),
                ecosystems   = EXCLUDED.ecosystems,
                asset_id     = COALESCE(EXCLUDED.asset_id, sca_projects.asset_id),
                last_scanned = NOW()
            RETURNING id::text, name, source_ref, ecosystems, asset_id::text,
                      created_at, last_scanned
            """,
            name, source_ref, ecosystems, asset_id,
        )
        return _clean(row)  # type: ignore[return-value]

    async def upsert_component(self, project_id: str, c: dict[str, Any]) -> dict[str, Any]:
        purl = _purl(c)
        row = await self.fetchrow(
            """
            INSERT INTO sbom_components
                (project_id, ecosystem, name, version, purl, direct, depth, paths, metadata, last_seen)
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, NOW())
            ON CONFLICT (project_id, ecosystem, name, version) DO UPDATE SET
                direct    = sbom_components.direct OR EXCLUDED.direct,
                depth     = LEAST(sbom_components.depth, EXCLUDED.depth),
                purl      = EXCLUDED.purl,
                paths     = EXCLUDED.paths,
                metadata  = sbom_components.metadata || EXCLUDED.metadata,
                last_seen = NOW()
            RETURNING id::text, ecosystem, name, version, direct, depth
            """,
            project_id, c["ecosystem"], c["name"], c["version"], purl,
            bool(c.get("direct")), int(c.get("depth") or 0),
            c.get("paths") or [], c.get("metadata") or {},
        )
        return _clean(row)  # type: ignore[return-value]

    async def upsert_vuln(self, component_id: str, v: dict[str, Any]) -> bool:
        row = await self.fetchrow(
            """
            INSERT INTO sbom_component_vulns
                (component_id, osv_id, cve_id, severity, cvss, summary, fixed_version, refs)
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8::jsonb)
            ON CONFLICT (component_id, osv_id) DO UPDATE SET
                cve_id        = EXCLUDED.cve_id,
                severity      = EXCLUDED.severity,
                cvss          = EXCLUDED.cvss,
                summary       = EXCLUDED.summary,
                fixed_version = EXCLUDED.fixed_version,
                refs          = EXCLUDED.refs,
                matched_at    = NOW()
            RETURNING (xmax = 0) AS inserted
            """,
            component_id, v.get("osv_id"), v.get("cve_id"),
            v.get("severity") or "medium", v.get("cvss"),
            v.get("summary"), v.get("fixed_version"), v.get("refs") or [],
        )
        return bool(row and row["inserted"])

    async def upsert_risk(self, project_id: str, component_id: Optional[str], r: dict[str, Any]) -> bool:
        row = await self.fetchrow(
            """
            INSERT INTO supply_chain_risks
                (project_id, component_id, risk_type, severity, summary, detail)
            VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb)
            ON CONFLICT (project_id, component_id, risk_type) DO UPDATE SET
                severity    = EXCLUDED.severity,
                summary     = EXCLUDED.summary,
                detail      = EXCLUDED.detail,
                detected_at = NOW()
            RETURNING (xmax = 0) AS inserted
            """,
            project_id, component_id, r["risk_type"],
            r.get("severity") or "medium", r["summary"], r.get("detail") or {},
        )
        return bool(row and row["inserted"])

    async def stats(self) -> dict[str, Any]:
        async with self.acquire() as conn:
            projects = await conn.fetchval("SELECT COUNT(*) FROM sca_projects")
            components = await conn.fetchval("SELECT COUNT(*) FROM sbom_components")
            vulns = await conn.fetchval("SELECT COUNT(*) FROM sbom_component_vulns")
            vuln_components = await conn.fetchval(
                "SELECT COUNT(DISTINCT component_id) FROM sbom_component_vulns"
            )
            risk_rows = await conn.fetch(
                "SELECT risk_type, COUNT(*) AS n FROM supply_chain_risks GROUP BY risk_type"
            )
        return {
            "projects": int(projects or 0),
            "components": int(components or 0),
            "vulns": int(vulns or 0),
            "vulnerable_components": int(vuln_components or 0),
            "risks_by_type": {r["risk_type"]: int(r["n"]) for r in risk_rows},
        }


def _purl(c: dict[str, Any]) -> Optional[str]:
    """Build a Package-URL (purl) for a component; best-effort."""
    eco = c.get("ecosystem")
    name = c.get("name")
    version = c.get("version")
    if not name or not version:
        return None
    purl_type = {
        "npm": "npm", "PyPI": "pypi", "Go": "golang",
        "crates.io": "cargo", "Maven": "maven", "RubyGems": "gem",
    }.get(eco)
    if not purl_type:
        return None
    if purl_type == "maven" and ":" in name:
        group, _, artifact = name.partition(":")
        return f"pkg:maven/{group}/{artifact}@{version}"
    return f"pkg:{purl_type}/{name}@{version}"
