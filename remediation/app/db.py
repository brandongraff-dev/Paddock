"""Asyncpg pool + helpers for the remediation tables.

We OWN writes to ``remediations`` (schema 014). We READ findings (003), the
SCA tables (009: sbom_component_vulns / sbom_components / sca_projects) and
assets to resolve a fix. The authoritative OSV ``fixed_version`` is read from
``sbom_component_vulns`` HERE — never taken from attacker-influenceable finding
text.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import asyncpg

log = logging.getLogger("remediation.db")


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


class Database:
    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 8) -> None:
        self.dsn = dsn
        self._min = min_size
        self._max = max_size
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            dsn=self.dsn, min_size=self._min, max_size=self._max,
            init=_init_connection, command_timeout=60,
        )
        log.info("db: pool connected (%s/%s)", self._min, self._max)

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

    async def ping(self) -> bool:
        try:
            async with self.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("db ping failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # findings (read)
    # ------------------------------------------------------------------
    async def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        async with self.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT f.id, f.asset_id, f.rule_id, f.rule_source, f.severity,
                       f.title, f.description, f.impact, f.remediation,
                       f.evidence, f.cvss, f.epss, f.status, f.metadata,
                       a.kind AS asset_kind, a.value AS asset_value
                  FROM findings f
                  LEFT JOIN assets a ON a.id = f.asset_id
                 WHERE f.id = $1
                """,
                finding_id,
            )
        if not row:
            return None
        d = dict(row)
        d["id"] = str(d["id"])
        d["asset"] = {"kind": d.pop("asset_kind", None), "value": d.pop("asset_value", None)}
        return d

    # ------------------------------------------------------------------
    # dependency spec (read; the DB is the source of fixed_version)
    # ------------------------------------------------------------------
    async def resolve_dependency_spec(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        """Resolve the AUTHORITATIVE bump spec from the SCA tables.

        Lookup keys (component_id / osv_id / ecosystem+package) come from the
        finding, but the returned ``fixed_version`` is strictly the value stored
        in ``sbom_component_vulns`` — the DB, not the model, not finding text.
        """
        keys = _lookup_keys(finding)
        component_id = keys.get("component_id")
        osv_id = keys.get("osv_id")
        ecosystem = keys.get("ecosystem")
        package = keys.get("package")
        current = keys.get("current_version")

        base = (
            "SELECT c.ecosystem, c.name AS package, c.version AS current_version, "
            "       v.osv_id, v.cve_id, v.fixed_version, p.source_ref AS repo "
            "  FROM sbom_component_vulns v "
            "  JOIN sbom_components c ON c.id = v.component_id "
            "  LEFT JOIN sca_projects p ON p.id = c.project_id "
        )
        async with self.acquire() as conn:
            row = None
            if component_id:
                row = await conn.fetchrow(
                    base + "WHERE v.component_id = $1 "
                    "  AND ($2::text IS NULL OR v.osv_id = $2) "
                    "ORDER BY v.fixed_version IS NULL, v.matched_at DESC LIMIT 1",
                    component_id, osv_id,
                )
            if row is None and osv_id:
                row = await conn.fetchrow(
                    base + "WHERE v.osv_id = $1 "
                    "ORDER BY v.fixed_version IS NULL, v.matched_at DESC LIMIT 1",
                    osv_id,
                )
            if row is None and ecosystem and package:
                row = await conn.fetchrow(
                    base + "WHERE lower(c.ecosystem) = lower($1) AND lower(c.name) = lower($2) "
                    "  AND ($3::text IS NULL OR c.version = $3) "
                    "ORDER BY v.fixed_version IS NULL, v.matched_at DESC LIMIT 1",
                    ecosystem, package, current,
                )
        if row is None:
            return None
        return dict(row)

    # ------------------------------------------------------------------
    # remediations (write + read)
    # ------------------------------------------------------------------
    async def insert_remediation(self, rec: dict[str, Any]) -> dict[str, Any]:
        async with self.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO remediations (
                    finding_id, repo, kind, summary, base_branch, head_branch,
                    diff, status, verifier_report, injection_checks,
                    pr_url, pr_number, created_by, verified_at
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                RETURNING id, finding_id, repo, kind, summary, base_branch,
                          head_branch, diff, status, verifier_report,
                          injection_checks, pr_url, pr_number, created_by,
                          created_at, verified_at
                """,
                rec.get("finding_id"),
                rec.get("repo"),
                rec["kind"],
                rec["summary"],
                rec.get("base_branch"),
                rec.get("head_branch"),
                rec.get("diff"),
                rec.get("status", "proposed"),
                rec.get("verifier_report") or {},
                rec.get("injection_checks") or {},
                rec.get("pr_url"),
                rec.get("pr_number"),
                rec.get("created_by"),
                rec.get("verified_at"),
            )
        return _normalize_remediation(dict(row))

    async def get_remediation(self, rid: str) -> dict[str, Any] | None:
        async with self.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM remediations WHERE id = $1", rid)
        return _normalize_remediation(dict(row)) if row else None

    async def list_remediations(
        self, status: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        args: list[Any] = []
        if status:
            args.append(status)
            clauses.append(f"status = ${len(args)}")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        args_list = list(args)
        args_list.extend([limit, offset])
        async with self.acquire() as conn:
            total = await conn.fetchval(
                f"SELECT COUNT(*) FROM remediations {where}", *args
            )
            rows = await conn.fetch(
                f"SELECT * FROM remediations {where} "
                f"ORDER BY created_at DESC LIMIT ${len(args_list)-1} OFFSET ${len(args_list)}",
                *args_list,
            )
        return [_normalize_remediation(dict(r)) for r in rows], int(total or 0)

    async def stats(self) -> dict[str, Any]:
        async with self.acquire() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM remediations")
            by_status = await conn.fetch(
                "SELECT status, COUNT(*) AS c FROM remediations GROUP BY status"
            )
            by_kind = await conn.fetch(
                "SELECT kind, COUNT(*) AS c FROM remediations GROUP BY kind"
            )
        return {
            "total": int(total or 0),
            "by_status": {r["status"]: int(r["c"]) for r in by_status},
            "by_kind": {r["kind"]: int(r["c"]) for r in by_kind},
        }


def _lookup_keys(finding: dict[str, Any]) -> dict[str, Any]:
    ev = finding.get("evidence") or {}
    meta = finding.get("metadata") or {}
    if not isinstance(ev, dict):
        ev = {}
    if not isinstance(meta, dict):
        meta = {}
    merged = {**meta, **ev}
    return {
        "component_id": merged.get("component_id"),
        "osv_id": merged.get("osv_id") or merged.get("ghsa_id"),
        "ecosystem": merged.get("ecosystem"),
        "package": merged.get("package") or merged.get("name"),
        "current_version": merged.get("current_version") or merged.get("version"),
    }


def _normalize_remediation(d: dict[str, Any]) -> dict[str, Any]:
    for key in ("id", "finding_id"):
        if d.get(key) is not None:
            d[key] = str(d[key])
    for key in ("verifier_report", "injection_checks"):
        v = d.get(key)
        if isinstance(v, str):
            try:
                d[key] = json.loads(v)
            except Exception:
                d[key] = {}
        elif v is None:
            d[key] = {}
    for key in ("created_at", "verified_at"):
        v = d.get(key)
        if isinstance(v, datetime):
            d[key] = v.isoformat()
    return d


def now() -> datetime:
    return datetime.now(timezone.utc)
