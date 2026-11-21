"""Neo4j async driver wrapper — lazy and guarded.

The driver is created lazily and every operation is guarded, so the service
boots and stays up even when Neo4j is unreachable. ``available()`` reflects the
last known connectivity; query endpoints consult it and degrade to
``{available: false, reason}`` rather than erroring.

All writes use parameterized ``UNWIND ... MERGE`` (idempotent). All reads are
parameterized and READ-only (run in a read transaction).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

log = logging.getLogger(__name__)

try:  # optional at import time; pyproject installs it as a dependency.
    from neo4j import AsyncGraphDatabase  # type: ignore
    from neo4j.exceptions import Neo4jError  # type: ignore
    _DRIVER_IMPORT_OK = True
except Exception:  # pragma: no cover - only when neo4j is not installed
    AsyncGraphDatabase = None  # type: ignore
    Neo4jError = Exception  # type: ignore
    _DRIVER_IMPORT_OK = False


# ---------------------------------------------------------------------------
# Cypher used for schema + writes (static; no user input interpolated).
# ---------------------------------------------------------------------------
_SCHEMA_STMTS = (
    "CREATE CONSTRAINT asset_id IF NOT EXISTS "
    "FOR (a:Asset) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT finding_id IF NOT EXISTS "
    "FOR (f:Finding) REQUIRE f.id IS UNIQUE",
)

_MERGE_ASSETS = (
    "UNWIND $rows AS row\n"
    "MERGE (a:Asset {id: row.id})\n"
    "SET a.kind = row.kind, a.value = row.value, "
    "a.blast_score = row.blast_score, a.env = row.env, "
    "a.crown = row.crown, a.entry = row.entry, "
    "a.max_severity = row.max_severity, a.kev = row.kev, a.cost = row.cost"
)

_MERGE_FINDINGS = (
    "UNWIND $rows AS row\n"
    "MATCH (a:Asset {id: row.asset_id})\n"
    "MERGE (f:Finding {id: row.id})\n"
    "SET f.severity = row.severity, f.kev = row.kev\n"
    "MERGE (a)-[:HAS_FINDING]->(f)"
)

_MERGE_EDGES = (
    "UNWIND $rows AS row\n"
    "MATCH (s:Asset {id: row.src})\n"
    "MATCH (d:Asset {id: row.dst})\n"
    "MERGE (s)-[e:EDGE {kind: row.kind}]->(d)\n"
    "SET e.weight = row.weight"
)

_WIPE = "MATCH (n) DETACH DELETE n"


class Neo4jUnavailable(RuntimeError):
    """Raised internally when the driver cannot be reached."""


class NeoClient:
    def __init__(
        self,
        uri: str,
        user: str,
        password: str,
        *,
        database: str = "neo4j",
        connect_timeout_s: int = 5,
    ) -> None:
        self._uri = uri
        self._auth = (user, password)
        self._database = database
        self._timeout = connect_timeout_s
        self._driver: Any = None
        self._available = False
        self._reason: Optional[str] = "not yet connected"
        self._apoc: Optional[bool] = None
        self._lock = asyncio.Lock()

    # -- state --------------------------------------------------------------
    def available(self) -> bool:
        return self._available

    def reason(self) -> Optional[str]:
        return self._reason

    def driver_installed(self) -> bool:
        return _DRIVER_IMPORT_OK

    # -- lifecycle ----------------------------------------------------------
    async def _ensure_driver(self) -> Any:
        if not _DRIVER_IMPORT_OK:
            self._available = False
            self._reason = "neo4j driver not installed"
            raise Neo4jUnavailable(self._reason)
        if self._driver is None:
            async with self._lock:
                if self._driver is None:
                    self._driver = AsyncGraphDatabase.driver(
                        self._uri,
                        auth=self._auth,
                        connection_timeout=self._timeout,
                    )
        return self._driver

    async def close(self) -> None:
        if self._driver is not None:
            try:
                await self._driver.close()
            except Exception:  # pragma: no cover
                pass
            self._driver = None

    async def ping(self) -> bool:
        """Verify connectivity; updates ``available`` / ``reason``."""
        try:
            driver = await self._ensure_driver()
            await driver.verify_connectivity()
            self._available = True
            self._reason = None
            return True
        except Neo4jUnavailable as exc:
            self._available = False
            self._reason = str(exc)
            return False
        except Exception as exc:
            self._available = False
            self._reason = f"{type(exc).__name__}: {exc}"
            # Drop the driver so the next attempt rebuilds it cleanly.
            await self.close()
            return False

    # -- apoc probe ---------------------------------------------------------
    async def has_apoc(self, *, recheck: bool = False) -> bool:
        if self._apoc is not None and not recheck:
            return self._apoc
        try:
            rows = await self.run_read("RETURN apoc.version() AS version", {})
            self._apoc = bool(rows)
        except Exception:
            self._apoc = False
        return self._apoc

    # -- reads (query endpoints) -------------------------------------------
    async def run_read(self, cypher: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Run a READ-only parameterized query. Raises Neo4jUnavailable when
        the database cannot be reached (caller degrades)."""
        try:
            driver = await self._ensure_driver()
            async with driver.session(
                database=self._database,
                default_access_mode="READ",
            ) as session:
                result = await session.run(cypher, params)  # type: ignore[arg-type]
                data = await result.data()
            self._available = True
            self._reason = None
            return data
        except Neo4jUnavailable:
            raise
        except Exception as exc:
            self._available = False
            self._reason = f"{type(exc).__name__}: {exc}"
            await self.close()
            raise Neo4jUnavailable(self._reason) from exc

    # -- writes (sync) ------------------------------------------------------
    async def _run_write(self, cypher: str, params: dict[str, Any]) -> None:
        try:
            driver = await self._ensure_driver()
            async with driver.session(
                database=self._database,
                default_access_mode="WRITE",
            ) as session:
                await session.run(cypher, params)  # type: ignore[arg-type]
            self._available = True
            self._reason = None
        except Neo4jUnavailable:
            raise
        except Exception as exc:
            self._available = False
            self._reason = f"{type(exc).__name__}: {exc}"
            await self.close()
            raise Neo4jUnavailable(self._reason) from exc

    async def ensure_schema(self) -> None:
        for stmt in _SCHEMA_STMTS:
            await self._run_write(stmt, {})

    async def wipe(self) -> None:
        await self._run_write(_WIPE, {})

    async def merge_assets(self, rows: list[dict[str, Any]]) -> None:
        if rows:
            await self._run_write(_MERGE_ASSETS, {"rows": rows})

    async def merge_findings(self, rows: list[dict[str, Any]]) -> None:
        if rows:
            await self._run_write(_MERGE_FINDINGS, {"rows": rows})

    async def merge_edges(self, rows: list[dict[str, Any]]) -> None:
        if rows:
            await self._run_write(_MERGE_EDGES, {"rows": rows})
