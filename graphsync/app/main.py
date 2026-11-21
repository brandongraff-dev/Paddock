"""Service entrypoint.

Runs one cooperative sync loop (Postgres -> Neo4j) with exponential backoff
when Neo4j is unreachable, plus an aiohttp server on :8096 for the read-only
Cypher query endpoints, health, resync, and stats.

Degrade contract: if Neo4j is unreachable the service STAYS UP —
  * /healthz          -> always ok
  * /readyz           -> pg status + neo4j:down (service still serves)
  * every query route -> {available: false, reason: ...} (never a 5xx)
  * the sync loop     -> retries with capped exponential backoff
"""
from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timezone
from typing import Any

from aiohttp import web

from . import config as config_module
from . import queries
from .db import Database
from .neo import NeoClient, Neo4jUnavailable
from .sync import SyncEngine

log = logging.getLogger("graphsync")


class GraphSyncService:
    def __init__(self, cfg: config_module.Config) -> None:
        self.cfg = cfg
        self.db = Database(cfg.database_url)
        self.neo = NeoClient(
            cfg.neo4j_uri,
            cfg.neo4j_user,
            cfg.neo4j_password,
            database=cfg.neo4j_database,
            connect_timeout_s=cfg.neo4j_connect_timeout_s,
        )
        self.sync = SyncEngine(self.db, self.neo)
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[Any]] = []
        self._ready = False
        self._sync_lock = asyncio.Lock()
        self.stats: dict[str, Any] = {
            "last_sync": None,
            "last_sync_mode": None,
            "last_error": None,
            "consecutive_failures": 0,
        }

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        logging.basicConfig(
            level=self.cfg.log_level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        await self.db.connect()
        # Best-effort initial ping; failure is fine (service degrades).
        await self.neo.ping()
        self._ready = True
        log.info("graphsync service started (neo4j available=%s)", self.neo.available())

    async def stop(self) -> None:
        log.info("graphsync service stopping")
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        await self.neo.close()
        await self.db.close()

    # ------------------------------------------------------------------
    # sync
    # ------------------------------------------------------------------
    async def run_sync(self, *, full: bool = False) -> dict[str, Any]:
        async with self._sync_lock:
            summary = await self.sync.run(full=full)
        self.stats.update({
            "last_sync": datetime.now(timezone.utc).isoformat(),
            "last_sync_mode": summary["mode"],
            "last_error": None,
            "consecutive_failures": 0,
        })
        return summary

    async def _sync_loop(self) -> None:
        await asyncio.sleep(3)  # small stagger at boot
        interval_s = self.cfg.sync_interval_min * 60
        backoff = self.cfg.neo4j_backoff_base_s
        while not self._stop.is_set():
            try:
                await self.run_sync(full=False)
                backoff = self.cfg.neo4j_backoff_base_s
                wait = interval_s
            except Neo4jUnavailable as exc:
                self.stats["last_error"] = str(exc)
                self.stats["consecutive_failures"] += 1
                log.warning("sync deferred, neo4j unavailable: %s (retry in %ss)",
                            exc, backoff)
                wait = backoff
                backoff = min(self.cfg.neo4j_backoff_max_s, backoff * 2)
            except Exception as exc:
                self.stats["last_error"] = f"{type(exc).__name__}: {exc}"
                self.stats["consecutive_failures"] += 1
                log.exception("sync pass failed")
                wait = backoff
                backoff = min(self.cfg.neo4j_backoff_max_s, backoff * 2)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=wait)
            except asyncio.TimeoutError:
                continue

    # ------------------------------------------------------------------
    # query helpers (degrade-aware)
    # ------------------------------------------------------------------
    async def _degraded(self) -> web.Response | None:
        """Return a 200 degrade response when Neo4j is unreachable, else None."""
        if await self.neo.ping():
            return None
        return web.json_response(
            {"available": False, "reason": self.neo.reason() or "neo4j unavailable"}
        )

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------
    async def _handle_healthz(self, _req: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def _handle_readyz(self, _req: web.Request) -> web.Response:
        pg_ok = self._ready and await self.db.ping()
        neo_ok = await self.neo.ping()
        # The service is "ready" when it can serve requests (pg reachable);
        # Neo4j being down is surfaced but does NOT fail readiness.
        status = 200 if pg_ok else 503
        return web.json_response(
            {
                "ready": bool(pg_ok),
                "pg": "up" if pg_ok else "down",
                "neo4j": "up" if neo_ok else "down",
                "neo4j_reason": None if neo_ok else self.neo.reason(),
            },
            status=status,
        )

    async def _handle_paths(self, req: web.Request) -> web.Response:
        degraded = await self._degraded()
        if degraded is not None:
            return degraded
        source = req.query.get("source") or None
        target = req.query.get("target") or None
        max_hops = req.query.get("max", str(queries.DEFAULT_MAX_HOPS))
        limit = req.query.get("limit", "10")
        try:
            limit_i = max(1, min(100, int(limit)))
        except ValueError:
            limit_i = 10
        source_kinds = None
        if source is None:
            raw = req.query.get("source_kinds")
            if raw:
                source_kinds = [k.strip() for k in raw.split(",") if k.strip()]
        apoc = await self.neo.has_apoc()
        cypher, params = queries.build_paths_cypher(
            source=source,
            target=target,
            source_kinds=source_kinds,
            max_hops=max_hops,
            limit=limit_i,
            apoc=apoc,
        )
        try:
            rows = await self.neo.run_read(cypher, params)
        except Neo4jUnavailable as exc:
            return web.json_response({"available": False, "reason": str(exc)})
        return web.json_response({
            "available": True,
            "engine": "apoc.dijkstra" if apoc else "allShortestPaths",
            "weighting": "exploit-cost (base 10 - KEV/crit/high bonus)",
            "count": len(rows),
            "paths": rows,
        })

    async def _handle_blast(self, req: web.Request) -> web.Response:
        degraded = await self._degraded()
        if degraded is not None:
            return degraded
        asset_id = req.match_info["asset_id"]
        depth = req.query.get("depth", str(queries.DEFAULT_DEPTH))
        cypher, params = queries.build_blast_cypher(asset_id, depth)
        try:
            rows = await self.neo.run_read(cypher, params)
        except Neo4jUnavailable as exc:
            return web.json_response({"available": False, "reason": str(exc)})
        row = rows[0] if rows else {}
        severities = [s for s in (row.get("severities") or []) if s]
        return web.json_response({
            "available": True,
            "asset_id": asset_id,
            "depth": queries._clamp_depth(depth),
            "neighborhood_size": row.get("neighborhood_size", 0),
            "reachable_crown_jewels": row.get("reachable_crown_jewels", 0),
            "max_severity": queries.max_severity(severities),
            "kev_present": bool(row.get("kev_present")),
        })

    async def _handle_neighborhood(self, req: web.Request) -> web.Response:
        degraded = await self._degraded()
        if degraded is not None:
            return degraded
        asset_id = req.match_info["asset_id"]
        depth = req.query.get("depth", str(queries.DEFAULT_DEPTH))
        cypher, params = queries.build_neighborhood_cypher(
            asset_id, depth, cap=self.cfg.neighborhood_cap
        )
        try:
            rows = await self.neo.run_read(cypher, params)
        except Neo4jUnavailable as exc:
            return web.json_response({"available": False, "reason": str(exc)})
        row = rows[0] if rows else {"nodes": [], "edges": []}
        nodes = row.get("nodes") or []
        edges = row.get("edges") or []
        return web.json_response({
            "available": True,
            "asset_id": asset_id,
            "depth": queries._clamp_depth(depth),
            "capped": len(nodes) >= self.cfg.neighborhood_cap,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
        })

    async def _handle_resync(self, _req: web.Request) -> web.Response:
        try:
            summary = await self.run_sync(full=True)
        except Neo4jUnavailable as exc:
            return web.json_response(
                {"available": False, "reason": str(exc)}, status=200
            )
        except Exception as exc:
            log.exception("resync failed")
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response({"available": True, "result": summary})

    async def _handle_stats(self, _req: web.Request) -> web.Response:
        neo_counts: dict[str, Any] | None = None
        neo_reason: str | None = None
        try:
            rows = await self.neo.run_read(queries.STATS_CYPHER, {})
            neo_counts = rows[0] if rows else {}
        except Neo4jUnavailable as exc:
            neo_reason = str(exc)
        try:
            cursor = await self.db.get_cursor()
        except Exception:
            cursor = None
        cursor_stats = (cursor or {}).get("stats") if cursor else None
        last_synced = (cursor or {}).get("last_synced") if cursor else None
        if isinstance(last_synced, datetime):
            last_synced = last_synced.isoformat()
        return web.json_response({
            "service": "graphsync",
            "neo4j_available": self.neo.available(),
            "neo4j": neo_counts,
            "neo4j_reason": neo_reason,
            "sync": self.stats,
            "cursor_last_synced": last_synced,
            "cursor_stats": cursor_stats,
        })

    def _make_app(self) -> web.Application:
        app = web.Application()
        app.add_routes([
            web.get("/healthz", self._handle_healthz),
            web.get("/readyz", self._handle_readyz),
            web.get("/paths", self._handle_paths),
            web.get("/blast/{asset_id}", self._handle_blast),
            web.get("/neighborhood/{asset_id}", self._handle_neighborhood),
            web.post("/resync", self._handle_resync),
            web.get("/stats", self._handle_stats),
        ])
        return app

    async def serve(self) -> None:
        app = self._make_app()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host="0.0.0.0", port=self.cfg.http_port)
        await site.start()
        log.info("http: listening on :%d", self.cfg.http_port)
        try:
            await self._stop.wait()
        finally:
            await runner.cleanup()


async def _amain() -> None:
    cfg = config_module.load()
    svc = GraphSyncService(cfg)
    loop = asyncio.get_running_loop()

    def _signal(_s: int, _f: Any = None) -> None:
        svc._stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _signal, sig)
        except NotImplementedError:  # pragma: no cover
            signal.signal(sig, _signal)

    try:
        await svc.start()
        svc._tasks.append(asyncio.create_task(svc._sync_loop()))
        await svc.serve()
    finally:
        await svc.stop()


def main() -> None:  # pragma: no cover
    try:
        import uvloop  # type: ignore
        uvloop.install()
    except Exception:
        pass
    asyncio.run(_amain())


if __name__ == "__main__":  # pragma: no cover
    main()
