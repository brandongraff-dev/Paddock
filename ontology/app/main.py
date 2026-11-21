"""Service entrypoint.

Runs one cooperative loop:
  * Projection pass on startup, then every ``ONTOLOGY_INTERVAL_MIN`` minutes.

Plus a small aiohttp server on port 8099 for health, manual projection, stats.
This service is a pure projector: it reads the raw ASM tables and writes only
its own ``ontology_*`` tables. It never probes, resolves, or reaches the
network.
"""
from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timezone
from typing import Any

from aiohttp import web

from . import config as config_module
from . import tenancy
from .db import Database

log = logging.getLogger("ontology")


class OntologyService:
    def __init__(self, cfg: config_module.Config) -> None:
        self.cfg = cfg
        self.db = Database(cfg.database_url)
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[Any]] = []
        self._ready = False
        self._lock = asyncio.Lock()
        self.last_run: dict[str, Any] = {
            "last_run": None, "objects": 0, "links": 0,
            "pruned_objects": 0, "pruned_links": 0,
        }

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        logging.basicConfig(
            level=self.cfg.log_level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        await self.db.connect()
        await self.db.seed_types()
        self._ready = True
        log.info("ontology service started")

    async def stop(self) -> None:
        log.info("ontology service stopping")
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        await self.db.close()

    # ------------------------------------------------------------------ #
    # projection
    # ------------------------------------------------------------------ #
    async def project(self) -> dict[str, Any]:
        async with self._lock:
            res = await self.db.project()
        self.last_run = {
            "last_run": datetime.now(timezone.utc).isoformat(),
            **res,
        }
        log.info("projection complete: %s", res)
        return res

    async def project_scoped(self) -> dict[str, Any]:
        """Project the tenant a trigger named, else every active tenant: each
        tenant's graph is built from, and written to, only its own rows."""
        return tenancy.merge_counts(
            await tenancy.run_for_request_or_all(self.db.pool, self.project))

    async def _loop(self) -> None:
        interval_s = self.cfg.interval_min * 60
        if self.cfg.project_on_start:
            try:
                await self.project_scoped()
            except Exception as exc:
                log.exception("initial projection failed: %s", exc)
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval_s)
            except asyncio.TimeoutError:
                pass
            if self._stop.is_set():
                break
            try:
                await self.project_scoped()
            except asyncio.CancelledError:  # pragma: no cover
                raise
            except Exception as exc:
                log.exception("scheduled projection failed: %s", exc)

    # ------------------------------------------------------------------ #
    # HTTP
    # ------------------------------------------------------------------ #
    async def _handle_healthz(self, _req: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def _handle_readyz(self, _req: web.Request) -> web.Response:
        ok = self._ready and await self.db.ping()
        return web.json_response({"ready": ok}, status=200 if ok else 503)

    async def _handle_project(self, _req: web.Request) -> web.Response:
        try:
            res = await self.project_scoped()
        except Exception as exc:
            log.exception("manual projection failed")
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response(res)

    async def _handle_stats(self, _req: web.Request) -> web.Response:
        stats = await self.db.stats()
        return web.json_response({"stats": self.last_run, "db": stats})

    def _make_app(self) -> web.Application:
        app = web.Application(middlewares=[tenancy.aiohttp_middleware()])
        app.add_routes([
            web.get("/healthz", self._handle_healthz),
            web.get("/readyz", self._handle_readyz),
            web.post("/project", self._handle_project),
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
    svc = OntologyService(cfg)
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
        svc._tasks.append(asyncio.create_task(svc._loop()))
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
