"""triage service entrypoint.

Runs three cooperative pieces in one asyncio process:

  * a periodic triage loop every ``TRIAGE_INTERVAL_MIN`` minutes;
  * a ``stream:events`` subscriber (consumer group ``triage``) that runs a
    triage pass promptly on ``finding_opened``;
  * an aiohttp HTTP server on ``TRIAGE_HTTP_PORT`` (default 8093) exposing
    ``GET /healthz``, ``GET /readyz``, ``GET /stats``, ``POST /run`` and
    ``POST /resolve-owners``.

A single lock serialises passes so periodic and event-driven work never
overlap.
"""
from __future__ import annotations

import asyncio
import json
import logging
import signal
from datetime import datetime, timezone
from typing import Any, Optional

from aiohttp import web

from . import config as config_module
from .db import Database
from .dispatch import TicketDispatcher
from .events import EventSubscriber
from .tickets import TicketManager

log = logging.getLogger("triage")

_TRIGGER_EVENTS = {"finding_opened"}


class TriageService:
    def __init__(self, cfg: config_module.Config) -> None:
        self.cfg = cfg
        self.db = Database(cfg.database_url)
        self.dispatcher = TicketDispatcher(cfg)
        self.manager = TicketManager(self.db, cfg, self.dispatcher, publish=self._publish)
        self.events: Optional[EventSubscriber] = None
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[Any]] = []
        self._run_lock = asyncio.Lock()
        self._ready = False
        self.stats: dict[str, Any] = {
            "runs": 0,
            "last_run": None,
            "last_counts": None,
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
        self.events = EventSubscriber(
            self.cfg.redis_url,
            self.cfg.events_stream,
            self.cfg.consumer_group,
            self.cfg.consumer_name,
            self._on_event,
        )
        await self.events.connect()
        self._ready = True
        log.info("triage service started")

    async def stop(self) -> None:
        log.info("triage service stopping")
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        if self.events is not None:
            await self.events.close()
        await self.db.close()

    async def _publish(self, event: dict[str, Any]) -> None:
        if self.events is not None:
            await self.events.publish(event)

    # ------------------------------------------------------------------
    # passes
    # ------------------------------------------------------------------
    async def run_pass(self) -> dict[str, Any]:
        """One triage + SLA-sweep pass."""
        async with self._run_lock:
            run_start = datetime.now(timezone.utc)
            counts = await self.manager.run_pass()
            counts["run_start"] = run_start.isoformat()
            self.stats["runs"] += 1
            self.stats["last_run"] = run_start.isoformat()
            self.stats["last_counts"] = counts
            log.info(json.dumps({"event": "triage_pass", **counts}, default=str))
            return counts

    async def resolve_owners_pass(self) -> dict[str, Any]:
        async with self._run_lock:
            result = await self.manager.resolve_owners()
            log.info(json.dumps({"event": "resolve_owners", **result}, default=str))
            return result

    # ------------------------------------------------------------------
    # schedulers
    # ------------------------------------------------------------------
    async def _periodic_loop(self) -> None:
        interval_s = max(1, self.cfg.interval_min) * 60
        await asyncio.sleep(2)  # small initial delay
        while not self._stop.is_set():
            try:
                await self.run_pass()
            except asyncio.CancelledError:  # pragma: no cover
                raise
            except Exception:
                log.exception("periodic triage pass failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval_s)
            except asyncio.TimeoutError:
                continue

    async def _on_event(self, payload: dict[str, Any]) -> None:
        if payload.get("event") in _TRIGGER_EVENTS:
            try:
                await self.run_pass()
            except Exception:
                log.exception("event-driven triage pass failed")

    def _start_background(self) -> None:
        self._tasks.append(asyncio.create_task(self._periodic_loop(), name="periodic"))
        if self.events is not None:
            self._tasks.append(
                asyncio.create_task(self.events.run(self._stop), name="events")
            )

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------
    async def _handle_healthz(self, _req: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def _handle_readyz(self, _req: web.Request) -> web.Response:
        db_ok = await self.db.ping()
        redis_ok = await self.events.ping() if self.events is not None else False
        ok = self._ready and db_ok
        return web.json_response(
            {"ready": ok, "db": db_ok, "redis": redis_ok},
            status=200 if ok else 503,
        )

    async def _handle_stats(self, _req: web.Request) -> web.Response:
        db_stats = await self.db.stats()
        return web.json_response({
            "service": self.stats,
            "db": db_stats,
        })

    async def _handle_run(self, _req: web.Request) -> web.Response:
        try:
            counts = await self.run_pass()
        except Exception as exc:
            log.exception("manual /run failed")
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response(counts)

    async def _handle_resolve_owners(self, _req: web.Request) -> web.Response:
        try:
            result = await self.resolve_owners_pass()
        except Exception as exc:
            log.exception("manual /resolve-owners failed")
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response(result)

    def _make_app(self) -> web.Application:
        app = web.Application()
        app.add_routes([
            web.get("/healthz", self._handle_healthz),
            web.get("/readyz", self._handle_readyz),
            web.get("/stats", self._handle_stats),
            web.post("/run", self._handle_run),
            web.post("/resolve-owners", self._handle_resolve_owners),
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
    svc = TriageService(cfg)
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
        svc._start_background()
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
