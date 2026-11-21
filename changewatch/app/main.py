"""changewatch service entrypoint.

Runs three cooperative pieces in one asyncio process:

  * a periodic detection loop every ``CHANGEWATCH_INTERVAL_MIN`` minutes;
  * a ``stream:events`` subscriber (consumer group ``changewatch``) that runs a
    detection pass promptly on ``asset_added`` / ``finding_opened``;
  * an aiohttp HTTP server on ``CHANGEWATCH_HTTP_PORT`` (default 8092) exposing
    ``GET /healthz``, ``GET /readyz``, ``GET /stats`` and ``POST /run``.

A single lock serialises detection so periodic and event-driven passes never
overlap. The cursor is advanced to the pass's start time only when the pass
completes without error.
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
from . import tenancy
from .alerts import AlertDispatcher
from .db import Database
from .detect import ChangeDetector
from .events import EventSubscriber

log = logging.getLogger("changewatch")

_TRIGGER_EVENTS = {"asset_added", "finding_opened"}


class ChangewatchService:
    def __init__(self, cfg: config_module.Config) -> None:
        self.cfg = cfg
        self.db = Database(cfg.database_url)
        self.detector = ChangeDetector(self.db, cfg)
        self.dispatcher = AlertDispatcher(self.db, cfg)
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
        log.info("changewatch service started")

    async def stop(self) -> None:
        log.info("changewatch service stopping")
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

    # ------------------------------------------------------------------
    # detection pass
    # ------------------------------------------------------------------
    async def run_pass(self) -> dict[str, Any]:
        """Detect for the tenant a trigger named, else every active tenant. Each
        tenant has its own cursor, so one tenant's failure never moves another's."""
        return tenancy.merge_counts(
            await tenancy.run_for_request_or_all(self.db.pool, self.run_tenant_pass))

    async def run_tenant_pass(self) -> dict[str, Any]:
        """One detection + alert pass for the CURRENT tenant. Advances that
        tenant's cursor only on success."""
        async with self._run_lock:
            run_start = datetime.now(timezone.utc)
            since = await self.db.get_since(self.cfg.cursor_source, fallback_days=1)

            inserted = await self.detector.run(since)
            delivery = await self.dispatcher.dispatch(inserted)

            by_type: dict[str, int] = {}
            for c in inserted:
                by_type[c["change_type"]] = by_type.get(c["change_type"], 0) + 1

            # Success → advance cursor to the start of this pass.
            await self.db.set_cursor(
                self.cfg.cursor_source,
                run_start,
                stats={"last_run": run_start.isoformat(), "changes": len(inserted)},
            )

            counts = {
                "changes": len(inserted),
                "by_type": by_type,
                "deliveries": delivery,
                "since": since.isoformat(),
                "run_start": run_start.isoformat(),
            }
            self.stats["runs"] += 1
            self.stats["last_run"] = run_start.isoformat()
            self.stats["last_counts"] = counts
            log.info(json.dumps(
                {"event": "detection_pass", "tenant": tenancy.current_tenant_id(), **counts}, default=str))
            return counts

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
                log.exception("periodic detection pass failed; cursor not advanced")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval_s)
            except asyncio.TimeoutError:
                continue

    async def _on_event(self, payload: dict[str, Any]) -> None:
        if payload.get("event") in _TRIGGER_EVENTS:
            try:
                with tenancy.bind_event(payload):  # only the event's tenant is re-scanned
                    await self.run_tenant_pass()
            except tenancy.TenantError as exc:
                log.warning("dropping %s event without a usable tenant: %s", payload.get("event"), exc)
            except Exception:
                log.exception("event-driven detection pass failed")

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

    def _make_app(self) -> web.Application:
        app = web.Application(middlewares=[tenancy.aiohttp_middleware()])
        app.add_routes([
            web.get("/healthz", self._handle_healthz),
            web.get("/readyz", self._handle_readyz),
            web.get("/stats", self._handle_stats),
            web.post("/run", self._handle_run),
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
    svc = ChangewatchService(cfg)
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
