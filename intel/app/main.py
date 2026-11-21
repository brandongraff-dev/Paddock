"""Service entrypoint.

Runs four cooperative loops:
  * NVD sync every ``SYNC_INTERVAL_MIN`` minutes
  * KEV sync every 6 hours
  * EPSS sync once a day
  * Linker batch pass every ``LINKER_INTERVAL_MIN`` minutes
  * Redis stream subscriber for ``asset_added`` events (event-driven linker)

Plus a small aiohttp server on port 8090 for health, manual sync, stats.
"""
from __future__ import annotations

import asyncio
import json
import logging
import signal
from datetime import datetime, timezone
from typing import Any

import aiohttp
from aiohttp import web

from . import config as config_module
from .db import Database
from .orchestrator import OrchestratorClient
from .sources import nvd as nvd_source
from .sources import epss as epss_source
from .sources import kev as kev_source
from .matchers import linker as linker_module


log = logging.getLogger("intel")


# ---------------------------------------------------------------------------
# Service state
# ---------------------------------------------------------------------------
class IntelService:
    def __init__(self, cfg: config_module.Config) -> None:
        self.cfg = cfg
        self.db = Database(cfg.database_url)
        self._http: aiohttp.ClientSession | None = None
        self.orch: OrchestratorClient | None = None
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[Any]] = []
        self._ready = False
        # Simple in-process stats, mirrored into intel_cursors.
        self.stats: dict[str, dict[str, Any]] = {
            "nvd": {"last_run": None, "ingested": 0, "changed": 0},
            "epss": {"last_run": None, "updated": 0},
            "kev": {"last_run": None, "marked": 0},
            "linker": {"last_run": None, "assets": 0, "matches": 0, "findings": 0},
        }
        self._sync_locks: dict[str, asyncio.Lock] = {
            "nvd": asyncio.Lock(),
            "epss": asyncio.Lock(),
            "kev": asyncio.Lock(),
            "linker": asyncio.Lock(),
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
        timeout = aiohttp.ClientTimeout(total=self.cfg.http_timeout_s)
        self._http = aiohttp.ClientSession(
            timeout=timeout, headers={"User-Agent": self.cfg.user_agent}
        )
        self.orch = OrchestratorClient(
            self.cfg.orchestrator_url,
            timeout_s=self.cfg.http_timeout_s,
            user_agent=self.cfg.user_agent,
        )
        await self.orch.ensure()
        self._ready = True
        log.info("intel service started")

    async def stop(self) -> None:
        log.info("intel service stopping")
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        if self.orch is not None:
            await self.orch.close()
        if self._http is not None:
            await self._http.close()
        await self.db.close()

    # ------------------------------------------------------------------
    # source wrappers
    # ------------------------------------------------------------------
    async def sync_nvd(self) -> dict[str, Any]:
        assert self._http is not None
        async with self._sync_locks["nvd"]:
            res = await nvd_source.sync(
                self.db,
                self._http,
                api_key=self.cfg.nvd_api_key,
                bootstrap_days=self.cfg.nvd_bootstrap_days,
            )
        self.stats["nvd"] = {
            "last_run": datetime.now(timezone.utc).isoformat(),
            **res,
        }
        return res

    async def sync_epss(self) -> dict[str, Any]:
        assert self._http is not None
        async with self._sync_locks["epss"]:
            res = await epss_source.sync(self.db, self._http)
        self.stats["epss"] = {
            "last_run": datetime.now(timezone.utc).isoformat(),
            **res,
        }
        return res

    async def sync_kev(self) -> dict[str, Any]:
        assert self._http is not None
        async with self._sync_locks["kev"]:
            res = await kev_source.sync(self.db, self._http)
        self.stats["kev"] = {
            "last_run": datetime.now(timezone.utc).isoformat(),
            **res,
        }
        return res

    async def run_linker(self) -> dict[str, Any]:
        assert self.orch is not None
        async with self._sync_locks["linker"]:
            res = await linker_module.run_all(
                self.db,
                self.orch,
                min_finding_confidence=self.cfg.finding_min_confidence,
            )
        self.stats["linker"] = {
            "last_run": datetime.now(timezone.utc).isoformat(),
            **res,
        }
        return res

    # ------------------------------------------------------------------
    # schedulers
    # ------------------------------------------------------------------
    async def _loop(self, name: str, interval_s: float, fn) -> None:
        # Initial delay so we don't hammer every feed at t=0; stagger.
        await asyncio.sleep({"nvd": 2, "kev": 8, "epss": 20, "linker": 30}.get(name, 5))
        while not self._stop.is_set():
            try:
                await fn()
            except asyncio.CancelledError:  # pragma: no cover
                raise
            except Exception as exc:
                log.exception("%s loop error: %s", name, exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval_s)
            except asyncio.TimeoutError:
                continue

    async def _run_scheduler(self) -> None:
        if self.cfg.enable_nvd:
            self._tasks.append(asyncio.create_task(
                self._loop("nvd", self.cfg.sync_interval_min * 60, self.sync_nvd)
            ))
        if self.cfg.enable_kev:
            self._tasks.append(asyncio.create_task(
                self._loop("kev", 6 * 60 * 60, self.sync_kev)
            ))
        if self.cfg.enable_epss:
            self._tasks.append(asyncio.create_task(
                self._loop("epss", 24 * 60 * 60, self.sync_epss)
            ))
        self._tasks.append(asyncio.create_task(
            self._loop("linker", self.cfg.linker_interval_min * 60, self.run_linker)
        ))

    # ------------------------------------------------------------------
    # event subscriber
    # ------------------------------------------------------------------
    async def _run_event_loop(self) -> None:
        """Consume Redis stream:events for ``asset_added`` on `technology`."""
        try:
            import redis.asyncio as redis  # type: ignore
        except Exception:
            log.warning("redis library not available; skipping event loop")
            return
        try:
            # socket_timeout > XREADGROUP block (redis-py >= 6 defaults it to 5s).
            client = redis.from_url(self.cfg.redis_url, decode_responses=True, socket_timeout=30)
        except Exception as exc:  # pragma: no cover
            log.warning("redis connect failed: %s", exc)
            return

        last_id = "$"  # only new events
        while not self._stop.is_set():
            try:
                resp = await client.xread({"stream:events": last_id},
                                          count=50, block=5000)
            except Exception as exc:
                log.warning("redis xread failed: %s", exc)
                await asyncio.sleep(2)
                continue
            if not resp:
                continue
            for _stream, entries in resp:
                for entry_id, fields in entries:
                    last_id = entry_id
                    try:
                        await self._handle_event(fields)
                    except Exception:
                        log.exception("event handler failed")
        try:
            await client.aclose()
        except Exception:
            pass

    async def _handle_event(self, fields: dict[str, Any]) -> None:
        # Redis stream fields come through as strings; our contract uses either
        # a single 'data' field with a JSON blob, or individual fields.
        if "data" in fields and isinstance(fields["data"], str):
            try:
                payload = json.loads(fields["data"])
            except json.JSONDecodeError:
                return
        else:
            payload = {k: v for k, v in fields.items()}
        event = payload.get("event")
        if event != "asset_added":
            return
        if payload.get("kind") != "technology":
            return
        asset_id = payload.get("asset_id")
        if not asset_id or self.orch is None:
            return
        asset = await self.orch.get_asset(asset_id)
        if not asset:
            return
        await linker_module.match_one_asset(
            self.db,
            self.orch,
            asset,
            min_finding_confidence=self.cfg.finding_min_confidence,
        )

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------
    async def _handle_healthz(self, _req: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def _handle_readyz(self, _req: web.Request) -> web.Response:
        ok = self._ready and await self.db.ping()
        status = 200 if ok else 503
        return web.json_response({"ready": ok}, status=status)

    async def _handle_sync(self, req: web.Request) -> web.Response:
        source = req.match_info["source"].lower()
        try:
            if source == "nvd":
                res = await self.sync_nvd()
            elif source == "epss":
                res = await self.sync_epss()
            elif source == "kev":
                res = await self.sync_kev()
            elif source == "linker":
                res = await self.run_linker()
            else:
                return web.json_response({"error": f"unknown source: {source}"}, status=404)
        except Exception as exc:
            log.exception("manual sync %s failed", source)
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response({"source": source, "result": res})

    async def _handle_stats(self, _req: web.Request) -> web.Response:
        counters = await self.db.counters()
        cursors = await self.db.all_cursors()
        # Cursors carry timestamps that aren't JSON by default — coerce.
        safe_cursors = []
        for c in cursors:
            ls = c.get("last_synced")
            if isinstance(ls, datetime):
                c["last_synced"] = ls.isoformat()
            safe_cursors.append(c)
        return web.json_response({
            "stats": self.stats,
            "db": counters,
            "cursors": safe_cursors,
        })

    def _make_app(self) -> web.Application:
        app = web.Application()
        app.add_routes([
            web.get("/healthz", self._handle_healthz),
            web.get("/readyz", self._handle_readyz),
            web.post("/sync/{source}", self._handle_sync),
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
    svc = IntelService(cfg)
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
        await svc._run_scheduler()
        event_task = asyncio.create_task(svc._run_event_loop())
        svc._tasks.append(event_task)
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
