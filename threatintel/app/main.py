"""Service entrypoint.

Runs a scheduler loop (poll every enabled feed every ``TI_POLL_INTERVAL_MIN``
minutes, then re-match) plus an aiohttp HTTP server on port 8100:

  GET  /healthz /readyz /stats
  POST /ingest/stix        body: a STIX bundle, or {"url": "..."} (user feed)
  POST /feeds              register a TAXII / STIX_URL feed
  GET  /feeds              list feeds
  POST /poll/{feed_id}     poll one feed now
  POST /match              re-run matching

SAFETY: outbound HTTP only ever targets a user-configured feed URL (see
app/__init__.py). Matching is read-only over the owner's own assets/findings.
"""
from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timezone
from typing import Any

import aiohttp
from aiohttp import web

from . import config as config_module
from . import match as match_module
from . import stix
from . import taxii as taxii_module
from .db import Database
from .orchestrator import OrchestratorClient

log = logging.getLogger("threatintel")


class ThreatIntelService:
    def __init__(self, cfg: config_module.Config) -> None:
        self.cfg = cfg
        self.db = Database(cfg.database_url)
        self._http: aiohttp.ClientSession | None = None
        self.orch: OrchestratorClient | None = None
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[Any]] = []
        self._ready = False
        self._poll_lock = asyncio.Lock()
        self._match_lock = asyncio.Lock()
        self.last_run: dict[str, Any] = {"poll": None, "match": None}

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
        log.info("threatintel service started")

    async def stop(self) -> None:
        log.info("threatintel service stopping")
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
    # work
    # ------------------------------------------------------------------
    async def ingest_bundle(
        self, bundle: Any, *, feed_id: str | None = None, source: str | None = None
    ) -> dict[str, Any]:
        records = stix.parse_bundle(bundle, source=source)
        inserted = 0
        for rec in records:
            res = await self.db.upsert_indicator(rec, feed_id=feed_id)
            if res.get("inserted"):
                inserted += 1
        return {"parsed": len(records), "inserted": inserted}

    async def poll_all(self) -> dict[str, Any]:
        assert self._http is not None
        async with self._poll_lock:
            feeds = await self.db.list_feeds(enabled_only=True)
            results = []
            for feed in feeds:
                res = await taxii_module.poll_feed(
                    self.db, self._http, feed,
                    timeout_s=self.cfg.poll_timeout_s,
                    max_pages=self.cfg.max_poll_pages,
                )
                results.append(res)
        summary = {
            "feeds": len(feeds),
            "inserted": sum(r.get("inserted", 0) for r in results),
            "results": results,
        }
        self.last_run["poll"] = {"at": datetime.now(timezone.utc).isoformat(), **summary}
        return summary

    async def poll_one(self, feed_id: str) -> dict[str, Any]:
        assert self._http is not None
        feed = await self.db.get_feed(feed_id)
        if feed is None:
            return {"error": "feed not found", "feed_id": feed_id}
        async with self._poll_lock:
            return await taxii_module.poll_feed(
                self.db, self._http, feed,
                timeout_s=self.cfg.poll_timeout_s,
                max_pages=self.cfg.max_poll_pages,
            )

    async def run_match(self) -> dict[str, Any]:
        assert self.orch is not None
        async with self._match_lock:
            res = await match_module.run_match(
                self.db, self.orch, scan_limit=self.cfg.match_scan_limit,
            )
        self.last_run["match"] = {"at": datetime.now(timezone.utc).isoformat(), **res}
        return res

    # ------------------------------------------------------------------
    # scheduler
    # ------------------------------------------------------------------
    async def _scheduler(self) -> None:
        await asyncio.sleep(5)  # small startup delay
        interval_s = self.cfg.poll_interval_min * 60
        while not self._stop.is_set():
            try:
                await self.poll_all()
                await self.run_match()
            except asyncio.CancelledError:  # pragma: no cover
                raise
            except Exception as exc:  # noqa: BLE001
                log.exception("scheduler pass error: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval_s)
            except asyncio.TimeoutError:
                continue

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------
    async def _healthz(self, _req: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def _readyz(self, _req: web.Request) -> web.Response:
        ok = self._ready and await self.db.ping()
        return web.json_response({"ready": ok}, status=200 if ok else 503)

    async def _stats(self, _req: web.Request) -> web.Response:
        stats = await self.db.stats()
        return web.json_response({"stats": stats, "last_run": self.last_run})

    async def _ingest_stix(self, req: web.Request) -> web.Response:
        try:
            body = await req.json()
        except Exception:  # noqa: BLE001
            return web.json_response({"error": "invalid JSON body"}, status=400)
        # {"url": ...} -> fetch a user-configured STIX bundle URL and ingest.
        if isinstance(body, dict) and "url" in body and "objects" not in body:
            url = str(body["url"]).strip()
            assert self._http is not None
            try:
                async with self._http.get(
                    url,
                    headers={"Accept": taxii_module.STIX_MEDIA_TYPE},
                    timeout=aiohttp.ClientTimeout(total=self.cfg.poll_timeout_s),
                ) as resp:
                    resp.raise_for_status()
                    bundle = await resp.json(content_type=None)
            except Exception as exc:  # noqa: BLE001
                return web.json_response(
                    {"error": f"fetch failed: {exc!s}"}, status=502
                )
            res = await self.ingest_bundle(bundle, source=url)
            return web.json_response({"source": url, **res})
        # otherwise treat the body as a STIX bundle
        res = await self.ingest_bundle(body, source="ingest")
        return web.json_response(res)

    async def _register_feed(self, req: web.Request) -> web.Response:
        try:
            body = await req.json()
        except Exception:  # noqa: BLE001
            return web.json_response({"error": "invalid JSON body"}, status=400)
        name = (body or {}).get("name")
        kind = (body or {}).get("kind")
        if not name or kind not in ("taxii", "stix_url", "stix_upload", "manual"):
            return web.json_response(
                {"error": "name and valid kind (taxii|stix_url|stix_upload|manual) required"},
                status=400,
            )
        feed = await self.db.insert_feed(
            name=name, kind=kind,
            url=(body.get("url") or None),
            collection=(body.get("collection") or None),
            enabled=bool(body.get("enabled", True)),
        )
        return web.json_response(feed, status=201)

    async def _list_feeds(self, _req: web.Request) -> web.Response:
        feeds = await self.db.list_feeds()
        return web.json_response({"items": feeds})

    async def _poll(self, req: web.Request) -> web.Response:
        feed_id = req.match_info["feed_id"]
        res = await self.poll_one(feed_id)
        status = 404 if res.get("error") == "feed not found" else 200
        return web.json_response(res, status=status)

    async def _match(self, _req: web.Request) -> web.Response:
        res = await self.run_match()
        return web.json_response(res)

    def _make_app(self) -> web.Application:
        app = web.Application()
        app.add_routes([
            web.get("/healthz", self._healthz),
            web.get("/readyz", self._readyz),
            web.get("/stats", self._stats),
            web.post("/ingest/stix", self._ingest_stix),
            web.post("/feeds", self._register_feed),
            web.get("/feeds", self._list_feeds),
            web.post("/poll/{feed_id}", self._poll),
            web.post("/match", self._match),
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
    svc = ThreatIntelService(cfg)
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
        if cfg.enable_scheduler:
            svc._tasks.append(asyncio.create_task(svc._scheduler()))
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
