"""Service entrypoint for the brain service (HTTP :8095).

Runs:
  * a periodic triage pass every ``TRIAGE_INTERVAL_MIN`` minutes
  * an aiohttp server: /healthz /readyz /stats /triage/run /ask /clusters

Boots and self-tests WITHOUT the anthropic package or a key — the optional
import is guarded in llm.py, and both capabilities degrade gracefully.
"""
from __future__ import annotations

import asyncio
import logging
import signal
from typing import Any

from aiohttp import web

from . import ask as ask_module
from . import config as config_module
from . import tenancy
from .config import Config
from .db import Database
from .llm import LLM
from .triage import run_triage

log = logging.getLogger("brain")


class BrainService:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.db = Database(cfg.database_url)
        self.llm = LLM(cfg)
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[Any]] = []
        self._ready = False
        self._triage_lock = asyncio.Lock()
        self.stats: dict[str, Any] = {"triage": {"last_run": None}}

    async def start(self) -> None:
        logging.basicConfig(
            level=self.cfg.log_level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        await self.db.connect()
        await self.llm.refresh_key(force=True)
        self._ready = True
        log.info("brain service started (llm_enabled=%s model=%s)",
                 self.llm.is_enabled(), self.cfg.anthropic_model)

    async def stop(self) -> None:
        log.info("brain service stopping")
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        await self.db.close()

    async def triage(self) -> dict[str, Any]:
        """Cluster the tenant a trigger named, else every active tenant (each
        tenant's findings are clustered, and the clusters stored, separately)."""
        await self.llm.refresh_key()

        async def _one() -> dict[str, Any]:
            async with self._triage_lock:
                return await run_triage(self.db, self.llm)

        res = tenancy.merge_counts(await tenancy.run_for_request_or_all(self.db.pool, _one))
        self.stats["triage"] = {"last_run": _now(), **res}
        return res

    # ------------------------------------------------------------------
    # schedulers
    # ------------------------------------------------------------------
    async def _triage_loop(self) -> None:
        await asyncio.sleep(10)
        interval = self.cfg.triage_interval_min * 60
        while not self._stop.is_set():
            try:
                await self.triage()
            except asyncio.CancelledError:  # pragma: no cover
                raise
            except Exception as exc:
                log.exception("triage loop error: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue

    async def _run_scheduler(self) -> None:
        self._tasks.append(asyncio.create_task(self._triage_loop()))

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------
    async def _healthz(self, _req: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def _readyz(self, _req: web.Request) -> web.Response:
        ok = self._ready and await self.db.ping()
        return web.json_response({"ready": ok}, status=200 if ok else 503)

    async def _stats(self, _req: web.Request) -> web.Response:
        await self.llm.refresh_key()
        try:
            clusters = await self.db.count_clusters()
            queries = await self.db.count_queries()
        except Exception:
            clusters = queries = -1
        return web.json_response({
            "llm_enabled": self.llm.is_enabled(),
            "model": self.cfg.anthropic_model,
            "clusters": clusters,
            "queries": queries,
            "stats": self.stats,
        })

    async def _triage_run(self, _req: web.Request) -> web.Response:
        try:
            res = await self.triage()
        except Exception as exc:
            log.exception("manual triage failed")
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response(res)

    async def _clusters(self, _req: web.Request) -> web.Response:
        try:
            items = await self.db.list_clusters()
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response({"items": items, "total": len(items)})

    async def _ask(self, req: web.Request) -> web.Response:
        try:
            body = await req.json()
        except Exception:
            return web.json_response({"ok": False, "reason": "invalid_json"}, status=400)
        question = (body or {}).get("question")
        if not question or not isinstance(question, str):
            return web.json_response(
                {"ok": False, "reason": "question_required"}, status=400
            )
        asked_by = (body or {}).get("asked_by")
        await self.llm.refresh_key()
        try:
            res = await ask_module.answer(
                self.db, self.llm, self.cfg, question, asked_by
            )
        except Exception as exc:
            log.exception("ask handler failed")
            return web.json_response({"ok": False, "reason": str(exc)}, status=500)
        status = 200 if res.get("ok") else 422
        return web.json_response(res, status=status)

    def _make_app(self) -> web.Application:
        app = web.Application(middlewares=[tenancy.aiohttp_middleware()])
        app.add_routes([
            web.get("/healthz", self._healthz),
            web.get("/readyz", self._readyz),
            web.get("/stats", self._stats),
            web.post("/triage/run", self._triage_run),
            web.get("/clusters", self._clusters),
            web.post("/ask", self._ask),
        ])
        return app

    async def serve(self) -> None:
        runner = web.AppRunner(self._make_app())
        await runner.setup()
        site = web.TCPSite(runner, host="0.0.0.0", port=self.cfg.http_port)
        await site.start()
        log.info("http: listening on :%d", self.cfg.http_port)
        try:
            await self._stop.wait()
        finally:
            await runner.cleanup()


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


async def _amain() -> None:
    cfg = config_module.load()
    svc = BrainService(cfg)
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
