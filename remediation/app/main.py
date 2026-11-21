"""Service entrypoint for the remediation service (HTTP :8102).

An aiohttp server exposing the auto-remediation pipeline:
  * POST /propose        {finding_id}  — run the full pipeline for one finding
  * POST /propose-batch  {finding_ids} — run it for several
  * GET  /healthz /readyz /stats

Boots and self-tests WITHOUT the anthropic package or a key: the deterministic
generators + gate + rule-based verifier work fully; the LLM is only used for a
prose explanation and a stricter-only second-opinion verify. PR opening is OFF
by default (REMEDIATION_OPEN_PR=false) — the service produces the verified diff
+ reports without pushing anywhere. NOTHING is ever auto-merged.
"""
from __future__ import annotations

import asyncio
import logging
import signal
from typing import Any

from aiohttp import web

from . import config as config_module
from . import github as gh
from .config import Config
from .db import Database
from .llm import LLM
from .pipeline import Pipeline

log = logging.getLogger("remediation")


class RemediationService:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.db = Database(cfg.database_url)
        self.llm = LLM(cfg)
        self.pipeline = Pipeline(self.db, self.llm, cfg)
        self._stop = asyncio.Event()
        self._ready = False

    async def start(self) -> None:
        logging.basicConfig(
            level=self.cfg.log_level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        await self.db.connect()
        self._ready = True
        can, why = gh.can_open(self.cfg)
        log.info(
            "remediation started (llm_enabled=%s open_pr=%s pr_ready=%s: %s)",
            self.llm.is_enabled(), self.cfg.open_pr, can, why,
        )

    async def stop(self) -> None:
        log.info("remediation stopping")
        self._stop.set()
        await self.db.close()

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------
    async def _healthz(self, _req: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def _readyz(self, _req: web.Request) -> web.Response:
        ok = self._ready and await self.db.ping()
        return web.json_response({"ready": ok}, status=200 if ok else 503)

    async def _stats(self, _req: web.Request) -> web.Response:
        try:
            stats = await self.db.stats()
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)
        can, why = gh.can_open(self.cfg)
        return web.json_response({
            "llm_enabled": self.llm.is_enabled(),
            "open_pr": self.cfg.open_pr,
            "pr_ready": can,
            "pr_note": why,
            "remediations": stats,
        })

    async def _propose(self, req: web.Request) -> web.Response:
        try:
            body = await req.json()
        except Exception:
            return web.json_response({"ok": False, "error": "invalid_json"}, status=400)
        finding_id = (body or {}).get("finding_id")
        if not finding_id or not isinstance(finding_id, str):
            return web.json_response({"ok": False, "error": "finding_id_required"}, status=400)
        created_by = (body or {}).get("created_by") or "remediation"
        try:
            res = await self.pipeline.propose(finding_id, created_by=created_by)
        except Exception as exc:
            log.exception("propose failed")
            return web.json_response({"ok": False, "error": str(exc)}, status=500)
        if res.get("error") == "finding_not_found":
            return web.json_response(res, status=404)
        return web.json_response(res, status=200)

    async def _propose_batch(self, req: web.Request) -> web.Response:
        try:
            body = await req.json()
        except Exception:
            return web.json_response({"ok": False, "error": "invalid_json"}, status=400)
        ids = (body or {}).get("finding_ids")
        if not isinstance(ids, list) or not ids:
            return web.json_response({"ok": False, "error": "finding_ids_required"}, status=400)
        created_by = (body or {}).get("created_by") or "remediation"
        results: list[dict[str, Any]] = []
        for fid in ids[:200]:
            if not isinstance(fid, str):
                continue
            try:
                results.append(await self.pipeline.propose(fid, created_by=created_by))
            except Exception as exc:  # pragma: no cover - defensive
                results.append({"ok": False, "finding_id": fid, "error": str(exc)})
        summary = {
            "verified": sum(1 for r in results if r.get("ok")),
            "rejected": sum(1 for r in results if r.get("status") == "rejected"),
            "total": len(results),
        }
        return web.json_response({"ok": True, "summary": summary, "results": results})

    def _make_app(self) -> web.Application:
        app = web.Application()
        app.add_routes([
            web.get("/healthz", self._healthz),
            web.get("/readyz", self._readyz),
            web.get("/stats", self._stats),
            web.post("/propose", self._propose),
            web.post("/propose-batch", self._propose_batch),
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


async def _amain() -> None:
    cfg = config_module.load()
    svc = RemediationService(cfg)
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
