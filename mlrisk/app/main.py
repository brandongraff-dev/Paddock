"""Service entrypoint.

Runs one cooperative loop:
  * every ``MLRISK_INTERVAL_MIN`` minutes: retrain the risk ranker from fresh
    triage labels, score all open findings, then detect anomalies.

Plus a small aiohttp server on :8098 for health + manual triggers:
  GET  /healthz /readyz /stats
  POST /retrain /score /detect-anomalies

The ML learns ONLY from the platform's own data. No external calls. scikit-learn
is a guarded optional import (see risk_model/anomaly): the service boots and the
heuristic-prior + z-score paths work without it.
"""
from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timezone
from typing import Any

from aiohttp import web

from . import config as config_module
from . import anomaly as anomaly_mod
from .db import Database
from .risk_model import RiskRanker, sklearn_available

log = logging.getLogger("mlrisk")


class MlRiskService:
    def __init__(self, cfg: config_module.Config) -> None:
        self.cfg = cfg
        self.db = Database(cfg.database_url)
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[Any]] = []
        self._ready = False
        self._lock = asyncio.Lock()
        self.ranker = RiskRanker(
            min_labels=cfg.min_labels,
            min_per_class=cfg.min_per_class,
            top_k=cfg.top_k,
        )
        self.stats: dict[str, Any] = {
            "last_run": None,
            "risk": {"n_samples": 0, "cold_start": True, "algo": "heuristic_prior",
                     "scored": 0, "metrics": {}, "top_features": []},
            "anomaly": {"subjects": 0, "velocity": 0, "written": 0,
                        "algo": "zscore_mad"},
            "sklearn": sklearn_available(),
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
        self._ready = True
        log.info("mlrisk service started (sklearn=%s)", sklearn_available())

    async def stop(self) -> None:
        log.info("mlrisk service stopping")
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        await self.db.close()

    # ------------------------------------------------------------------
    # work
    # ------------------------------------------------------------------
    async def retrain_and_score(self) -> dict[str, Any]:
        """Retrain the ranker from current labels and score all open findings."""
        async with self._lock:
            now = datetime.now(timezone.utc)
            labeled = await self.db.fetch_labeled_feature_rows()
            result = self.ranker.train(labeled, now=now)

            version = await self.db.next_version("risk_ranker")
            await self.db.insert_model(
                kind="risk_ranker",
                version=version,
                algo=result.algo,
                n_samples=result.n_samples,
                metrics=result.metrics,
                feature_importance=result.feature_importance,
                cold_start=result.cold_start,
                notes=result.notes,
            )

            open_rows = await self.db.fetch_open_feature_rows()
            scores = self.ranker.score_rows(open_rows, now=now)
            written = await self.db.upsert_risk_scores(scores, version)

            top_features = [
                k for k, _ in sorted(
                    result.feature_importance.items(), key=lambda kv: kv[1], reverse=True
                )[:5]
            ]
            self.stats["risk"] = {
                "version": version,
                "n_samples": result.n_samples,
                "cold_start": result.cold_start,
                "algo": result.algo,
                "scored": written,
                "metrics": result.metrics,
                "top_features": top_features,
            }
            self.stats["last_run"] = now.isoformat()
            return self.stats["risk"]

    async def detect_anomalies(self) -> dict[str, Any]:
        async with self._lock:
            subjects = await self.db.fetch_host_subject_rows()
            subject_anoms = anomaly_mod.detect_subject_anomalies(
                subjects, contamination=self.cfg.contamination
            )
            velocity_rows = await self.db.fetch_velocity_rows(
                window_h=self.cfg.velocity_window_h,
                baseline_days=self.cfg.velocity_baseline_days,
            )
            velocity_anoms = anomaly_mod.detect_velocity_anomalies(velocity_rows)

            all_anoms = subject_anoms + velocity_anoms
            algo = subject_anoms[0]["algo"] if subject_anoms else (
                "isolation_forest" if anomaly_mod.iforest_available() else "zscore_mad"
            )
            version = await self.db.next_version("anomaly_detector")
            await self.db.insert_model(
                kind="anomaly_detector",
                version=version,
                algo=algo,
                n_samples=len(subjects),
                metrics={"subjects": len(subjects), "flagged": len(all_anoms)},
                feature_importance={},
                cold_start=not anomaly_mod.iforest_available(),
                notes=f"{len(subject_anoms)} subject + {len(velocity_anoms)} velocity anomalies",
            )
            written = await self.db.insert_anomalies(all_anoms, version)
            self.stats["anomaly"] = {
                "version": version,
                "subjects": len(subject_anoms),
                "velocity": len(velocity_anoms),
                "written": written,
                "algo": algo,
            }
            return self.stats["anomaly"]

    async def run_once(self) -> dict[str, Any]:
        risk = await self.retrain_and_score()
        anom = await self.detect_anomalies()
        return {"risk": risk, "anomaly": anom}

    # ------------------------------------------------------------------
    # scheduler
    # ------------------------------------------------------------------
    async def _loop(self) -> None:
        await asyncio.sleep(5)  # small startup delay
        interval_s = self.cfg.interval_min * 60
        while not self._stop.is_set():
            try:
                await self.run_once()
            except asyncio.CancelledError:  # pragma: no cover
                raise
            except Exception as exc:
                log.exception("mlrisk loop error: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval_s)
            except asyncio.TimeoutError:
                continue

    async def _run_scheduler(self) -> None:
        self._tasks.append(asyncio.create_task(self._loop()))

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------
    async def _handle_healthz(self, _req: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def _handle_readyz(self, _req: web.Request) -> web.Response:
        ok = self._ready and await self.db.ping()
        return web.json_response({"ready": ok}, status=200 if ok else 503)

    async def _handle_stats(self, _req: web.Request) -> web.Response:
        try:
            counters = await self.db.counters()
        except Exception as exc:  # pragma: no cover - defensive
            counters = {"error": str(exc)}
        risk_model = await self._safe(self.db.active_model("risk_ranker"))
        anom_model = await self._safe(self.db.active_model("anomaly_detector"))
        return web.json_response({
            "sklearn": sklearn_available(),
            "stats": self.stats,
            "db": counters,
            "active_models": {
                "risk_ranker": _jsonable(risk_model),
                "anomaly_detector": _jsonable(anom_model),
            },
        })

    @staticmethod
    async def _safe(coro: Any) -> Any:
        try:
            return await coro
        except Exception:  # pragma: no cover - defensive
            return None

    async def _handle_retrain(self, _req: web.Request) -> web.Response:
        try:
            res = await self.retrain_and_score()
        except Exception as exc:
            log.exception("retrain failed")
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response({"ok": True, "risk": res})

    async def _handle_score(self, _req: web.Request) -> web.Response:
        try:
            res = await self.retrain_and_score()
        except Exception as exc:
            log.exception("score failed")
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response({"ok": True, "risk": res})

    async def _handle_detect(self, _req: web.Request) -> web.Response:
        try:
            res = await self.detect_anomalies()
        except Exception as exc:
            log.exception("detect-anomalies failed")
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response({"ok": True, "anomaly": res})

    def _make_app(self) -> web.Application:
        app = web.Application()
        app.add_routes([
            web.get("/healthz", self._handle_healthz),
            web.get("/readyz", self._handle_readyz),
            web.get("/stats", self._handle_stats),
            web.post("/retrain", self._handle_retrain),
            web.post("/score", self._handle_score),
            web.post("/detect-anomalies", self._handle_detect),
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


def _jsonable(model: dict[str, Any] | None) -> dict[str, Any] | None:
    if not model:
        return None
    out = dict(model)
    for key, val in list(out.items()):
        if isinstance(val, datetime):
            out[key] = val.isoformat()
        elif hasattr(val, "hex") and not isinstance(val, (bytes, str)):
            out[key] = str(val)  # UUID
    return out


async def _amain() -> None:
    cfg = config_module.load()
    svc = MlRiskService(cfg)
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
