"""otdiscovery service entrypoint.

An aiohttp server on :8101 exposing the passive IoT/OT discovery API:

  * ``POST /ingest``   -- ingest a capture and project devices/segments/findings.
                          Body is either a classic-pcap file (raw bytes or
                          ``{"pcap_base64": "..."}``) or
                          ``{"observations": [ ... ]}`` (packets/flows,
                          mDNS/SSDP/UPnP announcements, DHCP fingerprints, MACs).
                          ``?replace=true`` resets the stored observation set.
  * ``POST /analyze``  -- re-run fingerprint + exposure + cve-match over the
                          already-stored observations (no new input).
  * ``GET  /healthz``  -- liveness (+ the passive-only invariant).
  * ``GET  /readyz``   -- readiness (DB reachable, if DB enabled).
  * ``GET  /stats``    -- counters (devices, OT, segments, findings, guard).

SAFETY: this service never initiates a connection to a discovered device. It
parses passively-provided observations only. See app/__init__.py.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import signal
from typing import Any, Optional

import aiohttp
from aiohttp import web

from . import PASSIVE_ONLY, SAFETY_INVARIANT, __version__
from . import config as config_module
from . import pcap
from .db import Database
from .orchestrator import OrchestratorClient
from .pipeline import DiscoveryEngine

log = logging.getLogger("otdiscovery")


class OtDiscoveryService:
    def __init__(self, cfg: config_module.Config) -> None:
        self.cfg = cfg
        self.db: Optional[Database] = Database(cfg.database_url) if cfg.enable_db else None
        self.orch: Optional[OrchestratorClient] = None
        self.engine: Optional[DiscoveryEngine] = None
        self._stop = asyncio.Event()
        self._ready = False

    async def start(self) -> None:
        logging.basicConfig(
            level=self.cfg.log_level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        if self.db is not None:
            try:
                await self.db.connect()
            except Exception as exc:  # DB is optional; degrade gracefully
                log.warning("db unavailable, cve-match disabled: %s", exc)
                self.db = None
        self.orch = OrchestratorClient(
            self.cfg.orchestrator_url,
            timeout_s=self.cfg.http_timeout_s,
            user_agent=self.cfg.user_agent,
        )
        await self.orch.ensure()
        self.engine = DiscoveryEngine(self.cfg, db=self.db, orch=self.orch)
        self._ready = True
        log.info("otdiscovery started (passive_only=%s) on :%d",
                 PASSIVE_ONLY, self.cfg.http_port)

    async def stop(self) -> None:
        self._stop.set()
        if self.orch is not None:
            await self.orch.close()
        if self.db is not None:
            await self.db.close()

    # ------------------------------------------------------------------ #
    # handlers
    # ------------------------------------------------------------------ #
    async def _handle_healthz(self, _req: web.Request) -> web.Response:
        return web.json_response({
            "status": "ok",
            "service": "otdiscovery",
            "version": __version__,
            "passive_only": PASSIVE_ONLY,
            "invariant": SAFETY_INVARIANT,
        })

    async def _handle_readyz(self, _req: web.Request) -> web.Response:
        db_ok = True
        if self.db is not None:
            db_ok = await self.db.ping()
        ok = self._ready and db_ok
        return web.json_response(
            {"ready": ok, "db": (None if self.db is None else db_ok)},
            status=200 if ok else 503,
        )

    async def _handle_stats(self, _req: web.Request) -> web.Response:
        assert self.engine is not None
        return web.json_response({
            "service": self.engine.stats,
            "passive_only": PASSIVE_ONLY,
            "observations_stored": len(self.engine.observations),
            "last_active_probe_attempts_to_devices": len(self.engine.last_guard_violations),
        })

    async def _read_input(self, req: web.Request) -> tuple[Optional[bytes], Optional[list[Any]], Optional[web.Response]]:
        """Return (pcap_bytes, observations, error_response)."""
        ctype = (req.headers.get("Content-Type") or "").lower()
        raw = await req.read()
        if len(raw) > self.cfg.max_capture_bytes:
            return None, None, web.json_response(
                {"error": "capture too large"}, status=413)

        # Raw pcap upload (octet-stream, or a body that is literally a pcap).
        if pcap.looks_like_pcap(raw):
            return raw, None, None

        if "application/json" in ctype or raw[:1] in (b"{", b"["):
            try:
                body = await req.json()
            except Exception:
                return None, None, web.json_response(
                    {"error": "invalid JSON body"}, status=400)
            if isinstance(body, list):
                return None, body, None
            if not isinstance(body, dict):
                return None, None, web.json_response(
                    {"error": "body must be a JSON object or array"}, status=400)
            pcap_bytes: Optional[bytes] = None
            b64 = body.get("pcap_base64") or body.get("pcap")
            if isinstance(b64, str) and b64:
                try:
                    pcap_bytes = base64.b64decode(b64, validate=False)
                except (binascii.Error, ValueError):
                    return None, None, web.json_response(
                        {"error": "pcap_base64 is not valid base64"}, status=400)
            observations = body.get("observations")
            if observations is not None and not isinstance(observations, list):
                return None, None, web.json_response(
                    {"error": "observations must be a list"}, status=400)
            if pcap_bytes is None and not observations:
                return None, None, web.json_response(
                    {"error": "provide pcap_base64 and/or observations"}, status=400)
            return pcap_bytes, observations, None

        # Fall back: treat the raw body as pcap bytes if non-empty.
        if raw:
            return raw, None, None
        return None, None, web.json_response({"error": "empty body"}, status=400)

    async def _handle_ingest(self, req: web.Request) -> web.Response:
        assert self.engine is not None
        pcap_bytes, observations, err = await self._read_input(req)
        if err is not None:
            return err
        replace = req.query.get("replace", "").lower() in ("1", "true", "yes")
        try:
            result = await self.engine.ingest(
                pcap_bytes=pcap_bytes, observations=observations, replace=replace
            )
        except Exception as exc:
            log.exception("/ingest failed")
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response(result)

    async def _handle_analyze(self, _req: web.Request) -> web.Response:
        assert self.engine is not None
        try:
            result = await self.engine.analyze()
        except Exception as exc:
            log.exception("/analyze failed")
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response(result)

    def make_app(self) -> web.Application:
        app = web.Application(client_max_size=self.cfg.max_capture_bytes)
        app.add_routes([
            web.get("/healthz", self._handle_healthz),
            web.get("/readyz", self._handle_readyz),
            web.get("/stats", self._handle_stats),
            web.post("/ingest", self._handle_ingest),
            web.post("/analyze", self._handle_analyze),
        ])
        return app

    async def serve(self) -> None:
        app = self.make_app()
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
    svc = OtDiscoveryService(cfg)
    loop = asyncio.get_running_loop()

    def _signal(*_a: Any) -> None:
        svc._stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _signal)
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
