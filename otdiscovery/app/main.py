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
  * ``GET  /metrics``  -- Prometheus text: per-sensor last-ingest time (the
                          "Sentry silent" alert). Bearer METRICS_TOKEN when
                          set; otherwise open only if REQUIRE_SENTRY_TOKEN is
                          off (dev), else 404.

SAFETY: this service never initiates a connection to a discovered device. It
parses passively-provided observations only. See app/__init__.py.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import dataclasses
import hmac
import logging
import os
import signal
import time
from datetime import datetime
from typing import Any, Optional

import aiohttp
from aiohttp import web

from . import PASSIVE_ONLY, SAFETY_INVARIANT, __version__
from . import config as config_module
from . import pcap
from .db import Database
from .orchestrator import OrchestratorClient
from .pipeline import DiscoveryEngine
from .sensorapi import SENSOR_PREFIX, SensorGateway

log = logging.getLogger("otdiscovery")
_STARTED_AT = time.time()


def _esc(v: Any) -> str:
    s = str(v if v is not None else "")[:128]
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _render_metrics(sensors: dict[str, dict[str, Any]], last_ingest: float | None) -> str:
    """Prometheus text exposition (no client library needed)."""
    g = "paddock_sentry_last_ingest_timestamp_seconds"
    lines = [
        f"# HELP {g} Unix time a Sentry sensor last posted a batch.",
        f"# TYPE {g} gauge",
    ]
    batches = []
    for sid, rec in sorted(sensors.items()):
        try:
            ts = datetime.fromisoformat(str(rec.get("last_seen"))).timestamp()
        except (TypeError, ValueError):
            continue
        labels = f'sensor="{_esc(sid)}",site="{_esc(rec.get("site"))}"'
        lines.append(f"{g}{{{labels}}} {ts:.3f}")
        batches.append(f'paddock_sentry_batches_total{{sensor="{_esc(sid)}"}} {int(rec.get("batches") or 0)}')
    lines += [
        "# HELP paddock_sentry_batches_total Batches received per Sentry sensor since start.",
        "# TYPE paddock_sentry_batches_total counter",
        *batches,
        "# HELP paddock_otdiscovery_last_ingest_timestamp_seconds Last successful /ingest (0 = none since start).",
        "# TYPE paddock_otdiscovery_last_ingest_timestamp_seconds gauge",
        f"paddock_otdiscovery_last_ingest_timestamp_seconds {last_ingest or 0:.3f}",
        "# HELP paddock_otdiscovery_sensors Sentry sensors seen since start.",
        "# TYPE paddock_otdiscovery_sensors gauge",
        f"paddock_otdiscovery_sensors {len(sensors)}",
        "# HELP paddock_otdiscovery_start_timestamp_seconds Process start time.",
        "# TYPE paddock_otdiscovery_start_timestamp_seconds gauge",
        f"paddock_otdiscovery_start_timestamp_seconds {_STARTED_AT:.3f}",
    ]
    return "\n".join(lines) + "\n"


class OtDiscoveryService:
    def __init__(self, cfg: config_module.Config) -> None:
        self.cfg = cfg
        self.db: Optional[Database] = Database(cfg.database_url) if cfg.enable_db else None
        self.orch: Optional[OrchestratorClient] = None
        self.engine: Optional[DiscoveryEngine] = None
        self._stop = asyncio.Event()
        self._ready = False
        self._last_ingest_ts: float | None = None
        self.gateway: Optional[SensorGateway] = None
        self.tenant_engines: dict[str, DiscoveryEngine] = {}

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
        self.gateway = SensorGateway(self.orch)
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
    # per-tenant engines (managed sensors)
    # ------------------------------------------------------------------ #
    def engine_for(self, tenant_id: str | None) -> DiscoveryEngine:
        """The discovery engine for a sensor's tenant. Observations never mix
        across tenants: each tenant gets its own store, baselines and a
        tenant-bound orchestrator client. Legacy shared-token sensors use the
        default engine."""
        assert self.engine is not None
        if not tenant_id:
            return self.engine
        eng = self.tenant_engines.get(tenant_id)
        if eng is None:
            if len(self.tenant_engines) >= self.cfg.max_tenant_engines:
                raise RuntimeError("too many tenant engines")
            bp = self.cfg.baseline_path
            cfg = dataclasses.replace(self.cfg, baseline_path=f"{bp}.{tenant_id}" if bp else None,
                                      analyze_interval_s=self.cfg.managed_analyze_interval_s)
            orch = self.orch.for_tenant(tenant_id) if self.orch is not None else None
            eng = DiscoveryEngine(cfg, db=self.db, orch=orch)
            self.tenant_engines[tenant_id] = eng
        return eng

    def _all_sensors(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = dict(self.engine.sensors) if self.engine is not None else {}
        for eng in self.tenant_engines.values():
            out.update(eng.sensors)
        return out

    @staticmethod
    def _bearer(req: web.Request) -> str:
        auth = req.headers.get("Authorization", "")
        return auth[7:].strip() if auth.lower().startswith("bearer ") else ""

    def _client_ip(self, req: web.Request) -> str | None:
        if self.cfg.trust_proxy:
            fwd = req.headers.get("X-Forwarded-For", "")
            if fwd:
                return fwd.split(",")[0].strip()[:64] or None
        return req.remote

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
            "sensors": self._all_sensors(),
            "segment_matrix": self.engine.last_segment_matrix,
            "last_active_probe_attempts_to_devices": len(self.engine.last_guard_violations),
        })

    async def _handle_metrics(self, req: web.Request) -> web.Response:
        token = os.environ.get("METRICS_TOKEN", "")
        if token:
            got = req.headers.get("Authorization", "")
            if not (got[:7].lower() == "bearer " and hmac.compare_digest(
                    got[7:].strip().encode(), token.encode())):
                return web.json_response({"error": "metrics token required"}, status=401)
        elif self.cfg.require_sentry_token:
            return web.json_response({"error": "not found"}, status=404)
        sensors = self._all_sensors()
        return web.Response(
            text=_render_metrics(sensors, self._last_ingest_ts),
            content_type="text/plain", charset="utf-8",
        )

    async def _read_input(
        self, req: web.Request
    ) -> tuple[Optional[bytes], Optional[list[Any]], Optional[web.Response], Optional[dict[str, Any]]]:
        """Return (pcap_bytes, observations, error_response, sensor_envelope)."""
        ctype = (req.headers.get("Content-Type") or "").lower()
        raw = await req.read()
        if len(raw) > self.cfg.max_capture_bytes:
            return None, None, web.json_response(
                {"error": "capture too large"}, status=413), None

        # Raw pcap upload (octet-stream, or a body that is literally a pcap).
        if pcap.looks_like_pcap(raw):
            return raw, None, None, None

        if "application/json" in ctype or raw[:1] in (b"{", b"["):
            try:
                body = await req.json()
            except Exception:
                return None, None, web.json_response(
                    {"error": "invalid JSON body"}, status=400), None
            if isinstance(body, list):
                return None, body, None, None
            if not isinstance(body, dict):
                return None, None, web.json_response(
                    {"error": "body must be a JSON object or array"}, status=400), None
            pcap_bytes: Optional[bytes] = None
            b64 = body.get("pcap_base64") or body.get("pcap")
            if isinstance(b64, str) and b64:
                try:
                    pcap_bytes = base64.b64decode(b64, validate=False)
                except (binascii.Error, ValueError):
                    return None, None, web.json_response(
                        {"error": "pcap_base64 is not valid base64"}, status=400), None
            sensor = body.get("sensor") if isinstance(body.get("sensor"), dict) else None
            observations = body.get("observations")
            if observations is not None and not isinstance(observations, list):
                return None, None, web.json_response(
                    {"error": "observations must be a list"}, status=400), None
            if pcap_bytes is None and not observations:
                return None, None, web.json_response(
                    {"error": "provide pcap_base64 and/or observations"}, status=400), None
            return pcap_bytes, observations, None, sensor

        # Fall back: treat the raw body as pcap bytes if non-empty.
        if raw:
            return raw, None, None, None
        return None, None, web.json_response({"error": "empty body"}, status=400), None

    def _authorized(self, req: web.Request) -> bool:
        tokens = self.cfg.sentry_tokens
        if not tokens:
            return True
        auth = req.headers.get("Authorization", "")
        presented = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        return any(hmac.compare_digest(presented.encode(), t.encode()) for t in tokens)

    # -- sensor-facing proxy (enrollment + heartbeat) ----------------------- #
    async def _proxy(self, req: web.Request, call: str) -> web.Response:
        if self.gateway is None:
            return web.json_response({"detail": "starting"}, status=503)
        if (req.content_length or 0) > 65_536:
            return web.json_response({"detail": "request too large"}, status=413)
        try:
            body = await req.json()
        except Exception:  # noqa: BLE001
            return web.json_response({"detail": "invalid JSON body"}, status=400)
        if not isinstance(body, dict):
            return web.json_response({"detail": "body must be a JSON object"}, status=400)
        ip = self._client_ip(req)
        if call == "enroll":
            status, data = await self.gateway.enroll(body, ip)
        else:
            cred = self._bearer(req)
            if not cred.startswith(SENSOR_PREFIX):
                return web.json_response({"detail": "invalid sensor credential"}, status=401)
            status, data = await self.gateway.heartbeat(cred, body, ip)
        headers = {"Retry-After": "60"} if status == 429 else None
        return web.json_response(data, status=status, headers=headers)

    async def _handle_enroll(self, req: web.Request) -> web.Response:
        return await self._proxy(req, "enroll")

    async def _handle_heartbeat(self, req: web.Request) -> web.Response:
        return await self._proxy(req, "heartbeat")

    async def _ingest_managed(self, req: web.Request, credential: str) -> web.Response:
        """A per-sensor credential: authenticate (revocation is immediate),
        apply the batch id exactly once, ingest into the sensor's tenant."""
        assert self.gateway is not None
        key = req.headers.get("Idempotency-Key", "").strip()
        if not key:
            return web.json_response({"error": "missing Idempotency-Key header (batch id)"}, status=400)
        status, claim = await self.gateway.claim(credential, key, self._client_ip(req))
        if status in (401, 403):
            return web.json_response({"error": (claim or {}).get("detail", "sensor not authorized")}, status=status)
        if status == 422:
            return web.json_response({"error": "invalid Idempotency-Key"}, status=400)
        if status != 200:
            return web.json_response({"error": "paddock server unavailable, retry"}, status=503,
                                     headers={"Retry-After": "30"})
        state = claim.get("state")
        if state == "duplicate":
            return web.json_response({"duplicate": True, "batch_id": key})
        if state != "new":
            return web.json_response({"error": "batch is being processed, retry"}, status=409,
                                     headers={"Retry-After": "5"})
        ok, flows = False, 0
        try:
            pcap_bytes, observations, err, sensor = await self._read_input(req)
            if err is not None:
                return err
            flows = sum(1 for o in (observations or []) if isinstance(o, dict) and o.get("kind") == "flow")
            engine = self.engine_for(claim.get("tenant_id"))
            sid = str(claim.get("sensor_id") or "")
            engine.note_sensor({**(sensor or {}), "id": f"{claim.get('name')}@{sid[:8]}",
                                "site": claim.get("site")})
            result = await engine.ingest(pcap_bytes=pcap_bytes, observations=observations)
            failed = [k for k, v in (result.get("orchestrator") or {}).items()
                      if isinstance(v, dict) and "error" in v]
            if failed:  # the data did not land: let the sensor retry the same batch id
                log.warning("orchestrator rejected %s for batch %s", failed, key)
                return web.json_response({"error": "paddock server could not store the batch, retry"},
                                         status=503, headers={"Retry-After": "30"})
            ok = True
            self._last_ingest_ts = time.time()
            result["batch_id"] = key
            return web.json_response(result)
        except Exception as exc:  # noqa: BLE001
            log.exception("/ingest (managed) failed")
            return web.json_response({"error": str(exc)}, status=500)
        finally:
            await self.gateway.done(credential, key, ok=ok, flows=flows)

    async def _handle_ingest(self, req: web.Request) -> web.Response:
        assert self.engine is not None
        bearer = self._bearer(req)
        if self.cfg.managed_sensors and self.gateway is not None and bearer.startswith(SENSOR_PREFIX):
            return await self._ingest_managed(req, bearer)
        if self.cfg.require_sentry_token and not self.cfg.sentry_tokens:
            return web.json_response(
                {"error": "sensor ingest is disabled: set SENTRY_TOKENS (comma-separated) "
                          "and give each Sentry one of them"}, status=503)
        if not self._authorized(req):
            return web.json_response({"error": "invalid or missing sensor token"}, status=401)
        pcap_bytes, observations, err, sensor = await self._read_input(req)
        if err is not None:
            return err
        self.engine.note_sensor(sensor)
        replace = req.query.get("replace", "").lower() in ("1", "true", "yes")
        try:
            result = await self.engine.ingest(
                pcap_bytes=pcap_bytes, observations=observations, replace=replace
            )
        except Exception as exc:
            log.exception("/ingest failed")
            return web.json_response({"error": str(exc)}, status=500)
        self._last_ingest_ts = time.time()
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
            web.get("/metrics", self._handle_metrics),
            web.post("/ingest", self._handle_ingest),
            web.post("/enroll", self._handle_enroll),
            web.post("/heartbeat", self._handle_heartbeat),
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
