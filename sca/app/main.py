"""SCA service entrypoint.

An aiohttp server on :8094 plus an optional periodic re-scan loop. The server
exposes:

  * ``POST /scan``      -- body ``{project_name, source_ref?, files:{path:content}}``
  * ``POST /scan-dir``  -- body ``{project_name?, path}`` (reads lockfiles from a dir)
  * ``GET  /healthz``   -- liveness
  * ``GET  /readyz``    -- readiness (DB reachable)
  * ``GET  /stats``     -- SBOM / vuln / risk counters

The scan pipeline is: parse lockfiles -> upsert SBOM -> OSV match -> emit `sca`
findings for vulnerable components -> run supply-chain risk detectors -> write
``supply_chain_risks``. Lockfiles are untrusted DATA: they are parsed as text,
never executed, imported, or evaluated.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
from datetime import datetime, timezone
from typing import Any, Optional

import aiohttp
from aiohttp import web

from . import config as config_module
from . import tenancy
from . import osv as osv_module
from . import parsers
from .db import Database
from .orchestrator import OrchestratorClient, build_sca_finding
from .parsers._util import dedupe
from .risk import abandoned, confusion, malicious, pinning, typosquat
from .risk import _registry as registry_meta

log = logging.getLogger("sca")

# Safety limits for untrusted directory reads.
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_FILES = 200
MAX_REGISTRY_LOOKUPS = 300


class ScaService:
    def __init__(self, cfg: config_module.Config) -> None:
        self.cfg = cfg
        self.db = Database(cfg.database_url)
        self._http: Optional[aiohttp.ClientSession] = None
        self.orch: Optional[OrchestratorClient] = None
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[Any]] = []
        self._ready = False
        self._scan_lock = asyncio.Lock()
        self.stats: dict[str, Any] = {"scans": 0, "last_scan": None, "last_counts": None}

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
        log.info("sca service started")

    async def stop(self) -> None:
        log.info("sca service stopping")
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
    # scan pipeline
    # ------------------------------------------------------------------
    async def run_scan(
        self,
        project_name: str,
        files: dict[str, str],
        *,
        source_ref: Optional[str] = None,
    ) -> dict[str, Any]:
        """Parse, SBOM, OSV-match and risk-scan a set of lockfiles."""
        async with self._scan_lock:
            components = dedupe(parsers.parse_files(files))
            ecosystems = sorted({c["ecosystem"] for c in components if c.get("ecosystem")})

            project = await self.db.upsert_project(
                project_name, source_ref, ecosystems, asset_id=None
            )
            pid = project["id"]

            # --- SBOM upsert, remember component_id per (eco|name|version)
            comp_ids: dict[str, str] = {}
            for c in components:
                if not c.get("name") or not c.get("version"):
                    continue
                row = await self.db.upsert_component(pid, c)
                comp_ids[_key(c)] = row["id"]

            # --- OSV vuln match
            osv_results: dict[str, list[dict[str, Any]]] = {}
            vulnerable = 0
            vuln_rows = 0
            if self.cfg.enable_osv and self._http is not None:
                try:
                    osv_results = await osv_module.scan_components(self._http, components)
                except Exception:
                    log.exception("osv scan failed; continuing without vuln data")
            for key, vulns in osv_results.items():
                cid = comp_ids.get(key)
                if not cid or not vulns:
                    continue
                vulnerable += 1
                for v in vulns:
                    if v.get("osv_id"):
                        if await self.db.upsert_vuln(cid, v):
                            vuln_rows += 1

            # --- emit sca findings for vulnerable components
            findings = []
            by_key = {_key(c): c for c in components}
            for key, vulns in osv_results.items():
                comp = by_key.get(key)
                if comp and vulns:
                    findings.append(build_sca_finding(
                        component=comp, vulns=vulns, project=project
                    ))
            posted = 0
            if findings and self.orch is not None:
                res = await self.orch.bulk_findings(findings)
                posted = int(res.get("accepted", 0) or 0)

            # --- supply-chain risk detectors
            risks = await self._run_risks(components, osv_results)
            risk_written = 0
            for r in risks:
                cid = comp_ids.get(_risk_key(r)) if r.get("version") else None
                if await self.db.upsert_risk(pid, cid, r):
                    risk_written += 1

            counts = {
                "project": project_name,
                "project_id": pid,
                "components": len(components),
                "ecosystems": ecosystems,
                "vulnerable_components": vulnerable,
                "vuln_rows_written": vuln_rows,
                "findings_posted": posted,
                "risks": len(risks),
                "risks_written": risk_written,
            }
            self.stats["scans"] += 1
            self.stats["last_scan"] = datetime.now(timezone.utc).isoformat()
            self.stats["last_counts"] = counts
            log.info("scan complete: %s", counts)
            return counts

    async def _run_risks(
        self,
        components: list[dict[str, Any]],
        osv_results: dict[str, list[dict[str, Any]]],
    ) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        risks += confusion.detect(components)
        risks += typosquat.detect(components, max_distance=self.cfg.typosquat_distance)
        risks += pinning.detect(components)

        # registry-backed detectors (abandoned + yanked): best-effort, offline-safe
        last_release: dict[str, str] = {}
        yanked_keys: set[str] = set()
        if self.cfg.enable_registry and self._http is not None:
            last_release, yanked_keys = await self._fetch_registry(components)

        risks += malicious.detect(components, osv_results, yanked_keys=yanked_keys)
        risks += abandoned.detect(
            components, last_release, max_age_days=self.cfg.abandoned_days
        )
        return risks

    async def _fetch_registry(
        self, components: list[dict[str, Any]]
    ) -> tuple[dict[str, str], set[str]]:
        assert self._http is not None
        last_release: dict[str, str] = {}
        yanked_keys: set[str] = set()
        seen: set[tuple[str, str]] = set()
        lookups = 0
        for c in components:
            eco, name = c.get("ecosystem"), c.get("name")
            if eco not in ("npm", "PyPI") or not name:
                continue
            if (eco, name) in seen:
                meta = None
            else:
                seen.add((eco, name))
                lookups += 1
                if lookups > MAX_REGISTRY_LOOKUPS:
                    break
                try:
                    meta = await registry_meta.metadata(self._http, eco, name)
                except Exception:
                    meta = None
            if not meta:
                continue
            if meta.get("last_release"):
                last_release[f"{eco}|{name}"] = meta["last_release"]
            for yv in meta.get("yanked_versions") or set():
                yanked_keys.add(f"{eco}|{name}|{yv}")
        return last_release, yanked_keys

    # ------------------------------------------------------------------
    # directory reads (untrusted DATA -- read only, never execute)
    # ------------------------------------------------------------------
    def read_dir(self, path: str) -> dict[str, str]:
        files: dict[str, str] = {}
        base = os.path.abspath(path)
        if not os.path.isdir(base):
            raise FileNotFoundError(path)
        count = 0
        for root, dirs, names in os.walk(base):
            # don't descend into vendored dependency trees
            dirs[:] = [d for d in dirs if d not in (
                "node_modules", ".git", "vendor", "target", "dist", "build"
            )]
            for fname in names:
                if not parsers.is_supported(fname):
                    continue
                full = os.path.join(root, fname)
                try:
                    if os.path.getsize(full) > MAX_FILE_BYTES:
                        continue
                    with open(full, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read(MAX_FILE_BYTES)
                except OSError:
                    continue
                rel = os.path.relpath(full, base)
                files[rel] = content
                count += 1
                if count >= MAX_FILES:
                    return files
        return files

    # ------------------------------------------------------------------
    # schedulers
    # ------------------------------------------------------------------
    async def _periodic_loop(self) -> None:
        interval_s = max(1, self.cfg.scan_interval_min) * 60
        await asyncio.sleep(5)
        while not self._stop.is_set():
            # No standing project list to re-scan autonomously; the loop keeps
            # the lock warm and could be wired to re-scan registered projects.
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval_s)
            except asyncio.TimeoutError:
                continue

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
            db_stats = await self.db.stats()
        except Exception as exc:
            db_stats = {"error": str(exc)}
        return web.json_response({"service": self.stats, "db": db_stats})

    async def _handle_scan(self, req: web.Request) -> web.Response:
        try:
            body = await req.json()
        except Exception:
            return web.json_response({"error": "invalid JSON body"}, status=400)
        project_name = (body or {}).get("project_name")
        files = (body or {}).get("files")
        if not project_name or not isinstance(files, dict):
            return web.json_response(
                {"error": "project_name and files{path:content} are required"},
                status=400,
            )
        files = {str(k): v for k, v in files.items() if isinstance(v, str)}
        try:
            counts = await self.run_scan(
                str(project_name), files, source_ref=(body or {}).get("source_ref")
            )
        except Exception as exc:
            log.exception("/scan failed")
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response(counts)

    async def _handle_scan_dir(self, req: web.Request) -> web.Response:
        # /scan-dir reads the SERVICE HOST's filesystem: a platform-operator
        # facility, never something one tenant may point at paths another
        # tenant's checkouts could live under.
        caller = tenancy.requested_tenant()
        if (caller is not None and caller != tenancy.DEFAULT_TENANT_ID) or (
                caller is None and tenancy.strict()):
            return web.json_response({"error": "scan-dir is platform-tenant only"}, status=403)
        try:
            body = await req.json()
        except Exception:
            return web.json_response({"error": "invalid JSON body"}, status=400)
        path = (body or {}).get("path")
        if not path or not isinstance(path, str):
            return web.json_response({"error": "path is required"}, status=400)
        try:
            files = self.read_dir(path)
        except FileNotFoundError:
            return web.json_response({"error": f"not a directory: {path}"}, status=404)
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)
        if not files:
            return web.json_response({"error": "no supported lockfiles found", "path": path},
                                     status=404)
        project_name = (body or {}).get("project_name") or os.path.basename(os.path.abspath(path))
        try:
            counts = await self.run_scan(
                str(project_name), files,
                source_ref=(body or {}).get("source_ref") or path,
            )
        except Exception as exc:
            log.exception("/scan-dir failed")
            return web.json_response({"error": str(exc)}, status=500)
        counts["files_read"] = sorted(files.keys())
        return web.json_response(counts)

    def _make_app(self) -> web.Application:
        app = web.Application(
            client_max_size=64 * 1024 * 1024,
            middlewares=[tenancy.aiohttp_middleware()],
        )
        app.add_routes([
            web.get("/healthz", self._handle_healthz),
            web.get("/readyz", self._handle_readyz),
            web.get("/stats", self._handle_stats),
            web.post("/scan", self._handle_scan),
            web.post("/scan-dir", self._handle_scan_dir),
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


def _key(c: dict[str, Any]) -> str:
    return f"{c.get('ecosystem')}|{c.get('name')}|{c.get('version')}"


def _risk_key(r: dict[str, Any]) -> str:
    return f"{r.get('ecosystem')}|{r.get('name')}|{r.get('version')}"


async def _amain() -> None:
    cfg = config_module.load()
    svc = ScaService(cfg)
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
            svc._tasks.append(asyncio.create_task(svc._periodic_loop(), name="periodic"))
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
