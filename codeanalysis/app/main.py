"""codeanalysis service entrypoint.

An aiohttp server on :8097 exposing:

  * ``POST /analyze``      -- body ``{project_name, source_ref?, files:{path:content}}``
                              runs reachability (if an SBOM exists) + SAST
  * ``POST /reachability`` -- body ``{project_name, files:{...}}`` regrades the
                              project's existing dependency vulns (deterministic)
  * ``GET  /healthz``      -- liveness
  * ``GET  /readyz``       -- readiness (DB reachable)
  * ``GET  /stats``        -- code-finding / reachability counters

Provided files are untrusted DATA: parsed read-only (Python ``ast`` + text
scans) or written to a temp dir for Semgrep. They are never imported, executed,
or evaluated. Missing SBOM / absent tool -> an info note, never a crash.
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
from . import reachability as reach
from . import sast as sast_pkg
from . import tenancy
from .db import Database
from .orchestrator import OrchestratorClient
from .sast import normalize

log = logging.getLogger("codeanalysis")

# Safety limits for untrusted input.
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 2000


def sanitize_files(files: dict[str, Any]) -> dict[str, str]:
    """Keep only text source files within size/count caps; prune binaries."""
    out: dict[str, str] = {}
    for path, content in files.items():
        if len(out) >= MAX_FILES:
            break
        if not isinstance(path, str) or not isinstance(content, str):
            continue
        if "\x00" in content:  # binary
            continue
        if len(content.encode("utf-8", "replace")) > MAX_FILE_BYTES:
            continue
        out[str(path)] = content
    return out


class CodeAnalysisService:
    def __init__(self, cfg: config_module.Config) -> None:
        self.cfg = cfg
        self.db = Database(cfg.database_url)
        self.orch: Optional[OrchestratorClient] = None
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[Any]] = []
        self._ready = False
        self._db_ok = False
        self._lock = asyncio.Lock()
        self.stats: dict[str, Any] = {
            "analyses": 0, "reachability_runs": 0,
            "last_run": None, "last_counts": None,
        }

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        logging.basicConfig(
            level=self.cfg.log_level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        try:
            await self.db.connect()
            self._db_ok = True
        except Exception as exc:
            log.warning("db unavailable at start (continuing, SAST-only): %s", exc)
            self._db_ok = False
        self.orch = OrchestratorClient(
            self.cfg.orchestrator_url,
            timeout_s=self.cfg.http_timeout_s,
            user_agent=self.cfg.user_agent,
        )
        await self.orch.ensure()
        self._ready = True
        log.info("codeanalysis service started (semgrep=%s)",
                 sast_pkg.semgrep_runner.is_available(self.cfg.semgrep_bin))

    async def stop(self) -> None:
        log.info("codeanalysis service stopping")
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
        await self.db.close()

    # ------------------------------------------------------------------
    # reachability
    # ------------------------------------------------------------------
    async def run_reachability(self, project_name: str, files: dict[str, str]) -> dict[str, Any]:
        cg = reach.build_callgraph(files)
        result: dict[str, Any] = {
            "project": project_name,
            "files_parsed": cg.files_parsed,
            "files_skipped": cg.files_skipped,
            "imported_modules": len(cg.imported_modules),
            "graded": 0,
            "breakdown": {"reachable": 0, "potential": 0, "unreachable": 0, "unknown": 0},
            "reachable": [],
        }
        if not self._db_ok:
            result["note"] = "database unavailable; reachability not persisted"
            return result
        project = await self.db.get_project(project_name)
        if project is None:
            result["note"] = f"no SBOM for project '{project_name}'; run sca first"
            return result
        vulns = await self.db.fetch_project_vulns(project_name)
        if not vulns:
            result["note"] = "project has no dependency vulnerabilities to grade"
            return result

        for v in vulns:
            symbols = reach.symbols_from_row(v.get("refs"), v.get("summary"), v.get("name") or "")
            graded = reach.grade_vuln(
                cg, ecosystem=v.get("ecosystem"), name=v.get("name"), symbols=symbols,
            )
            await self.db.update_reachability(
                v["vuln_id"], graded["reachability"],
                graded["reachable_symbol"], graded["call_path"],
            )
            result["graded"] += 1
            result["breakdown"][graded["reachability"]] += 1
            if graded["reachability"] == "reachable":
                result["reachable"].append({
                    "osv_id": v.get("osv_id"), "package": v.get("name"),
                    "symbol": graded["reachable_symbol"],
                    "call_path": graded["call_path"],
                })
        return result

    # ------------------------------------------------------------------
    # SAST
    # ------------------------------------------------------------------
    async def run_sast(self, project_name: str, files: dict[str, str],
                       source_ref: Optional[str]) -> dict[str, Any]:
        engine_res = sast_pkg.run_sast(
            files,
            enable_semgrep=self.cfg.enable_semgrep,
            semgrep_bin=self.cfg.semgrep_bin,
            semgrep_config=self.cfg.semgrep_config,
            semgrep_timeout_s=self.cfg.semgrep_timeout_s,
        )
        hits = normalize.dedupe(engine_res.get("hits", []))
        result: dict[str, Any] = {
            "project": project_name,
            "engine": engine_res.get("engine"),
            "note": engine_res.get("note"),
            "hits": len(hits),
            "by_class": _count_by(hits, "rule_class"),
            "by_severity": _count_by(hits, "severity"),
            "code_findings_written": 0,
            "findings_posted": 0,
        }
        project = await self._project_for(project_name, source_ref)

        written = 0
        if self._db_ok and project.get("id"):
            for h in hits:
                try:
                    row = await self.db.upsert_code_finding(**normalize.code_finding_row(h, project))
                    if row:
                        written += 1
                except Exception:
                    log.exception("upsert_code_finding failed for %s", h.get("rule"))
        else:
            result.setdefault("note", "")
            result["persisted"] = False
        result["code_findings_written"] = written

        items = [normalize.build_sast_finding(h, project) for h in hits]
        if items and self.orch is not None:
            res = await self.orch.bulk_findings(items)
            result["findings_posted"] = int(res.get("accepted", 0) or 0)
        return result

    async def _project_for(self, project_name: str, source_ref: Optional[str]) -> dict[str, Any]:
        if self._db_ok:
            project = await self.db.get_project(project_name)
            if project:
                return project
        return {"id": None, "name": project_name, "asset_id": None, "source_ref": source_ref}

    # ------------------------------------------------------------------
    # combined
    # ------------------------------------------------------------------
    async def run_analyze(self, project_name: str, files: dict[str, str],
                          source_ref: Optional[str]) -> dict[str, Any]:
        async with self._lock:
            files = sanitize_files(files)
            reachability = await self.run_reachability(project_name, files)
            sast = await self.run_sast(project_name, files, source_ref)
            counts = {
                "project": project_name,
                "files": len(files),
                "reachability": reachability,
                "sast": sast,
            }
            self.stats["analyses"] += 1
            self.stats["last_run"] = datetime.now(timezone.utc).isoformat()
            self.stats["last_counts"] = {
                "reachability": reachability.get("breakdown"),
                "sast_hits": sast.get("hits"),
                "engine": sast.get("engine"),
            }
            log.info("analyze complete: %s", self.stats["last_counts"])
            return counts

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------
    async def _handle_healthz(self, _req: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def _handle_readyz(self, _req: web.Request) -> web.Response:
        ok = self._ready and (not self._db_ok or await self.db.ping())
        return web.json_response({"ready": ok, "db": self._db_ok}, status=200 if ok else 503)

    async def _handle_stats(self, _req: web.Request) -> web.Response:
        db_stats: dict[str, Any]
        try:
            db_stats = await self.db.stats() if self._db_ok else {"available": False}
        except Exception as exc:
            db_stats = {"error": str(exc)}
        return web.json_response({
            "service": self.stats,
            "semgrep_available": sast_pkg.semgrep_runner.is_available(self.cfg.semgrep_bin),
            "db": db_stats,
        })

    async def _read_body(self, req: web.Request) -> tuple[Optional[dict[str, Any]], Optional[web.Response]]:
        try:
            body = await req.json()
        except Exception:
            return None, web.json_response({"error": "invalid JSON body"}, status=400)
        if not isinstance(body, dict):
            return None, web.json_response({"error": "body must be an object"}, status=400)
        return body, None

    async def _handle_analyze(self, req: web.Request) -> web.Response:
        body, err = await self._read_body(req)
        if err:
            return err
        assert body is not None
        project_name = body.get("project_name")
        files = body.get("files")
        if not project_name or not isinstance(files, dict):
            return web.json_response(
                {"error": "project_name and files{path:content} are required"}, status=400)
        try:
            counts = await self.run_analyze(
                str(project_name),
                {str(k): v for k, v in files.items() if isinstance(v, str)},
                source_ref=body.get("source_ref"),
            )
        except Exception as exc:
            log.exception("/analyze failed")
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response(counts)

    async def _handle_reachability(self, req: web.Request) -> web.Response:
        body, err = await self._read_body(req)
        if err:
            return err
        assert body is not None
        project_name = body.get("project_name") or body.get("project")
        files = body.get("files")
        if not project_name or not isinstance(files, dict):
            return web.json_response(
                {"error": "project_name and files{path:content} are required"}, status=400)
        try:
            async with self._lock:
                clean = sanitize_files({str(k): v for k, v in files.items()})
                result = await self.run_reachability(str(project_name), clean)
            self.stats["reachability_runs"] += 1
        except Exception as exc:
            log.exception("/reachability failed")
            return web.json_response({"error": str(exc)}, status=500)
        return web.json_response(result)

    def _make_app(self) -> web.Application:
        # tenant = X-Paddock-Tenant from the orchestrator (needs the service key)
        app = web.Application(
            client_max_size=128 * 1024 * 1024,
            middlewares=[tenancy.aiohttp_middleware()],
        )
        app.add_routes([
            web.get("/healthz", self._handle_healthz),
            web.get("/readyz", self._handle_readyz),
            web.get("/stats", self._handle_stats),
            web.post("/analyze", self._handle_analyze),
            web.post("/reachability", self._handle_reachability),
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


def _count_by(hits: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for h in hits:
        k = str(h.get(key) or "unknown")
        out[k] = out.get(k, 0) + 1
    return out


async def _amain() -> None:
    cfg = config_module.load()
    svc = CodeAnalysisService(cfg)
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
