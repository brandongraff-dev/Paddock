"""Worker loop.

Consumes ``queue:active`` as a Redis stream in consumer group
``active-workers``. Each message is a job dict (see CONTRACTS.md); this
dispatcher routes it to a module and reports status to the orchestrator.

Per-job concurrency is capped globally by ``MAX_CONCURRENCY`` and per-host
by the PolitenessLimiter.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import socket
import sys
import time
import uuid
from typing import Any, Awaitable, Callable

import orjson
import structlog
from redis.asyncio import Redis

from app import tenancy
from app.config import settings
from app.orchestrator import OrchestratorClient
from app.scope_guard import ScopeDenied, ScopeGuard
from app.util.politeness import PolitenessLimiter

log = structlog.get_logger(__name__)


def _configure_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(message)s",
        stream=sys.stdout,
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.log_level, logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )


# ----- dispatcher ----------------------------------------------------------


class Worker:
    def __init__(self):
        self.consumer_name = f"{settings.worker_id}-{socket.gethostname()}-{os.getpid()}"
        self.redis: Redis | None = None
        self.orch: OrchestratorClient | None = None
        self.scope: ScopeGuard | None = None
        self.politeness: PolitenessLimiter | None = None
        self.sem: asyncio.Semaphore | None = None
        self._stop = asyncio.Event()

    async def setup(self) -> None:
        self.redis = Redis.from_url(settings.redis_url, decode_responses=True)
        # Ensure the consumer group exists; MKSTREAM auto-creates the stream
        # if a worker is up before the orchestrator writes to it.
        try:
            await self.redis.xgroup_create(
                settings.queue_stream, settings.consumer_group,
                id="$", mkstream=True,
            )
        except Exception as e:
            # BUSYGROUP means it already exists — expected.
            if "BUSYGROUP" not in str(e):
                raise
        self.orch = OrchestratorClient()
        self.scope = ScopeGuard(self.orch)
        self.politeness = PolitenessLimiter()
        self.sem = asyncio.Semaphore(settings.max_concurrency)
        log.info("worker.ready",
                 worker_id=settings.worker_id,
                 consumer=self.consumer_name,
                 max_concurrency=settings.max_concurrency,
                 per_target_concurrency=settings.max_concurrency_per_target)

    async def shutdown(self) -> None:
        self._stop.set()
        if self.orch:
            await self.orch.close()
        if self.redis:
            await self.redis.aclose()
        log.info("worker.shutdown")

    async def run_forever(self) -> None:
        assert self.redis is not None
        inflight: set[asyncio.Task] = set()
        while not self._stop.is_set():
            try:
                resp = await self.redis.xreadgroup(
                    groupname=settings.consumer_group,
                    consumername=self.consumer_name,
                    streams={settings.queue_stream: ">"},
                    count=max(1, settings.max_concurrency - len(inflight)),
                    block=2000,
                )
            except Exception as e:
                log.warning("worker.xreadgroup_failed", error=str(e))
                await asyncio.sleep(1.0)
                continue
            if not resp:
                # reap finished tasks
                done = {t for t in inflight if t.done()}
                inflight -= done
                continue
            for _stream, messages in resp:
                for msg_id, fields in messages:
                    job_raw = fields.get("job") or fields.get("payload") or ""
                    task = asyncio.create_task(self._run_with_sem(msg_id, job_raw))
                    inflight.add(task)
                    task.add_done_callback(inflight.discard)

        # drain
        if inflight:
            await asyncio.gather(*inflight, return_exceptions=True)

    async def _run_with_sem(self, msg_id: str, job_raw: str) -> None:
        assert self.sem is not None
        async with self.sem:
            await self._handle_job(msg_id, job_raw)

    async def _handle_job(self, msg_id: str, job_raw: str) -> None:
        assert self.redis is not None
        try:
            job = json.loads(job_raw) if isinstance(job_raw, str) else job_raw
        except json.JSONDecodeError:
            log.error("worker.bad_job_json", msg_id=msg_id)
            await self.redis.xack(settings.queue_stream, settings.consumer_group, msg_id)
            return
        # The job names its tenant (the orchestrator put it there). Bind it for
        # the WHOLE job: scope checks, results and status callbacks all echo it.
        try:
            with tenancy.bind_job(job if isinstance(job, dict) else {}):
                await self._handle_bound_job(msg_id, job)
        except tenancy.TenantError as e:
            log.error("worker.job_without_tenant_dropped", msg_id=msg_id, error=str(e))
            await self.redis.xack(settings.queue_stream, settings.consumer_group, msg_id)

    async def _handle_bound_job(self, msg_id: str, job: dict[str, Any]) -> None:
        assert self.redis is not None
        assert self.orch is not None

        scan_id = job.get("scan_id") or str(uuid.uuid4())
        kind = job.get("kind")
        target = job.get("target")
        config = job.get("config") or {}
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(scan_id=scan_id, kind=kind, target=target)
        log.info("job.start")

        try:
            await self.orch.scan_start(scan_id)
        except Exception as e:
            log.warning("job.start_report_failed", error=str(e))

        try:
            handler = _DISPATCH.get(kind)
            if handler is None:
                raise ValueError(f"unknown job kind: {kind!r}")
            result = await asyncio.wait_for(
                handler(self, scan_id, target, config),
                timeout=settings.job_timeout_sec,
            )
            await self._emit_results(result)
            try:
                await self.orch.scan_complete(scan_id, result.get("summary", {}))
            except Exception as e:
                log.warning("job.complete_report_failed", error=str(e))
            log.info("job.done", summary=result.get("summary"))
        except ScopeDenied as e:
            log.warning("job.scope_denied", reason=e.reason, normalized=e.normalized)
            try:
                await self.orch.scan_fail(scan_id, f"scope denied: {e.reason}")
            except Exception:
                pass
        except asyncio.TimeoutError:
            log.warning("job.timeout", timeout_sec=settings.job_timeout_sec)
            try:
                await self.orch.scan_fail(scan_id, "job timeout")
            except Exception:
                pass
        except Exception as e:
            log.exception("job.error")
            try:
                await self.orch.scan_fail(scan_id, str(e))
            except Exception:
                pass
        finally:
            try:
                await self.redis.xack(settings.queue_stream, settings.consumer_group, msg_id)
            except Exception as e:
                log.warning("job.ack_failed", error=str(e))
            try:
                await self.redis.xadd(settings.event_stream, {
                    "tenant_id": tenancy.current_tenant_id() or "",
                    "event": "scan_completed",
                    "ts": str(time.time()),
                    "scan_id": scan_id,
                    "kind": kind or "",
                    "target": target or "",
                })
            except Exception:
                pass
            structlog.contextvars.clear_contextvars()

    async def _emit_results(self, result: dict[str, Any]) -> None:
        assert self.orch is not None
        assets = result.get("assets") or []
        edges = result.get("edges") or []
        findings = result.get("findings") or []
        if assets or edges:
            try:
                await self.orch.assets_bulk(assets, edges)
            except Exception as e:
                log.warning("emit.assets_failed", error=str(e), count=len(assets))
        if findings:
            try:
                await self.orch.findings_bulk(findings)
            except Exception as e:
                log.warning("emit.findings_failed", error=str(e), count=len(findings))


# ----- handler dispatch ----------------------------------------------------


HandlerFn = Callable[["Worker", str, str, dict], Awaitable[dict]]


async def _h_http_probe(w: Worker, scan_id: str, target: str, config: dict) -> dict:
    from app.modules import http_probe

    return await http_probe.probe(
        target, scope=w.scope, politeness=w.politeness,
        orchestrator=w.orch, scan_id=scan_id,
    )


async def _h_port_scan(w: Worker, scan_id: str, target: str, config: dict) -> dict:
    from app.modules import port_scan

    return await port_scan.scan(
        target, scope=w.scope, politeness=w.politeness,
        orchestrator=w.orch, ports=config.get("ports", "top-100"),
        scan_id=scan_id,
    )


async def _h_tls_inspect(w: Worker, scan_id: str, target: str, config: dict) -> dict:
    from app.modules import tls_inspect

    return await tls_inspect.inspect(
        target, scope=w.scope, politeness=w.politeness,
        orchestrator=w.orch, scan_id=scan_id,
    )


async def _h_crawl(w: Worker, scan_id: str, target: str, config: dict) -> dict:
    from app.modules import crawler

    return await crawler.crawl(
        target, scope=w.scope, politeness=w.politeness,
        orchestrator=w.orch,
        depth=int(config.get("depth", 2)),
        respect_robots=bool(config.get("respect_robots", True)),
        scan_id=scan_id,
    )


async def _h_nuclei(w: Worker, scan_id: str, target: str, config: dict) -> dict:
    from app.modules import nuclei_runner

    return await nuclei_runner.run_nuclei(
        target, scope=w.scope, politeness=w.politeness, orchestrator=w.orch,
        severity=config.get("severity", "low,medium,high,critical"),
        tags=config.get("tags", "exposure,misconfig,cve"),
        scan_id=scan_id,
    )


async def _h_header_check(w: Worker, scan_id: str, target: str, config: dict) -> dict:
    """Standalone header check: perform a GET to collect headers, then run
    the pure-Python analyzer. Mostly used as a leaf of full_recon.
    """
    from app.modules import http_probe

    return await http_probe.probe(
        target, scope=w.scope, politeness=w.politeness,
        orchestrator=w.orch, scan_id=scan_id,
    )


async def _h_exposed_file(w: Worker, scan_id: str, target: str, config: dict) -> dict:
    from app.modules import exposed_file

    return await exposed_file.scan(
        target, scope=w.scope, politeness=w.politeness,
        orchestrator=w.orch, scan_id=scan_id,
    )


async def _h_screenshot(w: Worker, scan_id: str, target: str, config: dict) -> dict:
    from app.modules import screenshot

    return await screenshot.capture(
        target, scope=w.scope, politeness=w.politeness,
        orchestrator=w.orch, asset_id=config.get("asset_id"),
        scan_id=scan_id,
    )


async def _h_takeover_scan(w: Worker, scan_id: str, target: str, config: dict) -> dict:
    from app.modules import takeover_check

    return await takeover_check.check(
        target, scope=w.scope, politeness=w.politeness,
        orchestrator=w.orch, scan_id=scan_id,
        asset_metadata=config.get("asset_metadata") or config.get("metadata"),
    )


async def _h_tls_grade(w: Worker, scan_id: str, target: str, config: dict) -> dict:
    from app.modules import tls_grade

    return await tls_grade.grade_host(
        target, scope=w.scope, politeness=w.politeness,
        orchestrator=w.orch, scan_id=scan_id,
        asset_id=config.get("asset_id"),
    )


async def _h_verify_finding(w: Worker, scan_id: str, target: str, config: dict) -> dict:
    from app.modules import verify_finding

    return await verify_finding.verify(
        target, scope=w.scope, politeness=w.politeness,
        orchestrator=w.orch, scan_id=scan_id, config=config,
    )


async def _h_full_recon(w: Worker, scan_id: str, target: str, config: dict) -> dict:
    """Orchestrate the full pipeline:
        http_probe -> (if live) header_check + exposed_file + crawler
                   -> tls_inspect
                   -> port_scan (on resolved IPs)
                   -> nuclei
                   -> screenshot
    """
    from app.modules import (
        crawler, exposed_file, http_probe, nuclei_runner, port_scan,
        screenshot, takeover_check, tls_grade, tls_inspect,
    )

    assets: list[dict] = []
    edges: list[dict] = []
    findings: list[dict] = []
    summary: dict[str, Any] = {}

    # Target shape: a bare hostname. Promote to https://host for http probing.
    base_url = target if "://" in target else f"https://{target}"

    # 1. http_probe (also emits header_check findings)
    try:
        probe_child = await w.orch.scan_create_child(scan_id, "http_probe", base_url)
    except Exception:
        probe_child = scan_id
    r = await http_probe.probe(base_url, scope=w.scope, politeness=w.politeness,
                               orchestrator=w.orch, scan_id=probe_child)
    assets += r["assets"]; edges += r["edges"]; findings += r["findings"]
    summary["http_probe"] = r.get("summary", {})
    live = bool(r.get("summary", {}).get("status"))

    # 1b. Subdomain-takeover check (DNS CNAME -> third-party unclaimed fingerprint).
    # Independent of liveness; the module scope-gates its own DNS/HTTP.
    try:
        to_child = await w.orch.scan_create_child(scan_id, "takeover_scan", _hostonly(target))
    except Exception:
        to_child = scan_id
    r = await takeover_check.check(_hostonly(target), scope=w.scope, politeness=w.politeness,
                                   orchestrator=w.orch, scan_id=to_child,
                                   asset_metadata=config.get("asset_metadata") or config.get("metadata"))
    assets += r["assets"]; edges += r["edges"]; findings += r["findings"]
    summary["takeover"] = r.get("summary", {})

    if live:
        # 2. exposed_file + crawler
        try:
            ef_child = await w.orch.scan_create_child(scan_id, "exposed_file", base_url)
        except Exception:
            ef_child = scan_id
        r = await exposed_file.scan(base_url, scope=w.scope, politeness=w.politeness,
                                    orchestrator=w.orch, scan_id=ef_child)
        assets += r["assets"]; edges += r["edges"]; findings += r["findings"]
        summary["exposed_file"] = r.get("summary", {})

        try:
            cr_child = await w.orch.scan_create_child(scan_id, "crawl", base_url, {"depth": config.get("depth", 2)})
        except Exception:
            cr_child = scan_id
        r = await crawler.crawl(base_url, scope=w.scope, politeness=w.politeness,
                                orchestrator=w.orch,
                                depth=int(config.get("depth", 2)),
                                respect_robots=bool(config.get("respect_robots", True)),
                                scan_id=cr_child)
        assets += r["assets"]; edges += r["edges"]; findings += r["findings"]
        summary["crawl"] = r.get("summary", {})

    # 3. TLS inspect + grade. One handshake: gather_facts runs tlsx once and
    #    both inspect (assets/findings) and tls_grade (posture score) reuse it.
    tls_target = f"{_hostonly(target)}:443"
    try:
        tls_child = await w.orch.scan_create_child(scan_id, "tls_inspect", tls_target)
    except Exception:
        tls_child = scan_id
    tls_facts = await tls_inspect.gather_facts(tls_target, scope=w.scope,
                                               politeness=w.politeness,
                                               orchestrator=w.orch, scan_id=tls_child)
    r = await tls_inspect.inspect(tls_target, scope=w.scope, politeness=w.politeness,
                                  orchestrator=w.orch, scan_id=tls_child, facts=tls_facts)
    assets += r["assets"]; edges += r["edges"]; findings += r["findings"]
    summary["tls_inspect"] = r.get("summary", {})

    # 3b. TLS grade — right after tls_inspect, reusing the gathered handshake.
    try:
        grade_child = await w.orch.scan_create_child(scan_id, "tls_grade", tls_target)
    except Exception:
        grade_child = scan_id
    r = await tls_grade.grade_host(tls_target, scope=w.scope, politeness=w.politeness,
                                   orchestrator=w.orch, scan_id=grade_child,
                                   asset_id=config.get("asset_id"), facts=tls_facts)
    assets += r["assets"]; edges += r["edges"]; findings += r["findings"]
    summary["tls_grade"] = r.get("summary", {})

    # 4. Port scan: resolve host to IPs first; if unresolvable, skip quietly.
    ips = await _resolve(target)
    for ip in ips:
        try:
            ps_child = await w.orch.scan_create_child(scan_id, "port_scan", ip)
        except Exception:
            ps_child = scan_id
        r = await port_scan.scan(ip, scope=w.scope, politeness=w.politeness,
                                 orchestrator=w.orch,
                                 ports=config.get("ports", "top-100"),
                                 scan_id=ps_child)
        assets += r["assets"]; edges += r["edges"]; findings += r["findings"]
    summary["port_scan"] = {"ips": ips}

    # 5. Nuclei (only if we got a live endpoint).
    if live:
        try:
            nu_child = await w.orch.scan_create_child(scan_id, "nuclei", base_url)
        except Exception:
            nu_child = scan_id
        r = await nuclei_runner.run_nuclei(base_url, scope=w.scope,
                                           politeness=w.politeness,
                                           orchestrator=w.orch,
                                           severity=config.get("severity", "low,medium,high,critical"),
                                           tags=config.get("tags", "exposure,misconfig,cve"),
                                           scan_id=nu_child)
        assets += r["assets"]; edges += r["edges"]; findings += r["findings"]
        summary["nuclei"] = r.get("summary", {})

    # 6. Screenshot (one per endpoint).
    if live:
        try:
            ss_child = await w.orch.scan_create_child(scan_id, "screenshot", base_url)
        except Exception:
            ss_child = scan_id
        r = await screenshot.capture(base_url, scope=w.scope, politeness=w.politeness,
                                     orchestrator=w.orch, scan_id=ss_child)
        assets += r["assets"]; edges += r["edges"]; findings += r["findings"]
        summary["screenshot"] = r.get("summary", {})

    return {"assets": assets, "edges": edges, "findings": findings, "summary": summary}


def _hostonly(target: str) -> str:
    from urllib.parse import urlsplit

    if "://" in target:
        return urlsplit(target).hostname or target
    return target.split(":", 1)[0]


async def _resolve(target: str) -> list[str]:
    host = _hostonly(target)
    try:
        info = await asyncio.get_running_loop().getaddrinfo(
            host, None, type=socket.SOCK_STREAM
        )
    except Exception as e:
        log.info("resolve.failed", host=host, error=str(e))
        return []
    ips: list[str] = []
    for af, _, _, _, addr in info:
        if af == socket.AF_INET:
            ips.append(addr[0])
    # Dedupe, preserve order.
    seen: set[str] = set()
    out = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


_DISPATCH: dict[str, HandlerFn] = {
    "http_probe": _h_http_probe,
    "port_scan": _h_port_scan,
    "tls_inspect": _h_tls_inspect,
    "crawl": _h_crawl,
    "nuclei": _h_nuclei,
    "header_check": _h_header_check,
    "exposed_file": _h_exposed_file,
    "screenshot": _h_screenshot,
    "takeover_scan": _h_takeover_scan,
    "tls_grade": _h_tls_grade,
    "full_recon": _h_full_recon,
    "verify_finding": _h_verify_finding,
}


# ----- entrypoint ----------------------------------------------------------


async def amain() -> None:
    _configure_logging()
    w = Worker()
    await w.setup()
    loop = asyncio.get_running_loop()

    def _stop(*_):
        log.info("worker.signal", action="shutdown_requested")
        w._stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:  # pragma: no cover - windows
            pass
    try:
        await w.run_forever()
    finally:
        await w.shutdown()


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
