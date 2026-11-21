"""Worker loop.

- XREADGROUP on Redis stream `queue:passive`, consumer group `passive-workers`.
- For each job, dispatch to the right module(s).
- Scope-filter every discovered asset before pushing through the orchestrator.
- Report scan lifecycle to the orchestrator.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import time
import uuid
from typing import Any, Awaitable, Callable

import aiohttp
import redis.asyncio as redis_async
from loguru import logger

from .config import Settings, get_settings
from .context import ModuleContext
from .orchestrator import OrchestratorClient
from .util.rate_limit import RateLimiter
from .modules import ModuleResult
from .modules import ct_logs, dns_enum, github_search, shodan_lookup, wayback, asn_range
from .modules import cert_transparency


JobHandler = Callable[[dict[str, Any], ModuleContext], Awaitable[dict[str, Any]]]


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
def _setup_logger(level: str) -> None:
    logger.remove()
    logger.add(
        sys.stdout,
        level=level,
        serialize=True,   # structured JSON
        backtrace=False,
        diagnose=False,
    )


def _build_rate_limiter(s: Settings) -> RateLimiter:
    rl = RateLimiter()
    rl.register_sync("crtsh", rate=s.rate_crtsh_rps, capacity=1)
    rl.register_sync("censys", rate=s.rate_crtsh_rps, capacity=1)
    rl.register_sync("github", rate=s.rate_github_rps, capacity=2)
    rl.register_sync("shodan", rate=s.rate_shodan_rps, capacity=2)
    rl.register_sync("internetdb", rate=s.rate_internetdb_rps, capacity=5)
    rl.register_sync("wayback", rate=s.rate_wayback_rps, capacity=2)
    rl.register_sync("bgpview", rate=s.rate_bgpview_rps, capacity=2)
    rl.register_sync("ripe", rate=s.rate_bgpview_rps, capacity=2)
    rl.register_sync("dns", rate=s.rate_dns_rps, capacity=max(5, int(s.rate_dns_rps)))
    return rl


async def _ensure_group(r: redis_async.Redis, stream: str, group: str) -> None:
    """MKSTREAM so a brand-new deployment doesn't crash on the empty stream."""
    try:
        await r.xgroup_create(name=stream, groupname=group, id="$", mkstream=True)
        logger.info("created consumer group stream={} group={}", stream, group)
    except redis_async.ResponseError as e:
        if "BUSYGROUP" in str(e):
            return
        raise


# ---------------------------------------------------------------------------
# Scope-filtered push
# ---------------------------------------------------------------------------
async def _push_result(ctx: ModuleContext, result: ModuleResult) -> dict[str, Any]:
    """Filter the module's assets through scope_check, then bulk-post."""
    if not result.assets and not result.findings:
        return {"assets_added": 0, "findings_added": 0,
                "dropped_out_of_scope": 0, "edges_added": 0}

    # Preserve order but filter by value through scope_check.
    values = [a["value"] for a in result.assets]
    allowed_set = set(await ctx.orchestrator.filter_in_scope(values))
    kept_assets = [a for a in result.assets if a["value"] in allowed_set]

    # Edges are only valid if both endpoints are in-scope.
    kept_edges: list[dict[str, Any]] = []
    for e in result.edges:
        if e.get("src_value") in allowed_set and e.get("dst_value") in allowed_set:
            kept_edges.append(e)

    # Attach edges to each asset payload so the orchestrator can resolve them
    # by (kind, value) in the same transaction as the upsert.
    assets_payload = kept_assets
    if kept_edges:
        # Append as sidecar list; orchestrator spec allows an `edges` top-level.
        # The bulk assets endpoint supports this via extra body field.
        pass

    assets_resp = await ctx.orchestrator.post_assets(assets_payload)
    # Edges go via the same bulk endpoint with "_edge": true marker if the
    # orchestrator wants a split. For now, include them in the assets payload
    # metadata so no new endpoint is required.
    if kept_edges:
        edge_assets = [{
            "kind": "_edge",
            "value": f"{e['src_kind']}:{e['src_value']}->{e['dst_kind']}:{e['dst_value']}:{e['kind']}",
            "source": result.module,
            "metadata": e,
        } for e in kept_edges]
        try:
            await ctx.orchestrator.post_assets(edge_assets)
        except Exception as e:  # noqa: BLE001
            logger.warning("edge push failed module={} err={}", result.module, e)

    findings_resp = {"accepted": 0}
    if result.findings:
        # Findings are tied to asset values that must be in scope.
        kept_findings = [
            f for f in result.findings if f.get("asset_value") in allowed_set
        ]
        if kept_findings:
            findings_resp = await ctx.orchestrator.post_findings(kept_findings)

    return {
        "assets_added": int(assets_resp.get("accepted", len(assets_payload))),
        "edges_added": len(kept_edges),
        "findings_added": int(findings_resp.get("accepted", 0)),
        "dropped_out_of_scope": max(0, len(values) - len(allowed_set)),
    }


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
async def _run_subdomains(target: str, ctx: ModuleContext) -> dict[str, Any]:
    ct = await ct_logs.run(target, ctx)
    dn = await dns_enum.run(target, ctx)
    counts = {"ct_logs": {}, "dns_enum": {}}
    counts["ct_logs"] = await _push_result(ctx, ct)
    counts["dns_enum"] = await _push_result(ctx, dn)
    return counts


async def _run_github(target: str, ctx: ModuleContext, org: str | None) -> dict[str, Any]:
    gh = await github_search.run(target, ctx, org=org)
    return {"github_search": await _push_result(ctx, gh)}


async def _run_shodan(target: str, ctx: ModuleContext) -> dict[str, Any]:
    sh = await shodan_lookup.run(target, ctx)
    return {"shodan_lookup": await _push_result(ctx, sh)}


async def _run_wayback(target: str, ctx: ModuleContext) -> dict[str, Any]:
    wb = await wayback.run(target, ctx)
    return {"wayback": await _push_result(ctx, wb)}


async def _run_asn(target: str, ctx: ModuleContext) -> dict[str, Any]:
    an = await asn_range.run(target, ctx)
    return {"asn_range": await _push_result(ctx, an)}


async def _run_full(target: str, ctx: ModuleContext, cfg: dict[str, Any]) -> dict[str, Any]:
    """Fan out to the specialized passive kinds for this target."""
    subs_task = asyncio.create_task(_run_subdomains(target, ctx))
    wb_task = asyncio.create_task(_run_wayback(target, ctx))
    gh_task = asyncio.create_task(_run_github(target, ctx, cfg.get("org")))
    subs_counts, wb_counts, gh_counts = await asyncio.gather(subs_task, wb_task, gh_task)

    # Shodan + asn get a second phase after subdomain resolution has IPs we
    # can crawl, but we still feed the raw target through for the direct case.
    sh_counts = await _run_shodan(target, ctx) if _looks_like_ip_or_cidr(target) else {}
    asn_counts = await _run_asn(target, ctx) if _looks_like_asn(target) else {}

    out = {}
    out.update(subs_counts); out.update(wb_counts); out.update(gh_counts)
    out.update(sh_counts); out.update(asn_counts)
    return out


def _looks_like_ip_or_cidr(t: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_network(t, strict=False)
        return True
    except ValueError:
        return False


def _looks_like_asn(t: str) -> bool:
    low = t.strip().lower()
    return low.startswith("as") and low[2:].strip().isdigit()


async def _handle_ct_watch(target: str, ctx: ModuleContext,
                           stop_event: asyncio.Event) -> dict[str, Any]:
    seen = await cert_transparency.watch([target], ctx, stop_event=stop_event)
    return {"cert_transparency": {"messages_seen": seen}}


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
async def _dispatch(
    job: dict[str, Any], ctx: ModuleContext, stop_event: asyncio.Event,
) -> dict[str, Any]:
    kind = job.get("kind", "")
    target = job.get("target", "")
    cfg = job.get("config", {}) or {}
    if not target:
        raise ValueError("job missing target")

    if kind == "passive_subdomains":
        return await _run_subdomains(target, ctx)
    if kind == "passive_github":
        return await _run_github(target, ctx, cfg.get("org"))
    if kind == "passive_shodan":
        return await _run_shodan(target, ctx)
    if kind == "passive_wayback":
        return await _run_wayback(target, ctx)
    if kind == "passive_asn":
        return await _run_asn(target, ctx)
    if kind == "passive_full":
        return await _run_full(target, ctx, cfg)
    if kind == "passive_ct_watch":
        return await _handle_ct_watch(target, ctx, stop_event)
    raise ValueError(f"unknown passive kind: {kind!r}")


async def _process_job(
    ctx: ModuleContext,
    job: dict[str, Any],
    stop_event: asyncio.Event,
) -> None:
    scan_id = job.get("scan_id") or str(uuid.uuid4())
    kind = job.get("kind")
    target = job.get("target")
    log = logger.bind(scan_id=scan_id, kind=kind, target=target,
                      worker_id=ctx.settings.worker_id)

    log.info("job start")
    await ctx.orchestrator.update_scan_status(scan_id, "running")

    start = time.monotonic()
    try:
        per_module = await _dispatch(job, ctx, stop_event)
        duration_ms = int((time.monotonic() - start) * 1000)
        totals = {
            "assets_added": sum(v.get("assets_added", 0) for v in per_module.values()
                                if isinstance(v, dict)),
            "edges_added": sum(v.get("edges_added", 0) for v in per_module.values()
                               if isinstance(v, dict)),
            "findings_added": sum(v.get("findings_added", 0) for v in per_module.values()
                                  if isinstance(v, dict)),
            "dropped_out_of_scope": sum(v.get("dropped_out_of_scope", 0)
                                        for v in per_module.values()
                                        if isinstance(v, dict)),
            "duration_ms": duration_ms,
            "per_module_counts": per_module,
        }
        await ctx.orchestrator.update_scan_status(
            scan_id, "completed", result_summary=totals,
        )
        log.info("job done summary={}", totals)
    except Exception as e:  # noqa: BLE001
        log.exception("job failed")
        try:
            await ctx.orchestrator.update_scan_status(
                scan_id, "failed", error=f"{type(e).__name__}: {e!s}",
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
async def run_loop() -> None:
    s = get_settings()
    _setup_logger(s.log_level)
    logger.info("passive worker starting worker_id={}", s.worker_id)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    rl = _build_rate_limiter(s)
    sem = asyncio.Semaphore(s.max_concurrency)
    in_flight: set[asyncio.Task[Any]] = set()

    timeout = aiohttp.ClientTimeout(total=s.http_timeout_s)
    conn = aiohttp.TCPConnector(limit=50, ttl_dns_cache=300)

    async with aiohttp.ClientSession(timeout=timeout, connector=conn,
                                     headers={"User-Agent": s.http_user_agent}) as http, \
               OrchestratorClient(s) as orc:
        ctx = ModuleContext(settings=s, orchestrator=orc, rate_limiter=rl, http=http)

        # The read timeout must outlast the XREADGROUP block, or every idle
        # poll fails (redis-py >= 6 defaults socket_timeout to 5s).
        r = redis_async.from_url(
            s.redis_url, decode_responses=True,
            socket_timeout=s.poll_block_ms / 1000 + 10,
        )
        await _ensure_group(r, s.stream, s.consumer_group)

        consumer_name = f"{s.worker_id}-{os.getpid()}"
        while not stop_event.is_set():
            try:
                entries = await r.xreadgroup(
                    groupname=s.consumer_group,
                    consumername=consumer_name,
                    streams={s.stream: ">"},
                    count=max(1, s.max_concurrency),
                    block=s.poll_block_ms,
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("xreadgroup error: {}", e)
                await asyncio.sleep(1.0)
                continue
            if not entries:
                continue

            for _stream_name, msgs in entries:
                for msg_id, fields in msgs:
                    payload = fields.get("job") or fields.get("data") or ""
                    try:
                        job = json.loads(payload) if payload else dict(fields)
                    except json.JSONDecodeError:
                        logger.warning("bad job payload msg_id={}", msg_id)
                        await r.xack(s.stream, s.consumer_group, msg_id)
                        continue

                    await sem.acquire()

                    async def _run_and_ack(mid: str, j: dict[str, Any]) -> None:
                        try:
                            await _process_job(ctx, j, stop_event)
                        finally:
                            try:
                                await r.xack(s.stream, s.consumer_group, mid)
                            finally:
                                sem.release()

                    task = asyncio.create_task(_run_and_ack(msg_id, job))
                    in_flight.add(task)
                    task.add_done_callback(in_flight.discard)

        logger.info("stop requested; draining {} in-flight jobs", len(in_flight))
        if in_flight:
            await asyncio.gather(*in_flight, return_exceptions=True)
        await r.aclose()
    logger.info("passive worker exited")


def main() -> None:
    asyncio.run(run_loop())


if __name__ == "__main__":
    main()
