"""Correlation service entry point.

Responsibilities, running concurrently in one process:

* HTTP (FastAPI) on 8091: /healthz, /readyz, /rules, POST /sweep,
  POST /recompute-blast.
* Redis stream subscriber: `stream:events`, consumer group `correlation`.
  Reacts to `finding_opened` and `asset_added`.
* Periodic sweep every `SWEEP_INTERVAL_MIN` minutes.
* YAML hot-reload via watchfiles over the rules directories.

Everything is async; nothing blocks the event loop.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import tenancy
from .config import settings
from .db import Database
from .engine.attack_mapping import (
    AttackMapLoader,
    AttackMapper,
    default_rules_path,
)
from .engine.attackpath import AttackPathEngine
from .engine.blast import BlastScorer
from .engine.chain import ChainMatcher, PolicyEvaluator
from .engine.fusion import FusionEngine
from .engine.graph import Graph
from .engine.policy import RuleLoader
from .narratives.writer import NarrativeWriter
from .orchestrator import OrchestratorClient

log = logging.getLogger("correlation")


# ----------------------------------------------------------------------------
# Service composition
# ----------------------------------------------------------------------------

class Service:
    def __init__(self) -> None:
        self.cfg = settings()
        logging.basicConfig(
            level=self.cfg.log_level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        self.db = Database(self.cfg.database_url)
        self.orch = OrchestratorClient(self.cfg.orchestrator_url)
        self.loader = RuleLoader(
            builtin_dir=self.cfg.builtin_rules_dir,
            overlay_dir=self.cfg.policies_dir,
        )
        self.matcher: Optional[ChainMatcher] = None
        self.policy_eval: Optional[PolicyEvaluator] = None
        self.blast: Optional[BlastScorer] = None
        self.graph: Optional[Graph] = None
        self.attackpaths: Optional[AttackPathEngine] = None
        self.fusion: Optional[FusionEngine] = None
        self.attack_loader = AttackMapLoader(
            default_rules_path(self.cfg.builtin_rules_dir)
        )
        self.mapper: Optional[AttackMapper] = None
        self.narratives = NarrativeWriter()
        self._redis: Any = None
        self._bg_tasks: list[asyncio.Task[Any]] = []
        self._ready = False
        # Attack-path recompute debounce state, PER TENANT: one tenant's pending
        # recompute must never swallow another tenant's trigger.
        self._pathcompute_locks: dict[str, asyncio.Lock] = {}
        self._pathcompute_tasks: dict[str, asyncio.Task[Any]] = {}
        self._last_pathcompute: dict[str, float] = {}

    async def startup(self) -> None:
        self.loader.load_all()
        log.info(
            "loaded %d chains, %d policies, %d errors",
            len(self.loader.chains),
            len(self.loader.policies),
            len(self.loader.errors),
        )
        await self.db.connect()
        self.matcher = ChainMatcher(self.db, self.loader, self.orch)
        self.policy_eval = PolicyEvaluator(self.db, self.orch)
        self.blast = BlastScorer(self.db, self.orch)
        self.graph = Graph(self.db)
        self.attackpaths = AttackPathEngine(
            self.db, redis=None, events_stream=self.cfg.events_stream
        )
        self.fusion = FusionEngine(
            self.db, redis=None, events_stream=self.cfg.events_stream
        )

        # ATT&CK + CWE mapping: load the technique-map catalog and seed the
        # attack_technique_map table idempotently.
        self.attack_loader.load()
        self.mapper = AttackMapper(self.db, self.attack_loader.rules)
        log.info(
            "loaded %d attack-map rules, %d errors",
            len(self.attack_loader.rules),
            len(self.attack_loader.errors),
        )
        if self.cfg.attack_map_enabled:
            try:
                # attack_technique_map is a global catalogue: platform-only writes.
                with tenancy.platform_context():
                    n = await self.mapper.sync_catalog()
                log.info("attack_technique_map catalog synced: %d rules", n)
            except Exception:
                log.exception("attack catalog sync failed")

        # Redis is optional for tests; import lazily.
        try:
            import redis.asyncio as aioredis

            # socket_timeout > XREADGROUP block (redis-py >= 6 defaults it to 5s).
            self._redis = aioredis.from_url(
                self.cfg.redis_url, decode_responses=True, socket_timeout=30
            )
            await self._redis.ping()
            self.attackpaths.set_redis(self._redis)
            if self.fusion is not None:
                self.fusion.set_redis(self._redis)
            await self._ensure_consumer_group()
            self._bg_tasks.append(
                asyncio.create_task(self._consume_events(), name="events")
            )
        except Exception:
            log.exception("redis unavailable; running without event stream")

        self._bg_tasks.append(
            asyncio.create_task(self._periodic_sweep(), name="sweep")
        )
        self._bg_tasks.append(
            asyncio.create_task(self._periodic_pathsweep(), name="pathsweep")
        )
        self._bg_tasks.append(
            asyncio.create_task(self._watch_rules(), name="watch")
        )
        self._ready = True

    async def shutdown(self) -> None:
        self._ready = False
        for task in list(self._pathcompute_tasks.values()):
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._pathcompute_tasks.clear()
        for t in self._bg_tasks:
            t.cancel()
        for t in self._bg_tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        self._bg_tasks.clear()
        if self._redis is not None:
            try:
                await self._redis.aclose()
            except Exception:  # pragma: no cover
                pass
        await self.orch.close()
        await self.db.close()

    # ------------------------------------------------------------------
    # Event loop
    # ------------------------------------------------------------------

    async def _ensure_consumer_group(self) -> None:
        if self._redis is None:
            return
        try:
            await self._redis.xgroup_create(
                self.cfg.events_stream,
                self.cfg.consumer_group,
                id="$",
                mkstream=True,
            )
        except Exception as e:
            if "BUSYGROUP" not in str(e):
                log.warning("xgroup_create: %s", e)

    async def _consume_events(self) -> None:
        assert self._redis is not None
        stream = self.cfg.events_stream
        group = self.cfg.consumer_group
        name = self.cfg.consumer_name
        log.info("event consumer started: group=%s name=%s", group, name)
        while True:
            try:
                resp = await self._redis.xreadgroup(
                    groupname=group,
                    consumername=name,
                    streams={stream: ">"},
                    count=16,
                    block=5000,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("xreadgroup failed; backing off")
                await asyncio.sleep(2.0)
                continue
            if not resp:
                continue
            for _stream_name, items in resp:
                for msg_id, fields in items:
                    try:
                        await self._handle_event(fields)
                    except tenancy.TenantError as exc:
                        log.warning("dropping event %s without a usable tenant: %s", msg_id, exc)
                    except Exception:
                        log.exception("event %s failed", msg_id)
                    finally:
                        try:
                            await self._redis.xack(stream, group, msg_id)
                        except Exception:
                            log.warning(
                                "xack failed for %s", msg_id
                            )

    async def _handle_event(self, fields: dict[str, Any]) -> None:
        # Fields may arrive as a single "json" key or as flat kv.
        if "json" in fields:
            try:
                payload = json.loads(fields["json"])
            except json.JSONDecodeError:
                return
        else:
            payload = fields

        ev = payload.get("event")
        if ev not in ("finding_opened", "asset_added", "edge_added"):
            return
        # The event names its tenant; everything it triggers (DB reads/writes,
        # orchestrator calls, the debounced recompute task it spawns) runs as it.
        with tenancy.bind_event(payload):
            if ev == "finding_opened":
                fid = payload.get("finding_id")
                if fid:
                    await self._on_finding_opened(fid)
                self._trigger_pathcompute()
            elif ev == "asset_added":
                aid = payload.get("asset_id")
                if aid:
                    await self._on_asset_added(aid)
                self._trigger_pathcompute()
            elif ev == "edge_added":
                # A new edge reshapes reachability; recompute (debounced).
                self._trigger_pathcompute()
        # cve_published and finding_closed are informational; we handle
        # them via the periodic sweep for simplicity.

    async def _on_finding_opened(self, finding_id: str) -> None:
        assert self.matcher is not None and self.blast is not None
        # Chain detection
        chains = await self.matcher.match_for_finding(finding_id)
        for chain in chains:
            await self._finalize_and_upsert_chain(chain)
        # Blast score
        try:
            await self.blast.score_and_persist(finding_id)
        except Exception:
            log.exception("blast score failed for %s", finding_id)
        # ATT&CK + CWE mapping
        if self.mapper is not None and self.cfg.attack_map_enabled:
            try:
                await self.mapper.map_finding(finding_id)
            except Exception:
                log.exception("attack mapping failed for %s", finding_id)
        # Reachability × attack-path fusion. A newly-opened sca finding may
        # be the reachable dependency vuln that completes a fusion; recompute
        # the fusion set (bulk, deterministic).
        if self.fusion is not None and self.cfg.fusion_enabled:
            try:
                await self.fusion.run()
            except Exception:
                log.exception("fusion on finding_opened failed for %s", finding_id)

    async def _on_asset_added(self, asset_id: str) -> None:
        # New asset → re-run policies that might flag it.
        if self.policy_eval is None:
            return
        try:
            await self.policy_eval.evaluate_all(self.loader.policies.values())
        except Exception:
            log.exception("policy eval on asset_added failed")

    async def _finalize_and_upsert_chain(self, chain: dict[str, Any]) -> None:
        """Attach a narrative, then POST to the orchestrator."""
        assert self.matcher is not None
        rule = self.loader.chains.get(chain["chain_rule_id"])
        if rule is None:
            return
        # Rebuild anchor + matched findings for narrative templating.
        anchor_fid = chain["finding_ids"][0] if chain["finding_ids"] else None
        anchor = None
        matched_findings: list[dict[str, Any]] = []
        for fid in chain["finding_ids"]:
            row = await self.db.fetchrow(
                """
                SELECT f.id::text, f.rule_id, f.rule_source, f.severity,
                       f.cvss, f.epss, f.evidence, f.metadata,
                       a.value AS asset_value, a.kind AS asset_kind
                FROM findings f JOIN assets a ON a.id = f.asset_id
                WHERE f.id = $1::uuid
                """,
                fid,
            )
            if row is not None:
                matched_findings.append(dict(row))
        if matched_findings and anchor_fid:
            anchor = next(
                (f for f in matched_findings if f["id"] == anchor_fid),
                matched_findings[0],
            )
        narrative = self.narratives.write(
            rule.impact,
            anchor or {},
            matched_findings,
            chain.get("metadata", {}).get("matched_assets", []) or [],
        )
        chain["impact_narrative"] = narrative

        # Blast score for the chain = max blast of its component findings.
        if self.blast is not None:
            scores = []
            for f in matched_findings:
                try:
                    r = await self.blast.score_finding(f | {"asset_id": f.get("asset_id", chain["anchor_asset_id"])})
                    scores.append(r["score"])
                except Exception:
                    pass
            if scores:
                chain["blast_radius_score"] = max(scores)

        try:
            await self.orch.upsert_chain(chain)
        except Exception:
            log.exception(
                "orchestrator upsert_chain failed for %s",
                chain.get("chain_rule_id"),
            )

    async def _periodic_sweep(self) -> None:
        interval = max(1, self.cfg.sweep_interval_min) * 60
        while True:
            try:
                await asyncio.sleep(interval)
                await self.run_sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("periodic sweep crashed; continuing")

    async def run_sweep(self) -> dict[str, Any]:
        """Sweep the tenant named by the request, else every active tenant."""
        return tenancy.merge_counts(
            await tenancy.run_for_request_or_all(self.db.pool, self._sweep_tenant)
        )

    async def _sweep_tenant(self) -> dict[str, Any]:
        assert self.matcher is not None and self.policy_eval is not None
        chains = await self.matcher.sweep_open_findings()
        for c in chains:
            await self._finalize_and_upsert_chain(c)
        policy_hits = await self.policy_eval.evaluate_all(
            self.loader.policies.values()
        )
        attack: dict[str, Any] = {}
        if self.mapper is not None and self.cfg.attack_map_enabled:
            try:
                attack = await self.mapper.map_findings()
            except Exception:
                log.exception("attack mapping sweep failed")
        # Reachability × attack-path fusion runs last: it reads the
        # freshly-computed attack_paths, so recompute paths first (serialized
        # by the path lock), then fuse.
        fusion: dict[str, Any] = {}
        if self.fusion is not None and self.cfg.fusion_enabled:
            if self.attackpaths is not None:
                try:
                    await self.run_pathcompute()
                except Exception:
                    log.exception("attack-path compute before fusion failed")
            try:
                fusion = await self.fusion.run()
            except Exception:
                log.exception("fusion sweep failed")
        return {
            "chains_found": len(chains),
            "policy_findings": policy_hits,
            "attack_mapped": attack.get("mapped", 0),
            "attack_techniques": attack.get("techniques", 0),
            "attack_tactics": attack.get("tactics", 0),
            "fusion_chains": fusion.get("computed", 0),
        }

    # ------------------------------------------------------------------
    # Attack-path sweep + debounced recompute
    # ------------------------------------------------------------------

    async def _periodic_pathsweep(self) -> None:
        interval = max(1, self.cfg.attackpath_interval_min) * 60
        while True:
            try:
                await asyncio.sleep(interval)
                await self.run_pathcompute_scoped()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("periodic attack-path sweep crashed; continuing")

    @staticmethod
    def _pc_key() -> str:
        return tenancy.current_tenant_id() or "-"

    async def run_pathcompute(self) -> dict[str, Any]:
        """Recompute the CURRENT tenant's attack paths. Serialized per tenant so
        concurrent triggers and the periodic sweep never overlap."""
        assert self.attackpaths is not None
        key = self._pc_key()
        lock = self._pathcompute_locks.setdefault(key, asyncio.Lock())
        async with lock:
            result = await self.attackpaths.run()
            self._last_pathcompute[key] = asyncio.get_running_loop().time()
        return result

    async def run_pathcompute_scoped(self) -> dict[str, Any]:
        """The tenant named by the request, else every active tenant."""
        res = tenancy.merge_counts(
            await tenancy.run_for_request_or_all(self.db.pool, self.run_pathcompute)
        )
        res.setdefault("computed", 0)
        res.setdefault("elapsed_ms", 0.0)
        return res

    def _trigger_pathcompute(self) -> None:
        """Schedule a debounced attack-path recompute (≤ once per window) for
        the current tenant (the task inherits the tenant context)."""
        if self.attackpaths is None:
            return
        key = self._pc_key()
        pending = self._pathcompute_tasks.get(key)
        if pending is not None and not pending.done():
            # A recompute is already pending; it will pick up the latest graph.
            return
        self._pathcompute_tasks[key] = asyncio.create_task(
            self._debounced_pathcompute(), name=f"pathcompute-{key}"
        )

    async def _debounced_pathcompute(self) -> None:
        window = max(0, self.cfg.attackpath_debounce_sec)
        now = asyncio.get_running_loop().time()
        wait = self._last_pathcompute.get(self._pc_key(), 0.0) + window - now
        if wait > 0:
            await asyncio.sleep(wait)
        try:
            await self.run_pathcompute()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("debounced attack-path recompute failed")

    async def _watch_rules(self) -> None:
        paths = self.loader.watched_paths()
        if not paths:
            return
        try:
            from watchfiles import awatch
        except Exception:  # pragma: no cover
            log.warning("watchfiles unavailable; rule hot-reload disabled")
            return
        log.info("watching rule dirs: %s", paths)
        async for _changes in awatch(*paths, recursive=True, stop_event=None):
            try:
                self.loader.load_all()
                log.info(
                    "rules reloaded: %d chains, %d policies, %d errors",
                    len(self.loader.chains),
                    len(self.loader.policies),
                    len(self.loader.errors),
                )
            except Exception:
                log.exception("rule reload failed")


# ----------------------------------------------------------------------------
# FastAPI app
# ----------------------------------------------------------------------------

service = Service()


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    await service.startup()
    try:
        yield
    finally:
        await service.shutdown()


app = FastAPI(
    title="paddock correlation",
    version="0.1.0",
    lifespan=_lifespan,
)


@app.middleware("http")
async def _tenant_middleware(request: Request, call_next):
    """Bind the tenant the caller (the orchestrator, with the service key)
    names via X-Paddock-Tenant; naming one without the key is refused."""
    try:
        tid = tenancy.request_tenant(request.headers, path=request.url.path)
    except tenancy.TenantError as exc:
        return JSONResponse({"error": "tenant_forbidden", "detail": str(exc)}, status_code=403)
    if tid is None:
        return await call_next(request)
    with tenancy.tenant_context(tid):
        return await call_next(request)


class SweepResponse(BaseModel):
    chains_found: int
    policy_findings: int
    attack_mapped: int = 0
    attack_techniques: int = 0
    attack_tactics: int = 0
    fusion_chains: int = 0


class MapAttackResponse(BaseModel):
    mapped: int
    techniques: int
    tactics: int
    elapsed_ms: float


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> dict[str, Any]:
    if not service._ready:
        raise HTTPException(status_code=503, detail="not ready")
    return {"status": "ready", "rules": len(service.loader.chains) + len(service.loader.policies)}


@app.get("/rules")
async def rules() -> dict[str, Any]:
    summary = service.loader.summary()
    if service.attackpaths is not None:
        try:
            summary["attack_paths"] = await service.attackpaths.count()
        except Exception:
            summary["attack_paths"] = None
    # ATT&CK technique-map catalog + current coverage counts.
    attack: dict[str, Any] = {
        "enabled": service.cfg.attack_map_enabled,
        "rules": len(service.attack_loader.rules),
        "errors": service.attack_loader.errors,
    }
    if service.mapper is not None:
        try:
            cov = await service.mapper.coverage()
            attack["techniques"] = len(cov["by_technique"])
            attack["tactics"] = len(cov["by_tactic"])
            attack["by_tactic"] = cov["by_tactic"]
            attack["findings_mapped"] = cov["total"]
        except Exception:
            log.exception("attack coverage read failed")
    summary["attack"] = attack
    # Reachability × attack-path fusion coverage.
    fusion: dict[str, Any] = {"enabled": service.cfg.fusion_enabled}
    if service.fusion is not None:
        try:
            fusion["chains"] = await service.fusion.count()
        except Exception:
            fusion["chains"] = None
    summary["fusion"] = fusion
    return summary


@app.post("/map-attack", response_model=MapAttackResponse)
async def map_attack() -> MapAttackResponse:
    if service.mapper is None:
        raise HTTPException(status_code=503, detail="not ready")
    if not service.cfg.attack_map_enabled:
        raise HTTPException(status_code=409, detail="attack mapping disabled")
    res = tenancy.merge_counts(await tenancy.run_for_request_or_all(
        service.db.pool, service.mapper.map_findings))
    return MapAttackResponse(
        mapped=res.get("mapped", 0), techniques=res.get("techniques", 0),
        tactics=res.get("tactics", 0), elapsed_ms=res.get("elapsed_ms", 0.0))


@app.get("/attack/coverage")
async def attack_coverage() -> dict[str, Any]:
    if service.mapper is None:
        raise HTTPException(status_code=503, detail="not ready")
    return await service.mapper.coverage()


class ComputePathsResponse(BaseModel):
    computed: int
    elapsed_ms: float


@app.post("/compute-paths", response_model=ComputePathsResponse)
async def compute_paths() -> ComputePathsResponse:
    if service.attackpaths is None:
        raise HTTPException(status_code=503, detail="not ready")
    res = await service.run_pathcompute_scoped()
    return ComputePathsResponse(
        computed=res["computed"], elapsed_ms=res["elapsed_ms"]
    )


class FuseResponse(BaseModel):
    fused: int
    elapsed_ms: float


@app.post("/fuse", response_model=FuseResponse)
async def fuse() -> FuseResponse:
    if service.fusion is None:
        raise HTTPException(status_code=503, detail="not ready")
    if not service.cfg.fusion_enabled:
        raise HTTPException(status_code=409, detail="fusion disabled")
    res = tenancy.merge_counts(await tenancy.run_for_request_or_all(
        service.db.pool, service.fusion.run))
    return FuseResponse(fused=res.get("computed", 0), elapsed_ms=res.get("elapsed_ms", 0.0))


@app.post("/sweep", response_model=SweepResponse)
async def sweep() -> SweepResponse:
    res = await service.run_sweep()
    return SweepResponse(**res)


@app.post("/recompute-blast")
async def recompute_blast(limit: int = 2000) -> dict[str, int]:
    if service.blast is None:
        raise HTTPException(status_code=503, detail="not ready")
    async def _one() -> dict[str, Any]:
        return {"n": await service.blast.recompute_all_open(limit=limit)}

    res = tenancy.merge_counts(await tenancy.run_for_request_or_all(service.db.pool, _one))
    return {"recomputed": int(res.get("n", 0))}


# Entry point for `python -m app.main`
def _run() -> None:  # pragma: no cover
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings().http_port,
        log_level=settings().log_level.lower(),
    )


if __name__ == "__main__":  # pragma: no cover
    _run()
