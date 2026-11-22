"""Proving Ground service entry point.

HTTP (FastAPI) on 8097:
  GET  /healthz /readyz
  GET  /scenarios                 the scenario catalogue
  POST /prove                     prove a hop against an isolated replica
  GET  /runs                      recent runs
  GET  /runs/{id}                 one run
  GET  /runs/{id}/proofs          the run's signed proof chain
  POST /runs/{id}/verify          replay + verify the chain

The service is OFF by default (WARGAME_ENABLED=false): /prove returns 409 until
an operator enables it and configures a sandbox backend. The default "fake"
backend builds nothing; real runs use the "docker" backend. Tenancy mirrors the
other compute services (X-Paddock-Tenant + service key).
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import tenancy
from .config import settings
from .db import Database
from .engine.prover import Prover
from .engine.signing import ProofSigner, verify_chain
from .sandbox.backend import DockerBackend, FakeBackend
from .sandbox.guard import IsolationGuard
from .sandbox.types import IsolationError
from .scenarios.base import ScenarioCtx
from .scenarios.registry import REGISTRY, catalogue, resolve
from .store import WargameStore

log = logging.getLogger("wargame")


def _make_backend(name: str):
    if name == "docker":
        return DockerBackend()
    return FakeBackend()


class Service:
    def __init__(self) -> None:
        self.cfg = settings()
        logging.basicConfig(
            level=self.cfg.log_level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        self.db = Database(self.cfg.database_url)
        self.signer = ProofSigner(self.cfg.signing_key_id, self.cfg.signing_secret)
        self.store: Optional[WargameStore] = None
        self.guard: Optional[IsolationGuard] = None
        self.prover: Optional[Prover] = None
        self._ready = False

    async def startup(self) -> None:
        await self.db.connect()
        backend = _make_backend(self.cfg.sandbox_backend)
        self.guard = IsolationGuard(
            backend,
            max_ttl_sec=self.cfg.max_replica_ttl_sec,
            max_exec_timeout_sec=self.cfg.max_run_sec,
        )
        self.prover = Prover(self.guard, self.signer)
        self.store = WargameStore(self.db)
        try:
            n = await self.store.sync_catalog(catalogue())
            log.info("wargame scenario catalogue synced: %d", n)
        except Exception:
            log.exception("wargame catalogue sync failed")
        self._ready = True

    async def shutdown(self) -> None:
        self._ready = False
        await self.db.close()


service = Service()


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    await service.startup()
    try:
        yield
    finally:
        await service.shutdown()


app = FastAPI(title="paddock wargame", version="0.1.0", lifespan=_lifespan)


@app.middleware("http")
async def _tenant_middleware(request: Request, call_next):
    try:
        tid = tenancy.request_tenant(request.headers, path=request.url.path)
    except tenancy.TenantError as exc:
        return JSONResponse({"error": "tenant_forbidden", "detail": str(exc)}, status_code=403)
    if tid is None:
        return await call_next(request)
    with tenancy.tenant_context(tid):
        return await call_next(request)


class ProveRequest(BaseModel):
    component: dict[str, Any] = Field(default_factory=dict)
    finding: dict[str, Any] = Field(default_factory=dict)
    path: dict[str, Any] = Field(default_factory=dict)
    scenario_id: Optional[str] = None


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> dict[str, Any]:
    if not service._ready:
        raise HTTPException(status_code=503, detail="not ready")
    return {
        "status": "ready",
        "enabled": service.cfg.enabled,
        "backend": service.cfg.sandbox_backend,
        "scenarios": len(REGISTRY),
        "signed": service.signer.active,
    }


@app.get("/scenarios")
async def scenarios() -> dict[str, Any]:
    return {"scenarios": catalogue()}


@app.post("/prove")
async def prove(req: ProveRequest) -> dict[str, Any]:
    if not service.cfg.enabled:
        raise HTTPException(status_code=409, detail="wargame disabled (WARGAME_ENABLED=false)")
    if service.prover is None or service.store is None:
        raise HTTPException(status_code=503, detail="not ready")
    ctx = ScenarioCtx(
        component=req.component, finding=req.finding, path=req.path,
    )
    # Resolve the scenario: explicit id, else first matching in the registry.
    scenario = None
    if req.scenario_id:
        scenario = next((s for s in REGISTRY if s.id == req.scenario_id), None)
        if scenario is None:
            raise HTTPException(status_code=404, detail=f"unknown scenario {req.scenario_id}")
    else:
        scenario = resolve(ctx)
    if scenario is None:
        raise HTTPException(status_code=422, detail="no scenario matches this component/finding")
    try:
        result = await service.prover.prove(ctx, scenario)
    except IsolationError as e:
        # Belt and suspenders: the prover already catches this, but never leak.
        raise HTTPException(status_code=409, detail=f"isolation refused: {e}") from e
    run_id = await service.store.record(result, ctx)
    return {"run_id": run_id, **result.summary()}


@app.get("/runs")
async def runs(limit: int = 50) -> dict[str, Any]:
    if service.store is None:
        raise HTTPException(status_code=503, detail="not ready")
    return {"runs": await service.store.list_runs(limit)}


@app.get("/runs/{run_id}")
async def run(run_id: str) -> dict[str, Any]:
    if service.store is None:
        raise HTTPException(status_code=503, detail="not ready")
    r = await service.store.get_run(run_id)
    if r is None:
        raise HTTPException(status_code=404, detail="run not found")
    return r


@app.get("/runs/{run_id}/proofs")
async def proofs(run_id: str) -> dict[str, Any]:
    if service.store is None:
        raise HTTPException(status_code=503, detail="not ready")
    return {"proofs": await service.store.get_proofs(run_id)}


@app.post("/runs/{run_id}/verify")
async def verify(run_id: str) -> dict[str, Any]:
    if service.store is None:
        raise HTTPException(status_code=503, detail="not ready")
    entries = await service.store.get_proofs(run_id)
    if not entries:
        raise HTTPException(status_code=404, detail="no proof chain for this run")
    ok, reason = verify_chain(entries, service.signer)
    return {"run_id": run_id, "verified": ok, "reason": reason, "entries": len(entries)}


def _run() -> None:  # pragma: no cover
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=settings().http_port,
                log_level=settings().log_level.lower())


if __name__ == "__main__":  # pragma: no cover
    _run()
