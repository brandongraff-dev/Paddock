"""Provable containment API: invariants, zones, labels, reach graph, coverage, evaluation.

Owned by the API work package (docs/ASSURANCE_P1.md sections 7 and 8). Registered in main.py.

Conventions (all of them are load-bearing for the isolation sweeps):

* **Tenancy.** The governance middleware stamps the tenant on the request context, and the pool's
  setup hook stamps it on every ``pool.acquire()``; nothing in this file names ``tenant_id``.
* **Uniform 404.** A foreign id and an unknown id are answered by the *same* statement with the
  *same* body (RLS makes a foreign row invisible), and body validation always runs before any
  lookup, so a caller can never tell "not yours" from "does not exist".
* **RBAC.** Reads are ``read`` (the safe-method default); every mutation falls through to the
  deny-closed ``admin`` default in ``auth.required_capability``. No rule is added for them.
* **Billing.** Mutations that create or change paid work are gated with
  ``billing_gate.require_paid("assurance")``; reads and DELETEs are never gated (a downgraded
  tenant can read what it has and clean up, as for the other gated features).
* **Audit.** Every mutation writes a semantic ``audit.record`` (best effort, never fails the
  request); the middleware's generic per-request row exists as well.
* **Soundness.** A verdict is never reported fresher than it is: an invariant that was disabled
  and re-enabled, or whose definition changed, has its ``last_graph_version`` cleared so the runner
  treats it as due, and the list shows it as ``PENDING`` rather than as a stale ``HOLDS``.

``paddock_assurance`` is imported lazily inside handlers so ``scripts/export_openapi.py`` and the SDK
checks (which install only the orchestrator) can import this module.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Annotated, Any, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, StringConstraints, field_validator, model_validator

from .. import audit, tenancy
from ..assurance import store
from ..auth import Principal, current_principal
from ..billing import gate as billing_gate
from ..config import settings
from ..db import get_pool

logger = logging.getLogger(__name__)
router = APIRouter(tags=["assurance"])

#: ``POST /v1/assurance/evaluate`` gives up (answering 200 ``ok: false``) after this long; the
#: runner is cancelled cleanly (its lease is released in a ``finally``).
EVALUATE_TIMEOUT_S = 240.0
#: Hard caps for the coverage report so one huge tenant cannot make a read unbounded.
MAX_COVERAGE_NODES = 200_000
MAX_COVERAGE_FACTS = 400_000

_PAID = Depends(billing_gate.require_paid("assurance"))
_Tier = Literal["declared", "configured", "observed", "tested"]
_Id = Annotated[str, StringConstraints(min_length=1, max_length=128)]


# --------------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _not_found(what: str) -> HTTPException:
    """The ONE 404 for an unknown or foreign id (identical body, identical status)."""
    return HTTPException(status_code=404, detail=f"{what} not found")


def _unprocessable(msg: str, field: str = "body") -> HTTPException:
    return HTTPException(status_code=422, detail=[{"loc": ["body", field], "msg": msg,
                                                   "type": "value_error"}])


def _j(value: Any, default: Any) -> Any:
    """A jsonb value as Python (asyncpg hands jsonb back as text unless a codec is set)."""
    for _ in range(3):
        if isinstance(value, (str, bytes)):
            try:
                value = json.loads(value)
            except ValueError:
                return default
        else:
            break
    return value if isinstance(value, type(default)) else default


def _int(value: Any) -> int:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0


def _lib() -> Any:
    try:
        import paddock_assurance as lib  # noqa: PLC0415
        return lib
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="assurance library is not installed") from exc


def _page(items: list[Any], total: int, limit: int, offset: int) -> dict[str, Any]:
    return {"items": items, "total": int(total), "limit": limit, "offset": offset}


async def _audit(request: Request, pool: Any, principal: Principal, *, action: str,
                 resource_type: str, resource_id: Optional[str], details: dict[str, Any],
                 justification: Optional[str] = None, status: int = 200) -> None:
    """Semantic audit row (what changed, from what, why). Best effort: never fails the request."""
    try:
        await audit.record(
            pool, action=action, actor=principal.actor, actor_role=principal.role,
            resource_type=resource_type, resource_id=resource_id, method=request.method,
            path=request.url.path, status=status, justification=justification,
            request_id=getattr(request.state, "request_id", None), details=details)
    except Exception:  # noqa: BLE001 -- the change is committed; losing the extra row must not 500
        logger.exception("assurance_audit_failed", extra={"audit_action": action})


# --------------------------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------------------------

class _Justified(BaseModel):
    justification: str = Field(min_length=1, max_length=1000,
                               description="Why. Recorded with the change and in the audit log.")

    @field_validator("justification")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("a justification is required")
        return v


class InvariantOut(BaseModel):
    id: UUID
    invariant_id: str
    title: str
    severity: str
    enabled: bool
    source: Literal["std", "custom"]
    digest: str
    version: int
    status: str = Field(description="HOLDS | VIOLATED | UNKNOWN | EXPIRED (a HOLDS that outlived its "
                                    "evidence) | PENDING (not evaluated for this definition yet) | DISABLED")
    last_verdict: Optional[str] = None
    stale: bool = Field(False, description="Evaluated against an older graph version than the current one.")
    reasons: list[str] = Field(default_factory=list)
    violation_count: int = 0
    evidence_tier: Optional[str] = None
    coverage: Optional[dict[str, Any]] = None
    last_graph_version: Optional[int] = None
    last_evaluated_at: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_by: Optional[str] = None
    updated_at: Optional[datetime] = None


class InvariantVersionOut(BaseModel):
    digest: str
    version: int
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None


class InvariantDetail(InvariantOut):
    yaml: str
    last_result: Optional[dict[str, Any]] = None
    versions: list[InvariantVersionOut] = Field(default_factory=list)


class InvariantPage(BaseModel):
    items: list[InvariantOut]
    total: int
    limit: int
    offset: int


class InvariantCreate(BaseModel):
    yaml: str = Field(min_length=1, max_length=65536)
    enabled: bool = True


class InvariantUpdate(BaseModel):
    yaml: Optional[str] = Field(None, min_length=1, max_length=65536)
    enabled: Optional[bool] = None

    @model_validator(mode="after")
    def _something(self) -> "InvariantUpdate":
        if self.yaml is None and self.enabled is None:
            raise ValueError("supply yaml and/or enabled")
        return self


class InvariantChange(BaseModel):
    invariant: InvariantOut
    changed: bool = Field(description="False when nothing moved (same definition, same enabled flag).")
    created: bool = False
    new_version: bool = False


class StdInvariantOut(BaseModel):
    id: str
    title: str
    severity: str
    description: Optional[str] = None
    assertion: str
    digest: str
    installed: bool
    enabled: bool
    up_to_date: bool = Field(description="The tenant's copy has the shipped digest.")
    installed_digest: Optional[str] = None
    version: Optional[int] = None
    invariant_row_id: Optional[UUID] = None


class RunOut(BaseModel):
    id: UUID
    invariant_id: str
    digest: str
    verdict: str
    reasons: list[str] = Field(default_factory=list)
    graph_version: int
    violation_count: int
    coverage_covered: int
    coverage_universe: int
    evaluated_at: datetime
    valid_until: Optional[datetime] = None
    result: Optional[dict[str, Any]] = None


class RunPage(BaseModel):
    items: list[RunOut]
    total: int
    limit: int
    offset: int


class EvaluateIn(BaseModel):
    invariant_ids: Optional[list[_Id]] = Field(
        None, max_length=100, description="std:x / acme:y ids or row UUIDs; default: every enabled invariant.")
    rebuild: bool = Field(False, description="Re-run the graph builders first.")


class EvaluateOut(BaseModel):
    ok: bool
    degraded: bool = False
    skipped: Optional[str] = None
    built: bool = False
    graph_version: Optional[int] = None
    evaluated: int = 0
    results: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    builders: dict[str, Any] = Field(default_factory=dict)
    ignored_disabled: list[str] = Field(default_factory=list)


class ZoneOut(BaseModel):
    id: UUID
    name: str
    kind: str
    cidrs: list[str]
    description: str = ""
    source: str = "declared"
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ZonePage(BaseModel):
    items: list[ZoneOut]
    total: int
    limit: int
    offset: int


class ZoneCreate(_Justified):
    name: str = Field(max_length=64)
    cidrs: list[Annotated[str, StringConstraints(max_length=64)]] = Field(max_length=256)
    kind: str = Field("custom", max_length=32)
    description: str = Field("", max_length=1000)


class ZoneUpdate(_Justified):
    cidrs: Optional[list[Annotated[str, StringConstraints(max_length=64)]]] = Field(None, max_length=256)
    kind: Optional[str] = Field(None, max_length=32)
    description: Optional[str] = Field(None, max_length=1000)

    @model_validator(mode="after")
    def _something(self) -> "ZoneUpdate":
        if self.cidrs is None and self.kind is None and self.description is None:
            raise ValueError("supply cidrs, kind and/or description")
        return self


class ZoneChangeOut(BaseModel):
    zone: ZoneOut
    changed: bool
    created: bool = False
    overlaps: list[str] = Field(default_factory=list,
                                description="Other zones sharing address space (most specific wins).")
    graph_version: Optional[int] = None


class ZoneDeleteOut(BaseModel):
    deleted: bool = True
    name: str
    graph_version: Optional[int] = None
    labels_still_naming_it: int = 0


class LabelOut(BaseModel):
    id: UUID
    node_ref: str
    tag: str
    value: str
    source: str
    set_by: Optional[str] = None
    justification: str = ""
    set_at: Optional[datetime] = None


class LabelPage(BaseModel):
    items: list[LabelOut]
    total: int
    limit: int
    offset: int


class LabelSet(_Justified):
    node_ref: str = Field(max_length=128)
    tag: str = Field(max_length=64)
    value: str = Field("", max_length=128)


class LabelChangeOut(BaseModel):
    label: LabelOut
    changed: bool
    previous: Optional[str] = None
    graph_version: Optional[int] = None
    warnings: list[str] = Field(default_factory=list)


class LabelDeleteOut(BaseModel):
    deleted: bool = True
    node_ref: str
    tag: str
    previous: Optional[str] = None
    graph_version: Optional[int] = None


# --------------------------------------------------------------------------------------------
# Invariants: row -> API
# --------------------------------------------------------------------------------------------

_INV_COLS = ("id, invariant_id, title, severity, enabled, source, digest, version, last_verdict, "
             "last_result, last_graph_version, last_evaluated_at, valid_until, created_by, created_at, "
             "updated_by, updated_at")


def _status(row: Any, now: datetime) -> str:
    """The verdict as it may be shown *now*: never a HOLDS that outlived its evidence or that was
    never evaluated for the current definition."""
    if not row["enabled"]:
        return "DISABLED"
    verdict = row["last_verdict"]
    if verdict is None:
        return "PENDING"
    if verdict == "HOLDS":
        if row["last_graph_version"] is None:
            return "PENDING"          # re-enabled / retry-marked: the old HOLDS is not trusted
        vu = row["valid_until"]
        if vu is not None and now >= vu:
            return "EXPIRED"
    return verdict


def _inv_out(row: Any, now: datetime, graph_version: int, *, detail: bool = False,
             versions: Optional[list[Any]] = None) -> dict[str, Any]:
    last = _j(row["last_result"], {})
    cov = last.get("coverage") if isinstance(last.get("coverage"), dict) else None
    lgv = row["last_graph_version"]
    out: dict[str, Any] = {
        "id": row["id"], "invariant_id": row["invariant_id"], "title": row["title"],
        "severity": row["severity"], "enabled": row["enabled"], "source": row["source"],
        "digest": row["digest"], "version": row["version"], "status": _status(row, now),
        "last_verdict": row["last_verdict"], "stale": lgv is None or int(lgv) != int(graph_version),
        "reasons": [str(r) for r in (last.get("reasons") or []) if isinstance(r, str)],
        "violation_count": _int(last.get("violation_count")),
        "evidence_tier": last.get("evidence_tier") if isinstance(last.get("evidence_tier"), str) else None,
        "coverage": cov, "last_graph_version": lgv, "last_evaluated_at": row["last_evaluated_at"],
        "valid_until": row["valid_until"], "created_by": row["created_by"],
        "created_at": row["created_at"], "updated_by": row["updated_by"], "updated_at": row["updated_at"],
    }
    if detail:
        out["yaml"] = row["yaml"]
        out["last_result"] = last or None
        out["versions"] = [dict(v) for v in (versions or [])]
    return out


async def _graph_version(con: Any) -> int:
    return (await store.get_state(con)).graph_version


def _compile(text: str) -> Any:
    """Parse + compile via the library. 422 with the library's problem list when it is not valid."""
    lib = _lib()
    try:
        return lib.compile_text(text)
    except lib.ParseError as exc:
        problems = list(exc.problems)
    except lib.CompileError as exc:
        problems = [str(exc)]
    except Exception as exc:  # noqa: BLE001 -- a library bug is the caller's 422, never a 500
        logger.exception("assurance_compile_failed")
        problems = [f"could not be compiled ({type(exc).__name__})"]
    raise HTTPException(status_code=422, detail={"error": "invalid_invariant", "problems": problems[:100]})


@lru_cache(maxsize=1)
def _std_catalog() -> tuple[dict[str, Any], ...]:
    """The shipped std invariants (compiled once; they only change with the library version)."""
    from paddock_assurance import stdlib  # noqa: PLC0415

    out = []
    for sid in stdlib.list_std():
        plan = stdlib.load_std(sid)
        out.append({"id": sid, "title": plan.invariant.title, "severity": plan.invariant.severity,
                    "description": plan.invariant.description, "assertion": plan.invariant.assert_,
                    "digest": plan.digest, "yaml": stdlib.std_text(sid)})
    return tuple(out)


def _std_entry(std_id: str) -> dict[str, Any]:
    sid = std_id if std_id.startswith("std:") else f"std:{std_id}"
    _lib()
    for e in _std_catalog():
        if e["id"] == sid:
            return e
    raise _not_found("std invariant")


async def _versions(con: Any, invariant_id: str) -> list[Any]:
    return await con.fetch(
        "SELECT digest, version, created_by, created_at FROM invariant_versions "
        "WHERE invariant_id = $1 ORDER BY created_at DESC, version DESC LIMIT 200", invariant_id)


async def _invariant_row(con: Any, inv_uuid: UUID, *, lock: bool = False) -> Any:
    row = await con.fetchrow(
        f"SELECT {_INV_COLS}, yaml FROM invariants WHERE id = $1{' FOR UPDATE' if lock else ''}", inv_uuid)
    if row is None:
        raise _not_found("invariant")
    return row


async def _detail(pool: Any, inv_uuid: UUID) -> dict[str, Any]:
    async with pool.acquire() as con:
        row = await _invariant_row(con, inv_uuid)
        gv = await _graph_version(con)
        vers = await _versions(con, row["invariant_id"])
    return _inv_out(row, _now(), gv, detail=True, versions=vers)


async def _insert_version(con: Any, invariant_id: str, digest: str, version: int, text: str,
                          actor: str) -> None:
    await con.execute(
        "INSERT INTO invariant_versions (invariant_id, digest, version, yaml, created_by) "
        "VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, invariant_id, digest) DO NOTHING",
        invariant_id, digest, version, text, actor)


# --------------------------------------------------------------------------------------------
# Invariants: routes
# --------------------------------------------------------------------------------------------

@router.get("/v1/invariants", response_model=InvariantPage)
async def list_invariants(
    enabled: Optional[bool] = Query(None),
    source: Optional[Literal["std", "custom"]] = Query(None),
    status: Optional[str] = Query(None, max_length=16),
    q: Optional[str] = Query(None, max_length=128),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
    pool=Depends(get_pool),
):
    """Invariants with their last verdict, freshness (``EXPIRED``) and coverage ratio."""
    where, args = [], []
    if enabled is not None:
        args.append(enabled)
        where.append(f"enabled = ${len(args)}")
    if source is not None:
        args.append(source)
        where.append(f"source = ${len(args)}")
    if q:
        args.append(f"%{q}%")
        where.append(f"(invariant_id ILIKE ${len(args)} OR title ILIKE ${len(args)})")
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    now = _now()
    async with pool.acquire() as con:
        gv = await _graph_version(con)
        if status:
            # The status is derived (expiry, pending), so it is filtered after the read. Bounded.
            rows = await con.fetch(f"SELECT {_INV_COLS} FROM invariants {clause} "
                                   "ORDER BY invariant_id LIMIT 5000", *args)
            outs = [_inv_out(r, now, gv) for r in rows]
            outs = [o for o in outs if o["status"] == status.upper()]
            return _page(outs[offset:offset + limit], len(outs), limit, offset)
        total = await con.fetchval(f"SELECT count(*) FROM invariants {clause}", *args)
        rows = await con.fetch(
            f"SELECT {_INV_COLS} FROM invariants {clause} ORDER BY invariant_id "
            f"LIMIT ${len(args) + 1} OFFSET ${len(args) + 2}", *args, limit, offset)
    return _page([_inv_out(r, now, gv) for r in rows], total, limit, offset)


@router.get("/v1/invariants/std", response_model=list[StdInvariantOut])
async def list_std_invariants(pool=Depends(get_pool)):
    """The shipped std invariants and whether this tenant has each one enabled."""
    _lib()
    async with pool.acquire() as con:
        rows = await con.fetch("SELECT id, invariant_id, enabled, digest, version FROM invariants "
                               "WHERE source = 'std'")
    have = {r["invariant_id"]: r for r in rows}
    out = []
    for e in _std_catalog():
        r = have.get(e["id"])
        out.append({
            "id": e["id"], "title": e["title"], "severity": e["severity"], "description": e["description"],
            "assertion": e["assertion"], "digest": e["digest"], "installed": r is not None,
            "enabled": bool(r and r["enabled"]), "up_to_date": bool(r and r["digest"] == e["digest"]),
            "installed_digest": r["digest"] if r else None, "version": r["version"] if r else None,
            "invariant_row_id": r["id"] if r else None,
        })
    return out


@router.post("/v1/invariants/std/{std_id}/enable", response_model=InvariantChange, dependencies=[_PAID])
async def enable_std_invariant(
    std_id: str, request: Request, response: Response, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Copy a shipped invariant into the tenant and enable it (idempotent; refreshes a stale copy)."""
    e = _std_entry(std_id)
    actor, created, new_version, prev_digest = principal.actor, False, False, None
    async with pool.acquire() as con:
        async with con.transaction():
            cur = await con.fetchrow("SELECT id, enabled, digest, version FROM invariants "
                                     "WHERE invariant_id = $1 FOR UPDATE", e["id"])
            if cur is None:
                rid = await con.fetchval(
                    "INSERT INTO invariants (invariant_id, title, severity, enabled, source, yaml, digest, "
                    "version, created_by, updated_by) VALUES ($1, $2, $3, TRUE, 'std', $4, $5, 1, $6, $6) "
                    "ON CONFLICT (tenant_id, invariant_id) DO UPDATE SET enabled = TRUE RETURNING id",
                    e["id"], e["title"], e["severity"], e["yaml"], e["digest"], actor)
                await _insert_version(con, e["id"], e["digest"], 1, e["yaml"], actor)
                created = changed = True
            else:
                rid, prev_digest = cur["id"], cur["digest"]
                changed = not cur["enabled"] or cur["digest"] != e["digest"]
                if changed:
                    new_version = cur["digest"] != e["digest"]
                    ver = cur["version"] + 1 if new_version else cur["version"]
                    # last_graph_version/valid_until cleared: the old verdict (from before it was
                    # disabled, or for the old definition) must not be shown or trusted as current.
                    await con.execute(
                        "UPDATE invariants SET enabled = TRUE, yaml = $2, digest = $3, title = $4, "
                        "severity = $5, version = $6, last_graph_version = NULL, valid_until = NULL, "
                        "updated_by = $7, updated_at = NOW() WHERE id = $1",
                        rid, e["yaml"], e["digest"], e["title"], e["severity"], ver, actor)
                    if new_version:
                        await _insert_version(con, e["id"], e["digest"], ver, e["yaml"], actor)
        gv = await _graph_version(con)
        row = await _invariant_row(con, rid)
    if changed:
        await _audit(request, pool, principal, action="assurance_std_enable", resource_type="invariants",
                     resource_id=str(rid), details={"invariant_id": e["id"], "digest": e["digest"],
                                                    "previous_digest": prev_digest, "created": created})
    response.status_code = 201 if created else 200
    return {"invariant": _inv_out(row, _now(), gv), "changed": changed, "created": created,
            "new_version": new_version or created}


@router.post("/v1/invariants", response_model=InvariantChange, status_code=201, dependencies=[_PAID])
async def create_invariant(
    body: InvariantCreate, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Create a custom invariant from YAML (parsed and compiled by the library; 422 lists the problems)."""
    plan = _compile(body.yaml)
    if plan.id.startswith("std:"):
        raise HTTPException(status_code=422, detail={"error": "invalid_invariant", "problems": [
            "id: the 'std:' namespace is reserved for the shipped library (use POST "
            "/v1/invariants/std/{id}/enable)"]})
    inv = plan.invariant
    async with pool.acquire() as con:
        async with con.transaction():
            rid = await con.fetchval(
                "INSERT INTO invariants (invariant_id, title, severity, enabled, source, yaml, digest, "
                "version, created_by, updated_by) VALUES ($1, $2, $3, $4, 'custom', $5, $6, 1, $7, $7) "
                "ON CONFLICT (tenant_id, invariant_id) DO NOTHING RETURNING id",
                plan.id, inv.title, inv.severity, body.enabled, body.yaml, plan.digest, principal.actor)
            if rid is None:
                raise HTTPException(status_code=409, detail=f"invariant {plan.id!r} already exists "
                                                            "(use PUT to change it)")
            await _insert_version(con, plan.id, plan.digest, 1, body.yaml, principal.actor)
        gv = await _graph_version(con)
        row = await _invariant_row(con, rid)
    await _audit(request, pool, principal, action="assurance_invariant_create", resource_type="invariants",
                 resource_id=str(rid), status=201,
                 details={"invariant_id": plan.id, "digest": plan.digest, "severity": inv.severity,
                          "assertion": inv.assert_, "enabled": body.enabled})
    return {"invariant": _inv_out(row, _now(), gv), "changed": True, "created": True, "new_version": True}


@router.get("/v1/invariants/{invariant_id}", response_model=InvariantDetail)
async def get_invariant(invariant_id: UUID, pool=Depends(get_pool)):
    return await _detail(pool, invariant_id)


@router.put("/v1/invariants/{invariant_id}", response_model=InvariantChange, dependencies=[_PAID])
async def update_invariant(
    invariant_id: UUID, body: InvariantUpdate, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Change the definition (new digest => new version row) and/or toggle ``enabled``.

    A std invariant's text is owned by the shipped library (it would be overwritten), so only
    ``enabled`` can change there.
    """
    plan = _compile(body.yaml) if body.yaml is not None else None
    changed = new_version = False
    prev: dict[str, Any] = {}
    async with pool.acquire() as con:
        async with con.transaction():
            cur = await _invariant_row(con, invariant_id, lock=True)
            prev = {"digest": cur["digest"], "enabled": cur["enabled"], "version": cur["version"]}
            sets: list[tuple[str, Any]] = []     # (column, value) -> "col = $n"
            clears: list[str] = []               # columns reset to NULL
            version = cur["version"]
            if plan is not None:
                if cur["source"] == "std":
                    raise _unprocessable("a std invariant's definition is managed by the shipped library; "
                                         "only 'enabled' can be changed", "yaml")
                if plan.id != cur["invariant_id"]:
                    raise HTTPException(status_code=422, detail={"error": "invalid_invariant", "problems": [
                        f"id: the definition says {plan.id!r} but this invariant is "
                        f"{cur['invariant_id']!r} (the id cannot change)"]})
                if plan.digest != cur["digest"]:
                    version += 1
                    new_version = changed = True
                    sets += [("yaml", body.yaml), ("digest", plan.digest), ("title", plan.invariant.title),
                             ("severity", plan.invariant.severity), ("version", version)]
                    clears += ["last_graph_version", "valid_until"]
                    await _insert_version(con, cur["invariant_id"], plan.digest, version, body.yaml,
                                          principal.actor)
            if body.enabled is not None and body.enabled != cur["enabled"]:
                changed = True
                sets.append(("enabled", body.enabled))
                if body.enabled:
                    # Re-enabled: whatever verdict is stored predates this moment. Make it due.
                    clears += ["last_graph_version", "valid_until"]
            if changed:
                sets.append(("updated_by", principal.actor))
                assigns = [f"{c} = ${i}" for i, (c, _) in enumerate(sets, 1)]
                assigns += [f"{c} = NULL" for c in dict.fromkeys(clears)]
                await con.execute(
                    f"UPDATE invariants SET {', '.join(assigns)}, updated_at = NOW() "
                    f"WHERE id = ${len(sets) + 1}", *[v for _, v in sets], invariant_id)
        gv = await _graph_version(con)
        row = await _invariant_row(con, invariant_id)
    if changed:
        await _audit(request, pool, principal, action="assurance_invariant_update",
                     resource_type="invariants", resource_id=str(invariant_id),
                     details={"invariant_id": row["invariant_id"], "previous": prev,
                              "digest": row["digest"], "version": row["version"],
                              "enabled": row["enabled"], "new_version": new_version})
    return {"invariant": _inv_out(row, _now(), gv), "changed": changed, "created": False,
            "new_version": new_version}


@router.delete("/v1/invariants/{invariant_id}", response_model=InvariantChange)
async def delete_invariant(
    invariant_id: UUID, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Disable and archive. The row, every ``invariant_versions`` row and the run ledger stay
    (they are evidence); the runner stops evaluating it. ``PUT {"enabled": true}`` brings it back.
    Never gated: a downgraded tenant can always switch containment checks off cleanly."""
    async with pool.acquire() as con:
        async with con.transaction():
            cur = await _invariant_row(con, invariant_id, lock=True)
            changed = bool(cur["enabled"])
            if changed:
                await con.execute("UPDATE invariants SET enabled = FALSE, updated_by = $2, "
                                  "updated_at = NOW() WHERE id = $1", invariant_id, principal.actor)
        gv = await _graph_version(con)
        row = await _invariant_row(con, invariant_id)
    await _audit(request, pool, principal, action="assurance_invariant_archive",
                 resource_type="invariants", resource_id=str(invariant_id),
                 details={"invariant_id": row["invariant_id"], "digest": row["digest"],
                          "was_enabled": changed, "rows_kept": True})
    return {"invariant": _inv_out(row, _now(), gv), "changed": changed, "created": False,
            "new_version": False}


@router.get("/v1/invariants/{invariant_id}/runs", response_model=RunPage)
async def list_invariant_runs(
    invariant_id: UUID,
    verdict: Optional[Literal["HOLDS", "VIOLATED", "UNKNOWN"]] = Query(None),
    include_result: bool = Query(False, description="Include the stored result (witnesses, blind spots)."),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
    pool=Depends(get_pool),
):
    """The verdict-transition ledger of one invariant, newest first."""
    async with pool.acquire() as con:
        inv = await _invariant_row(con, invariant_id)
        args: list[Any] = [inv["invariant_id"]]
        clause = "WHERE invariant_id = $1"
        if verdict:
            args.append(verdict)
            clause += " AND verdict = $2"
        total = await con.fetchval(f"SELECT count(*) FROM invariant_runs {clause}", *args)
        rows = await con.fetch(
            "SELECT id, invariant_id, digest, verdict, reasons, result, graph_version, violation_count, "
            f"coverage_covered, coverage_universe, evaluated_at, valid_until FROM invariant_runs {clause} "
            f"ORDER BY evaluated_at DESC, id LIMIT ${len(args) + 1} OFFSET ${len(args) + 2}",
            *args, limit, offset)
    items = []
    for r in rows:
        d = dict(r)
        d["reasons"] = [x for x in _j(d["reasons"], []) if isinstance(x, str)]
        d["result"] = (_j(d["result"], {}) or None) if include_result else None
        items.append(d)
    return _page(items, total, limit, offset)


# --------------------------------------------------------------------------------------------
# Evaluate
# --------------------------------------------------------------------------------------------

def _runner_kwargs(fn: Any, **want: Any) -> dict[str, Any]:
    """Only the keyword arguments ``fn`` accepts (the runner's optional ones may not all exist)."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return {}
    return {k: v for k, v in want.items() if k in params}


@router.post("/v1/assurance/evaluate", response_model=EvaluateOut, dependencies=[_PAID])
async def evaluate_now(
    request: Request, body: Optional[EvaluateIn] = None, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Evaluate now (optionally after rebuilding the graph). Always 200: a degraded run answers
    ``ok: false`` with the reason, never a 5xx, and never turns a failure into a ``HOLDS``."""
    body = body or EvaluateIn()
    only: Optional[list[str]] = None
    ignored: list[str] = []
    if body.invariant_ids:
        async with pool.acquire() as con:
            rows = await con.fetch(
                "SELECT id::text AS rid, invariant_id, enabled FROM invariants "
                "WHERE invariant_id = ANY($1::text[]) OR id::text = ANY($1::text[])", body.invariant_ids)
        known = {r["invariant_id"]: r for r in rows} | {r["rid"]: r for r in rows}
        if any(i not in known for i in body.invariant_ids):
            raise _not_found("invariant")
        only = sorted({known[i]["invariant_id"] for i in body.invariant_ids if known[i]["enabled"]})
        ignored = sorted({known[i]["invariant_id"] for i in body.invariant_ids if not known[i]["enabled"]})
        if not only:
            # An empty 'only' means "everything" to the runner: never pass it.
            out = EvaluateOut(ok=True, skipped="none_enabled", ignored_disabled=ignored)
            await _audit_eval(request, pool, principal, body, out)
            return out
    out = await _run_evaluation(request, pool, only, body.rebuild)
    out.ignored_disabled = ignored
    await _audit_eval(request, pool, principal, body, out)
    return out


async def _audit_eval(request: Request, pool: Any, principal: Principal, body: EvaluateIn,
                      out: EvaluateOut) -> None:
    await _audit(request, pool, principal, action="assurance_evaluate", resource_type="assurance",
                 resource_id=None, details={"invariant_ids": body.invariant_ids, "rebuild": body.rebuild,
                                            "ok": out.ok, "skipped": out.skipped,
                                            "evaluated": out.evaluated, "errors": out.errors[:5]})


async def _run_evaluation(request: Request, pool: Any, only: Optional[list[str]],
                          rebuild: bool) -> EvaluateOut:
    tid = tenancy.current_tenant_id()
    if tid is None:
        return EvaluateOut(ok=False, degraded=True, skipped="no_tenant", errors=["no tenant in context"])
    try:
        from ..assurance import runner  # noqa: PLC0415
        kw = _runner_kwargs(runner.evaluate_tenant, rebuild=rebuild,
                            redis=getattr(request.app.state, "redis", None))
        summary = await asyncio.wait_for(
            runner.evaluate_tenant(pool, tid, force=True, only=only, **kw), EVALUATE_TIMEOUT_S)
    except asyncio.TimeoutError:
        return EvaluateOut(ok=False, degraded=True, skipped="timeout",
                           errors=[f"evaluation did not finish within {int(EVALUATE_TIMEOUT_S)}s"])
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 -- the contract: 200 with ok=false, never a 5xx
        logger.exception("assurance_evaluate_api_failed")
        return EvaluateOut(ok=False, degraded=True, skipped="error",
                           errors=[f"{type(exc).__name__}: {exc}"[:300]])
    if not isinstance(summary, dict):
        return EvaluateOut(ok=False, degraded=True, skipped="error", errors=["runner returned no summary"])
    return EvaluateOut(
        ok=bool(summary.get("ok")), degraded=not summary.get("ok"),
        skipped=summary.get("skipped"), built=bool(summary.get("built")),
        graph_version=summary.get("graph_version"), evaluated=int(summary.get("evaluated") or 0),
        results=[r for r in (summary.get("results") or []) if isinstance(r, dict)][:500],
        errors=[str(e)[:300] for e in (summary.get("errors") or [])][:50],
        builders={k: v for k, v in (summary.get("builders") or {}).items()} if isinstance(
            summary.get("builders"), dict) else {})


# --------------------------------------------------------------------------------------------
# State and coverage
# --------------------------------------------------------------------------------------------

@router.get("/v1/assurance/state")
async def assurance_state(pool=Depends(get_pool)) -> dict[str, Any]:
    """Graph version, last build/evaluation, counts, and what the builders last did."""
    now = _now()
    async with pool.acquire() as con:
        st = await store.get_state(con)
        counts = {
            "nodes": await con.fetchval("SELECT count(*) FROM reach_nodes"),
            "edges": await con.fetchval("SELECT count(*) FROM reach_edges"),
            "coverage_facts": await con.fetchval("SELECT count(*) FROM reach_coverage"),
            "zones": await con.fetchval("SELECT count(*) FROM zones"),
            "labels": await con.fetchval("SELECT count(*) FROM asset_labels"),
        }
        edges_by_source = {r["source"]: r["n"] for r in await con.fetch(
            "SELECT source, count(*) AS n FROM reach_edges GROUP BY source ORDER BY source")}
        inv_rows = await con.fetch(f"SELECT {_INV_COLS} FROM invariants")
    by_status: dict[str, int] = {}
    for r in inv_rows:
        s = _status(r, now)
        by_status[s] = by_status.get(s, 0) + 1
    builders: dict[str, Any] = {}
    try:
        from ..assurance import runner  # noqa: PLC0415
        tid = tenancy.current_tenant_id()
        builders = runner.last_build(tid) if tid else {}
    except Exception:  # noqa: BLE001 -- informational only
        logger.exception("assurance_state_builders_failed")
    try:
        import paddock_assurance as lib  # noqa: PLC0415
        lib_version: Optional[str] = lib.__version__
    except ImportError:
        lib_version = None
    return {
        "graph_version": st.graph_version, "last_build_at": st.last_build_at,
        "last_eval_at": st.last_eval_at, "last_eval_version": st.last_eval_version,
        "evaluation_pending": st.graph_version != st.last_eval_version,
        "evaluation_in_progress": bool(st.lease_until and st.lease_until > now),
        "enabled": bool(getattr(settings, "assurance_enabled", False)),
        "library_version": lib_version, "counts": counts, "edges_by_source": edges_by_source,
        "invariants": {"total": len(inv_rows), "by_status": by_status},
        "builders": builders,
        "builders_note": "what this replica's last build did per source; other replicas keep their own",
    }


def _coverage_state(lib_graph: Any, rows: list[Any], facts: dict[str, list[Any]], now: datetime,
                    min_tier: Any, max_age: timedelta) -> list[dict[str, Any]]:
    """Per-node directional coverage using the library's own rule (so this view and a verdict agree)."""
    out = []
    for r in rows:
        node = lib_graph.Node(id=r["node_ref"], kind=r["kind"], coverage=tuple(facts.get(r["node_ref"], ())))
        din = lib_graph.direction_state(node, "in", now, min_tier, max_age)
        dout = lib_graph.direction_state(node, "out", now, min_tier, max_age)
        out.append({
            "node_ref": r["node_ref"], "kind": r["kind"], "label": r["label"],
            "covered_in": din.covered, "covered_out": dout.covered,
            "covered": din.covered and dout.covered, "reason_in": din.reason, "reason_out": dout.reason,
            "facts": [{"direction": c.direction, "tier": c.tier.value, "source": c.source,
                       "observed_at": c.observed_at} for c in sorted(
                           node.coverage, key=lambda c: (c.direction, c.source))],
        })
    return out


@router.get("/v1/assurance/coverage")
async def assurance_coverage(
    min_tier: _Tier = Query("configured", description="Weakest evidence that counts as coverage."),
    max_age_h: int = Query(24, ge=1, le=720, description="Oldest observation that still counts."),
    only_blind: bool = Query(False, description="Only nodes not covered in both directions."),
    kind: Optional[str] = Query(None, max_length=32),
    q: Optional[str] = Query(None, max_length=128, description="Substring of the node ref."),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
    pool=Depends(get_pool),
) -> dict[str, Any]:
    """Coverage per source and per node (directional), blind spots by reason, stale sensors.

    A node counts as covered only when it is covered inbound AND outbound by a fresh fact of at
    least ``min_tier`` (the same rule the evaluator applies). The internet node is excluded: nobody
    can instrument it, so it is never part of the universe.
    """
    lib = _lib()
    from paddock_assurance import graph as lib_graph  # noqa: PLC0415

    now = _now()
    max_age = timedelta(hours=max_age_h)
    tier = lib.Tier(min_tier)
    async with pool.acquire() as con:
        nodes = await con.fetch(
            "SELECT node_ref, kind, label FROM reach_nodes WHERE kind <> 'internet' AND node_ref <> 'internet' "
            "ORDER BY node_ref LIMIT $1", MAX_COVERAGE_NODES + 1)
        fact_rows = await con.fetch(
            "SELECT node_ref, direction, tier, source, observed_at FROM reach_coverage "
            "ORDER BY node_ref, direction, source LIMIT $1", MAX_COVERAGE_FACTS + 1)
        by_source_rows = await con.fetch(
            "SELECT source, direction, tier, count(*) AS facts, count(DISTINCT node_ref) AS nodes, "
            "min(observed_at) AS oldest, max(observed_at) AS newest, "
            "count(*) FILTER (WHERE observed_at >= $1 AND observed_at <= $2) AS fresh "
            "FROM reach_coverage GROUP BY source, direction, tier ORDER BY source, direction, tier",
            now - max_age, now + lib_graph.FUTURE_SLACK)
        sensor_rows = await con.fetch(
            "SELECT id, name, site, online, status, last_seen_at, last_upload_at, offline_since "
            "FROM sensors WHERE status = 'active' AND (NOT online OR last_upload_at IS NULL "
            "OR last_upload_at < $1) ORDER BY name, id LIMIT 200", now - max_age)
        inv_rows = await con.fetch("SELECT invariant_id, last_result FROM invariants WHERE enabled "
                                   "ORDER BY invariant_id")
    truncated = len(nodes) > MAX_COVERAGE_NODES or len(fact_rows) > MAX_COVERAGE_FACTS
    nodes, fact_rows = nodes[:MAX_COVERAGE_NODES], fact_rows[:MAX_COVERAGE_FACTS]
    facts: dict[str, list[Any]] = {}
    for f in fact_rows:
        try:
            facts.setdefault(f["node_ref"], []).append(lib_graph.Coverage(
                tier=lib.Tier(f["tier"]), observed_at=f["observed_at"], source=f["source"],
                direction=f["direction"]))
        except ValueError:
            continue  # a tier outside the vocabulary asserts nothing
    per_node = _coverage_state(lib_graph, nodes, facts, now, tier, max_age)
    n = len(per_node)
    both = sum(1 for p in per_node if p["covered"])
    reasons: dict[str, dict[str, int]] = {"in": {}, "out": {}}
    for p in per_node:
        for d in ("in", "out"):
            rsn = p[f"reason_{d}"]
            if rsn:
                reasons[d][rsn] = reasons[d].get(rsn, 0) + 1
    summary = {
        "nodes": n, "covered": both,
        "covered_in_only": sum(1 for p in per_node if p["covered_in"] and not p["covered_out"]),
        "covered_out_only": sum(1 for p in per_node if p["covered_out"] and not p["covered_in"]),
        "blind": n - both, "ratio": 1.0 if n == 0 else round(both / n, 4),
        "min_tier": min_tier, "max_age_h": max_age_h, "truncated": truncated,
    }
    sel = [p for p in per_node if (not only_blind or not p["covered"])
           and (kind is None or p["kind"] == kind) and (not q or q in p["node_ref"])]
    inv_spots = []
    totals: dict[str, int] = {}
    for r in inv_rows:
        summ = _j(r["last_result"], {}).get("blind_spot_summary")
        if not isinstance(summ, dict):
            continue
        by_reason = {str(k): int(v) for k, v in _j(summ.get("by_reason"), {}).items()
                     if isinstance(v, (int, float))}
        for k, v in by_reason.items():
            totals[k] = totals.get(k, 0) + v
        inv_spots.append({"invariant_id": r["invariant_id"], "total": _int(summ.get("total")),
                          "by_reason": by_reason})
    return {
        "summary": summary,
        "by_source": [{
            "source": r["source"], "direction": r["direction"], "tier": r["tier"], "facts": r["facts"],
            "nodes": r["nodes"], "fresh": r["fresh"], "stale": r["facts"] - r["fresh"],
            "oldest": r["oldest"], "newest": r["newest"]} for r in by_source_rows],
        "nodes": _page(sel[offset:offset + limit], len(sel), limit, offset),
        "blind_spots": {"nodes_by_reason": reasons, "evaluated_by_reason": totals,
                        "invariants": inv_spots},
        "stale_sensors": [dict(r) for r in sensor_rows],
        "evaluated_at": now,
    }


# --------------------------------------------------------------------------------------------
# Reach graph reads
# --------------------------------------------------------------------------------------------

@router.get("/v1/reach/nodes")
async def list_reach_nodes(
    kind: Optional[str] = Query(None, max_length=32),
    source: Optional[str] = Query(None, max_length=64),
    q: Optional[str] = Query(None, max_length=128, description="Substring of the node ref or label."),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
    pool=Depends(get_pool),
) -> dict[str, Any]:
    where, args = [], []
    for col, val in (("kind", kind), ("source", source)):
        if val is not None:
            args.append(val)
            where.append(f"n.{col} = ${len(args)}")
    if q:
        args.append(f"%{q}%")
        where.append(f"(n.node_ref ILIKE ${len(args)} OR n.label ILIKE ${len(args)})")
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    async with pool.acquire() as con:
        total = await con.fetchval(f"SELECT count(*) FROM reach_nodes n {clause}", *args)
        rows = await con.fetch(
            "SELECT n.node_ref, n.kind, n.label, n.asset_id, n.attrs, n.source, n.first_seen, n.last_seen "
            f"FROM reach_nodes n {clause} ORDER BY n.node_ref LIMIT ${len(args) + 1} OFFSET ${len(args) + 2}",
            *args, limit, offset)
        refs_ = [r["node_ref"] for r in rows]
        cov = await con.fetch(
            "SELECT node_ref, direction, tier, source, observed_at FROM reach_coverage "
            "WHERE node_ref = ANY($1::text[]) ORDER BY node_ref, direction, source", refs_) if refs_ else []
    by_node: dict[str, list[dict[str, Any]]] = {}
    for c in cov:
        by_node.setdefault(c["node_ref"], []).append(
            {k: c[k] for k in ("direction", "tier", "source", "observed_at")})
    items = [{**{k: r[k] for k in ("node_ref", "kind", "label", "asset_id", "source", "first_seen",
                                   "last_seen")},
              "attrs": _j(r["attrs"], {}), "coverage": by_node.get(r["node_ref"], [])} for r in rows]
    return _page(items, total, limit, offset)


@router.get("/v1/reach/edges")
async def list_reach_edges(
    source: Optional[str] = Query(None, max_length=64),
    basis: Optional[_Tier] = Query(None),
    proto: Optional[Literal["icmp", "tcp", "udp", "any"]] = Query(None),
    node: Optional[str] = Query(None, max_length=128, description="Edges into or out of this node ref."),
    src: Optional[str] = Query(None, max_length=128),
    dst: Optional[str] = Query(None, max_length=128),
    include_evidence: bool = Query(False),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
    pool=Depends(get_pool),
) -> dict[str, Any]:
    where, args = [], []
    for col, val in (("source", source), ("basis", basis), ("proto", proto), ("src_ref", src),
                     ("dst_ref", dst)):
        if val is not None:
            args.append(val)
            where.append(f"{col} = ${len(args)}")
    if node is not None:
        args.append(node)
        where.append(f"(src_ref = ${len(args)} OR dst_ref = ${len(args)})")
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    cols = ("id, src_ref, dst_ref, proto, port_lo, port_hi, basis, source, confidence, first_seen, last_seen"
            + (", evidence" if include_evidence else ""))
    async with pool.acquire() as con:
        total = await con.fetchval(f"SELECT count(*) FROM reach_edges {clause}", *args)
        rows = await con.fetch(
            f"SELECT {cols} FROM reach_edges {clause} ORDER BY src_ref, dst_ref, proto, port_lo, port_hi, "
            f"source, id LIMIT ${len(args) + 1} OFFSET ${len(args) + 2}", *args, limit, offset)
    items = []
    for r in rows:
        d = dict(r)
        if include_evidence:
            d["evidence"] = _j(d["evidence"], {})
        items.append(d)
    return _page(items, total, limit, offset)


# --------------------------------------------------------------------------------------------
# Zones
# --------------------------------------------------------------------------------------------

def _zone_out(z: Any) -> dict[str, Any]:
    return {"id": z.id, "name": z.name, "kind": z.kind, "cidrs": list(z.cidrs), "description": z.description,
            "source": z.source, "created_by": z.created_by, "created_at": z.created_at,
            "updated_at": z.updated_at}


async def _lock_zones(con: Any) -> None:
    """The store's own advisory key, so API check-then-write and the store's upsert serialise."""
    await con.execute("SELECT pg_advisory_xact_lock(hashtextextended("
                      "coalesce(current_setting('app.tenant_id', true), '') || ':zones', 0))")


async def _zone_by_id(con: Any, zone_id: UUID) -> Any:
    """The zone with this row id (RLS-scoped, so a foreign id is simply absent): 404 otherwise."""
    row = await con.fetchrow("SELECT name FROM zones WHERE id = $1", zone_id)
    zone = None if row is None else next((z for z in await store.list_zones(con) if z.id == str(zone_id)
                                          or z.name == row["name"]), None)
    if zone is None:
        raise _not_found("zone")
    return zone


@router.get("/v1/zones", response_model=ZonePage)
async def list_zones(
    limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=1_000_000),
    pool=Depends(get_pool),
):
    async with pool.acquire() as con:
        zones = await store.list_zones(con)
    return _page([_zone_out(z) for z in zones[offset:offset + limit]], len(zones), limit, offset)


@router.post("/v1/zones", response_model=ZoneChangeOut, status_code=201, dependencies=[_PAID])
async def create_zone(
    body: ZoneCreate, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Declare a zone. Names ``^[a-z][a-z0-9-]{0,31}$``; CIDRs are validated and canonicalised."""
    try:
        store.validate_zone_name(body.name)
        if body.name in store.RESERVED_ZONES:
            raise ValueError(f"zone name {body.name!r} is reserved")
    except ValueError as exc:
        raise _unprocessable(str(exc), "name") from exc
    async with pool.acquire() as con:
        async with con.transaction():
            await _lock_zones(con)
            if await con.fetchval("SELECT 1 FROM zones WHERE name = $1", body.name):
                raise HTTPException(status_code=409, detail=f"zone {body.name!r} already exists "
                                                            "(use PUT to change it)")
            try:
                ch = await store.upsert_zone(con, body.name, body.cidrs, kind=body.kind,
                                             description=body.description, set_by=principal.actor,
                                             justification=body.justification)
            except ValueError as exc:
                raise _unprocessable(str(exc)) from exc
        z = next(z for z in await store.list_zones(con) if z.name == body.name)
    await _audit(request, pool, principal, action="assurance_zone_create", resource_type="zones",
                 resource_id=str(z.id), justification=body.justification, status=201,
                 details={"name": z.name, "kind": z.kind, "cidrs": list(ch.cidrs),
                          "overlaps": list(ch.overlaps), "graph_version": ch.graph_version})
    return {"zone": _zone_out(z), "changed": ch.changed, "created": True,
            "overlaps": list(ch.overlaps), "graph_version": ch.graph_version}


@router.get("/v1/zones/{zone_id}", response_model=ZoneOut)
async def get_zone(zone_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        return _zone_out(await _zone_by_id(con, zone_id))


@router.put("/v1/zones/{zone_id}", response_model=ZoneChangeOut, dependencies=[_PAID])
async def update_zone(
    zone_id: UUID, body: ZoneUpdate, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Change a zone's CIDRs, kind or description (the name is its identity and cannot change)."""
    async with pool.acquire() as con:
        async with con.transaction():
            await _lock_zones(con)
            cur = await _zone_by_id(con, zone_id)
            try:
                ch = await store.upsert_zone(
                    con, cur.name, cur.cidrs if body.cidrs is None else body.cidrs,
                    kind=cur.kind if body.kind is None else body.kind,
                    description=cur.description if body.description is None else body.description,
                    set_by=principal.actor, justification=body.justification)
            except ValueError as exc:
                raise _unprocessable(str(exc)) from exc
        z = await _zone_by_id(con, zone_id)
    await _audit(request, pool, principal, action="assurance_zone_update", resource_type="zones",
                 resource_id=str(zone_id), justification=body.justification,
                 details={"name": z.name, "previous_cidrs": list(cur.cidrs), "cidrs": list(ch.cidrs),
                          "kind": z.kind, "changed": ch.changed, "overlaps": list(ch.overlaps),
                          "graph_version": ch.graph_version})
    return {"zone": _zone_out(z), "changed": ch.changed, "created": False,
            "overlaps": list(ch.overlaps), "graph_version": ch.graph_version}


@router.delete("/v1/zones/{zone_id}", response_model=ZoneDeleteOut)
async def delete_zone(
    zone_id: UUID, request: Request,
    justification: Optional[str] = Query(None, max_length=1000),
    pool=Depends(get_pool), principal: Principal = Depends(current_principal),
):
    """Delete a zone (bumps the graph version). Nodes in it lose the zone; invariants that select it
    then select nothing and answer UNKNOWN, never HOLDS. Never gated (clean-up)."""
    why = (justification or "").strip() or "deleted via API (no justification given)"
    async with pool.acquire() as con:
        async with con.transaction():
            await _lock_zones(con)
            cur = await _zone_by_id(con, zone_id)
            version = await store.delete_zone(con, cur.name, set_by=principal.actor, justification=why)
            if version is None:
                raise _not_found("zone")
            naming = await con.fetchval("SELECT count(*) FROM asset_labels WHERE tag = 'zone' AND value = $1",
                                        cur.name)
    await _audit(request, pool, principal, action="assurance_zone_delete", resource_type="zones",
                 resource_id=str(zone_id), justification=why,
                 details={"name": cur.name, "cidrs": list(cur.cidrs), "graph_version": version,
                          "labels_still_naming_it": int(naming)})
    return {"deleted": True, "name": cur.name, "graph_version": version,
            "labels_still_naming_it": int(naming)}


# --------------------------------------------------------------------------------------------
# Labels
# --------------------------------------------------------------------------------------------

_LABEL_COLS = "id, node_ref, tag, value, source, set_by, justification, set_at"


@router.get("/v1/labels", response_model=LabelPage)
async def list_labels(
    node_ref: Optional[str] = Query(None, max_length=128),
    tag: Optional[str] = Query(None, max_length=64),
    source: Optional[Literal["declared", "metadata", "connector"]] = Query(None),
    limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=1_000_000),
    pool=Depends(get_pool),
):
    """Labels with their provenance (who set them, why, when)."""
    where, args = [], []
    for col, val in (("node_ref", node_ref), ("tag", tag), ("source", source)):
        if val is not None:
            args.append(val)
            where.append(f"{col} = ${len(args)}")
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    async with pool.acquire() as con:
        total = await con.fetchval(f"SELECT count(*) FROM asset_labels {clause}", *args)
        rows = await con.fetch(
            f"SELECT {_LABEL_COLS} FROM asset_labels {clause} ORDER BY node_ref, tag "
            f"LIMIT ${len(args) + 1} OFFSET ${len(args) + 2}", *args, limit, offset)
    return _page([dict(r) for r in rows], total, limit, offset)


@router.put("/v1/labels", response_model=LabelChangeOut, dependencies=[_PAID])
async def set_label(
    body: LabelSet, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Declare a label (zone, class, crown-jewel, app-tier, ...) with a mandatory justification.
    Changing one changes verdicts, so it bumps the graph version and is audited."""
    warnings: list[str] = []
    try:
        node_ref, tag, value = store.validate_label(body.node_ref, body.tag, body.value)
    except ValueError as exc:
        raise _unprocessable(str(exc)) from exc
    if tag == "zone" and value in store.RESERVED_ZONES:
        raise _unprocessable(f"zone {value!r} is reserved for the internet node", "value")
    async with pool.acquire() as con:
        if node_ref.startswith("asset:"):
            if not await con.fetchval("SELECT 1 FROM assets WHERE id = $1", UUID(node_ref[6:])):
                raise _unprocessable("no such asset in this tenant", "node_ref")
        if tag == "zone" and not await con.fetchval("SELECT 1 FROM zones WHERE name = $1", value):
            warnings.append(f"zone {value!r} is not declared; the label still places the node in it")
        try:
            ch = await store.set_label(con, node_ref, tag, value, set_by=principal.actor,
                                       justification=body.justification)
        except ValueError as exc:
            raise _unprocessable(str(exc)) from exc
        row = await con.fetchrow(f"SELECT {_LABEL_COLS} FROM asset_labels WHERE node_ref = $1 AND tag = $2",
                                 node_ref, tag)
    await _audit(request, pool, principal, action="assurance_label_set", resource_type="asset_labels",
                 resource_id=str(row["id"]), justification=body.justification,
                 details={"node_ref": node_ref, "tag": tag, "value": value, "previous": ch.previous,
                          "changed": ch.changed, "graph_version": ch.graph_version})
    return {"label": dict(row), "changed": ch.changed, "previous": ch.previous,
            "graph_version": ch.graph_version, "warnings": warnings}


@router.delete("/v1/labels/{label_id}", response_model=LabelDeleteOut)
async def delete_label(
    label_id: UUID, request: Request,
    justification: Optional[str] = Query(None, max_length=1000),
    pool=Depends(get_pool), principal: Principal = Depends(current_principal),
):
    """Remove a label (bumps the graph version). Never gated (clean-up)."""
    why = (justification or "").strip() or "removed via API (no justification given)"
    async with pool.acquire() as con:
        row = await con.fetchrow("SELECT node_ref, tag FROM asset_labels WHERE id = $1", label_id)
        if row is None:
            raise _not_found("label")
        try:
            ch = await store.delete_label(con, row["node_ref"], row["tag"], set_by=principal.actor,
                                          justification=why)
        except ValueError as exc:
            # A row that cannot be addressed through the store's validation (e.g. a legacy ref).
            raise _unprocessable(str(exc)) from exc
    if not ch.changed:
        raise _not_found("label")      # a concurrent delete won
    await _audit(request, pool, principal, action="assurance_label_delete", resource_type="asset_labels",
                 resource_id=str(label_id), justification=why,
                 details={"node_ref": row["node_ref"], "tag": row["tag"], "previous": ch.previous,
                          "graph_version": ch.graph_version})
    return {"deleted": True, "node_ref": row["node_ref"], "tag": row["tag"], "previous": ch.previous,
            "graph_version": ch.graph_version}

