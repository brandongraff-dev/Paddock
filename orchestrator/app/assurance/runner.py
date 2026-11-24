"""Per-tenant build + evaluate loop (docs/ASSURANCE_P1.md section 6).

One pass for one tenant, under the tenant's evaluation lease (``store.claim_eval``) so N
replicas never build or evaluate the same tenant twice:

1. **Build**: if the last full build is older than ``assurance_rebuild_min`` (or a caller asks),
   run every builder: ``load`` -> ``build`` (pure, off the event loop) -> ``persist_build``. Each
   builder is isolated; one that raises is logged and noted and the others still run.
2. **Evaluate** the enabled invariants that are due: the graph version moved, the backstop
   (``assurance_backstop_min``) elapsed, a HOLDS outlived its evidence (``valid_until``), the
   definition changed or was never evaluated, or a caller forced it.
3. **Record**: ``invariants.last_*``, a ``invariant_runs`` row on a verdict or digest change (or
   when the last row is a day old), then the findings (``findings_sync``).

Soundness notes: a stored definition is **re-compiled every time**; one that no longer compiles is
recorded as ``UNKNOWN`` / ``invalid_definition`` (never skipped, never a stale HOLDS). A library
bug while evaluating is ``UNKNOWN`` / ``evaluation_error``. Neither opens or closes a finding.
Nothing here ever raises out of the loop, and nothing here reads or writes another tenant: all
SQL runs on connections acquired inside ``tenancy.tenant_context(tid)``.

``paddock_assurance`` is imported lazily inside functions so ``scripts/export_openapi.py`` and the
SDK checks (which install only the orchestrator) can import this module.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import socket
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .. import tenancy
from ..config import settings
from . import builders as builders_pkg
from . import findings_sync, graph_loader, store
from .types import BuildOutput

logger = logging.getLogger(__name__)

ACTOR = findings_sync.ACTOR
LEASE_S = 300
#: Soft per-tenant budget per tick: no new invariant is started after it (the rest stay due and
#: run next tick), so one huge tenant cannot starve the others. Forced runs ignore it.
TENANT_BUDGET_S = 30.0
#: Hard cap on one tenant's whole pass (cancels it; the lease is released in a ``finally``).
TENANT_HARD_TIMEOUT_S = 900.0
BUILDER_TIMEOUT_S = 180.0
HEARTBEAT = timedelta(days=1)
MAX_STORED_BLIND_SPOTS = 200
PROCESS_ID = f"{socket.gethostname()}:{os.getpid()}"

_app_redis: Any = None
#: tenant id -> source -> what the last build of that source did (process-local; see last_build).
_LAST_BUILD: dict[str, dict[str, dict[str, Any]]] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def last_build(tenant_id: str) -> dict[str, dict[str, Any]]:
    """What this process's last build did per source (ok, changed, counts, notes, at). Empty
    before the first build here; other replicas keep their own."""
    return {k: dict(v) for k, v in _LAST_BUILD.get(str(tenant_id), {}).items()}


# --------------------------------------------------------------------------------------------
# Library access (lazy)
# --------------------------------------------------------------------------------------------

def _lib() -> Any:
    """The assurance library, or ``None`` if it is not installed (the loop then idles loudly)."""
    try:
        import paddock_assurance as lib  # noqa: PLC0415
        return lib
    except ImportError:
        return None


def _std_module() -> Any:
    from paddock_assurance import stdlib  # noqa: PLC0415
    return stdlib


# --------------------------------------------------------------------------------------------
# Definitions
# --------------------------------------------------------------------------------------------

_INV_COLS = ("id, invariant_id, title, severity, enabled, source, yaml, digest, version, last_verdict, "
             "last_result, last_graph_version, last_evaluated_at, valid_until")


def _loads(v: Any) -> Any:
    if isinstance(v, (str, bytes)):
        try:
            return json.loads(v)
        except ValueError:
            return None
    return v


async def install_std(conn: Any, std_id: str, *, actor: str = ACTOR, enabled: bool = True) -> bool:
    """Copy a shipped ``std:*`` invariant into the tenant (idempotent; returns True if created).

    Used by the enable route and by tests. Creates the ``invariant_versions`` row too.
    """
    std = _std_module()
    text = std.std_text(std_id)
    plan = std.load_std(std_id)
    async with conn.transaction():
        row = await conn.fetchval(
            "INSERT INTO invariants (invariant_id, title, severity, enabled, source, yaml, digest, version, "
            "created_by, updated_by) VALUES ($1, $2, $3, $4, 'std', $5, $6, 1, $7, $7) "
            "ON CONFLICT (tenant_id, invariant_id) DO NOTHING RETURNING id",
            plan.id, plan.invariant.title, plan.invariant.severity, enabled, text, plan.digest, actor)
        if row is None:
            return False
        await conn.execute(
            "INSERT INTO invariant_versions (invariant_id, digest, version, yaml, created_by) "
            "VALUES ($1, $2, 1, $3, $4) ON CONFLICT (tenant_id, invariant_id, digest) DO NOTHING",
            plan.id, plan.digest, text, actor)
    return True


async def refresh_std(pool: Any) -> list[str]:
    """Bring the tenant's ``std:*`` copies up to the shipped library: when the shipped digest differs
    from the stored one, store the new text, bump ``version`` and append an ``invariant_versions``
    row. Returns the ids refreshed. A std id the library no longer ships is left as it is."""
    lib = _lib()
    if lib is None:
        return []
    std = _std_module()
    refreshed: list[str] = []
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT invariant_id, digest FROM invariants WHERE source = 'std'")
        for r in rows:
            try:
                plan = std.load_std(r["invariant_id"])
                text = std.std_text(r["invariant_id"])
            except Exception:  # noqa: BLE001 -- no longer shipped (or broken): leave the copy alone
                continue
            if plan.digest == r["digest"]:
                continue
            async with conn.transaction():
                # the WHERE re-checks under the row lock: of two racing replicas only one bumps
                ver = await conn.fetchval(
                    "UPDATE invariants SET yaml = $2, digest = $3, title = $4, severity = $5, "
                    "version = version + 1, updated_by = $6, updated_at = NOW() "
                    "WHERE invariant_id = $1 AND source = 'std' AND digest <> $3 RETURNING version",
                    r["invariant_id"], text, plan.digest, plan.invariant.title, plan.invariant.severity, ACTOR)
                if ver is None:
                    continue
                await conn.execute(
                    "INSERT INTO invariant_versions (invariant_id, digest, version, yaml, created_by) "
                    "VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, invariant_id, digest) DO NOTHING",
                    r["invariant_id"], plan.digest, ver, text, ACTOR)
                refreshed.append(r["invariant_id"])
    return refreshed


@dataclass
class _Def:
    """One enabled invariant with its compiled plan (or the reason it has none)."""

    row: Any
    plan: Any = None
    error: Optional[str] = None

    @property
    def invariant_id(self) -> str:
        return self.row["invariant_id"]

    @property
    def digest(self) -> str:
        return self.plan.digest if self.plan is not None else str(self.row["digest"])


def _compile(row: Any) -> _Def:
    """Re-compile the stored YAML. Anything that goes wrong is ``invalid_definition``, including a
    definition whose own id disagrees with the row it is stored under (it would write its verdict,
    and its findings, under another invariant's name)."""
    lib = _lib()
    try:
        plan = lib.compile_text(row["yaml"])
    except Exception as exc:  # noqa: BLE001 -- ParseError, CompileError, pydantic, anything
        return _Def(row, error=f"{type(exc).__name__}: {exc}"[:500])
    if plan.id != row["invariant_id"]:
        return _Def(row, error=f"definition id {plan.id!r} does not match {row['invariant_id']!r}")
    return _Def(row, plan=plan)


# --------------------------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------------------------

def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def synthetic_result(d: _Def, reason: str, now: datetime, error: Optional[str] = None) -> dict[str, Any]:
    """A result dict (same shape as ``Result.to_dict()``) for an invariant that could not be evaluated."""
    out: dict[str, Any] = {
        "invariant": d.invariant_id, "digest": d.digest, "severity": d.row["severity"],
        "assertion": "", "verdict": "UNKNOWN", "reasons": [reason], "evaluated_at": _iso(now),
        "valid_until": None, "evidence_tier": None,
        "coverage": {"universe": 0, "covered": 0, "ratio": 1.0, "required": 0.0},
        "violation_count": 0, "witnesses": [], "blind_spots": [], "exceptions_used": [],
        "expired_exceptions": [], "confirmation": "not_run", "boundaries_reached": [],
    }
    if error:
        out["error"] = error
    return out


def compact_result(rd: dict[str, Any], graph_version: int) -> dict[str, Any]:
    """What is stored: the library's dict, with the blind-spot list capped (a 20k-node estate would
    otherwise store 40k rows per evaluation) but summarised, relevant spots first."""
    out = dict(rd)
    spots = list(rd.get("blind_spots") or [])
    by_reason: dict[str, int] = {}
    for s in spots:
        by_reason[s.get("reason", "")] = by_reason.get(s.get("reason", ""), 0) + 1
    spots.sort(key=lambda s: (not s.get("relevant"), s.get("node", ""), s.get("direction", "")))
    out["blind_spots"] = spots[:MAX_STORED_BLIND_SPOTS]
    out["blind_spot_summary"] = {"total": len(spots), "stored": len(out["blind_spots"]), "by_reason": by_reason}
    out["graph_version"] = graph_version
    return out


async def _record(pool: Any, d: _Def, rd: dict[str, Any], valid_until: Optional[datetime],
                  graph_version: int, now: datetime) -> Optional[bool]:
    """Write ``invariants.last_*`` and (on a transition / heartbeat) an ``invariant_runs`` row.

    ``None``: the definition changed while we evaluated, so this result describes the old one and
    is dropped (the invariant stays due). Otherwise True iff the verdict changed.
    """
    stored = compact_result(rd, graph_version)
    verdict = rd["verdict"]
    cov = rd.get("coverage") or {}
    async with pool.acquire() as conn:
        async with conn.transaction():
            cur = await conn.fetchrow(
                "SELECT yaml, digest, last_verdict FROM invariants WHERE id = $1 FOR UPDATE", d.row["id"])
            if cur is None or cur["yaml"] != d.row["yaml"] or cur["digest"] != d.row["digest"]:
                return None
            await conn.execute(
                "UPDATE invariants SET last_verdict = $2, last_result = $3::jsonb, last_graph_version = $4, "
                "last_evaluated_at = $5, valid_until = $6 WHERE id = $1",
                d.row["id"], verdict, json.dumps(stored), graph_version, now, valid_until)
            prev = await conn.fetchrow(
                "SELECT verdict, digest, evaluated_at FROM invariant_runs WHERE invariant_id = $1 "
                "ORDER BY evaluated_at DESC LIMIT 1", d.invariant_id)
            if (prev is None or prev["verdict"] != verdict or prev["digest"] != rd["digest"]
                    or now - prev["evaluated_at"] >= HEARTBEAT):
                await conn.execute(
                    "INSERT INTO invariant_runs (invariant_id, digest, verdict, reasons, result, graph_version, "
                    "violation_count, coverage_covered, coverage_universe, evaluated_at, valid_until) "
                    "VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8, $9, $10, $11)",
                    d.invariant_id, rd["digest"], verdict, json.dumps(rd.get("reasons") or []),
                    json.dumps(stored), graph_version, int(rd.get("violation_count") or 0),
                    int(cov.get("covered") or 0), int(cov.get("universe") or 0), now, valid_until)
    return cur["last_verdict"] != verdict


async def _mark_retry(pool: Any, d: _Def) -> None:
    """A findings sync failed after the verdict was recorded: make the invariant due again next tick."""
    try:
        async with pool.acquire() as conn:
            await conn.execute("UPDATE invariants SET last_graph_version = NULL WHERE id = $1", d.row["id"])
    except Exception:  # noqa: BLE001
        logger.exception("assurance_mark_retry_failed", extra={"invariant": d.invariant_id})


def _is_due(d: _Def, state: store.AssuranceState, now: datetime, *, tenant_due: bool) -> bool:
    """Should this enabled invariant be evaluated now (non-forced)?"""
    row = d.row
    if tenant_due or row["last_evaluated_at"] is None or row["last_graph_version"] is None:
        return True
    if row["valid_until"] is not None and row["valid_until"] <= now:
        return True
    last = _loads(row["last_result"]) or {}
    if last.get("digest") != d.digest:
        return True                      # the definition changed since the last verdict
    was_invalid = last.get("reasons") == ["invalid_definition"]
    return was_invalid != (d.plan is None)   # it stopped (or started) compiling under an unchanged digest


def _tenant_due(state: store.AssuranceState, now: datetime) -> bool:
    backstop = timedelta(minutes=settings.assurance_backstop_min)
    return (state.graph_version != state.last_eval_version
            or state.last_eval_at is None or now - state.last_eval_at >= backstop)


# --------------------------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------------------------

def _accepted_opts(fn: Any, opts: dict[str, Any]) -> dict[str, Any]:
    """The subset of ``opts`` a builder function takes (by name, or all if it has ``**kwargs``)."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return {}
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return dict(opts)
    return {k: v for k, v in opts.items() if k in params}


async def _run_builder(pool: Any, mod: Any, now: datetime, opts: dict[str, Any]) -> dict[str, Any]:
    async with pool.acquire() as conn:
        rows = await mod.load(conn, now, **_accepted_opts(mod.load, opts))
    out: BuildOutput = await asyncio.to_thread(mod.build, rows, now, **_accepted_opts(mod.build, opts))
    if not isinstance(out, BuildOutput):
        raise TypeError(f"builder returned {type(out).__name__}, not BuildOutput")
    async with pool.acquire() as conn:
        rep = await store.persist_build(conn, out, now)
    return {"ok": True, "changed": rep.changed, "edges_added": rep.edges_added,
            "edges_removed": rep.edges_removed, "coverage_changed": rep.coverage_changed,
            "nodes_added": rep.nodes_added, "nodes_removed": rep.nodes_removed, "skipped": rep.skipped,
            "notes": list(rep.notes)[:50], "graph_version": rep.graph_version}


async def build_tenant(pool: Any, tenant_id: str, *, now: Optional[datetime] = None) -> dict[str, Any]:
    """Run every builder once for ``tenant_id`` (no lease: ``run_tenant`` holds it). Failures are
    isolated per builder and reported; returns ``{source: {...}}`` plus nothing is raised."""
    now = now or _now()
    summary: dict[str, Any] = {}
    try:
        mods = builders_pkg.load_builders()
    except Exception as exc:  # noqa: BLE001 -- a malformed builder module
        logger.exception("assurance_builders_unavailable")
        return {"_registry": {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}}
    opts = {
        "max_age": timedelta(hours=settings.assurance_external_max_age_h),
        "window": timedelta(hours=settings.assurance_edge_window_h),
    }
    with tenancy.tenant_context(tenant_id):
        for mod in mods:
            name = getattr(mod, "SOURCE", getattr(mod, "__name__", "?"))
            try:
                res = await asyncio.wait_for(_run_builder(pool, mod, now, opts), BUILDER_TIMEOUT_S)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 -- one builder never takes the others down
                logger.exception("assurance_builder_failed", extra={"builder": name, "tenant": tenant_id})
                res = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}
            summary[name] = res
            _LAST_BUILD.setdefault(tenant_id, {})[name] = {**res, "at": _iso(now)}
        try:
            async with pool.acquire() as conn:
                await store.prune_flow_obs(conn, now - 3 * timedelta(hours=settings.assurance_edge_window_h))
        except Exception:  # noqa: BLE001
            logger.exception("assurance_flow_prune_failed", extra={"tenant": tenant_id})
        async with pool.acquire() as conn:
            await store.touch_build(conn, now)
    return summary


# --------------------------------------------------------------------------------------------
# Evaluate
# --------------------------------------------------------------------------------------------

def _select(defs: list[_Def], only: Optional[Any]) -> list[_Def]:
    """Restrict to ``only`` (invariant ids, as ``std:x`` strings or row UUIDs)."""
    if not only:
        return defs
    wanted = {str(x) for x in only}
    return [d for d in defs if d.invariant_id in wanted or str(d.row["id"]) in wanted]


async def _evaluate_one(pool: Any, redis: Any, d: _Def, graph: Any, graph_version: int, now: datetime,
                        graph_error: Optional[str]) -> dict[str, Any]:
    """Evaluate, record and sync one invariant. Never raises (except cancellation)."""
    item: dict[str, Any] = {"invariant_id": d.invariant_id}
    valid_until: Optional[datetime] = None
    result_obj = None
    if d.plan is None:
        rd = synthetic_result(d, "invalid_definition", now, d.error)
    elif graph is None:
        rd = synthetic_result(d, "graph_unavailable", now, graph_error)
        rd["assertion"] = d.plan.invariant.assert_
    else:
        try:
            result_obj = await asyncio.to_thread(_lib().evaluate, d.plan, graph, now)
            rd = result_obj.to_dict()
            valid_until = result_obj.valid_until
        except Exception as exc:  # noqa: BLE001 -- a library bug is UNKNOWN, never a crash or a HOLDS
            logger.exception("assurance_evaluate_failed", extra={"invariant": d.invariant_id})
            rd = synthetic_result(d, "evaluation_error", now, f"{type(exc).__name__}: {exc}"[:300])
            rd["assertion"] = d.plan.invariant.assert_
    item.update(verdict=rd["verdict"], reasons=rd["reasons"], violation_count=rd.get("violation_count", 0))
    changed = await _record(pool, d, rd, valid_until, graph_version, now)
    if changed is None:
        item.update(skipped="definition_changed")
        return item
    item["changed"] = changed
    on_violation = d.plan.invariant.on_violation if d.plan is not None else None
    try:
        rep = await findings_sync.sync_findings(
            pool, redis, invariant_id=d.invariant_id, title=d.row["title"] or d.invariant_id,
            finding_enabled=True if on_violation is None else on_violation.finding,
            proposed_fixes=tuple(on_violation.propose) if on_violation is not None else (),
            result=rd, graph_version=graph_version, now=now)
        item["findings"] = rep.as_dict()
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("assurance_findings_sync_failed", extra={"invariant": d.invariant_id})
        item["findings"] = {"error": f"{type(exc).__name__}: {exc}"[:300]}
        await _mark_retry(pool, d)
    return item


async def _evaluate_pass(pool: Any, redis: Any, owner: str, defs: list[_Def], now: datetime,
                         summary: dict[str, Any], *, budgeted: bool) -> tuple[int, bool]:
    """Evaluate ``defs`` against one graph snapshot. Returns ``(graph_version, completed)``;
    ``completed`` is False if the lease was lost, the budget ran out or the graph is unusable."""
    t0 = time.monotonic()
    graph, graph_error = None, None
    async with pool.acquire() as conn:
        doc, diag = await graph_loader.load_graph_doc_with_diagnostics(conn, now)
    version = int(diag.graph_version)
    summary["graph_version"] = version
    try:
        graph = await asyncio.to_thread(_lib().ReachGraph.from_dict, doc)
    except Exception as exc:  # noqa: BLE001 -- GraphError: bad data must not become a verdict
        graph_error = f"{type(exc).__name__}: {exc}"[:300]
        logger.error("assurance_graph_invalid", extra={"error": graph_error})
        summary["errors"].append(f"graph: {graph_error}")
    complete = graph is not None
    for d in defs:
        if budgeted and time.monotonic() - t0 > TENANT_BUDGET_S:
            summary["deferred"] = summary.get("deferred", 0) + 1
            complete = False
            continue
        async with pool.acquire() as conn:
            if not await store.extend_eval(conn, owner, _now(), LEASE_S):
                summary["errors"].append("lease lost mid-evaluation")
                return version, False
        item = await _evaluate_one(pool, redis, d, graph, version, now, graph_error)
        summary["results"].append(item)
        if item.get("skipped"):
            complete = False
        if (item.get("findings") or {}).get("error"):
            complete = False
            summary["errors"].append(f"findings {item['invariant_id']}: {item['findings']['error']}")
    return version, complete


async def run_tenant(
    pool: Any, tenant_id: str, *, force: bool = False, only: Optional[Any] = None, rebuild: bool = False,
    redis: Any = None, now: Optional[datetime] = None,
) -> dict[str, Any]:
    """One build + evaluate pass for one tenant (what the loop does per tick, and what the API calls).

    ``force`` evaluates everything selected by ``only`` regardless of due-ness (and ignores the
    time budget); ``rebuild`` runs the builders first even if they ran recently. Returns a summary
    ``{ok, tenant_id, skipped, built, builders, graph_version, evaluated, results, errors}``. It
    never raises (cancellation excepted); ``ok`` is False if anything failed or another evaluation
    holds the lease (``skipped='lease_held'``).
    """
    now = now or _now()
    redis = redis if redis is not None else _app_redis
    summary: dict[str, Any] = {"ok": True, "tenant_id": str(tenant_id), "skipped": None, "built": False,
                               "builders": {}, "graph_version": None, "evaluated": 0, "results": [],
                               "errors": []}
    try:
        tid = tenancy.norm(tenant_id)
        if tid is None:
            raise ValueError("tenant id required")
    except ValueError:
        return {**summary, "ok": False, "skipped": "bad_tenant", "errors": ["invalid tenant id"]}
    summary["tenant_id"] = tid
    if _lib() is None:
        return {**summary, "ok": False, "skipped": "library_missing",
                "errors": ["paddock_assurance is not installed"]}
    owner = f"{PROCESS_ID}:{uuid.uuid4().hex[:8]}"
    try:
        with tenancy.tenant_context(tid):
            state, enabled, due = await _plan_due(pool, now, force=force, only=only)
            build_due = rebuild or state.last_build_at is None or \
                now - state.last_build_at >= timedelta(minutes=settings.assurance_rebuild_min)
            if not build_due and not due:
                summary["skipped"] = "up_to_date" if enabled else "no_invariants"
                summary["graph_version"] = state.graph_version
                return summary
            async with pool.acquire() as conn:
                # Lease times are wall-clock (they must really expire); ``now`` is the data clock.
                claimed = await store.claim_eval(conn, owner, _now(), LEASE_S)
            if claimed is None:
                return {**summary, "ok": False, "skipped": "lease_held"}
            try:
                if build_due:
                    summary["builders"] = await build_tenant(pool, tid, now=now)
                    summary["built"] = True
                    summary["errors"] += [f"builder {k}: {v.get('error')}" for k, v in summary["builders"].items()
                                          if not v.get("ok")]
                await refresh_std(pool)
                await _evaluate_tenant_locked(pool, redis, owner, now, summary, force=force, only=only)
            finally:
                await asyncio.shield(_release(pool, tid, owner, now, summary))
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 -- the loop must never die on one tenant
        logger.exception("assurance_tenant_failed", extra={"tenant": tenant_id})
        summary["errors"].append(f"{type(exc).__name__}: {exc}"[:300])
    summary["evaluated"] = len(summary["results"])
    summary["ok"] = not summary["errors"]
    return summary


async def _plan_due(pool: Any, now: datetime, *, force: bool, only: Optional[Any]
                    ) -> tuple[store.AssuranceState, list[_Def], list[_Def]]:
    """``(state, enabled invariants, the ones to evaluate now)``; tenant-bound by the caller."""
    async with pool.acquire() as conn:
        state = await store.get_state(conn)
        rows = await conn.fetch(f"SELECT {_INV_COLS} FROM invariants WHERE enabled ORDER BY invariant_id")
    enabled = [_compile(r) for r in rows]
    wanted = _select(enabled, only)
    if force:
        return state, enabled, wanted
    tenant_due = _tenant_due(state, now)
    return state, enabled, [d for d in wanted if _is_due(d, state, now, tenant_due=tenant_due)]


async def _evaluate_tenant_locked(pool: Any, redis: Any, owner: str, now: datetime,
                                  summary: dict[str, Any], *, force: bool, only: Optional[Any]) -> None:
    state, enabled, due = await _plan_due(pool, now, force=force, only=only)
    summary["graph_version"] = state.graph_version
    if not due:
        summary["skipped"] = "up_to_date" if enabled else "no_invariants"
        return
    version, complete = await _evaluate_pass(pool, redis, owner, due, now, summary, budgeted=not force)
    # The watermark only advances when every enabled invariant was evaluated at this version:
    # a partial run (forced subset, budget, failed sync) must leave the rest due.
    summary["_watermark"] = version if (complete and len(due) == len(enabled)) else None


async def _release(pool: Any, tid: str, owner: str, now: datetime, summary: dict[str, Any]) -> None:
    mark = summary.pop("_watermark", None)
    try:
        with tenancy.tenant_context(tid):
            async with pool.acquire() as conn:
                await store.release_eval(conn, owner, now, evaluated_version=mark)
    except Exception:  # noqa: BLE001 -- the lease also expires on its own
        logger.exception("assurance_release_failed", extra={"tenant": tid})


async def evaluate_tenant(pool: Any, tenant_id: str, *, force: bool = False, only: Optional[Any] = None,
                          rebuild: bool = False, redis: Any = None) -> dict[str, Any]:
    """Evaluate ``tenant_id``'s enabled invariants now. This is the function the API calls.

    ``only``: invariant ids (``'std:no-internet-to-datastore'``) or row UUIDs. ``force``: evaluate
    them whether or not they are due. ``rebuild``: re-run the builders first (the API's
    ``rebuild: true``). ``redis``: pass ``request.app.state.redis`` so finding events are published;
    omitted, the loop's client is used if the loop runs, else events are skipped. See ``run_tenant``
    for the summary shape. Never raises.
    """
    return await run_tenant(pool, tenant_id, force=force, only=only, rebuild=rebuild, redis=redis)


# --------------------------------------------------------------------------------------------
# The loop
# --------------------------------------------------------------------------------------------

async def tick_once(pool: Any, *, redis: Any = None, now: Optional[datetime] = None) -> dict[str, dict[str, Any]]:
    """One pass over every tenant. Each tenant is independent: a failure, a timeout or a held lease
    for one never delays the budgeted work of the next beyond its own hard cap."""
    out: dict[str, dict[str, Any]] = {}
    for tid in await tenancy.list_tenant_ids(pool):
        try:
            out[tid] = await asyncio.wait_for(
                run_tenant(pool, tid, redis=redis, now=now), TENANT_HARD_TIMEOUT_S)
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            logger.error("assurance_tenant_timeout", extra={"tenant": tid})
            out[tid] = {"ok": False, "tenant_id": tid, "errors": ["tenant pass timed out"]}
        except Exception as exc:  # noqa: BLE001
            logger.exception("assurance_tenant_failed", extra={"tenant": tid})
            out[tid] = {"ok": False, "tenant_id": tid, "errors": [f"{type(exc).__name__}: {exc}"[:300]]}
    return out


async def assurance_loop(app: Any) -> None:
    """Forever: every ``assurance_tick_s``, build and evaluate each tenant. Only cancellation ends it."""
    global _app_redis
    if _lib() is None:
        logger.warning("assurance_library_missing: the assurance loop is idle (install paddock_assurance)")
    logger.info("assurance_started", extra={"tick_s": settings.assurance_tick_s})
    while True:
        try:
            await asyncio.sleep(max(1, int(settings.assurance_tick_s)))
            pool = getattr(app.state, "pool", None)
            if pool is None or _lib() is None:
                continue
            _app_redis = getattr(app.state, "redis", None)
            await tick_once(pool, redis=_app_redis)
        except asyncio.CancelledError:
            logger.info("assurance_stopped")
            raise
        except Exception:  # noqa: BLE001
            logger.exception("assurance_tick_failed")
