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

Rebuild requests: posture ingest and the API ask for a rebuild by setting
``assurance_state.last_build_at = NULL``; a NULL (or never-built) tenant is always due on the next
tick. The build is stamped BEFORE the builders read anything, so a request that arrives while a
build runs is not overwritten by that build's own stamp. Builders receive the options they declare
(``max_age``, ``window``, ``agent_posture_max_age``: how old an agent posture may be and still count).

Soundness notes: a stored definition is compiled from its YAML (plans are cached by
``(invariant_id, digest, yaml hash)`` so an unchanged one is never recompiled, and a compile that
is needed runs off the event loop); one that does not compile is recorded as ``UNKNOWN`` /
``invalid_definition`` (never skipped, never a stale HOLDS). A library bug while evaluating is
``UNKNOWN`` / ``evaluation_error``. Neither opens or closes a finding. Nothing here ever raises
out of the loop, and nothing here reads or writes another tenant: all SQL runs on connections
acquired inside ``tenancy.tenant_context(tid)``.

Fencing (a stale evaluator must never overwrite a newer verdict or close its finding): the
evaluation lease is claimed and extended on the DATABASE clock, and ``_record`` and
``findings_sync`` prove inside their own transaction that this process still owns a live lease
and that the graph version they evaluated is not older than what is stored. Otherwise the result
is discarded (``skipped='lease_lost'`` / ``'stale_result'``) and the invariant stays due.

Due-ness is per invariant: never evaluated, a ``last_graph_version`` that is not the current one,
older than the backstop, ``valid_until`` passed, a changed digest, or (when the hash of the graph
DOCUMENT differs from the one it was evaluated on) a different ``doc_sha``. The document hash
catches inputs that do not move ``graph_version`` (node attrs, asset metadata). A graph the CIDR
expansion could not complete makes every invariant UNKNOWN (``graph_incomplete:...``).

Lifecycle (docs/ASSURANCE_P2_1.md 6.1, D33: annotate, never close). The runner only visits enabled
invariants, so nothing re-evaluates the findings of a disabled or archived one and no HOLDS can close
them; closing them as "fixed" would be a false verification, so they stay open. They are ANNOTATED
(``findings.metadata.invariant_state``: ``disabled``, ``archived``, ``invalid_definition``,
``not_entitled``) so nobody mistakes them for live ones: the API toggles annotate in the same
transaction, the runner annotates what only it can see (an invariant whose stored definition does not
compile, a tenant that is not entitled to ``assurance``) and ``housekeeping.reconcile_orphans`` repairs
drift once per tick. A person gives up on them with ``POST /v1/invariants/{id}/findings/release``
(``wontfix``, sticky). A result computed for an invariant that was disabled while it was evaluated is
discarded (``invariant_disabled``) and writes nothing.

``paddock_assurance`` is imported lazily inside functions so ``scripts/export_openapi.py`` and the
SDK checks (which install only the orchestrator) can import this module.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import inspect
import json
import logging
import os
import socket
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .. import tenancy
from ..config import settings
from . import builders as builders_pkg
from . import findings_sync, graph_loader, housekeeping, store
from .types import BuildOutput

logger = logging.getLogger(__name__)

ACTOR = findings_sync.ACTOR
LEASE_S = 300
#: Soft per-tenant budget per tick, measured from AFTER the graph is loaded and parsed: no new
#: invariant is started after it (the rest stay due and go FIRST next tick), so one huge tenant
#: cannot starve the others and none of its invariants starves. Forced runs ignore it.
TENANT_BUDGET_S = 30.0
#: Hard cap on one tenant's whole pass (cancels it; the lease is released in a ``finally``).
TENANT_HARD_TIMEOUT_S = 900.0
BUILDER_TIMEOUT_S = 180.0
HEARTBEAT = timedelta(days=1)
#: Builders that read agent postures ignore a posture older than this (``agent_posture_max_age``
#: builder option). Matches the std host invariants' ``max_age`` (6h); ``settings`` may override it
#: with ``assurance_agent_posture_max_age_h``.
AGENT_POSTURE_MAX_AGE_H = 6
MAX_STORED_BLIND_SPOTS = 200
PROCESS_ID = f"{socket.gethostname()}:{os.getpid()}"
#: a tenant's annotation drift is repaired at most this often (process-local); the toggles themselves annotate at once.
RECONCILE_EVERY_S = 120.0
#: tenant id -> (monotonic time of the last reconcile, the ``entitled`` flag it ran with)
_RECONCILE_LAST: dict[str, tuple[float, bool]] = {}

_app_redis: Any = None
#: tenant id -> source -> what the last build of that source did (process-local; see last_build).
_LAST_BUILD: dict[str, dict[str, dict[str, Any]]] = {}
#: tenant id -> diagnostics of the last evaluation pass (process-local; see last_evaluation).
_LAST_EVAL: dict[str, dict[str, Any]] = {}
#: (invariant_id, digest, sha256(yaml)) -> (plan, error). LRU, shared by tenants: a plan is a pure
#: function of the YAML text, and the key contains a hash of that text.
_PLAN_CACHE: "OrderedDict[tuple[str, str, str], tuple[Any, Optional[str]]]" = OrderedDict()
_PLAN_CACHE_MAX = 2048
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _agent_posture_max_age() -> timedelta:
    raw = getattr(settings, "assurance_agent_posture_max_age_h", AGENT_POSTURE_MAX_AGE_H)
    try:
        hours = int(raw)
    except (TypeError, ValueError):
        hours = AGENT_POSTURE_MAX_AGE_H
    return timedelta(hours=hours if hours > 0 else AGENT_POSTURE_MAX_AGE_H)


def last_build(tenant_id: str) -> dict[str, dict[str, Any]]:
    """What this process's last build did per source (ok, changed, counts, notes, at). Empty
    before the first build here; other replicas keep their own."""
    return {k: dict(v) for k, v in _LAST_BUILD.get(str(tenant_id), {}).items()}


def last_evaluation(tenant_id: str) -> dict[str, Any]:
    """Diagnostics of this process's last evaluation pass for the tenant (graph version, document
    hash, ``cidr_unexpanded`` destinations when the CIDR cap was hit, zone conflicts, how many
    invariants were deferred, ...). Empty before the first pass here."""
    return dict(_LAST_EVAL.get(str(tenant_id), {}))


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


def _compile_row(row: Any) -> tuple[Any, Optional[str]]:
    """Compile the stored YAML -> ``(plan, None)`` or ``(None, why)``. Anything that goes wrong is
    ``invalid_definition``, including a definition whose own id disagrees with the row it is
    stored under (it would write its verdict, and its findings, under another invariant's name).
    Synchronous and CPU-bound (a 60 KB definition takes ~0.4 s): call it via ``_compile_defs``."""
    lib = _lib()
    try:
        plan = lib.compile_text(row["yaml"])
    except Exception as exc:  # noqa: BLE001 -- ParseError, CompileError, pydantic, anything
        return None, f"{type(exc).__name__}: {exc}"[:500]
    if plan.id != row["invariant_id"]:
        return None, f"definition id {plan.id!r} does not match {row['invariant_id']!r}"
    return plan, None


def _plan_key(row: Any) -> tuple[str, str, str]:
    return (str(row["invariant_id"]), str(row["digest"]),
            hashlib.sha256(str(row["yaml"]).encode()).hexdigest())


async def _compile_defs(rows: list[Any]) -> list[_Def]:
    """One ``_Def`` per row. A plan is compiled once per ``(invariant_id, digest, yaml hash)`` and
    cached (the loop used to recompile every enabled invariant of every tenant on every tick,
    twice, on the event loop); a miss is compiled in a worker thread. The YAML hash is in the key
    so an edit that kept the stored digest still recompiles, and a failed compile is cached too (an
    invalid definition must not cost a compile per tick either)."""
    out: list[_Def] = []
    for r in rows:
        key = _plan_key(r)
        hit = _PLAN_CACHE.get(key)
        if hit is None:
            hit = await asyncio.to_thread(_compile_row, r)
            _PLAN_CACHE[key] = hit
            while len(_PLAN_CACHE) > _PLAN_CACHE_MAX:
                _PLAN_CACHE.popitem(last=False)
        else:
            _PLAN_CACHE.move_to_end(key)
        plan, err = hit
        out.append(_Def(r, plan=plan, error=err))
    return out


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


def compact_result(rd: dict[str, Any], graph_version: int, doc_sha: Optional[str] = None) -> dict[str, Any]:
    """What is stored: the library's dict, with the blind-spot list capped (a 20k-node estate would
    otherwise store 40k rows per evaluation) but summarised, relevant spots first. ``doc_sha`` is
    the hash of the graph document the verdict was computed on (see ``_is_due``)."""
    out = dict(rd)
    spots = list(rd.get("blind_spots") or [])
    by_reason: dict[str, int] = {}
    for s in spots:
        by_reason[s.get("reason", "")] = by_reason.get(s.get("reason", ""), 0) + 1
    spots.sort(key=lambda s: (not s.get("relevant"), s.get("node", ""), s.get("direction", "")))
    out["blind_spots"] = spots[:MAX_STORED_BLIND_SPOTS]
    out["blind_spot_summary"] = {"total": len(spots), "stored": len(out["blind_spots"]), "by_reason": by_reason}
    out["graph_version"] = graph_version
    if doc_sha is not None:
        out["doc_sha"] = doc_sha
    return out


class _Discarded(Exception):
    """A computed result that must not be written (its evaluator is stale). ``reason`` is reported."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


async def _record(pool: Any, owner: str, d: _Def, rd: dict[str, Any], valid_until: Optional[datetime],
                  graph_version: int, now: datetime, doc_sha: Optional[str] = None) -> Optional[bool]:
    """Write ``invariants.last_*`` and (on a transition / heartbeat) an ``invariant_runs`` row.

    Fenced: in the SAME transaction that writes, the tenant's evaluation lease must still be ours
    and live (database clock) and our graph version must not be older than the stored
    ``last_graph_version``; otherwise ``_Discarded`` is raised and nothing is written. Without that
    a replica whose lease lapsed mid-evaluation (a stall, a clock error) could overwrite a newer
    VIOLATED with its older HOLDS.

    ``None``: the definition changed while we evaluated, so this result describes the old one and
    is dropped (the invariant stays due). Otherwise True iff the verdict changed.
    """
    stored = compact_result(rd, graph_version, doc_sha)
    verdict = rd["verdict"]
    cov = rd.get("coverage") or {}
    async with pool.acquire() as conn:
        async with conn.transaction():
            if await store.fence_lease(conn, owner) is None:
                raise _Discarded("lease_lost")
            cur = await conn.fetchrow(
                "SELECT yaml, digest, enabled, last_verdict, last_graph_version FROM invariants "
                "WHERE id = $1 FOR UPDATE", d.row["id"])
            if cur is None or cur["yaml"] != d.row["yaml"] or cur["digest"] != d.row["digest"]:
                return None
            if not cur["enabled"]:
                # Disabled or archived while this pass evaluated it: record nothing and (the caller) sync nothing. A
                # verdict written now would look like a fresh check of an invariant the operator switched off.
                raise _Discarded("invariant_disabled")
            if cur["last_graph_version"] is not None and graph_version < int(cur["last_graph_version"]):
                raise _Discarded("stale_result")      # never overwrite a newer world's verdict
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


#: how long the enabled guard may wait for a toggle that is committing right now (it is a few milliseconds in practice)
_GUARD_LOCK_TIMEOUT = "5s"


@contextlib.asynccontextmanager
async def _enabled_guard(pool: Any, d: _Def) -> Any:
    """Yield ``True`` (enabled), ``False`` (disabled or archived) or ``None`` (could not tell) for ``d`` and, while
    the body runs, keep the invariant row ``FOR SHARE``-locked on a connection of its own.

    This is what makes "no machine closes a finding of an invariant that is not enabled" hold without a change to the
    findings sync: a toggle (PUT enabled=false, DELETE) takes ``FOR UPDATE`` on the same row before it writes, so it
    WAITS for the sync that was admitted while the invariant was enabled and lands strictly after it, instead of
    landing between the check and the close (the verifier's RACE1) or between the check and the runner's own
    annotation clear (RACE2). A finding the sync closes is thus closed by an evaluation that finished while the
    invariant was enabled; the toggle then annotates whatever is still open. The body must not write ``invariants``
    for this row (it would wait for its own share lock): ``_mark_retry`` runs after the guard.

    ``None`` (lock wait timed out or the look-up failed) is NOT treated as enabled: the caller skips the sync and
    marks the invariant due again (fail safe, nothing is closed on a guess)."""
    async with pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()
        try:
            state: Optional[bool] = None
            try:
                await conn.execute(f"SET LOCAL lock_timeout = '{_GUARD_LOCK_TIMEOUT}'")
                enabled = await conn.fetchval("SELECT enabled AND archived_at IS NULL FROM invariants "
                                              "WHERE id = $1 FOR SHARE", d.row["id"])
                state = None if enabled is None else bool(enabled)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("assurance_enabled_check_failed", extra={"invariant": d.invariant_id})
            yield state
        finally:
            with contextlib.suppress(Exception):
                await tx.rollback()


async def _note_state(pool: Any, d: _Def) -> None:
    """After a verdict is recorded: an invariant whose definition does not compile annotates its findings
    ``invalid_definition`` (they are not being re-checked); one that was evaluated clears any annotation (it is
    being checked again, and only while it is enabled: a disable that just landed keeps its annotation). Best effort:
    ``reconcile_orphans`` repairs a miss. Never changes a finding's status."""
    try:
        async with pool.acquire() as conn:
            if d.plan is None:
                await housekeeping.annotate_findings(conn, d.invariant_id, housekeeping.STATE_INVALID)
            else:
                await housekeeping.clear_annotations(conn, d.invariant_id, only_if_enabled=True)
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001
        logger.exception("assurance_note_state_failed", extra={"invariant": d.invariant_id})


async def _mark_retry(pool: Any, d: _Def) -> None:
    """A findings sync failed (or was cancelled) after the verdict was recorded: make the invariant
    due again next tick. Over-marking is harmless (one extra evaluation); under-marking strands the
    sync until the backstop."""
    try:
        async with pool.acquire() as conn:
            await conn.execute("UPDATE invariants SET last_graph_version = NULL WHERE id = $1", d.row["id"])
    except Exception:  # noqa: BLE001
        logger.exception("assurance_mark_retry_failed", extra={"invariant": d.invariant_id})


def _is_due(d: _Def, now: datetime, *, version: int, doc_sha: Optional[str]) -> bool:
    """Should this enabled invariant be evaluated now (non-forced)?

    Per invariant, not per tenant, so a pass that evaluated only some (budget, failure) does not
    make the finished ones run again before the rest: due when it was never evaluated, was
    evaluated at another graph version, is older than the backstop, outlived its evidence
    (``valid_until``), changed definition, or it was evaluated on a different document than
    ``doc_sha`` (``None`` skips that check: the cheap pre-load decision). The hash is compared per
    invariant, against the one stored in its own result, rather than against the tenant-level
    ``last_eval_doc_sha``: that one only advances when a whole pass completes, and an incomplete
    pass can leave invariants evaluated on a document it does not describe.
    """
    row = d.row
    if row["last_evaluated_at"] is None or row["last_graph_version"] is None:
        return True
    if row["last_graph_version"] != version:
        return True
    if now - row["last_evaluated_at"] >= timedelta(minutes=settings.assurance_backstop_min):
        return True
    if row["valid_until"] is not None and row["valid_until"] <= now:
        return True
    last = _loads(row["last_result"]) or {}
    if last.get("digest") != d.digest:
        return True                      # the definition changed since the last verdict
    if doc_sha is not None and last.get("doc_sha") != doc_sha:
        return True                      # the graph's inputs changed without moving graph_version
    was_invalid = last.get("reasons") == ["invalid_definition"]
    return was_invalid != (d.plan is None)   # it stopped (or started) compiling under an unchanged digest


def _rotation_key(d: _Def, version: int) -> tuple[bool, datetime, str]:
    """Order for evaluation: invariants not yet evaluated at this graph version first, then the
    longest-unevaluated first (never-evaluated = oldest). A pass cut short by the budget therefore
    resumes with exactly the ones it skipped."""
    row = d.row
    done = row["last_evaluated_at"] is not None and row["last_graph_version"] == version
    return (done, row["last_evaluated_at"] or _EPOCH, d.invariant_id)


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
            "facts_changed": rep.facts_changed, "facts_stored": rep.facts_stored,
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
        "agent_posture_max_age": _agent_posture_max_age(),
    }
    with tenancy.tenant_context(tenant_id):
        # Stamp the build BEFORE the builders read anything. Ingest (a new agent posture) and the
        # API ask for a rebuild by setting ``last_build_at = NULL`` at any moment; stamping at the
        # END would overwrite a request that arrived while we built, and the posture it announced
        # would then wait out the whole rebuild interval. A request that lands after this stamp
        # survives, so the next tick rebuilds. (A pass that dies half-way is retried at the normal
        # interval, not hot.)
        try:
            async with pool.acquire() as conn:
                await store.touch_build(conn, now)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 -- the builders still run; the old stamp makes the next tick rebuild sooner
            logger.exception("assurance_build_stamp_failed", extra={"tenant": tenant_id})
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


@dataclass
class _Snapshot:
    """One load of the tenant's graph document and what was derived from it."""

    doc: dict[str, Any]
    diag: Any
    version: int
    doc_sha: str
    graph: Any = None
    error: Optional[str] = None           # why there is no usable graph
    reason: Optional[str] = None          # the UNKNOWN reason every invariant then gets
    parsed: bool = False


async def _load_snapshot(pool: Any, now: datetime) -> _Snapshot:
    """Load the graph document and hash it (no parse yet; see ``_parse_graph``)."""
    async with pool.acquire() as conn:
        doc, diag = await graph_loader.load_graph_doc_with_diagnostics(conn, now)
    sha = await asyncio.to_thread(graph_loader.doc_sha, doc)
    return _Snapshot(doc=doc, diag=diag, version=int(diag.graph_version), doc_sha=sha)


async def _parse_graph(snap: _Snapshot, summary: dict[str, Any]) -> None:
    """Parse ``snap.doc`` into a graph, or record why there is none. A document the loader itself
    flags as incomplete is NOT parsed: evaluating it would under-approximate the estate."""
    if snap.parsed:
        return
    snap.parsed = True
    unexpanded = list(getattr(snap.diag, "cidr_unexpanded", None) or [])
    if unexpanded or getattr(snap.diag, "cidr_overflow", False):
        snap.reason = "graph_incomplete:cidr_expansion_overflow"
        snap.error = (f"CIDR expansion hit its cap for {len(unexpanded)} destination(s), e.g. "
                      f"{', '.join(unexpanded[:3])}; the graph would miss configured edges")
        logger.error("assurance_graph_incomplete", extra={"reason": snap.reason, "destinations": len(unexpanded)})
        summary["errors"].append(f"graph incomplete: cidr_expansion_overflow ({len(unexpanded)} destinations)")
        return
    if _zone_unknown_nodes(snap.doc) and not _lib_knows_zone_unknown():
        # An older library ignores ``zone_unknown`` and would not select such a node for any zone: a false HOLDS.
        snap.reason = "graph_unavailable"
        snap.error = "the assurance library does not understand zone_unknown nodes (version skew)"
        logger.error("assurance_graph_invalid", extra={"error": snap.error})
        summary["errors"].append(f"graph: {snap.error}")
        return
    try:
        snap.graph = await asyncio.to_thread(_lib().ReachGraph.from_dict, snap.doc)
    except Exception as exc:  # noqa: BLE001 -- GraphError: bad data must not become a verdict
        snap.error = f"{type(exc).__name__}: {exc}"[:300]
        snap.reason = "graph_unavailable"
        logger.error("assurance_graph_invalid", extra={"error": snap.error})
        summary["errors"].append(f"graph: {snap.error}")


def _zone_unknown_nodes(doc: Any) -> bool:
    nodes = doc.get("nodes") if isinstance(doc, dict) else None
    return isinstance(nodes, list) and any(isinstance(n, dict) and n.get("zone_unknown") for n in nodes)


def _lib_knows_zone_unknown() -> bool:
    try:
        from paddock_assurance import graph as G  # noqa: PLC0415
        return "zone_unknown" in getattr(G.Node, "__dataclass_fields__", {})
    except Exception:  # noqa: BLE001 -- unreadable library: treat as not supported (the graph is then unavailable)
        return False


def _diagnostics(snap: _Snapshot, summary: dict[str, Any]) -> dict[str, Any]:
    diag = snap.diag
    unexpanded = list(getattr(diag, "cidr_unexpanded", None) or [])
    zone_unknown = list(getattr(diag, "zone_unknown", None) or [])
    return {
        "at": summary.get("_at"), "graph_version": snap.version, "doc_sha": snap.doc_sha,
        "graph_ok": snap.graph is not None, "graph_reason": snap.reason,
        "cidr_unexpanded": unexpanded[:50], "cidr_unexpanded_count": len(unexpanded),
        "zone_conflicts": dict(list((getattr(diag, "zone_conflicts", None) or {}).items())[:50]),
        # nodes the library treats as possible members of every zone (no independent placement, hostfw-1)
        "zone_unknown": zone_unknown[:50], "zone_unknown_count": len(zone_unknown),
        "facts_dropped": int(getattr(diag, "facts_dropped", 0) or 0),
        "fact_issues": list(getattr(diag, "fact_issues", None) or [])[:20],
    }


async def _evaluate_one(pool: Any, redis: Any, owner: str, d: _Def, snap: _Snapshot, now: datetime
                        ) -> dict[str, Any]:
    """Evaluate, record and sync one invariant. Never raises (except cancellation)."""
    item: dict[str, Any] = {"invariant_id": d.invariant_id}
    valid_until: Optional[datetime] = None
    if d.plan is None:
        rd = synthetic_result(d, "invalid_definition", now, d.error)
    elif snap.graph is None:
        rd = synthetic_result(d, snap.reason or "graph_unavailable", now, snap.error)
        rd["assertion"] = d.plan.invariant.assert_
        if snap.diag is not None and getattr(snap.diag, "cidr_unexpanded", None):
            rd["diagnostics"] = {"cidr_unexpanded": list(snap.diag.cidr_unexpanded)[:50],
                                 "cidr_unexpanded_count": len(snap.diag.cidr_unexpanded)}
    else:
        try:
            result_obj = await asyncio.to_thread(_lib().evaluate, d.plan, snap.graph, now)
            rd = result_obj.to_dict()
            valid_until = result_obj.valid_until
        except Exception as exc:  # noqa: BLE001 -- a library bug is UNKNOWN, never a crash or a HOLDS
            logger.exception("assurance_evaluate_failed", extra={"invariant": d.invariant_id})
            rd = synthetic_result(d, "evaluation_error", now, f"{type(exc).__name__}: {exc}"[:300])
            rd["assertion"] = d.plan.invariant.assert_
    item.update(verdict=rd["verdict"], reasons=rd["reasons"], violation_count=rd.get("violation_count", 0))
    try:
        changed = await _record(pool, owner, d, rd, valid_until, snap.version, now, snap.doc_sha)
        if changed is None:
            item.update(skipped="definition_changed")
            return item
        item["changed"] = changed
        retry = False
        async with _enabled_guard(pool, d) as enabled:
            if enabled is False:
                # switched off after the verdict was recorded and before the findings were synced: the toggle already
                # annotated them, and a close now would be a "fixed" from an invariant its owner just turned off
                item.update(skipped="invariant_disabled")
                return item
            if enabled is None:
                item.update(skipped="enabled_check_failed")        # cannot tell: close nothing, look again next tick
                retry = True
            else:
                await _note_state(pool, d)
                on_violation = d.plan.invariant.on_violation if d.plan is not None else None
                try:
                    rep = await findings_sync.sync_findings(
                        pool, redis, invariant_id=d.invariant_id, title=d.row["title"] or d.invariant_id,
                        finding_enabled=True if on_violation is None else on_violation.finding,
                        proposed_fixes=tuple(on_violation.propose) if on_violation is not None else (),
                        result=rd, graph_version=snap.version, now=now, lease_owner=owner)
                    item["findings"] = rep.as_dict()
                    if rep.skipped in ("lease_lost", "graph_moved"):
                        # the verdict is recorded but the findings were fenced out: make it due again
                        item["skipped"] = rep.skipped
                        retry = True
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    logger.exception("assurance_findings_sync_failed", extra={"invariant": d.invariant_id})
                    item["findings"] = {"error": f"{type(exc).__name__}: {exc}"[:300]}
                    retry = True
        if retry:
            await _mark_retry(pool, d)          # after the guard: it writes the row the guard share-locked
    except _Discarded as gone:
        logger.warning("assurance_result_discarded",
                       extra={"invariant": d.invariant_id, "reason": gone.reason})
        # an invariant switched off mid-pass is the operator's decision, not a fault: skipped, not an error
        item.update(skipped=gone.reason, discarded=gone.reason != "invariant_disabled")
    except asyncio.CancelledError:
        # Cancelled (hard timeout, shutdown) after the verdict may already be committed and before
        # the findings sync finished: without this the row looks up to date and the sync is lost
        # until the backstop. Shielded, so a second cancel cannot cut the retry mark short.
        with contextlib.suppress(BaseException):
            await asyncio.shield(asyncio.ensure_future(_mark_retry(pool, d)))
        raise
    return item


async def _evaluate_pass(pool: Any, redis: Any, owner: str, defs: list[_Def], now: datetime,
                         summary: dict[str, Any], snap: _Snapshot, *, budgeted: bool) -> bool:
    """Evaluate ``defs`` against the one graph snapshot ``snap``. Returns ``complete``: False if the
    lease was lost, the budget ran out, the graph is unusable or a record/sync did not finish."""
    summary["graph_version"] = snap.version
    await _parse_graph(snap, summary)
    complete = snap.graph is not None
    # The budget clock starts HERE, after load + parse: a graph that takes longer than the budget
    # to load must not defer every invariant forever.
    t0 = time.monotonic()
    deferred: list[str] = []
    for d in sorted(defs, key=lambda x: _rotation_key(x, snap.version)):
        if budgeted and time.monotonic() - t0 > TENANT_BUDGET_S:
            deferred.append(d.invariant_id)
            complete = False
            continue
        async with pool.acquire() as conn:
            if not await store.extend_eval(conn, owner, None, LEASE_S):
                summary["errors"].append("lease lost mid-evaluation")
                return False
        item = await _evaluate_one(pool, redis, owner, d, snap, now)
        if item.get("skipped") == "lease_lost":
            summary["errors"].append("lease lost mid-evaluation")
            summary["results"].append(item)
            return False
        summary["results"].append(item)
        if item.get("skipped"):
            complete = False
        if item.get("discarded"):
            summary["errors"].append(f"result discarded for {item['invariant_id']}: {item['skipped']}")
        if (item.get("findings") or {}).get("error"):
            complete = False
            summary["errors"].append(f"findings {item['invariant_id']}: {item['findings']['error']}")
    if deferred:
        summary["deferred"] = len(deferred)
        summary["deferred_ids"] = deferred[:50]
        logger.warning("assurance_deferred", extra={
            "tenant": summary.get("tenant_id"), "deferred": len(deferred), "evaluated": len(summary["results"]),
            "budget_s": TENANT_BUDGET_S, "ids": deferred[:10]})
    return complete


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
            state, enabled, due, _snap = await _plan_due(pool, now, force=force, only=only)
            build_due = rebuild or state.last_build_at is None or \
                now - state.last_build_at >= timedelta(minutes=settings.assurance_rebuild_min)
            if not build_due and not due:
                summary["skipped"] = "up_to_date" if enabled else "no_invariants"
                summary["graph_version"] = state.graph_version
                return summary
            async with pool.acquire() as conn:
                # The lease is judged on the DATABASE clock (``now=None``): replicas' own clocks
                # can disagree, and ``now`` below is the data clock (freshness), not a lease clock.
                claimed = await store.claim_eval(conn, owner, None, LEASE_S)
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


async def _plan_due(pool: Any, now: datetime, *, force: bool, only: Optional[Any], full: bool = False
                    ) -> tuple[store.AssuranceState, list[_Def], list[_Def], Optional[_Snapshot]]:
    """``(state, enabled invariants, the ones to evaluate now, snapshot used)``; tenant-bound by
    the caller.

    ``full=False`` (the cheap pre-lease check): the stored columns decide first; only if nothing is
    due by them is the graph document loaded and hashed (one load per tick) to see whether its
    INPUTS changed without moving ``graph_version`` (node attrs, asset metadata). A failed probe
    means "cannot tell": everything is due (fail closed), never "up to date".

    ``full=True`` (inside the lease, about to evaluate): always load the snapshot the pass will
    evaluate (when anything is selected) and decide on it; a load failure propagates.
    """
    async with pool.acquire() as conn:
        state = await store.get_state(conn)
        rows = await conn.fetch(f"SELECT {_INV_COLS} FROM invariants WHERE enabled ORDER BY invariant_id")
    enabled = await _compile_defs(list(rows))
    wanted = _select(enabled, only)
    if not wanted:
        return state, enabled, [], None
    if force and not full:
        return state, enabled, wanted, None
    if not full:
        cheap = [d for d in wanted if _is_due(d, now, version=state.graph_version, doc_sha=None)]
        if cheap:
            return state, enabled, cheap, None
    try:
        snap = await _load_snapshot(pool, now)
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001
        if full:
            raise
        logger.exception("assurance_doc_probe_failed")
        return state, enabled, wanted, None
    if force:
        return state, enabled, wanted, snap
    return state, enabled, [d for d in wanted if _is_due(
        d, now, version=snap.version, doc_sha=snap.doc_sha)], snap


async def _evaluate_tenant_locked(pool: Any, redis: Any, owner: str, now: datetime,
                                  summary: dict[str, Any], *, force: bool, only: Optional[Any]) -> None:
    summary["_at"] = _iso(now)
    state, enabled, due, snap = await _plan_due(pool, now, force=force, only=only, full=True)
    summary["graph_version"] = snap.version if snap is not None else state.graph_version
    if not due or snap is None:
        summary["skipped"] = "up_to_date" if enabled else "no_invariants"
        return
    complete = await _evaluate_pass(pool, redis, owner, due, now, summary, snap, budgeted=not force)
    _LAST_EVAL[summary["tenant_id"]] = _diagnostics(snap, summary) | {
        "deferred": summary.get("deferred", 0), "evaluated": len(summary["results"])}
    summary["diagnostics"] = dict(_LAST_EVAL[summary["tenant_id"]])
    # The watermark (and the document hash that goes with it) only advances when EVERY enabled
    # invariant is now current at this graph version and document: the ones evaluated in this pass
    # (and recorded) plus the ones that were already current. A partial run (forced subset,
    # budget, failed sync, fenced-out result) must leave the rest due.
    ids = {d.invariant_id for d in due}
    others_current = all(
        not _is_due(d, now, version=snap.version, doc_sha=snap.doc_sha)
        for d in enabled if d.invariant_id not in ids)
    if complete and others_current:
        summary["_watermark"] = snap.version
        summary["_doc_sha"] = snap.doc_sha
    else:
        summary["_watermark"] = None


async def _release(pool: Any, tid: str, owner: str, now: datetime, summary: dict[str, Any]) -> None:
    mark = summary.pop("_watermark", None)
    sha = summary.pop("_doc_sha", None)
    summary.pop("_at", None)
    try:
        with tenancy.tenant_context(tid):
            async with pool.acquire() as conn:
                await store.release_eval(conn, owner, now, evaluated_version=mark, doc_sha=sha)
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

async def _entitled(pool: Any, tid: str) -> bool:
    """May the background loop do paid assurance work for this tenant?

    Same gate as the API (``billing.gate``): with no enforcement (a plain self-hosted install)
    everyone is entitled and nothing changes. With billing or ``PADDOCK_ENFORCE_EDITIONS`` on, a
    tenant whose plan lacks ``assurance`` (trial lapsed, downgraded) is neither built nor
    evaluated: the API refuses to serve it, and the loop must not quietly do the paid work and
    open findings. Reads of existing data stay open (the API never gates reads). A failure to
    LOOK UP the entitlement fails open, like ``billing.gate.scans_allowed``: a billing blip must
    not switch assurance off for paying tenants (a stale verdict is flagged stale, never HOLDS).
    """
    try:
        from .. import licensing  # noqa: PLC0415
        from ..billing import gate as billing_gate  # noqa: PLC0415
        from ..billing import service as billing_service  # noqa: PLC0415
        if not billing_gate.enforcement_active():
            return True
        with tenancy.tenant_context(tid):
            lic = await licensing.load_active_license(pool)
            ent = await billing_service.resolve(pool, lic)
        return bool(ent.has("assurance"))
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001
        logger.exception("assurance_entitlement_check_failed", extra={"tenant": tid})
        return True


async def _reconcile(pool: Any, tid: str, entitled: bool) -> None:
    """Once per tick per tenant (at most every ``RECONCILE_EVERY_S``, or at once when the entitlement flipped): repair
    the lifecycle annotation of the tenant's findings. Never raises, never changes a status."""
    mono = time.monotonic()
    last = _RECONCILE_LAST.get(tid)
    if last is not None and last[1] == entitled and mono - last[0] < RECONCILE_EVERY_S:
        return
    _RECONCILE_LAST[tid] = (mono, entitled)
    try:
        await housekeeping.reconcile_orphans(pool, tid, entitled=entitled)
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 -- housekeeping must never stop the loop
        logger.exception("assurance_reconcile_failed", extra={"tenant": tid})


async def tick_once(pool: Any, *, redis: Any = None, now: Optional[datetime] = None) -> dict[str, dict[str, Any]]:
    """One pass over every tenant. Each tenant is independent: a failure, a timeout or a held lease
    for one never delays the budgeted work of the next beyond its own hard cap. Tenants that are
    not entitled to ``assurance`` (when editions are enforced) are skipped (``not_entitled``)."""
    out: dict[str, dict[str, Any]] = {}
    for tid in await tenancy.list_tenant_ids(pool):
        try:
            entitled = await _entitled(pool, tid)
            await _reconcile(pool, tid, entitled)
            if not entitled:
                out[tid] = {"ok": True, "tenant_id": tid, "skipped": "not_entitled", "built": False,
                            "builders": {}, "graph_version": None, "evaluated": 0, "results": [], "errors": []}
                continue
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
