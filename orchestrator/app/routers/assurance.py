"""Provable containment API: invariants, zones, labels, reach graph, coverage, evaluation.

Owned by the API work package (docs/ASSURANCE_P1.md sections 7 and 8). Registered in main.py.

Conventions (all of them are load-bearing for the isolation sweeps):

* **Tenancy.** The governance middleware stamps the tenant on the request context, and the pool's
  setup hook stamps it on every ``pool.acquire()``; nothing in this file names ``tenant_id``.
* **Uniform 404.** A foreign id and an unknown id are answered by the *same* statement with the
  *same* body (RLS makes a foreign row invisible), and body validation always runs before any
  lookup, so a caller can never tell "not yours" from "does not exist".
* **RBAC.** Reads are ``read`` (the safe-method default); every mutation falls through to the
  deny-closed ``admin`` default in ``auth.required_capability``. The one explicit rule is the human-only
  ``POST /v1/invariants/{id}/findings/release`` (admin, never billing-gated, P2.1 6.1).
* **Billing.** Mutations that create or change paid work are gated with
  ``billing_gate.require_paid("assurance")``; reads and DELETEs are never gated (a downgraded
  tenant can read what it has and clean up, as for the other gated features).
* **Audit.** Every mutation writes a semantic ``audit.record`` (best effort, never fails the
  request); the middleware's generic per-request row exists as well.
* **Lifecycle (P2.1 6.1, D33: annotate, never close).** Disabling or archiving an invariant annotates its open and
  triaged findings (``metadata.invariant_state``) in the same transaction and never changes a status: nothing re-checks
  them, so nothing may close them. A person gives up on them with the release route (``wontfix``, sticky).
* **Soundness.** A verdict is never reported fresher than it is: an invariant that was disabled
  and re-enabled, or whose definition changed, has its ``last_graph_version`` cleared so the runner
  treats it as due, and the list shows it as ``PENDING`` rather than as a stale ``HOLDS``.

``paddock_assurance`` is imported lazily inside handlers so ``scripts/export_openapi.py`` and the SDK
checks (which install only the orchestrator) can import this module.
"""
from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import logging
import re
import threading
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from typing import Annotated, Any, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import AfterValidator, BaseModel, Field, StringConstraints, field_validator, model_validator

from .. import audit, lifecycle, tenancy
from ..assurance import housekeeping, store
from ..auth import CLASS_RANK, Principal, classification_rank_sql, current_principal
from ..billing import gate as billing_gate
from ..config import settings
from ..db import get_pool

logger = logging.getLogger(__name__)
router = APIRouter(tags=["assurance"])

#: ``POST /v1/assurance/evaluate`` gives up (answering 200 ``ok: false``) after this long; the
#: runner is cancelled cleanly (its lease is released in a ``finally``).
EVALUATE_TIMEOUT_S = 240.0

# Per-tenant caps (review finding security-3). Every enabled invariant is re-compiled and
# re-evaluated, every zone CIDR is matched against every node address, so unbounded counts let one
# tenant stall the shared loop. Hitting a cap is a clear 409; nothing is silently dropped.
#: enabled invariants per tenant (std copies included).
MAX_INVARIANTS_ENABLED = 200
#: all invariant rows incl. disabled/archived ones (DELETE keeps rows as evidence, so they are
#: bounded separately and generously rather than never freed).
MAX_INVARIANTS_TOTAL = 1000
MAX_ZONES = 200
#: CIDRs in ONE zone (the store enforces the same number).
MAX_ZONE_CIDRS = 256
#: CIDRs over ALL of a tenant's zones: zone resolution is O(nodes x CIDRs).
MAX_TOTAL_ZONE_CIDRS = 4096
#: declared labels (metadata/connector-derived labels are not counted: the tenant did not write them).
MAX_LABELS = 20_000
#: CIDRs a sensor's declared scope may list.
MAX_SENSOR_CIDRS = 64
#: a declared scope shorter than this is a "wide" scope: refused unless ``allow_wide`` and a real reason (D37).
WIDE_V4_PREFIX, WIDE_V6_PREFIX = 16, 48
WIDE_JUSTIFICATION_MIN = 20
#: sensor advisories read this many days of flows, show this many prefixes and consider this many per sensor.
SCOPE_WINDOW_DAYS = 7
OBSERVED_SHOWN = 32
OBSERVED_SCAN = 512
SUGGEST_MAX = 16
#: an ``allow`` exception may not run longer than this from today (review finding security-7: a
#: 3-letter reason with ``expires: 9999-12-31`` is a permanent, silent hole).
MAX_ALLOW_DAYS = 90

# Parsing is attacker-controlled CPU (PyYAML is pure Python and slow on deep flow nesting).
#: wall-clock budget for one parse+compile before the request is answered 422.
COMPILE_TIMEOUT_S = 5.0
#: parse+compile threads that may run at once (a hung parse keeps its slot until it ends).
COMPILE_SLOTS = 4
#: deepest ``[``/``{`` nesting accepted before any parser sees the text (the library allows 12).
MAX_YAML_NESTING = 64

#: classification filtering materialises the caller's hidden assets; beyond this we refuse
#: (503) rather than answer with an incomplete filter.
MAX_HIDDEN_ASSETS = 100_000
_REDACTED = "[redacted]"

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


def _storable(v: str) -> str:
    """Text Postgres can store: a NUL byte raises ``CharacterNotInRepertoire``, an unhandled 500 (a lone surrogate
    cannot arrive: the JSON parser and the query decoder refuse it first)."""
    if "\x00" in v:
        raise ValueError("must not contain a NUL byte")
    return v


def _storable_opt(v: Optional[str]) -> Optional[str]:
    return v if v is None else _storable(v)


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
# Classification (ABAC) over the reach graph (review finding security-4)
# --------------------------------------------------------------------------------------------
# The reach tables carry no classification of their own; a node is as classified as the asset that
# backs it. /v1/assets and /v1/findings hide assets above the caller's clearance, so every read
# here must hide the same assets (and everything that names them) or it re-opens the hole: node
# refs, private IPs, edges, coverage facts, labels and the witnesses/blind spots inside invariant
# results. A hidden thing answers exactly like a missing one.

_FULL_RANK = CLASS_RANK["restricted"]
# A "word" of an address/ref/uuid/hostname: what we compare against the hidden set token by token.
_RUN = re.compile(r"[A-Za-z0-9_.:/%@-]+")
_SIMPLE = re.compile(r"[A-Za-z0-9_.:/%@-]+")
_MIN_VALUE_LEN = 4
_MAX_ODD_TOKENS = 500


def _norm_addr(text: Any) -> Optional[str]:
    """Canonical address text (the builders' spelling) or None. Scope ids are not addresses."""
    if not isinstance(text, str) or len(text) > 64 or "%" in text:
        return None
    t = text.strip()
    if t.startswith("[") and t.endswith("]"):
        t = t[1:-1]
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.compressed.lower()


def _ips_in(value: Any) -> list[str]:
    if isinstance(value, (str, bytes)):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    if isinstance(value, str):
        value = [value]
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


class _Vis:
    """What the caller may NOT see. ``active`` is False for a fully cleared principal (no work)."""

    __slots__ = ("active", "refs", "ids", "_refset", "_simple", "_odd")

    def __init__(self, refs: Optional[set[str]] = None, ids: Optional[list[str]] = None,
                 simple: Optional[set[str]] = None, odd: Optional[list[str]] = None,
                 active: bool = False) -> None:
        self.active = active
        self._refset: frozenset[str] = frozenset(refs or ())
        self.refs: list[str] = sorted(self._refset)
        self.ids: list[str] = ids or []
        self._simple: frozenset[str] = frozenset(simple or ())
        self._odd: tuple[str, ...] = tuple(odd or ())

    def hidden(self, ref: str) -> bool:
        return self.active and ref in self._refset

    # -- redaction of arbitrary JSON-ish data ---------------------------------------------------
    def _token_hidden(self, tok: str) -> bool:
        low = tok.lower()
        if low in self._simple:
            return True
        low = low.strip(".-:/_@%")            # ``10.7.7.7.`` at the end of a sentence, ``ref->``
        if low in self._simple:
            return True
        # ``ip:10.7.7.7:5432``-style compounds: test the pieces too (coarser is safer).
        if ":" in low or "/" in low:
            for part in re.split(r"[:/]", low):
                if part and part in self._simple:
                    return True
            if low.partition(":")[2] in self._simple:
                return True
        return False

    def text(self, s: str) -> str:
        if not self.active or not s:
            return s
        out = _RUN.sub(lambda m: _REDACTED if self._token_hidden(m.group(0)) else m.group(0), s)
        if self._odd:
            low = out.lower()
            for tok in self._odd:
                if tok in low:
                    out = re.sub(re.escape(tok), _REDACTED, out, flags=re.IGNORECASE)
                    low = out.lower()
        return out

    def scrub(self, obj: Any) -> Any:
        """A copy of ``obj`` with every hidden ref / address / asset value replaced by a marker."""
        if not self.active:
            return obj
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            out: dict[Any, Any] = {}
            for k, v in obj.items():
                nk = self.text(k) if isinstance(k, str) else k
                while nk in out:          # two hidden keys collapse to the same marker: keep both
                    nk = f"{nk}~"
                out[nk] = self.scrub(v)
            return out
        if isinstance(obj, (list, tuple)):
            return [self.scrub(v) for v in obj]
        return obj


_FULL = _Vis()


async def _vis(con: Any, principal: Principal) -> _Vis:
    """The hidden set for ``principal``: assets whose classification outranks its clearance."""
    if principal.clearance_rank >= _FULL_RANK:
        return _FULL
    rows = await con.fetch(
        "SELECT a.id, a.value, a.canonical, a.metadata->'public_ips' AS pub, "
        "a.metadata->'private_ips' AS priv, a.metadata->'ips' AS ips, a.metadata->'ip' AS ip1 "
        f"FROM assets a WHERE {classification_rank_sql('a.classification')} > $1 LIMIT $2",
        principal.clearance_rank, MAX_HIDDEN_ASSETS + 1)
    if len(rows) > MAX_HIDDEN_ASSETS:
        # An incomplete filter would leak; refuse instead.
        raise HTTPException(status_code=503, detail="too many classified assets to filter this view")
    refs: set[str] = set()
    ids: list[str] = []
    simple: set[str] = set()
    odd: list[str] = []

    def add_ip(addr: str) -> None:
        n = _norm_addr(addr)
        if n is None:
            return
        suffix = "128" if ":" in n else "32"
        for tok in (f"ip:{n}", f"cidr:{n}/{suffix}"):
            refs.add(tok)
            simple.add(tok)
        simple.add(n)

    for r in rows:
        aid = str(r["id"])
        ids.append(aid)
        refs.add(f"asset:{aid}")
        simple.update((aid, f"asset:{aid}"))
        for v in (r["pub"], r["priv"], r["ips"], r["ip1"]):
            for a in _ips_in(v):
                add_ip(a)
        for v in (r["value"], r["canonical"]):
            if not isinstance(v, str):
                continue
            add_ip(v)
            v = v.strip().lower()
            if len(v) < _MIN_VALUE_LEN:
                continue
            if _SIMPLE.fullmatch(v):
                simple.add(v)
            elif len(odd) < _MAX_ODD_TOKENS:
                odd.append(v)
    return _Vis(refs, ids, simple, odd, active=True)


def _hide_sql(col: str, vis: _Vis, where: list[str], args: list[Any]) -> None:
    """Append ``col`` is-not-hidden to a WHERE clause (no-op for a fully cleared caller)."""
    if vis.active and vis.refs:
        args.append(vis.refs)
        where.append(f"{col} <> ALL(${len(args)}::text[])")


# --------------------------------------------------------------------------------------------
# Threads: attacker-controlled CPU must never run on the event loop (review findings 2 and 5)
# --------------------------------------------------------------------------------------------

_compile_slots = threading.BoundedSemaphore(COMPILE_SLOTS)


class _Busy(Exception):
    """Every compile slot is taken (by slow parses): refuse rather than queue behind them."""


def _nesting_problem(text: str) -> Optional[str]:
    """A cheap O(n) scan, BEFORE any parser sees the text: PyYAML's scanner is pure Python and its
    cost grows with flow depth (4,000 ``[`` took 6s and froze every tenant). Quotes are ignored on
    purpose: 64 unbalanced openers is not a legitimate invariant either way."""
    depth = 0
    for ch in text:
        if ch == "[" or ch == "{":
            depth += 1
            if depth > MAX_YAML_NESTING:
                return f"document: flow nesting deeper than {MAX_YAML_NESTING} levels"
        elif (ch == "]" or ch == "}") and depth:
            depth -= 1
    return None


# --------------------------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------------------------

class _Justified(BaseModel):
    justification: str = Field(min_length=1, max_length=1000,
                               description="Why. Recorded with the change and in the audit log.")

    @field_validator("justification")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = _storable(v).strip()
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
    state: str = Field("active", description="active | disabled | archived | invalid_definition | not_entitled. "
                                             "A non-active invariant is not evaluated: its open findings stay open "
                                             "and are annotated, never closed by the machine.")
    disabled_at: Optional[datetime] = None
    disabled_by: Optional[str] = None
    archived_at: Optional[datetime] = None
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
    open_findings: int = Field(0, description="Open and triaged findings of this invariant.")
    findings_not_rechecked: int = Field(
        0, description="Of those, the ones nobody is re-checking (the invariant is disabled, archived, invalid or "
                       "not entitled). Release them with POST /v1/invariants/{id}/findings/release.")
    yaml: str
    redacted: bool = Field(False, description="Parts were withheld because they name assets above the "
                                              "caller's clearance.")
    last_result: Optional[dict[str, Any]] = None
    versions: list[InvariantVersionOut] = Field(default_factory=list)


class InvariantPage(BaseModel):
    items: list[InvariantOut]
    total: int
    limit: int
    offset: int


_OptWhy = Annotated[Optional[str], StringConstraints(max_length=1000), AfterValidator(_storable_opt)]


class InvariantCreate(BaseModel):
    yaml: str = Field(min_length=1, max_length=65536)
    enabled: bool = True
    justification: _OptWhy = Field(None, description="Optional: why. Recorded in the audit log.")


class InvariantUpdate(BaseModel):
    yaml: Optional[str] = Field(None, min_length=1, max_length=65536)
    enabled: Optional[bool] = None
    justification: _OptWhy = Field(None, description="Optional: why. Recorded in the audit log.")

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
    redacted: bool = Field(False, description="The result had parts withheld (clearance).")
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
    compacted_at: Optional[datetime] = Field(
        None, description="Set when the heavy parts of ``result`` (target lists, blind spots, all but the first 5 "
                          "witnesses) were dropped after the compaction horizon; the decision itself is kept.")
    pinned: bool = Field(False, description="Held whole: never compacted or deleted (attestations pin rows).")
    result: Optional[dict[str, Any]] = None


class RunPage(BaseModel):
    items: list[RunOut]
    total: int
    limit: int
    offset: int


class ReleaseIn(BaseModel):
    model_config = {"extra": "forbid"}
    justification: str = Field(min_length=1, max_length=1000,
                               description="Why these findings are given up on (10+ characters; audited and written "
                                           "into each finding's status reason).")

    @field_validator("justification")
    @classmethod
    def _enough(cls, v: str) -> str:
        v = _storable(v).strip()
        if len(v) < 10:
            raise ValueError("a justification of at least 10 characters is required")
        return v


class ReleaseOut(BaseModel):
    released: int = Field(description="Findings marked wontfix.")


class EvaluateIn(BaseModel):
    invariant_ids: Optional[list[_Id]] = Field(
        None, max_length=100, description="std:x / acme:y ids or row UUIDs; default: every enabled invariant.")
    rebuild: bool = Field(False, description="Re-run the graph builders first.")


class SensorScopeIn(_Justified):
    cidrs: list[Annotated[str, StringConstraints(max_length=64)]] = Field(
        min_length=1, max_length=MAX_SENSOR_CIDRS,
        description="The networks this sensor can actually see (mirror/SPAN coverage). Coverage is "
                    "asserted only for hosts inside them.")
    allow_wide: bool = Field(
        False, description="Accept a prefix shorter than /16 (IPv4) or /48 (IPv6). Needs a justification of at "
                           "least 20 characters; the audit row records it.")


class ObservedPrefix(BaseModel):
    prefix: str = Field(description="An IPv4 /24 seen as a flow source or destination by THIS sensor.")
    flows: int = Field(description="Distinct flow records touching the prefix in the window.")
    last_seen: Optional[datetime] = None
    private: bool = Field(True, description="RFC 1918 or shared (100.64/10) address space. Any other prefix (public, or "
                                            "special-use such as loopback, link-local, multicast) is shown but never "
                                            "suggested or flagged: every sensor sees the internet's endpoints.")


class SensorObserved(BaseModel):
    prefixes: list[ObservedPrefix] = Field(default_factory=list)
    truncated: bool = Field(False, description="More prefixes were seen than listed.")
    window_days: int = Field(SCOPE_WINDOW_DAYS, description="The flows were read from the last N days (the flow "
                                                           "table keeps a bounded history, so possibly less).")


class SensorScopeOut(BaseModel):
    sensor_id: UUID
    name: Optional[str] = None
    site: Optional[str] = None
    status: Optional[str] = None
    online: Optional[bool] = None
    cidrs: list[str] = Field(default_factory=list)
    scope_declared: bool = True
    set_by: Optional[str] = None
    justification: str = ""
    set_at: Optional[datetime] = None
    observed: Optional[SensorObserved] = Field(
        None, description="What this sensor actually saw (evidence for what to declare). Observed coverage proves "
                          "'no such traffic was seen', never 'impossible'.")
    declared_but_unobserved: list[str] = Field(
        default_factory=list, description="Declared IPv4 CIDRs with no observed address inside in the window.")
    observed_outside_scope: list[str] = Field(
        default_factory=list, description="Private /24s this sensor saw that no declared CIDR overlaps.")
    suggested_cidrs: list[str] = Field(
        default_factory=list, description="The observed private /24s merged into at most 16 supernets, none "
                                          "shorter than /16. A suggestion to review, never applied by itself.")
    advisory_notes: list[str] = Field(default_factory=list)


class SensorScopeList(BaseModel):
    items: list[SensorScopeOut]
    unscoped_sensors: list[SensorScopeOut] = Field(
        default_factory=list, description="Active sensors with no declared scope: they cover nothing.")
    total: int


class SensorScopeChange(BaseModel):
    scope: SensorScopeOut
    changed: bool
    previous: Optional[list[str]] = None
    graph_version: Optional[int] = None
    warnings: list[str] = Field(default_factory=list, description="Things worth a second look: a declared CIDR "
                                "this sensor saw no flows in, a scope on a sensor that is offline or revoked.")


class SensorScopeDeleteOut(BaseModel):
    deleted: bool = True
    sensor_id: UUID
    previous: list[str] = Field(default_factory=list)
    graph_version: Optional[int] = None


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
             "updated_by, updated_at, disabled_at, disabled_by, archived_at")


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
        "state": housekeeping.state_of(row["enabled"], row["archived_at"], lgv, last.get("reasons")),
        "disabled_at": row["disabled_at"], "disabled_by": row["disabled_by"], "archived_at": row["archived_at"],
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


def _invalid(problems: list[str]) -> HTTPException:
    return HTTPException(status_code=422, detail={"error": "invalid_invariant", "problems": problems[:100]})


async def _compile(text: str) -> Any:
    """Parse + compile via the library, OFF the event loop, with a timeout.

    422 with the library's problem list when it is not valid, and 422 when it takes longer than
    ``COMPILE_TIMEOUT_S`` (a thread cannot be killed, so a hung parse keeps its slot until it ends
    and at most ``COMPILE_SLOTS`` can ever be wedged; the nesting pre-scan keeps hostile input from
    getting that far).
    """
    lib = _lib()
    bad = _nesting_problem(text)
    if bad:
        raise _invalid([bad])

    def work() -> Any:
        if not _compile_slots.acquire(blocking=False):
            raise _Busy()
        try:
            return lib.compile_text(text)
        finally:
            _compile_slots.release()

    try:
        return await asyncio.wait_for(asyncio.to_thread(work), COMPILE_TIMEOUT_S)
    except asyncio.TimeoutError:
        problems = [f"document: could not be parsed within {COMPILE_TIMEOUT_S:g}s"]
    except _Busy:
        raise HTTPException(status_code=429, detail="too many invariant compilations in flight; retry",
                            headers={"Retry-After": "5"}) from None
    except lib.ParseError as exc:
        problems = list(exc.problems)
    except lib.CompileError as exc:
        problems = [str(exc)]
    except Exception as exc:  # noqa: BLE001 -- a library bug is the caller's 422, never a 500
        logger.exception("assurance_compile_failed")
        problems = [f"could not be compiled ({type(exc).__name__})"]
    raise _invalid(problems)


def _allow_problems(plan: Any, today: Optional[date] = None) -> list[str]:
    """``allow`` exceptions must expire soon: an exception is a hole in the proof, not a setting."""
    today = today or _now().date()
    limit = today + timedelta(days=MAX_ALLOW_DAYS)
    out = []
    for i, a in enumerate(plan.invariant.allow):
        if a.expires > limit:
            out.append(f"allow[{i}].expires: {a.expires.isoformat()} is more than {MAX_ALLOW_DAYS} days "
                       f"away (latest {limit.isoformat()}); renew the exception instead")
    return out


def _allow_audit(plan: Any) -> list[dict[str, Any]]:
    """What an exception says, for the audit row: target, ports, the reason given and the expiry."""
    out = []
    for a in plan.invariant.allow:
        out.append({"to": a.to.model_dump(mode="json", exclude_none=True, exclude_defaults=True)
                    if hasattr(a.to, "model_dump") else str(a.to),
                    "ports": a.ports, "reason": a.reason, "expires": a.expires.isoformat()})
    return out[:50]


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


def _inv_view(row: Any, now: datetime, gv: int, vis: _Vis, *, detail: bool = False,
              versions: Optional[list[Any]] = None) -> dict[str, Any]:
    """``_inv_out`` as this caller may see it: the stored result and the definition can name
    assets (witness hops, blind spots, selectors) above the caller's clearance."""
    out = _inv_out(row, now, gv, detail=detail, versions=versions)
    if not vis.active:
        return out
    scrubbed = vis.scrub({k: v for k, v in out.items() if k not in ("id", "versions")})
    scrubbed["id"] = out["id"]
    if detail:
        scrubbed["versions"] = out["versions"]
        scrubbed["redacted"] = scrubbed.get("yaml") != out.get("yaml") or scrubbed.get(
            "last_result") != out.get("last_result")
    return scrubbed


_OWN_FINDINGS = ("f.rule_source = 'invariant' AND (f.rule_id = 'invariant:' || $1::text "
                 "OR starts_with(f.rule_id, 'invariant:' || $1::text || '@'))")


def _visible_findings(vis: _Vis, args: list[Any]) -> str:
    """Extra WHERE for the findings the caller may see (a finding of a classified asset above the caller's clearance is
    neither counted nor released: it would confirm that the asset exists)."""
    if vis.active and vis.ids:
        args.append(vis.ids)
        return f" AND f.asset_id::text <> ALL(${len(args)}::text[])"
    return ""


async def _finding_counts(con: Any, invariant_id: str, vis: _Vis) -> tuple[int, int, Optional[str]]:
    """``(open+triaged findings, of them not re-checked, the runner-detected state if any)`` for one invariant."""
    args: list[Any] = [invariant_id]
    extra = _visible_findings(vis, args)
    r = await con.fetchrow(
        "SELECT count(*) FILTER (WHERE f.status IN ('open', 'triaged')) AS open_n, "
        "count(*) FILTER (WHERE f.status IN ('open', 'triaged') AND f.metadata ? 'invariant_state') AS stale_n, "
        "min(f.metadata->>'invariant_state') FILTER (WHERE f.status IN ('open', 'triaged') AND "
        "f.metadata->>'invariant_state' IN ('invalid_definition', 'not_entitled')) AS runner_state "
        f"FROM findings f WHERE {_OWN_FINDINGS}{extra}", *args)
    return int(r["open_n"] or 0), int(r["stale_n"] or 0), r["runner_state"]


async def _detail(pool: Any, inv_uuid: UUID, principal: Principal) -> dict[str, Any]:
    async with pool.acquire() as con:
        row = await _invariant_row(con, inv_uuid)
        gv = await _graph_version(con)
        vers = await _versions(con, row["invariant_id"])
        vis = await _vis(con, principal)
        open_n, stale_n, runner_state = await _finding_counts(con, row["invariant_id"], vis)
    out = _inv_view(row, _now(), gv, vis, detail=True, versions=vers)
    if out.get("state") == "active" and runner_state:
        out["state"] = runner_state          # the runner saw something the columns cannot show (not_entitled)
    out["open_findings"], out["findings_not_rechecked"] = open_n, stale_n
    return out


async def _lock_invariants(con: Any) -> None:
    """Serialises the count-then-insert of the per-tenant caps (same key shape as the store's)."""
    await con.execute("SELECT pg_advisory_xact_lock(hashtextextended("
                      "coalesce(current_setting('app.tenant_id', true), '') || ':invariants', 0))")


async def _check_invariant_caps(con: Any, *, adding_row: bool, enabling: bool) -> None:
    """409 with the cap named when a new or newly enabled invariant would exceed it."""
    if adding_row:
        total = await con.fetchval("SELECT count(*) FROM invariants")
        if total >= MAX_INVARIANTS_TOTAL:
            raise HTTPException(status_code=409, detail={
                "error": "invariant_limit", "limit": MAX_INVARIANTS_TOTAL, "scope": "total",
                "message": f"this tenant already has {total} invariants including archived ones "
                           f"(max {MAX_INVARIANTS_TOTAL})"})
    if enabling:
        n = await con.fetchval("SELECT count(*) FROM invariants WHERE enabled")
        if n >= MAX_INVARIANTS_ENABLED:
            raise HTTPException(status_code=409, detail={
                "error": "invariant_limit", "limit": MAX_INVARIANTS_ENABLED, "scope": "enabled",
                "message": f"this tenant already has {n} enabled invariants (max {MAX_INVARIANTS_ENABLED}); "
                           "disable one first"})


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
    pool=Depends(get_pool), principal: Principal = Depends(current_principal),
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
        vis = await _vis(con, principal)
        if status:
            # The status is derived (expiry, pending), so it is filtered after the read. Bounded
            # by MAX_INVARIANTS_TOTAL.
            rows = await con.fetch(f"SELECT {_INV_COLS} FROM invariants {clause} "
                                   "ORDER BY invariant_id LIMIT 5000", *args)
            outs = [_inv_view(r, now, gv, vis) for r in rows]
            outs = [o for o in outs if o["status"] == status.upper()]
            return _page(outs[offset:offset + limit], len(outs), limit, offset)
        total = await con.fetchval(f"SELECT count(*) FROM invariants {clause}", *args)
        rows = await con.fetch(
            f"SELECT {_INV_COLS} FROM invariants {clause} ORDER BY invariant_id "
            f"LIMIT ${len(args) + 1} OFFSET ${len(args) + 2}", *args, limit, offset)
    return _page([_inv_view(r, now, gv, vis) for r in rows], total, limit, offset)


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


def _why(text: Optional[str]) -> Optional[str]:
    """An optional justification, trimmed; empty means none."""
    try:
        t = _storable(text or "").strip()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=[{"loc": ["query", "justification"], "type": "value_error",
                                                      "msg": f"Value error, {exc}"}]) from exc
    return t or None


@router.post("/v1/invariants/std/{std_id}/enable", response_model=InvariantChange, dependencies=[_PAID])
async def enable_std_invariant(
    std_id: str, request: Request, response: Response, pool=Depends(get_pool),
    justification: Optional[str] = Query(None, max_length=1000, description="Optional: why (audited)."),
    principal: Principal = Depends(current_principal),
):
    """Copy a shipped invariant into the tenant and enable it (idempotent; refreshes a stale copy)."""
    e = _std_entry(std_id)
    why = _why(justification)
    actor, created, new_version, prev_digest, was_enabled = principal.actor, False, False, None, None
    async with pool.acquire() as con:
        async with con.transaction():
            await _lock_invariants(con)
            cur = await con.fetchrow("SELECT id, enabled, digest, version FROM invariants "
                                     "WHERE invariant_id = $1 FOR UPDATE", e["id"])
            if cur is None:
                await _check_invariant_caps(con, adding_row=True, enabling=True)
                rid = await con.fetchval(
                    "INSERT INTO invariants (invariant_id, title, severity, enabled, source, yaml, digest, "
                    "version, created_by, updated_by) VALUES ($1, $2, $3, TRUE, 'std', $4, $5, 1, $6, $6) "
                    "ON CONFLICT (tenant_id, invariant_id) DO UPDATE SET enabled = TRUE RETURNING id",
                    e["id"], e["title"], e["severity"], e["yaml"], e["digest"], actor)
                await _insert_version(con, e["id"], e["digest"], 1, e["yaml"], actor)
                created = changed = True
            else:
                rid, prev_digest, was_enabled = cur["id"], cur["digest"], cur["enabled"]
                changed = not cur["enabled"] or cur["digest"] != e["digest"]
                if changed:
                    if not cur["enabled"]:
                        await _check_invariant_caps(con, adding_row=False, enabling=True)
                    new_version = cur["digest"] != e["digest"]
                    ver = cur["version"] + 1 if new_version else cur["version"]
                    # last_graph_version/valid_until cleared: the old verdict (from before it was
                    # disabled, or for the old definition) must not be shown or trusted as current.
                    await con.execute(
                        "UPDATE invariants SET enabled = TRUE, yaml = $2, digest = $3, title = $4, "
                        "severity = $5, version = $6, last_graph_version = NULL, valid_until = NULL, "
                        "disabled_at = NULL, disabled_by = NULL, archived_at = NULL, "
                        "updated_by = $7, updated_at = NOW() WHERE id = $1",
                        rid, e["yaml"], e["digest"], e["title"], e["severity"], ver, actor)
                    if not cur["enabled"]:
                        # back from disabled/archived: whatever the annotation said, the runner re-evaluates first
                        await housekeeping.clear_annotations(con, e["id"])
                    if new_version:
                        await _insert_version(con, e["id"], e["digest"], ver, e["yaml"], actor)
        gv = await _graph_version(con)
        row = await _invariant_row(con, rid)
        vis = await _vis(con, principal)
    if changed:
        await _audit(request, pool, principal, action="assurance_std_enable", resource_type="invariants",
                     resource_id=str(rid), justification=why,
                     details={"invariant_id": e["id"], "digest": e["digest"],
                              "previous_digest": prev_digest, "created": created,
                              "was_enabled": was_enabled})
    response.status_code = 201 if created else 200
    return {"invariant": _inv_view(row, _now(), gv, vis), "changed": changed, "created": created,
            "new_version": new_version or created}


@router.post("/v1/invariants", response_model=InvariantChange, status_code=201, dependencies=[_PAID])
async def create_invariant(
    body: InvariantCreate, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Create a custom invariant from YAML (parsed and compiled by the library; 422 lists the problems)."""
    plan = await _compile(body.yaml)
    if plan.id.startswith("std:"):
        raise _invalid(["id: the 'std:' namespace is reserved for the shipped library (use POST "
                        "/v1/invariants/std/{id}/enable)"])
    if (late := _allow_problems(plan)):
        raise _invalid(late)
    inv = plan.invariant
    why = _why(body.justification)
    async with pool.acquire() as con:
        async with con.transaction():
            await _lock_invariants(con)
            await _check_invariant_caps(con, adding_row=True, enabling=body.enabled)
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
        vis = await _vis(con, principal)
    await _audit(request, pool, principal, action="assurance_invariant_create", resource_type="invariants",
                 resource_id=str(rid), status=201, justification=why,
                 details={"invariant_id": plan.id, "digest": plan.digest, "severity": inv.severity,
                          "assertion": inv.assert_, "enabled": body.enabled,
                          "exceptions": _allow_audit(plan)})
    return {"invariant": _inv_view(row, _now(), gv, vis), "changed": True, "created": True,
            "new_version": True}


@router.get("/v1/invariants/{invariant_id}", response_model=InvariantDetail)
async def get_invariant(invariant_id: UUID, pool=Depends(get_pool),
                        principal: Principal = Depends(current_principal)):
    return await _detail(pool, invariant_id, principal)


@router.put("/v1/invariants/{invariant_id}", response_model=InvariantChange, dependencies=[_PAID])
async def update_invariant(
    invariant_id: UUID, body: InvariantUpdate, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Change the definition (new digest => new version row) and/or toggle ``enabled``.

    A std invariant's text is owned by the shipped library (it would be overwritten), so only
    ``enabled`` can change there. An optional ``justification`` is recorded in the audit log, and
    every ``allow`` exception (reason, expiry) of a new definition is written to it.
    """
    plan = await _compile(body.yaml) if body.yaml is not None else None
    if plan is not None and (late := _allow_problems(plan)):
        raise _invalid(late)
    why = _why(body.justification)
    changed = new_version = False
    prev: dict[str, Any] = {}
    async with pool.acquire() as con:
        async with con.transaction():
            await _lock_invariants(con)
            cur = await _invariant_row(con, invariant_id, lock=True)
            prev = {"digest": cur["digest"], "enabled": cur["enabled"], "version": cur["version"]}
            sets: list[tuple[str, Any]] = []     # (column, value) -> "col = $n"
            clears: list[str] = []               # columns reset to NULL
            raws: list[str] = []                 # constant assignments
            disabled = reenabled = False
            version = cur["version"]
            if plan is not None:
                if cur["source"] == "std":
                    raise _unprocessable("a std invariant's definition is managed by the shipped library; "
                                         "only 'enabled' can be changed", "yaml")
                if plan.id != cur["invariant_id"]:
                    raise _invalid([f"id: the definition says {plan.id!r} but this invariant is "
                                    f"{cur['invariant_id']!r} (the id cannot change)"])
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
                if body.enabled:
                    await _check_invariant_caps(con, adding_row=False, enabling=True)
                sets.append(("enabled", body.enabled))
                if body.enabled:
                    # Re-enabled: whatever verdict is stored predates this moment. Make it due. Back from disabled
                    # or archived: the lifecycle columns reset (6.1); the findings' annotation is cleared below.
                    clears += ["last_graph_version", "valid_until", "disabled_at", "disabled_by", "archived_at"]
                    reenabled = True
                else:
                    sets.append(("disabled_by", principal.actor))
                    raws.append("disabled_at = NOW()")
                    disabled = True
            if changed:
                sets.append(("updated_by", principal.actor))
                assigns = [f"{c} = ${i}" for i, (c, _) in enumerate(sets, 1)]
                assigns += [f"{c} = NULL" for c in dict.fromkeys(clears)] + raws
                await con.execute(
                    f"UPDATE invariants SET {', '.join(assigns)}, updated_at = NOW() "
                    f"WHERE id = ${len(sets) + 1}", *[v for _, v in sets], invariant_id)
                # Annotate, never close (D33): in the SAME transaction as the toggle, so no observer sees a disabled
                # invariant whose findings still look live. No status changes here.
                if disabled:
                    await housekeeping.annotate_findings(con, cur["invariant_id"], housekeeping.STATE_DISABLED)
                elif reenabled:
                    await housekeeping.clear_annotations(con, cur["invariant_id"])
        gv = await _graph_version(con)
        row = await _invariant_row(con, invariant_id)
        vis = await _vis(con, principal)
    if changed:
        details: dict[str, Any] = {"invariant_id": row["invariant_id"], "previous": prev,
                                   "digest": row["digest"], "version": row["version"],
                                   "enabled": row["enabled"], "new_version": new_version}
        if plan is not None and new_version:
            details["exceptions"] = _allow_audit(plan)
        await _audit(request, pool, principal, action="assurance_invariant_update",
                     resource_type="invariants", resource_id=str(invariant_id), justification=why,
                     details=details)
    return {"invariant": _inv_view(row, _now(), gv, vis), "changed": changed, "created": False,
            "new_version": new_version}


@router.delete("/v1/invariants/{invariant_id}", response_model=InvariantChange)
async def delete_invariant(
    invariant_id: UUID, request: Request, pool=Depends(get_pool),
    justification: Optional[str] = Query(None, max_length=1000, description="Optional: why (audited)."),
    principal: Principal = Depends(current_principal),
):
    """Archive: disable and mark deleted. The row, every ``invariant_versions`` row and the run ledger stay
    (they are evidence); the runner stops evaluating it, and its open findings stay open, annotated
    ``invariant_state: archived`` (nothing re-checks them, so nothing may close them; a person can release them with
    ``POST .../findings/release``). ``PUT {"enabled": true}`` brings it back.
    Never gated: a downgraded tenant can always switch containment checks off cleanly."""
    why = _why(justification)
    async with pool.acquire() as con:
        async with con.transaction():
            cur = await _invariant_row(con, invariant_id, lock=True)
            was_state = housekeeping.state_of(cur["enabled"], cur["archived_at"])
            changed = cur["archived_at"] is None
            if changed:
                await con.execute(
                    "UPDATE invariants SET enabled = FALSE, archived_at = NOW(), "
                    "disabled_at = COALESCE(disabled_at, NOW()), disabled_by = COALESCE(disabled_by, $2), "
                    "updated_by = $2, updated_at = NOW() WHERE id = $1", invariant_id, principal.actor)
                await housekeeping.annotate_findings(con, cur["invariant_id"], housekeeping.STATE_ARCHIVED)
        gv = await _graph_version(con)
        row = await _invariant_row(con, invariant_id)
        vis = await _vis(con, principal)
    await _audit(request, pool, principal, action="assurance_invariant_archive",
                 resource_type="invariants", resource_id=str(invariant_id), justification=why,
                 details={"invariant_id": row["invariant_id"], "digest": row["digest"],
                          "was_enabled": bool(cur["enabled"]), "was_state": was_state, "rows_kept": True})
    return {"invariant": _inv_view(row, _now(), gv, vis), "changed": changed, "created": False,
            "new_version": False}


@router.post("/v1/invariants/{invariant_id}/findings/release", response_model=ReleaseOut)
async def release_invariant_findings(
    invariant_id: UUID, body: ReleaseIn, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Give up on the open findings of an invariant that is NOT being evaluated (a human decision, admin only).

    Allowed only when nobody re-checks the invariant: it is disabled or archived, or the runner marked its findings
    ``invalid_definition`` / ``not_entitled`` (otherwise 409 ``invariant_active``: an active invariant closes its own
    findings when it holds). Sets ``wontfix`` with the reason ``invariant <state>: <justification>``, leaves
    ``fix_verified_at`` empty (this is a decision, not a verification) and writes a history row per finding and one
    audit row. A later re-enable, violation or HOLDS never reopens a ``wontfix`` (the machine does not undo a human
    decision; a person can reopen with PATCH). Never billing-gated.
    """
    actor = principal.actor
    async with pool.acquire() as con:
        async with con.transaction():
            cur = await _invariant_row(con, invariant_id, lock=True)
            vis = await _vis(con, principal)
            own = housekeeping.state_of(cur["enabled"], cur["archived_at"])     # disabled | archived | active
            flagged = (" AND f.metadata->>'invariant_state' IN ('invalid_definition', 'not_entitled')"
                       if own == "active" else "")
            if own == "active":
                # an enabled invariant: only what the runner flagged as not being re-checked may be released
                # counted as the caller sees them: a flagged finding of an asset above their clearance must not turn
                # the 409 into a 200 (that would confirm it exists)
                cnt_args: list[Any] = [cur["invariant_id"]]
                cnt_extra = _visible_findings(vis, cnt_args)
                n_flagged = await con.fetchval(
                    "SELECT count(*) FROM findings f WHERE " + _OWN_FINDINGS +
                    " AND f.status IN ('open', 'triaged')" + flagged + cnt_extra, *cnt_args)
                if not n_flagged:
                    raise HTTPException(status_code=409, detail={
                        "error": "invariant_active",
                        "message": "this invariant is active: it re-checks and closes its own findings; disable "
                                   "or delete it first to release them by hand"})
            # $4 is the state named in the reason: the invariant's own, or (enabled) the one the runner flagged
            args: list[Any] = [cur["invariant_id"], body.justification, actor, own]
            extra = _visible_findings(vis, args)
            rows = await con.fetch(
                "WITH due AS (SELECT f.id, f.status FROM findings f WHERE " + _OWN_FINDINGS +
                " AND f.status IN ('open', 'triaged')" + flagged + extra + " FOR UPDATE) "
                "UPDATE findings f SET status = 'wontfix', "
                "status_reason = 'invariant ' || CASE WHEN $4::text = 'active' THEN f.metadata->>'invariant_state' ELSE $4::text END || ': ' || $2::text, "
                "status_by = $3::text, status_changed_at = now(), accepted_until = NULL, fix_verified_at = NULL "
                "FROM due WHERE f.id = due.id RETURNING f.id, due.status AS from_status, f.status_reason",
                *args)
            for r in rows:
                await lifecycle.record_history(con, r["id"], r["from_status"], "wontfix", r["status_reason"],
                                               None, actor)
    await _audit(request, pool, principal, action="assurance_findings_release", resource_type="invariants",
                 resource_id=str(invariant_id), justification=body.justification,
                 details={"invariant_id": cur["invariant_id"], "state": own if own != "active" else "runner_flagged",
                          "released": len(rows), "finding_ids": [str(r["id"]) for r in rows[:50]]})
    return {"released": len(rows)}


@router.get("/v1/invariants/{invariant_id}/runs", response_model=RunPage)
async def list_invariant_runs(
    invariant_id: UUID,
    verdict: Optional[Literal["HOLDS", "VIOLATED", "UNKNOWN"]] = Query(None),
    include_result: bool = Query(False, description="Include the stored result (witnesses, blind spots)."),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
    pool=Depends(get_pool), principal: Principal = Depends(current_principal),
):
    """The verdict-transition ledger of one invariant, newest first. Below full clearance the
    stored results have everything naming a hidden asset replaced by ``[redacted]``."""
    async with pool.acquire() as con:
        inv = await _invariant_row(con, invariant_id)
        vis = await _vis(con, principal)
        args: list[Any] = [inv["invariant_id"]]
        clause = "WHERE invariant_id = $1"
        if verdict:
            args.append(verdict)
            clause += " AND verdict = $2"
        total = await con.fetchval(f"SELECT count(*) FROM invariant_runs {clause}", *args)
        rows = await con.fetch(
            "SELECT id, invariant_id, digest, verdict, reasons, result, graph_version, violation_count, "
            "coverage_covered, coverage_universe, evaluated_at, valid_until, compacted_at, pinned "
            f"FROM invariant_runs {clause} "
            f"ORDER BY evaluated_at DESC, id LIMIT ${len(args) + 1} OFFSET ${len(args) + 2}",
            *args, limit, offset)
    items = []
    for r in rows:
        d = dict(r)
        d["reasons"] = vis.scrub([x for x in _j(d["reasons"], []) if isinstance(x, str)])
        raw = (_j(d["result"], {}) or None) if include_result else None
        d["result"] = vis.scrub(raw)
        d["redacted"] = bool(vis.active and raw is not None and d["result"] != raw)
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
    if principal.clearance_rank < _FULL_RANK:
        # The runner's summaries can carry witnesses, blind spots and builder notes that name
        # assets above this caller's clearance.
        async with pool.acquire() as con:
            vis = await _vis(con, principal)
        out = EvaluateOut(**vis.scrub(out.model_dump()))
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

def _node_vis_sql(alias: str, vis: _Vis, where: list[str], args: list[Any]) -> None:
    """``reach_nodes`` rows the caller may see: not a hidden ref AND not backed by a hidden asset
    (an ``ip:`` node can carry the ``asset_id`` of the machine it was merged into)."""
    if vis.active and vis.refs:
        args.append(vis.refs)
        where.append(f"{alias}.node_ref <> ALL(${len(args)}::text[])")
    if vis.active and vis.ids:
        args.append(vis.ids)
        where.append(f"({alias}.asset_id IS NULL OR {alias}.asset_id::text <> ALL(${len(args)}::text[]))")


def _edge_vis_sql(vis: _Vis, where: list[str], args: list[Any]) -> None:
    """An edge touching a hidden node is hidden (it would name that node)."""
    if vis.active and vis.refs:
        args.append(vis.refs)
        n = len(args)
        where.append(f"src_ref <> ALL(${n}::text[]) AND dst_ref <> ALL(${n}::text[])")


def _w(where: list[str]) -> str:
    return ("WHERE " + " AND ".join(where)) if where else ""


@router.get("/v1/assurance/state")
async def assurance_state(pool=Depends(get_pool),
                          principal: Principal = Depends(current_principal)) -> dict[str, Any]:
    """Graph version, last build/evaluation, counts, and what the builders last did. Counts and
    notes cover only what the caller's clearance lets them see."""
    now = _now()
    async with pool.acquire() as con:
        vis = await _vis(con, principal)
        st = await store.get_state(con)
        nw: list[str] = []
        na: list[Any] = []
        _node_vis_sql("n", vis, nw, na)
        ew: list[str] = []
        ea: list[Any] = []
        _edge_vis_sql(vis, ew, ea)
        cw: list[str] = []
        ca: list[Any] = []
        _hide_sql("node_ref", vis, cw, ca)
        counts = {
            "nodes": await con.fetchval(f"SELECT count(*) FROM reach_nodes n {_w(nw)}", *na),
            "edges": await con.fetchval(f"SELECT count(*) FROM reach_edges {_w(ew)}", *ea),
            "coverage_facts": await con.fetchval(f"SELECT count(*) FROM reach_coverage {_w(cw)}", *ca),
            "zones": await con.fetchval("SELECT count(*) FROM zones"),
            "labels": await con.fetchval(f"SELECT count(*) FROM asset_labels {_w(cw)}", *ca),
        }
        edges_by_source = {r["source"]: r["n"] for r in await con.fetch(
            f"SELECT source, count(*) AS n FROM reach_edges {_w(ew)} GROUP BY source ORDER BY source", *ea)}
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
        "builders": vis.scrub(builders),
        "builders_note": "what this replica's last build did per source; other replicas keep their own",
    }


# Coverage -----------------------------------------------------------------------------------
# One SQL pass classifies every visible node per direction with the library's own rule (any
# unqualified fact of at least ``min_tier`` that is neither stale nor from the future covers the
# direction; otherwise the reason is the one closest to qualifying). Only the requested PAGE of
# nodes is then re-derived through ``direction_state`` (so the per-node text is the library's, not
# a copy), and a test pins the SQL summary to the library over the same facts. Review finding
# security-5: ``limit=1`` used to load 200k nodes / 400k facts into the event loop.

_TIER_RANK_SQL = "(CASE {c} WHEN 'declared' THEN 0 WHEN 'configured' THEN 1 WHEN 'observed' THEN 2 " \
                 "WHEN 'tested' THEN 3 ELSE -1 END)"

# $1 = min tier rank, $2 = oldest acceptable observed_at, $3 = newest acceptable (now + slack)
_DIR_CTE = """
fd AS (
  SELECT node_ref, direction,
         count(*) AS facts,
         bool_or(rk >= $1 AND observed_at >= $2 AND observed_at <= $3) AS ok,
         bool_or(rk >= $1 AND observed_at > $3) AS r_future,
         bool_or(rk >= $1 AND observed_at <= $3 AND observed_at < $2) AS r_stale,
         bool_or(rk < $1) AS r_tier
  FROM (SELECT node_ref, direction, observed_at, {rank} AS rk FROM reach_coverage
        WHERE coalesce(detail->>'origin', '') = '' AND coalesce(detail->>'proto', '') = ''
          {cov_vis}) c
  GROUP BY node_ref, direction
),
nd AS (
  SELECT n.node_ref, n.kind, n.label,
         coalesce(i.ok, FALSE) AS cin, coalesce(o.ok, FALSE) AS cout,
         CASE WHEN coalesce(i.ok, FALSE) THEN NULL WHEN i.facts IS NULL THEN 'no_sensor'
              WHEN i.r_stale THEN 'stale' WHEN i.r_future THEN 'future_timestamp'
              WHEN i.r_tier THEN 'tier_below_min' END AS rin,
         CASE WHEN coalesce(o.ok, FALSE) THEN NULL WHEN o.facts IS NULL THEN 'no_sensor'
              WHEN o.r_stale THEN 'stale' WHEN o.r_future THEN 'future_timestamp'
              WHEN o.r_tier THEN 'tier_below_min' END AS rout
  FROM reach_nodes n
  LEFT JOIN fd i ON i.node_ref = n.node_ref AND i.direction = 'in'
  LEFT JOIN fd o ON o.node_ref = n.node_ref AND o.direction = 'out'
  WHERE n.kind <> 'internet' AND n.node_ref <> 'internet' {node_vis}
)
"""

def _cov_cte(vis: _Vis, args: list[Any]) -> str:
    """The CTE text with the visibility predicates spliced in (their params appended to ``args``)."""
    cov_where: list[str] = []
    node_where: list[str] = []
    _hide_sql("node_ref", vis, cov_where, args)
    _node_vis_sql("n", vis, node_where, args)
    return _DIR_CTE.format(
        rank=_TIER_RANK_SQL.format(c="tier"),
        cov_vis=("AND " + " AND ".join(cov_where)) if cov_where else "",
        node_vis=("AND " + " AND ".join(node_where)) if node_where else "")


async def _coverage_summary(con: Any, vis: _Vis, tier_rank: int, lo: datetime, hi: datetime) -> dict[str, Any]:
    args: list[Any] = [tier_rank, lo, hi]
    cte = _cov_cte(vis, args)
    row = await con.fetchrow(
        f"WITH {cte} SELECT count(*) AS n, count(*) FILTER (WHERE cin AND cout) AS both, "
        "count(*) FILTER (WHERE cin AND NOT cout) AS in_only, "
        "count(*) FILTER (WHERE cout AND NOT cin) AS out_only FROM nd", *args)
    reasons: dict[str, dict[str, int]] = {"in": {}, "out": {}}
    for d, col in (("in", "rin"), ("out", "rout")):
        for r in await con.fetch(f"WITH {cte} SELECT {col} AS r, count(*) AS n FROM nd "
                                 f"WHERE {col} IS NOT NULL GROUP BY {col} ORDER BY {col}", *args):
            reasons[d][r["r"]] = r["n"]
    return {"n": row["n"], "both": row["both"], "in_only": row["in_only"], "out_only": row["out_only"],
            "reasons": reasons}


def _page_coverage(lib: Any, lib_graph: Any, rows: list[Any], fact_rows: list[Any], now: datetime,
                   tier: Any, max_age: timedelta) -> list[dict[str, Any]]:
    """The library's own per-node view for one page of nodes (small: <= 500)."""
    facts: dict[str, list[Any]] = {}
    for f in fact_rows:
        det = _j(f["detail"], {})
        kw: dict[str, Any] = {}
        if det.get("origin"):
            kw["origin"] = str(det["origin"])
        if det.get("proto"):
            kw["proto"] = str(det["proto"])
        try:
            facts.setdefault(f["node_ref"], []).append(lib_graph.Coverage(
                tier=lib.Tier(f["tier"]), observed_at=f["observed_at"], source=f["source"],
                direction=f["direction"], **kw))
        except (ValueError, TypeError):
            continue  # a tier or qualifier outside the vocabulary asserts nothing
    return _coverage_state(lib_graph, rows, facts, now, tier, max_age)


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
    pool=Depends(get_pool), principal: Principal = Depends(current_principal),
) -> dict[str, Any]:
    """Coverage per source and per node (directional), blind spots by reason, stale sensors.

    A node counts as covered only when it is covered inbound AND outbound by a fresh fact of at
    least ``min_tier`` (the same rule the evaluator applies). The internet node is excluded: nobody
    can instrument it, so it is never part of the universe. Qualified facts (an outside-in TCP scan
    speaks only for internet-origin TCP) never count here: the unqualified question is the one this
    report answers. Nodes backed by assets above the caller's clearance are not listed or counted.
    """
    lib = _lib()
    from paddock_assurance import graph as lib_graph  # noqa: PLC0415

    now = _now()
    max_age = timedelta(hours=max_age_h)
    tier = lib.Tier(min_tier)
    lo, hi = now - max_age, now + lib_graph.FUTURE_SLACK
    async with pool.acquire() as con:
        vis = await _vis(con, principal)
        agg = await _coverage_summary(con, vis, tier.rank, lo, hi)

        # the page of nodes (SQL does the filtering, ordering and paging)
        pargs: list[Any] = [tier.rank, lo, hi]
        cte = _cov_cte(vis, pargs)
        sel: list[str] = []
        if only_blind:
            sel.append("NOT (cin AND cout)")
        if kind is not None:
            pargs.append(kind)
            sel.append(f"kind = ${len(pargs)}")
        if q:
            pargs.append(q)
            sel.append(f"strpos(node_ref, ${len(pargs)}) > 0")
        if sel:
            total = await con.fetchval(f"WITH {cte} SELECT count(*) FROM nd {_w(sel)}", *pargs)
        else:
            total = agg["n"]
        pargs += [limit, offset]
        page = await con.fetch(
            f"WITH {cte} SELECT node_ref, kind, label FROM nd {_w(sel)} ORDER BY node_ref "
            f"LIMIT ${len(pargs) - 1} OFFSET ${len(pargs)}", *pargs)
        fact_rows = await con.fetch(
            "SELECT node_ref, direction, tier, source, observed_at, detail FROM reach_coverage "
            "WHERE node_ref = ANY($1::text[]) ORDER BY node_ref, direction, source",
            [r["node_ref"] for r in page]) if page else []
        sw: list[str] = []
        sa: list[Any] = []
        _hide_sql("node_ref", vis, sw, sa)
        by_source_rows = await con.fetch(
            "SELECT source, direction, tier, count(*) AS facts, count(DISTINCT node_ref) AS nodes, "
            "min(observed_at) AS oldest, max(observed_at) AS newest, "
            f"count(*) FILTER (WHERE observed_at >= ${len(sa) + 1} AND observed_at <= ${len(sa) + 2}) AS fresh "
            f"FROM reach_coverage {_w(sw)} GROUP BY source, direction, tier ORDER BY source, direction, tier",
            *sa, lo, hi)
        sensor_rows = await con.fetch(
            "SELECT id, name, site, online, status, last_seen_at, last_upload_at, offline_since "
            "FROM sensors WHERE status = 'active' AND (NOT online OR last_upload_at IS NULL "
            "OR last_upload_at < $1) ORDER BY name, id LIMIT 200", lo)
        inv_rows = await con.fetch(
            "SELECT invariant_id, last_result->'blind_spot_summary' AS summ FROM invariants WHERE enabled "
            "ORDER BY invariant_id")
    per_node = _page_coverage(lib, lib_graph, page, fact_rows, now, tier, max_age)
    n, both = agg["n"], agg["both"]
    summary = {
        "nodes": n, "covered": both, "covered_in_only": agg["in_only"], "covered_out_only": agg["out_only"],
        "blind": n - both, "ratio": 1.0 if n == 0 else round(both / n, 4),
        "min_tier": min_tier, "max_age_h": max_age_h, "truncated": False,
    }
    inv_spots = []
    totals: dict[str, int] = {}
    for r in inv_rows:
        summ = _j(r["summ"], {})
        if not summ:
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
        "nodes": _page(per_node, total, limit, offset),
        "blind_spots": {"nodes_by_reason": agg["reasons"], "evaluated_by_reason": totals,
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
    pool=Depends(get_pool), principal: Principal = Depends(current_principal),
) -> dict[str, Any]:
    where, args = [], []
    for col, val in (("kind", kind), ("source", source)):
        if val is not None:
            args.append(val)
            where.append(f"n.{col} = ${len(args)}")
    if q:
        args.append(f"%{q}%")
        where.append(f"(n.node_ref ILIKE ${len(args)} OR n.label ILIKE ${len(args)})")
    async with pool.acquire() as con:
        vis = await _vis(con, principal)
        _node_vis_sql("n", vis, where, args)
        clause = _w(where)
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
              "attrs": vis.scrub(_j(r["attrs"], {})), "coverage": by_node.get(r["node_ref"], [])}
             for r in rows]
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
    pool=Depends(get_pool), principal: Principal = Depends(current_principal),
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
    cols = ("id, src_ref, dst_ref, proto, port_lo, port_hi, basis, source, confidence, first_seen, last_seen"
            + (", evidence" if include_evidence else ""))
    async with pool.acquire() as con:
        vis = await _vis(con, principal)
        _edge_vis_sql(vis, where, args)
        clause = _w(where)
        total = await con.fetchval(f"SELECT count(*) FROM reach_edges {clause}", *args)
        rows = await con.fetch(
            f"SELECT {cols} FROM reach_edges {clause} ORDER BY src_ref, dst_ref, proto, port_lo, port_hi, "
            f"source, id LIMIT ${len(args) + 1} OFFSET ${len(args) + 2}", *args, limit, offset)
    items = []
    for r in rows:
        d = dict(r)
        if include_evidence:
            d["evidence"] = vis.scrub(_j(d["evidence"], {}))
        items.append(d)
    return _page(items, total, limit, offset)


# --------------------------------------------------------------------------------------------
# Zones
# --------------------------------------------------------------------------------------------

def _zone_out(z: Any, vis: _Vis = _FULL) -> dict[str, Any]:
    # A host-sized CIDR that is exactly a hidden asset's address would name that asset.
    cidrs = [c for c in z.cidrs if not vis.hidden(f"cidr:{c}")]
    return {"id": z.id, "name": z.name, "kind": z.kind, "cidrs": cidrs, "description": z.description,
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


def _need_why(justification: Optional[str]) -> str:
    """A removal that moves verdicts must say why (review finding security-7): at least 3 characters
    after trimming, else 422 (an absent parameter is FastAPI's own 422 first)."""
    try:
        why = _storable(justification or "").strip()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=[{"loc": ["query", "justification"], "type": "value_error",
                                                      "msg": f"Value error, {exc}"}]) from exc
    if len(why) < 3:
        raise HTTPException(status_code=422, detail=[{
            "loc": ["query", "justification"], "type": "value_error",
            "msg": "a justification of at least 3 characters is required to delete this"}])
    return why


@router.get("/v1/zones", response_model=ZonePage)
async def list_zones(
    limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=1_000_000),
    pool=Depends(get_pool), principal: Principal = Depends(current_principal),
):
    async with pool.acquire() as con:
        zones = await store.list_zones(con)
        vis = await _vis(con, principal)
    return _page([_zone_out(z, vis) for z in zones[offset:offset + limit]], len(zones), limit, offset)


@router.post("/v1/zones", response_model=ZoneChangeOut, status_code=201, dependencies=[_PAID])
async def create_zone(
    body: ZoneCreate, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Declare a zone. Names ``^[a-z][a-z0-9-]{0,31}$``; CIDRs are validated and canonicalised.
    At most ``MAX_ZONES`` zones and ``MAX_TOTAL_ZONE_CIDRS`` CIDRs over all zones (409)."""
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
            await _check_zone_caps(con, new_cidrs=len(body.cidrs), replacing=None)
            try:
                ch = await store.upsert_zone(con, body.name, body.cidrs, kind=body.kind,
                                             description=body.description, set_by=principal.actor,
                                             justification=body.justification)
            except ValueError as exc:
                raise _unprocessable(str(exc)) from exc
        z = next(z for z in await store.list_zones(con) if z.name == body.name)
        vis = await _vis(con, principal)
    await _audit(request, pool, principal, action="assurance_zone_create", resource_type="zones",
                 resource_id=str(z.id), justification=body.justification, status=201,
                 details={"name": z.name, "kind": z.kind, "cidrs": list(ch.cidrs),
                          "overlaps": list(ch.overlaps), "graph_version": ch.graph_version})
    return {"zone": _zone_out(z, vis), "changed": ch.changed, "created": True,
            "overlaps": list(ch.overlaps), "graph_version": ch.graph_version}


async def _check_zone_caps(con: Any, *, new_cidrs: int, replacing: Optional[str]) -> None:
    """409 when one more zone / these CIDRs would pass the per-tenant caps. ``replacing`` is the
    name of the zone being updated (its current CIDRs stop counting); ``None`` means a new zone."""
    rows = await con.fetch("SELECT name, coalesce(cardinality(cidrs), 0) AS n FROM zones")
    if replacing is None and len(rows) >= MAX_ZONES:
        raise HTTPException(status_code=409, detail={
            "error": "zone_limit", "limit": MAX_ZONES,
            "message": f"this tenant already has {len(rows)} zones (max {MAX_ZONES})"})
    others = sum(int(r["n"]) for r in rows if r["name"] != replacing)
    if others + new_cidrs > MAX_TOTAL_ZONE_CIDRS:
        raise HTTPException(status_code=409, detail={
            "error": "zone_cidr_limit", "limit": MAX_TOTAL_ZONE_CIDRS,
            "message": f"zones would hold {others + new_cidrs} CIDRs in total (max {MAX_TOTAL_ZONE_CIDRS}); "
                       "widen a prefix instead of listing hosts"})


@router.get("/v1/zones/{zone_id}", response_model=ZoneOut)
async def get_zone(zone_id: UUID, pool=Depends(get_pool),
                   principal: Principal = Depends(current_principal)):
    async with pool.acquire() as con:
        vis = await _vis(con, principal)
        return _zone_out(await _zone_by_id(con, zone_id), vis)


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
            if body.cidrs is not None:
                await _check_zone_caps(con, new_cidrs=len(body.cidrs), replacing=cur.name)
            try:
                ch = await store.upsert_zone(
                    con, cur.name, cur.cidrs if body.cidrs is None else body.cidrs,
                    kind=cur.kind if body.kind is None else body.kind,
                    description=cur.description if body.description is None else body.description,
                    set_by=principal.actor, justification=body.justification)
            except ValueError as exc:
                raise _unprocessable(str(exc)) from exc
        z = await _zone_by_id(con, zone_id)
        vis = await _vis(con, principal)
    await _audit(request, pool, principal, action="assurance_zone_update", resource_type="zones",
                 resource_id=str(zone_id), justification=body.justification,
                 details={"name": z.name, "previous_cidrs": list(cur.cidrs), "cidrs": list(ch.cidrs),
                          "kind": z.kind, "changed": ch.changed, "overlaps": list(ch.overlaps),
                          "graph_version": ch.graph_version})
    return {"zone": _zone_out(z, vis), "changed": ch.changed, "created": False,
            "overlaps": list(ch.overlaps), "graph_version": ch.graph_version}


@router.delete("/v1/zones/{zone_id}", response_model=ZoneDeleteOut)
async def delete_zone(
    zone_id: UUID, request: Request,
    justification: str = Query(..., max_length=1000,
                               description="Why the zone is removed (>= 3 characters; audited)."),
    pool=Depends(get_pool), principal: Principal = Depends(current_principal),
):
    """Delete a zone (bumps the graph version). Nodes in it lose the zone; invariants that select it
    then select nothing and answer UNKNOWN, never HOLDS. A justification is REQUIRED: removing the
    zone that defines a boundary changes verdicts. Never billing-gated (clean-up)."""
    why = _need_why(justification)
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
    pool=Depends(get_pool), principal: Principal = Depends(current_principal),
):
    """Labels with their provenance (who set them, why, when). Labels on nodes above the caller's
    clearance are not listed."""
    where, args = [], []
    for col, val in (("node_ref", node_ref), ("tag", tag), ("source", source)):
        if val is not None:
            args.append(val)
            where.append(f"{col} = ${len(args)}")
    async with pool.acquire() as con:
        vis = await _vis(con, principal)
        _hide_sql("node_ref", vis, where, args)
        clause = _w(where)
        total = await con.fetchval(f"SELECT count(*) FROM asset_labels {clause}", *args)
        rows = await con.fetch(
            f"SELECT {_LABEL_COLS} FROM asset_labels {clause} ORDER BY node_ref, tag "
            f"LIMIT ${len(args) + 1} OFFSET ${len(args) + 2}", *args, limit, offset)
    return _page([vis.scrub(dict(r)) if vis.active else dict(r) for r in rows], total, limit, offset)


@router.put("/v1/labels", response_model=LabelChangeOut, dependencies=[_PAID])
async def set_label(
    body: LabelSet, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Declare a label (zone, class, crown-jewel, app-tier, ...) with a mandatory justification.
    Changing one changes verdicts, so it bumps the graph version and is audited. At most
    ``MAX_LABELS`` declared labels per tenant (409)."""
    warnings: list[str] = []
    try:
        node_ref, tag, value = store.validate_label(body.node_ref, body.tag, body.value)
    except ValueError as exc:
        raise _unprocessable(str(exc)) from exc
    if tag == "zone" and value in store.RESERVED_ZONES:
        raise _unprocessable(f"zone {value!r} is reserved for the internet node", "value")
    async with pool.acquire() as con:
        vis = await _vis(con, principal)
        # A node above the caller's clearance answers exactly like a missing one: a principal that
        # cannot see an asset must not be able to relabel it (e.g. strip its crown-jewel tag).
        if vis.hidden(node_ref):
            raise _unprocessable("no such asset in this tenant", "node_ref")
        if node_ref.startswith("asset:"):
            where, args = ["id = $1"], [UUID(node_ref[6:])]
            if vis.active:
                args.append(principal.clearance_rank)
                where.append(f"{classification_rank_sql('classification')} <= $2")
            if not await con.fetchval(f"SELECT 1 FROM assets {_w(where)}", *args):
                raise _unprocessable("no such asset in this tenant", "node_ref")
        if tag == "zone" and not await con.fetchval("SELECT 1 FROM zones WHERE name = $1", value):
            warnings.append(f"zone {value!r} is not declared; the label still places the node in it")
        async with con.transaction():
            await con.execute("SELECT pg_advisory_xact_lock(hashtextextended("
                              "coalesce(current_setting('app.tenant_id', true), '') || ':labels', 0))")
            exists = await con.fetchval("SELECT 1 FROM asset_labels WHERE node_ref = $1 AND tag = $2",
                                        node_ref, tag)
            if not exists:
                n = await con.fetchval("SELECT count(*) FROM asset_labels WHERE source = 'declared'")
                if n >= MAX_LABELS:
                    raise HTTPException(status_code=409, detail={
                        "error": "label_limit", "limit": MAX_LABELS,
                        "message": f"this tenant already has {n} declared labels (max {MAX_LABELS})"})
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
    justification: str = Query(..., max_length=1000,
                               description="Why the label is removed (>= 3 characters; audited)."),
    pool=Depends(get_pool), principal: Principal = Depends(current_principal),
):
    """Remove a label (bumps the graph version). A justification is REQUIRED: dropping an
    ``app-tier``/``crown-jewel``/``zone`` label changes verdicts. Never billing-gated (clean-up)."""
    why = _need_why(justification)
    async with pool.acquire() as con:
        vis = await _vis(con, principal)
        row = await con.fetchrow("SELECT node_ref, tag FROM asset_labels WHERE id = $1", label_id)
        if row is None or vis.hidden(row["node_ref"]):
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


# --------------------------------------------------------------------------------------------
# Sensor scopes (schema 040): which networks a Sentry sensor can actually see
# --------------------------------------------------------------------------------------------
# WHY: a sensor that saw ONE flow to a host does not see all of that host's traffic. Coverage
# ("no such traffic was seen") may therefore be asserted only for addresses inside a network its
# operator declared here, and a sensor with no declared scope covers nothing. The sentry_flows
# builder reads this table directly; this API only edits it.

_SCOPE_COLS = "sensor_id, cidrs, set_by, justification, set_at"

#: a strict dotted quad (0-255 per octet, no leading zeros): the flow table stores whatever a sensor sent as text, and
#: the ``::inet`` cast of anything else would fail the whole query.
_V4_RE = (r"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$")

#: Per sensor, the busiest /24s it saw as a flow endpoint. NB the network is ``network(set_masklen(ip, 24))``: the
#: contract's sketch used ``host(...) || '/24'``, which yields a HOST address with mask bits ('10.20.0.5/24').
_OBSERVED_SQL = f"""
WITH ends AS (
  SELECT id, sensor_id, src_ip AS ip, last_seen FROM reach_flow_obs
   WHERE sensor_id = ANY($2::uuid[]) AND last_seen >= $1 AND src_ip ~ '{_V4_RE}'
  UNION ALL
  SELECT id, sensor_id, dst_ip AS ip, last_seen FROM reach_flow_obs
   WHERE sensor_id = ANY($2::uuid[]) AND last_seen >= $1 AND dst_ip ~ '{_V4_RE}'
), grouped AS (
  SELECT sensor_id, network(set_masklen(ip::inet, 24))::text AS prefix,
         count(DISTINCT id) AS flows, max(last_seen) AS last_seen
    FROM ends GROUP BY 1, 2
), ranked AS (
  SELECT g.*, row_number() OVER (PARTITION BY sensor_id ORDER BY flows DESC, prefix) AS rn FROM grouped g
)
SELECT sensor_id, prefix, flows, last_seen FROM ranked WHERE rn <= $3 ORDER BY sensor_id, rn
"""


_V4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
#: the networks an operator can sensibly declare as "what this sensor sees": RFC 1918 and shared address space (CGNAT).
_LAN_NETS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))


def _effective_net(net: Any) -> Any:
    """The network the sentry_flows builder reads for ``net``: a v4-mapped IPv6 network (``::ffff:a.b.c.d/N``) is the
    IPv4 network ``a.b.c.d/(N-96)``. The wide-scope guard and the advisories must judge THAT, or ``::ffff:10.0.0.0/104``
    declares a /8 under a /104 name."""
    if net.version == 6 and net.subnet_of(_V4_MAPPED):
        return ipaddress.ip_network((net.network_address.ipv4_mapped, net.prefixlen - 96), strict=False)
    return net


def _is_lan(net: Any) -> bool:
    """A network worth suggesting or flagging: private or shared address space. Public prefixes (every sensor sees the
    internet's endpoints) and special-use ones (0.0.0.0/8, 127/8, link-local, multicast, reserved, broadcast) are not."""
    return net.version == 4 and any(net.subnet_of(n) for n in _LAN_NETS)


def _wide_cidrs(cidrs: list[str]) -> list[str]:
    """The entries shorter than /16 (IPv4) or /48 (IPv6), in the given order. A v4-mapped IPv6 entry counts as the
    IPv4 network it means (see ``_effective_net``)."""
    out = []
    for c in cidrs:
        net = _effective_net(ipaddress.ip_network(c, strict=False))
        if net.prefixlen < (WIDE_V4_PREFIX if net.version == 4 else WIDE_V6_PREFIX):
            out.append(c)
    return out


def _clamp16(nets: list[Any]) -> list[Any]:
    """No network shorter than /16: a collapsed run of /24s may have become a /15; split it back into /16s."""
    out: list[Any] = []
    for n in nets:
        out.extend(n.subnets(new_prefix=16) if n.prefixlen < 16 else [n])
    return out


def _suggest(private: list[dict[str, Any]], notes: list[str]) -> list[str]:
    """The observed private /24s merged to at most ``SUGGEST_MAX`` supernets, none shorter than /16.

    Exact first (adjacent /24s collapse losslessly); if that is still too many, widen to /22, /20, /18, /16 until it
    fits; if even the /16s are too many, the busiest ones, and the note says so. Deterministic."""
    nets = [(ipaddress.ip_network(p["prefix"]), int(p["flows"])) for p in private]
    if not nets:
        return []
    exact = _clamp16(list(ipaddress.collapse_addresses(n for n, _ in nets)))
    if len(exact) <= SUGGEST_MAX:
        return [str(n) for n in sorted(exact)]
    for plen in (22, 20, 18, 16):
        grouped = sorted({n.supernet(new_prefix=plen) for n, _ in nets})
        if len(grouped) <= SUGGEST_MAX:
            return [str(n) for n in grouped]
    weight: dict[Any, int] = {}
    for n, flows in nets:
        sup = n.supernet(new_prefix=16)
        weight[sup] = weight.get(sup, 0) + flows
    top = sorted(weight, key=lambda k: (-weight[k], k))[:SUGGEST_MAX]
    notes.append(f"the sensor saw {len(weight)} distinct /16 networks: only the {SUGGEST_MAX} busiest are suggested")
    return [str(n) for n in sorted(top)]


def scope_advisories(declared: list[str], seen: list[dict[str, Any]], *, capped: bool) -> dict[str, Any]:
    """Evidence-based advisories for one sensor (pure). ``seen``: its /24 prefixes (``prefix``, ``flows``,
    ``last_seen``, ``private``), any order. ``capped``: the scan hit ``OBSERVED_SCAN`` so the list is not complete.

    * ``declared_but_unobserved``: declared IPv4 CIDRs overlapping no observed /24 (not judged when the scan was capped:
      an absent prefix proves nothing then; IPv6 is not judged at all, only IPv4 flows are read);
    * ``observed_outside_scope``: private /24s overlapping no declared CIDR (public ones are every sensor's);
    * ``suggested_cidrs``: see ``_suggest``.
    Nothing here changes a scope: it is evidence for the operator, never an enforced equality (D37)."""
    ordered = sorted(seen, key=lambda p: (-int(p["flows"]), p["prefix"]))
    notes: list[str] = []
    obs_nets = [(ipaddress.ip_network(p["prefix"]), p) for p in ordered]
    declared_nets = [_effective_net(ipaddress.ip_network(c, strict=False)) for c in declared]
    v4_declared = [n for n in declared_nets if n.version == 4]
    if any(n.version == 6 for n in declared_nets):
        notes.append("IPv6 scopes are not compared with observations (only IPv4 flows are read)")
    unobserved: list[str] = []
    if capped:
        notes.append("too many distinct prefixes were seen to compare with the declared scope; "
                     "declared_but_unobserved is not judged")
    else:
        unobserved = [str(n) for n in v4_declared if not any(n.overlaps(o) for o, _ in obs_nets)]
    private = [p for o, p in obs_nets if p.get("private", True)]
    outside = sorted((o for o, p in obs_nets if p.get("private", True)
                      and declared_nets and not any(o.overlaps(d) for d in v4_declared)))
    return {
        "observed": {"prefixes": [dict(p) for p in ordered[:OBSERVED_SHOWN]],
                     "truncated": bool(capped or len(ordered) > OBSERVED_SHOWN),
                     "window_days": SCOPE_WINDOW_DAYS},
        "declared_but_unobserved": unobserved,
        "observed_outside_scope": [str(n) for n in outside],
        "suggested_cidrs": _suggest(private, notes),
        "notes": notes,
    }


async def _observed(con: Any, sensor_ids: list[Any], since: datetime) -> dict[Any, tuple[list[dict[str, Any]], bool]]:
    """``{sensor id: (prefixes, capped)}`` for the sensors named (their own flows only, never pooled)."""
    out: dict[Any, tuple[list[dict[str, Any]], bool]] = {sid: ([], False) for sid in sensor_ids}
    if not sensor_ids:
        return out
    rows = await con.fetch(_OBSERVED_SQL, since, list(sensor_ids), OBSERVED_SCAN + 1)
    by: dict[Any, list[dict[str, Any]]] = {}
    for r in rows:
        net = ipaddress.ip_network(r["prefix"])
        by.setdefault(r["sensor_id"], []).append(
            {"prefix": str(net), "flows": int(r["flows"]), "last_seen": r["last_seen"], "private": _is_lan(net)})
    for sid, lst in by.items():
        capped = len(lst) > OBSERVED_SCAN
        out[sid] = (lst[:OBSERVED_SCAN], capped)
    return out


def _scope_out(sensor_id: Any, scope: Optional[Any], sensor: Optional[Any],
               advisory: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    out = {
        "sensor_id": sensor_id,
        "name": sensor["name"] if sensor else None, "site": sensor["site"] if sensor else None,
        "status": sensor["status"] if sensor else None, "online": sensor["online"] if sensor else None,
        "cidrs": list(scope["cidrs"] or ()) if scope else [], "scope_declared": scope is not None,
        "set_by": scope["set_by"] if scope else None,
        "justification": (scope["justification"] or "") if scope else "",
        "set_at": scope["set_at"] if scope else None,
    }
    if advisory is not None:
        out.update(observed=advisory["observed"], declared_but_unobserved=advisory["declared_but_unobserved"],
                   observed_outside_scope=advisory["observed_outside_scope"],
                   suggested_cidrs=advisory["suggested_cidrs"], advisory_notes=advisory["notes"])
    return out


def _sensor_cidrs(cidrs: list[str]) -> list[str]:
    """Canonical, de-duplicated, capped; ``/0`` is refused (a sensor never sees "everything")."""
    try:
        out = list(store.validate_zone_cidrs(cidrs))
    except ValueError as exc:
        raise _unprocessable(str(exc), "cidrs") from exc
    if len(out) > MAX_SENSOR_CIDRS:
        raise _unprocessable(f"too many CIDRs (max {MAX_SENSOR_CIDRS})", "cidrs")
    return out


def _since() -> datetime:
    return _now() - timedelta(days=SCOPE_WINDOW_DAYS)


@router.get("/v1/assurance/sensor-scopes", response_model=SensorScopeList)
async def list_sensor_scopes(pool=Depends(get_pool)):
    """Declared sensor scopes, plus the active sensors that have none (they cover nothing).

    Every item also says what that sensor actually saw in the last 7 days (observed /24 prefixes, declared CIDRs it saw
    nothing in, private prefixes outside the declared scope, a suggested scope). The declared scope stays an
    accountability record (who declared what and why), not an equality check: a sensor cannot prove what it does not
    see, and observed coverage proves "no such traffic was seen", never "impossible"."""
    since = _since()
    async with pool.acquire() as con:
        scopes = await con.fetch(f"SELECT {_SCOPE_COLS} FROM sensor_scopes ORDER BY set_at, sensor_id LIMIT 1000")
        sensors = {r["id"]: r for r in await con.fetch(
            "SELECT id, name, site, status, online FROM sensors ORDER BY name, id LIMIT 5000")}
        have = {r["sensor_id"] for r in scopes}
        unscoped_rows = [(sid, r) for sid, r in sensors.items() if sid not in have and r["status"] == "active"][:200]
        seen = await _observed(con, [*have, *(sid for sid, _ in unscoped_rows)], since)

    def adv(sid: Any, cidrs: list[str]) -> dict[str, Any]:
        lst, capped = seen.get(sid, ([], False))
        return scope_advisories(cidrs, lst, capped=capped)

    items = [_scope_out(r["sensor_id"], r, sensors.get(r["sensor_id"]), adv(r["sensor_id"], list(r["cidrs"] or ())))
             for r in scopes]
    unscoped = [_scope_out(sid, None, r, adv(sid, [])) for sid, r in unscoped_rows]
    return {"items": items, "unscoped_sensors": unscoped, "total": len(items)}


@router.put("/v1/assurance/sensor-scopes/{sensor_uuid}", response_model=SensorScopeChange,
            dependencies=[_PAID])
async def put_sensor_scope(
    sensor_uuid: UUID, body: SensorScopeIn, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Declare (replace) the networks a sensor can see. Admin only; justification required.

    A prefix shorter than /16 (IPv4) or /48 (IPv6) is refused with 422 ``scope_too_wide`` unless ``allow_wide`` is set
    AND the justification has at least 20 characters (a /8 declared silently would assert "no such traffic seen" for a
    whole campus); the audit row records it. The response's ``warnings`` list a declared CIDR this sensor saw no flows
    in and a scope on a sensor that is offline or revoked.

    Changing the CIDR set bumps the graph version and marks the builders due at once, so coverage
    that this change withdraws is withdrawn on the next tick, not after the rebuild interval."""
    cidrs = _sensor_cidrs(body.cidrs)
    wide = _wide_cidrs(cidrs)
    if wide and not (body.allow_wide and len(body.justification) >= WIDE_JUSTIFICATION_MIN):
        raise HTTPException(status_code=422, detail={
            "error": "scope_too_wide", "cidrs": wide[:10],
            "message": f"{', '.join(wide[:3])}: shorter than /{WIDE_V4_PREFIX} (IPv4) or /{WIDE_V6_PREFIX} (IPv6); "
                       f"set allow_wide and give a justification of {WIDE_JUSTIFICATION_MIN}+ characters"})
    since = _since()
    async with pool.acquire() as con:
        async with con.transaction():
            sensor = await con.fetchrow("SELECT id, name, site, status, online FROM sensors WHERE id = $1",
                                        sensor_uuid)
            if sensor is None:
                raise _not_found("sensor")
            await con.execute("SELECT pg_advisory_xact_lock(hashtextextended("
                              "coalesce(current_setting('app.tenant_id', true), '') || ':sensor_scopes', 0))")
            prev = await con.fetchrow("SELECT cidrs FROM sensor_scopes WHERE sensor_id = $1 FOR UPDATE",
                                      sensor_uuid)
            await con.execute(
                "INSERT INTO sensor_scopes (sensor_id, cidrs, set_by, justification, set_at) "
                "VALUES ($1, $2::text[], $3, $4, NOW()) "
                "ON CONFLICT (tenant_id, sensor_id) DO UPDATE SET cidrs = EXCLUDED.cidrs, "
                "set_by = EXCLUDED.set_by, justification = EXCLUDED.justification, set_at = EXCLUDED.set_at",
                sensor_uuid, cidrs, principal.actor, body.justification)
            before = sorted(prev["cidrs"] or ()) if prev else None
            changed = before != sorted(cidrs)
            version = None
            if changed:
                version = await store.bump_graph_version(con)
                await _rebuild_soon(con)
        row = await con.fetchrow(f"SELECT {_SCOPE_COLS} FROM sensor_scopes WHERE sensor_id = $1", sensor_uuid)
        seen, capped = (await _observed(con, [sensor_uuid], since))[sensor_uuid]
    warnings = _scope_warnings(cidrs, sensor, seen, capped)
    await _audit(request, pool, principal, action="assurance_sensor_scope_set",
                 resource_type="sensor_scopes", resource_id=str(sensor_uuid),
                 justification=body.justification,
                 details={"sensor": sensor["name"], "previous_cidrs": before, "cidrs": cidrs,
                          "changed": changed, "graph_version": version,
                          "allow_wide": bool(body.allow_wide), "wide_cidrs": wide})
    return {"scope": _scope_out(sensor_uuid, row, sensor), "changed": changed,
            "previous": before, "graph_version": version, "warnings": warnings}


def _scope_warnings(cidrs: list[str], sensor: Any, seen: list[dict[str, Any]], capped: bool) -> list[str]:
    out: list[str] = []
    adv = scope_advisories(cidrs, seen, capped=capped)
    for c in adv["declared_but_unobserved"]:
        out.append(f"{c}: this sensor saw no flows in it in the last {SCOPE_WINDOW_DAYS} days "
                   "(declare only what the sensor can see)")
    if sensor["status"] != "active":
        out.append(f"the sensor is {sensor['status']}: a revoked sensor covers nothing")
    elif not sensor["online"]:
        out.append("the sensor is offline: it covers nothing while it is offline")
    return out


@router.delete("/v1/assurance/sensor-scopes/{sensor_uuid}", response_model=SensorScopeDeleteOut)
async def delete_sensor_scope(
    sensor_uuid: UUID, request: Request,
    justification: str = Query(..., max_length=1000,
                               description="Why the scope is removed (>= 3 characters; audited)."),
    pool=Depends(get_pool), principal: Principal = Depends(current_principal),
):
    """Remove a sensor's declared scope: it then covers nothing. A justification is REQUIRED.
    Never billing-gated (withdrawing coverage is always allowed)."""
    why = _need_why(justification)
    async with pool.acquire() as con:
        async with con.transaction():
            row = await con.fetchrow("DELETE FROM sensor_scopes WHERE sensor_id = $1 RETURNING cidrs",
                                     sensor_uuid)
            if row is None:
                raise _not_found("sensor scope")
            version = await store.bump_graph_version(con)
            await _rebuild_soon(con)
    prev = list(row["cidrs"] or ())
    await _audit(request, pool, principal, action="assurance_sensor_scope_delete",
                 resource_type="sensor_scopes", resource_id=str(sensor_uuid), justification=why,
                 details={"previous_cidrs": prev, "graph_version": version})
    return {"deleted": True, "sensor_id": sensor_uuid, "previous": prev, "graph_version": version}


async def _rebuild_soon(con: Any) -> None:
    """Make the next runner tick rebuild the graph (a never-built tenant is always due)."""
    await con.execute("UPDATE assurance_state SET last_build_at = NULL")
