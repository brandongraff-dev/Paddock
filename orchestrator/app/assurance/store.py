"""Persist a BuildOutput; maintain graph_version, labels, zones and the evaluation lease.

Owned by the store work package (docs/ASSURANCE_P1.md section 5).

Tenancy: nothing here names ``tenant_id``. The connection comes from a pool whose ``setup``
hook stamped ``app.tenant_id`` (``tenancy.tenant_context(tid)`` BEFORE ``pool.acquire()``), RLS
scopes every statement, and ``ON CONFLICT`` targets include ``tenant_id`` (the column default
reads the same GUC).

Soundness stance (a false HOLDS is the worst bug): the graph version must move whenever the
*meaning* of the graph moves (edge set, coverage facts, node set/kind, zones, labels) and must
NOT move on a pure ``last_seen`` / ``observed_at`` refresh, or the runner would re-evaluate
forever. Rows that cannot be stored are skipped and counted, never silently: a non-zero
``BuildReport.skipped`` means the stored graph may under-approximate what the builder saw, and
the caller should treat the build as degraded.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Sequence

from .refs import INTERNET, KINDS, RefError, cidr_ref, is_valid_ref, is_valid_tag, parse_ref
from .types import BuildOutput, FactOut

logger = logging.getLogger(__name__)

PROTOS = ("icmp", "tcp", "udp", "any")
BASES = ("declared", "configured", "observed", "tested")
_BASIS_RANK = {b: i for i, b in enumerate(BASES)}
DIRECTIONS = ("in", "out")

#: Unreferenced nodes are only pruned once nothing has emitted them for this long, so two
#: builders that emit the same node cannot make it flap in and out between their runs.
NODE_GRACE = dt.timedelta(hours=1)
#: Future timestamps beyond this slack are not trusted (the library ignores them as well).
CLOCK_SLACK = dt.timedelta(minutes=5)

_CHUNK = 2000
_MAX_EVIDENCE_BYTES = 16 * 1024
_MAX_LABEL_VALUE = 128
_MAX_PROVENANCE = 1000
_MAX_ZONE_CIDRS = 256
ZONE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_ZONE_KIND_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
#: 'internet' is the fixed zone of the internet node; tenants may not declare it.
RESERVED_ZONES = frozenset({"internet"})

# Host facts (docs/ASSURANCE_P2.md section 5 / 7.2). The caps mirror the library's
# (``paddock_assurance.hostfacts``) so a row this module stores is one the library can parse.
FACT_COLLECTOR_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
FACT_STATUSES = ("ok", "error", "unavailable")
FACT_CONFS = ("exact", "approximate")
MAX_FACT_COLLECTORS = 16          # collectors per node
MAX_FACT_LIST = 5000              # entries in any list/object inside a fact
MAX_FACT_ELEMENTS = 100_000       # values inside one collector entry's data
MAX_FACT_TOTAL_ELEMENTS = 4_000_000   # across the whole graph document
MAX_FACT_DEPTH = 12
MAX_FACT_STRING = 2048
MAX_FACT_REF = 256                # key_id / evidence_ref
MAX_FACT_ROW_BYTES = 256 * 1024   # one (node, source) row, serialised
#: Entry keys that are timestamps or pure provenance. They are NOT part of the fact digest: a
#: re-signed posture with the same content (a new ``seq``, a new ``observed_at``) is a refresh, not
#: a change, and must not bump the graph version (the runner would re-evaluate every hour).
FACT_DIGEST_SKIP = frozenset({"observed_at", "seq", "evidence_ref"})
#: The same provenance, repeated INSIDE the builder's ``host_agent`` summary (``data``): the posture's sequence number,
#: its payload digest and its collection time change with every re-signed posture and say nothing about the host
#: (review finding hostfw-6: they bumped the graph version at least hourly per agent).
HOST_AGENT_DATA_DIGEST_SKIP = frozenset({"seq", "payload_sha256", "collected_at"})
_FACT_KEYS = frozenset({"status", "signed", "key_id", "seq", "evidence_ref", "conf", "partial", "reason",
                        "conflict", "tier", "observed_at", "data"})

# Generic kinds never overwrite a more specific one (two builders emit the same node; a
# kind that ping-ponged would bump graph_version on every build).
_KIND_RANK = {"cloud_instance": 3, "cloud_db": 3, "cloud_lb": 3, "device": 3,
              "host": 2, "internet": 2, "ip": 1, "cidr": 1}
_KIND_RANK_SQL = ("(CASE {c} WHEN 'cloud_instance' THEN 3 WHEN 'cloud_db' THEN 3 "
                  "WHEN 'cloud_lb' THEN 3 WHEN 'device' THEN 3 WHEN 'host' THEN 2 "
                  "WHEN 'internet' THEN 2 ELSE 1 END)")


# --------------------------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------------------------

@dataclass
class BuildReport:
    """What one ``persist_build`` did. ``changed`` is what drives the graph version."""
    changed: bool = False
    edges_added: int = 0
    edges_removed: int = 0
    coverage_changed: int = 0        # coverage facts (node, direction) added/removed/tier-changed
    nodes_upserted: int = 0
    skipped: int = 0                 # invalid rows dropped (see notes); >0 => possibly degraded
    nodes_removed: int = 0           # unreferenced, long-unemitted nodes pruned
    nodes_added: int = 0             # new nodes or kind changes (they change the node universe)
    facts_changed: int = 0           # fact rows added/removed/changed, timestamps and seq excluded
    facts_stored: int = 0            # fact rows this source has after the build
    facts_digest: str = ""           # digest of this source's facts minus timestamps (diagnostics)
    graph_version: Optional[int] = None   # the version after this build
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AssuranceState:
    graph_version: int = 0
    last_build_at: Optional[dt.datetime] = None
    last_eval_at: Optional[dt.datetime] = None
    last_eval_version: int = -1
    lease_until: Optional[dt.datetime] = None
    lease_owner: Optional[str] = None
    #: sha256 of the graph document the last COMPLETE evaluation ran on (graph_loader.doc_sha).
    #: ``None`` = never recorded (a tenant evaluated before migration 040): treated as changed.
    last_eval_doc_sha: Optional[str] = None


@dataclass(frozen=True)
class LabelChange:
    changed: bool                    # the VALUE changed (or the row is new): verdicts may move
    previous: Optional[str]          # previous value, None if there was no row
    graph_version: Optional[int]     # new version when bumped


@dataclass(frozen=True)
class Zone:
    id: str
    name: str
    kind: str
    cidrs: tuple[str, ...]
    description: str = ""
    source: str = "declared"
    created_by: Optional[str] = None
    created_at: Optional[dt.datetime] = None
    updated_at: Optional[dt.datetime] = None


@dataclass(frozen=True)
class ZoneChange:
    changed: bool
    created: bool
    cidrs: tuple[str, ...]
    overlaps: tuple[str, ...] = ()   # other zones sharing address space (resolved most-specific)
    graph_version: Optional[int] = None


# --------------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------------

def _aware(t: dt.datetime, what: str = "now") -> dt.datetime:
    if not isinstance(t, dt.datetime) or t.tzinfo is None:
        raise ValueError(f"{what} must be a timezone-aware datetime")
    return t.astimezone(dt.timezone.utc)


def _json(value: Any) -> Optional[str]:
    """Compact deterministic JSON text, or None when the value cannot be serialised."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return None


def _chunks(seq: Sequence[Any], n: int = _CHUNK) -> Iterable[Sequence[Any]]:
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _require_provenance(set_by: str, justification: str) -> tuple[str, str]:
    by, why = (set_by or "").strip(), (justification or "").strip()
    if not by:
        raise ValueError("set_by is required")
    if not why:
        raise ValueError("a justification is required")
    return by[:200], why[:_MAX_PROVENANCE]


# --------------------------------------------------------------------------------------------
# Graph state: version + evaluation lease
# --------------------------------------------------------------------------------------------

def _state(row: Any) -> AssuranceState:
    return AssuranceState(
        graph_version=int(row["graph_version"]),
        last_build_at=row["last_build_at"], last_eval_at=row["last_eval_at"],
        last_eval_version=int(row["last_eval_version"]),
        lease_until=row["lease_until"], lease_owner=row["lease_owner"],
        last_eval_doc_sha=row["last_eval_doc_sha"])


_STATE_COLS = ("graph_version, last_build_at, last_eval_at, last_eval_version, lease_until, lease_owner, "
               "last_eval_doc_sha")


async def get_state(conn) -> AssuranceState:
    """The tenant's state; a never-built tenant reads as version 0 / never evaluated (no write)."""
    row = await conn.fetchrow(f"SELECT {_STATE_COLS} FROM assurance_state")
    return _state(row) if row else AssuranceState()


async def bump_graph_version(conn) -> int:
    """Atomically increment the tenant's graph version (creating the row) and return it."""
    return int(await conn.fetchval(
        "INSERT INTO assurance_state (graph_version) VALUES (1) "
        "ON CONFLICT (tenant_id) DO UPDATE SET graph_version = assurance_state.graph_version + 1 "
        "RETURNING graph_version"))


async def touch_build(conn, now: dt.datetime) -> None:
    """Record that a full builder pass finished at ``now`` (no version change)."""
    await conn.execute(
        "INSERT INTO assurance_state (last_build_at) VALUES ($1) "
        "ON CONFLICT (tenant_id) DO UPDATE SET last_build_at = EXCLUDED.last_build_at",
        _aware(now))


async def claim_eval(conn, owner: str, now: Optional[dt.datetime] = None,
                     lease_s: int = 300) -> Optional[AssuranceState]:
    """Try to take the tenant's evaluation lease; ``None`` if another owner holds a live one.

    One statement, so of N concurrent claimers exactly one wins: the loser's ON CONFLICT
    re-checks the WHERE against the committed row and returns nothing. The returned state is
    the snapshot the winner must evaluate (``graph_version`` at claim time).

    ``now=None`` (what the runner passes) uses the DATABASE clock: a lease is a contract between
    replicas, and comparing it against each replica's own clock lets one whose clock runs ahead
    steal a live lease (and then both write verdicts). An explicit ``now`` is for tests.
    """
    if not owner:
        raise ValueError("owner is required")
    secs = max(1, int(lease_s))
    if now is None:
        row = await conn.fetchrow(
            "INSERT INTO assurance_state (lease_until, lease_owner) "
            "VALUES (now() + make_interval(secs => $1::int), $2) "
            "ON CONFLICT (tenant_id) DO UPDATE "
            "SET lease_until = EXCLUDED.lease_until, lease_owner = EXCLUDED.lease_owner "
            "WHERE assurance_state.lease_until IS NULL OR assurance_state.lease_until < now() "
            f"RETURNING {_STATE_COLS}",
            secs, owner)
        return _state(row) if row else None
    now = _aware(now)
    until = now + dt.timedelta(seconds=secs)
    row = await conn.fetchrow(
        "INSERT INTO assurance_state (lease_until, lease_owner) VALUES ($1, $2) "
        "ON CONFLICT (tenant_id) DO UPDATE "
        "SET lease_until = EXCLUDED.lease_until, lease_owner = EXCLUDED.lease_owner "
        "WHERE assurance_state.lease_until IS NULL OR assurance_state.lease_until < $3 "
        f"RETURNING {_STATE_COLS}",
        until, owner, now)
    return _state(row) if row else None


async def extend_eval(conn, owner: str, now: Optional[dt.datetime] = None, lease_s: int = 300) -> bool:
    """Extend a lease this ``owner`` still holds (long evaluations). False if it was lost.
    ``now=None`` = database clock (see ``claim_eval``)."""
    secs = max(1, int(lease_s))
    if now is None:
        res = await conn.execute(
            "UPDATE assurance_state SET lease_until = now() + make_interval(secs => $1::int) "
            "WHERE lease_owner = $2 AND lease_until >= now()", secs, owner)
        return res.endswith(" 1")
    now = _aware(now)
    res = await conn.execute(
        "UPDATE assurance_state SET lease_until = $1 WHERE lease_owner = $2 AND lease_until >= $3",
        now + dt.timedelta(seconds=secs), owner, now)
    return res.endswith(" 1")


async def fence_lease(conn, owner: str) -> Optional[int]:
    """Prove, INSIDE the caller's transaction, that ``owner`` still holds a live lease.

    Returns the tenant's current ``graph_version`` if so (the caller may compare it with the
    version it evaluated), else ``None``: someone else owns the lease, or ours expired (judged by
    the database clock). The state row is read ``FOR SHARE`` so a competing ``claim_eval`` (an
    UPDATE of that row) has to wait until the caller's transaction ends: a verdict or a finding
    status written after this call, in this transaction, cannot be a stale evaluator's.

    This is the write-side fence for "lease expired while we were evaluating, a newer evaluator
    recorded a VIOLATED, then we woke up and wrote HOLDS over it and closed its finding".
    """
    if not owner:
        return None
    row = await conn.fetchrow(
        "SELECT graph_version FROM assurance_state "
        "WHERE lease_owner = $1 AND lease_until IS NOT NULL AND lease_until > now() FOR SHARE", owner)
    return int(row["graph_version"]) if row else None


async def release_eval(conn, owner: str, now: dt.datetime, *,
                       evaluated_version: Optional[int] = None, doc_sha: Optional[str] = None) -> bool:
    """Release the lease ``owner`` holds. With ``evaluated_version`` also record the watermark
    (``last_eval_at``/``last_eval_version``, and ``last_eval_doc_sha`` when given); without it (a
    failed run) the watermark is left so the next tick retries. Returns False when the lease was
    no longer ours (expired and taken)."""
    now = _aware(now)
    if evaluated_version is None:
        res = await conn.execute(
            "UPDATE assurance_state SET lease_until = NULL, lease_owner = NULL "
            "WHERE lease_owner = $1", owner)
    else:
        res = await conn.execute(
            "UPDATE assurance_state SET lease_until = NULL, lease_owner = NULL, "
            "last_eval_at = $2, last_eval_version = $3, last_eval_doc_sha = $4 WHERE lease_owner = $1",
            owner, now, int(evaluated_version), doc_sha)
    return res.endswith(" 1")


# --------------------------------------------------------------------------------------------
# persist_build
# --------------------------------------------------------------------------------------------

def _clean_nodes(out: BuildOutput, rep: BuildReport) -> dict[str, dict[str, Any]]:
    nodes: dict[str, dict[str, Any]] = {}
    for n in out.nodes:
        try:
            if not is_valid_ref(n.ref) or n.kind not in KINDS:
                raise ValueError("bad ref/kind")
            if (n.ref == INTERNET) != (n.kind == "internet"):
                raise ValueError("internet ref/kind mismatch")
            asset_id = str(uuid.UUID(str(n.asset_id))) if n.asset_id else None
            attrs = _json(n.attrs if isinstance(n.attrs, dict) else None)
            if attrs is None:
                raise ValueError("attrs not serialisable")
            nodes[n.ref] = {"ref": n.ref, "kind": n.kind, "label": str(n.label or "")[:512],
                            "asset_id": asset_id, "attrs": attrs}
        except Exception as exc:  # noqa: BLE001 - one bad row never aborts the build
            rep.skipped += 1
            rep.notes.append(f"skipped node {str(n.ref)[:80]!r}: {exc}")
    return nodes


def _widen_port_zero(e: Any) -> Any:
    """Port 0 is not a TCP/UDP port and the table forbids it; a builder that means "all ports" and
    wrote 0-65535 must get 1-65535, not a skipped edge (a dropped edge under-approximates)."""
    lo, hi = e.port_lo, e.port_hi
    if e.proto == "icmp" or isinstance(lo, bool) or isinstance(hi, bool) \
            or not isinstance(lo, int) or not isinstance(hi, int) or lo != 0:
        return e
    return dataclasses.replace(e, port_lo=1, port_hi=65535 if hi < 1 else hi)


def _edge_issue(e: Any, source: str) -> Optional[str]:
    if e.source != source:
        return f"edge source {e.source!r} != build source {source!r}"
    if not (is_valid_ref(e.src_ref) and is_valid_ref(e.dst_ref)):
        return "bad src/dst ref"
    if e.proto not in PROTOS or e.basis not in BASES:
        return "bad proto/basis"
    if isinstance(e.port_lo, bool) or isinstance(e.port_hi, bool) \
            or not isinstance(e.port_lo, int) or not isinstance(e.port_hi, int):
        return "ports must be integers"
    if e.proto == "icmp":
        if not (0 <= e.port_lo <= e.port_hi <= 65535):
            return "port range out of bounds"
    elif not (1 <= e.port_lo <= e.port_hi <= 65535):
        return "port range out of bounds"
    if not isinstance(e.last_seen, dt.datetime) or e.last_seen.tzinfo is None:
        return "last_seen must be timezone-aware"
    if e.first_seen is not None and (not isinstance(e.first_seen, dt.datetime)
                                     or e.first_seen.tzinfo is None):
        return "first_seen must be timezone-aware"
    return None


def _clean_edges(out: BuildOutput, now: dt.datetime, rep: BuildReport) -> dict[tuple, dict[str, Any]]:
    cutoff = now - out.window if out.mode == "window" and out.window else None
    edges: dict[tuple, dict[str, Any]] = {}
    expired = 0
    for e in out.edges:
        try:
            e = _widen_port_zero(e)
            issue = _edge_issue(e, out.source)
            if issue:
                raise ValueError(issue)
            last = min(e.last_seen.astimezone(dt.timezone.utc), now)   # a future clock earns no life
            if cutoff is not None and last < cutoff:
                expired += 1
                continue
            first = min(e.first_seen.astimezone(dt.timezone.utc), last) if e.first_seen else last
            ev = _json(e.evidence if isinstance(e.evidence, dict) else {})
            if ev is None:
                ev = "{}"
                rep.notes.append("edge evidence not serialisable; stored empty")
            elif len(ev) > _MAX_EVIDENCE_BYTES:
                # Dropping the edge would under-approximate reachability; drop the detail.
                ev = _json({"truncated": True, "original_bytes": len(ev)}) or "{}"
            key = (e.src_ref, e.dst_ref, e.proto, e.port_lo, e.port_hi)
            conf = max(0, min(100, int(e.confidence)))
            row = {"key": key, "basis": e.basis, "confidence": conf, "first": first,
                   "last": last, "evidence": ev}
            old = edges.get(key)
            if old is not None:   # same key twice in one build: strongest basis, widest time span
                row["basis"] = max(old["basis"], row["basis"], key=_BASIS_RANK.__getitem__)
                row["first"] = min(old["first"], first)
                row["last"] = max(old["last"], last)
                row["confidence"] = max(old["confidence"], conf)
            edges[key] = row
        except Exception as exc:  # noqa: BLE001
            rep.skipped += 1
            rep.notes.append(f"skipped edge {str(getattr(e, 'src_ref', ''))[:60]!r}->"
                             f"{str(getattr(e, 'dst_ref', ''))[:60]!r}: {exc}")
    if expired:
        rep.notes.append(f"{expired} edge(s) already older than the window were ignored")
    return edges


def _clean_coverage(out: BuildOutput, rep: BuildReport) -> dict[tuple, dict[str, Any]]:
    cov: dict[tuple, dict[str, Any]] = {}
    for c in out.coverage:
        try:
            if c.source != out.source:
                raise ValueError(f"coverage source {c.source!r} != build source {out.source!r}")
            if not is_valid_ref(c.node_ref) or c.node_ref == INTERNET:
                raise ValueError("bad node ref (the internet is never covered)")
            if c.direction not in DIRECTIONS or c.tier not in BASES:
                raise ValueError("bad direction/tier")
            if not isinstance(c.observed_at, dt.datetime) or c.observed_at.tzinfo is None:
                raise ValueError("observed_at must be timezone-aware")
            detail = _json(c.detail if isinstance(c.detail, dict) else {}) or "{}"
            row = {"key": (c.node_ref, c.direction), "tier": c.tier,
                   "observed_at": c.observed_at.astimezone(dt.timezone.utc), "detail": detail}
            old = cov.get(row["key"])
            if old is not None:
                # Two facts for one (node, direction, source): keep the WEAKER (lower tier,
                # older). Coverage only ever narrows what HOLDS may claim.
                row["tier"] = min(old["tier"], row["tier"], key=_BASIS_RANK.__getitem__)
                row["observed_at"] = min(old["observed_at"], row["observed_at"])
            cov[row["key"]] = row
        except Exception as exc:  # noqa: BLE001
            rep.skipped += 1
            rep.notes.append(f"skipped coverage {str(getattr(c, 'node_ref', ''))[:60]!r}: {exc}")
    return cov


# --------------------------------------------------------------------------------------------
# Host facts (reach_node_facts)
# --------------------------------------------------------------------------------------------

class FactInvalid(ValueError):
    """A collector entry (or one value inside it) the graph document cannot carry."""


def _parse_ts(value: Any) -> Optional[dt.datetime]:
    """An ISO-8601 string WITH a timezone -> aware UTC datetime, else ``None``."""
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        t = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if t.tzinfo is None:
        return None
    try:
        return t.astimezone(dt.timezone.utc)
    except (ValueError, OverflowError):
        return None


def _check_text(value: str, what: str, limit: int) -> None:
    if len(value) > limit:
        raise FactInvalid(f"{what} longer than {limit} characters")
    if "\x00" in value:
        raise FactInvalid(f"{what} contains a NUL character")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise FactInvalid(f"{what} is not valid unicode") from exc


def count_fact_elements(value: Any) -> int:
    """Values (leaves and containers) inside ``value``; iterative, so depth cannot blow the stack."""
    n, todo = 0, [value]
    while todo:
        v = todo.pop()
        n += 1
        if isinstance(v, dict):
            todo.extend(v.values())
        elif isinstance(v, (list, tuple)):
            todo.extend(v)
    return n


def _check_fact_value(value: Any, depth: int, left: list[int], what: str) -> None:
    left[0] -= 1
    if left[0] < 0:
        raise FactInvalid(f"{what}: too many values (max {MAX_FACT_ELEMENTS})")
    if depth > MAX_FACT_DEPTH:
        raise FactInvalid(f"{what}: nested deeper than {MAX_FACT_DEPTH} levels")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > 2 ** 63 - 1:
            raise FactInvalid(f"{what}: integer out of range")
        return
    if isinstance(value, float):
        raise FactInvalid(f"{what}: floats are not allowed")
    if isinstance(value, str):
        _check_text(value, what, MAX_FACT_STRING)
        return
    if isinstance(value, list):
        if len(value) > MAX_FACT_LIST:
            raise FactInvalid(f"{what}: more than {MAX_FACT_LIST} rows in a list")
        for v in value:
            _check_fact_value(v, depth + 1, left, what)
        return
    if isinstance(value, dict):
        if len(value) > MAX_FACT_LIST:
            raise FactInvalid(f"{what}: more than {MAX_FACT_LIST} keys in an object")
        for k, v in value.items():
            if not isinstance(k, str):
                raise FactInvalid(f"{what}: object keys must be strings")
            _check_text(k, what, 256)
            _check_fact_value(v, depth + 1, left, what)
        return
    raise FactInvalid(f"{what}: unsupported value type {type(value).__name__}")


def _conflict_ok(value: Any) -> bool:
    """The library's rule: false/null/[] = none; true / non-empty object / non-empty list of
    non-empty objects = conflict; anything else cannot be read and is refused."""
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, dict):
        return bool(value)
    if isinstance(value, list):
        return all(isinstance(x, dict) and x for x in value)
    return False       # 0, "", 1.5, ...: unreadable, so refused (never read as "no conflict")


def normalise_fact_entry(name: str, entry: Any) -> dict[str, Any]:
    """One collector entry in storage form, or ``FactInvalid``.

    Defaults are made explicit and are the SAFE ones: a missing ``conf`` is ``approximate`` and a
    missing ``partial`` is ``True`` (both mean "never HOLDS"). ``signed`` has no default: a builder
    that forgot it must fail loudly, not look unsigned by accident. Unknown keys are dropped (they
    never reach the evaluator), except one that looks like a misspelt conflict marker, which would
    otherwise read as "no conflict".
    """
    what = f"facts.{name}"
    if not isinstance(entry, dict):
        raise FactInvalid(f"{what}: an entry must be an object")
    for k in entry:
        if isinstance(k, str) and "conflict" in k.lower() and k != "conflict":
            raise FactInvalid(f"{what}: unknown key {k!r} (the conflict marker is 'conflict')")
    status = entry.get("status")
    if not isinstance(status, str) or status not in FACT_STATUSES:
        raise FactInvalid(f"{what}: status must be one of {FACT_STATUSES}")
    signed = entry.get("signed")
    if not isinstance(signed, bool):
        raise FactInvalid(f"{what}: 'signed' must be a boolean")
    seq = entry.get("seq", 0)
    if seq is None:
        seq = 0
    if type(seq) is not int or not 0 <= seq <= 2 ** 63 - 1:
        raise FactInvalid(f"{what}: 'seq' must be a non-negative integer")
    conf = entry.get("conf", "approximate")
    if conf is None:
        conf = "approximate"
    if not isinstance(conf, str) or conf not in FACT_CONFS:
        raise FactInvalid(f"{what}: 'conf' must be exact or approximate")
    partial = entry.get("partial", True)
    if partial is None:
        partial = True
    if not isinstance(partial, bool):
        raise FactInvalid(f"{what}: 'partial' must be a boolean")
    out: dict[str, Any] = {"status": status, "signed": signed, "conf": conf, "partial": partial, "seq": seq}
    for key, limit in (("key_id", MAX_FACT_REF), ("evidence_ref", MAX_FACT_REF), ("reason", 64)):
        v = entry.get(key, "")
        if v is None:
            v = ""
        if not isinstance(v, str):
            raise FactInvalid(f"{what}: {key!r} must be a string")
        _check_text(v, f"{what}.{key}", limit)
        if v or key != "reason":
            out[key] = v
    if "conflict" in entry:
        c = entry["conflict"]
        if not _conflict_ok(c):
            raise FactInvalid(f"{what}: 'conflict' must be a boolean, a non-empty object or a list of them")
        if c is True or (isinstance(c, (dict, list)) and c):      # absent / false / null / [] = none
            _check_fact_value(c, 0, [MAX_FACT_ELEMENTS], f"{what}.conflict")
            out["conflict"] = c
    if entry.get("tier") is not None:
        if not isinstance(entry["tier"], str) or entry["tier"] not in BASES:
            raise FactInvalid(f"{what}: bad tier {entry['tier']!r}")
        out["tier"] = entry["tier"]
    if entry.get("observed_at") is not None:
        ts = _parse_ts(entry["observed_at"])
        if ts is None:
            raise FactInvalid(f"{what}: observed_at must be an ISO-8601 timestamp with a timezone")
        out["observed_at"] = ts.isoformat()
    data = entry.get("data", {})
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise FactInvalid(f"{what}: 'data' must be an object")
    _check_fact_value(data, 0, [MAX_FACT_ELEMENTS], f"{what}.data")
    out["data"] = data
    return out


def _strip_timestamps(value: Any) -> Any:
    """Drop ``*_at`` keys, recursively (a conflict record says when a scan saw the port: that moves
    with every scan and is not a change of state)."""
    if isinstance(value, dict):
        return {k: _strip_timestamps(v) for k, v in value.items() if not str(k).endswith("_at")}
    if isinstance(value, list):
        return [_strip_timestamps(v) for v in value]
    return value


def digest_view(name: str, entry: Any) -> Any:
    """What of one collector entry counts as its MEANING (the fact digest and ``graph_loader.doc_sha`` both read it):
    every key except the top-level provenance (``FACT_DIGEST_SKIP``), ``*_at`` inside the conflict records, and for
    the ``host_agent`` summary the provenance copied into ``data`` (``HOST_AGENT_DATA_DIGEST_SKIP``)."""
    if not isinstance(entry, dict):
        return entry
    d = {k: v for k, v in entry.items() if k not in FACT_DIGEST_SKIP}
    if "conflict" in d:
        d["conflict"] = _strip_timestamps(d["conflict"])
    if name == "host_agent" and isinstance(d.get("data"), dict):
        data = {k: v for k, v in d["data"].items() if k not in HOST_AGENT_DATA_DIGEST_SKIP}
        if "conflicts" in data:
            data["conflicts"] = _strip_timestamps(data["conflicts"])
        d["data"] = data
    return d


def fact_row_digest(tier: str, entries: dict[str, dict[str, Any]]) -> str:
    """sha256 over a fact row's MEANING: tier, collectors and every entry field except
    ``observed_at`` / ``seq`` / ``evidence_ref`` (and ``*_at`` inside a conflict record, and the ``host_agent``
    summary's own copy of seq / payload digest / collection time: :func:`digest_view`). A pure
    refresh therefore keeps the digest; a changed value, ``signed``, ``key_id`` (a different
    trust root), ``conf``, ``partial``, ``status``, ``conflict`` or tier changes it."""
    stripped: dict[str, Any] = {}
    for name in sorted(entries):
        stripped[name] = digest_view(name, entries[name])
    blob = _json({"tier": tier, "facts": stripped}) or ""
    return hashlib.sha256(blob.encode()).hexdigest()


HOST_AGENT = "host_agent"


def _error_entry(name: str, reason: str) -> dict[str, Any]:
    """What replaces a collector entry that cannot be stored: an unsigned, approximate, partial ``error`` entry
    with no data. A host with such an entry is in scope and that collector is UNKNOWN on it (never a pass)."""
    return normalise_fact_entry(name, {"status": "error", "signed": False, "conf": "approximate", "partial": True,
                                       "reason": reason, "data": {}})


def _fit_row(ref: str, entries: dict[str, dict[str, Any]], rep: BuildReport) -> tuple[dict[str, dict[str, Any]], str]:
    """The serialised row, within ``MAX_FACT_ROW_BYTES``. A row that is too big is NEVER dropped (the host would
    leave every host-config invariant without a trace and read as passing, review finding hostfw-7): the largest
    entries are replaced by an ``error`` entry (reason ``facts_too_large``, that collector is UNKNOWN) until the row
    fits, so the node keeps its facts, its ``agent`` tag and its UNKNOWN."""
    text = _json(entries)
    if text is None:
        raise ValueError("facts are not serialisable")
    if len(text) <= MAX_FACT_ROW_BYTES:
        return entries, text
    entries = dict(entries)
    sizes = {n: len(_json(e) or "") for n, e in entries.items()}
    for name in sorted(entries, key=lambda n: (-sizes[n], n)):
        entries[name] = _error_entry(name, "facts_too_large")
        rep.skipped += 1
        rep.notes.append(f"facts {ref!r} {name!r}: larger than the row allows, replaced by an error entry "
                         f"(facts_too_large)")
        text = _json(entries)
        if text is not None and len(text) <= MAX_FACT_ROW_BYTES:
            return entries, text
    raise ValueError(f"facts larger than {MAX_FACT_ROW_BYTES} bytes")


def _clean_facts(out: BuildOutput, rep: BuildReport) -> dict[str, dict[str, Any]]:
    """``node_ref -> row`` for the rows that can be stored. A bad collector entry is dropped on its
    own (that collector is then unknown on the host; the others stay); a bad row is skipped; two
    rows for one node are BOTH dropped (which one is right?). Everything dropped is counted."""
    rows: dict[str, dict[str, Any]] = {}
    clashed: set[str] = set()
    for f in out.facts:
        ref = str(getattr(f, "node_ref", ""))[:80]
        try:
            if not isinstance(f, FactOut):
                raise ValueError("not a FactOut")
            if f.source != out.source:
                raise ValueError(f"fact source {f.source!r} != build source {out.source!r}")
            if not is_valid_ref(f.node_ref) or f.node_ref == INTERNET:
                raise ValueError("bad node ref (the internet carries no host facts)")
            if f.tier not in BASES:
                raise ValueError("bad tier")
            if not isinstance(f.observed_at, dt.datetime) or f.observed_at.tzinfo is None:
                raise ValueError("observed_at must be timezone-aware")
            if not isinstance(f.facts, dict):
                raise ValueError("facts must be an object keyed by collector")
            if len(f.facts) > MAX_FACT_COLLECTORS:
                raise ValueError(f"more than {MAX_FACT_COLLECTORS} collectors")
            entries: dict[str, dict[str, Any]] = {}
            for name in sorted(f.facts, key=str):
                try:
                    if not isinstance(name, str) or not FACT_COLLECTOR_RE.fullmatch(name):
                        raise FactInvalid(f"bad collector name {str(name)[:40]!r}")
                    entries[name] = normalise_fact_entry(name, f.facts[name])
                except FactInvalid as exc:
                    rep.skipped += 1
                    rep.notes.append(f"dropped fact {ref!r} {str(name)[:40]!r}: {exc}")
            if not entries and f.facts:
                # every entry was invalid: the host must still be in scope (and unknown), not silently gone
                entries[HOST_AGENT] = _error_entry(HOST_AGENT, "facts_invalid")
            entries, text = _fit_row(ref, entries, rep)
            if f.node_ref in clashed or f.node_ref in rows:
                rows.pop(f.node_ref, None)
                clashed.add(f.node_ref)
                raise ValueError("two fact rows for one node: neither is trusted")
            rows[f.node_ref] = {
                "node_ref": f.node_ref, "tier": f.tier, "observed_at": f.observed_at.astimezone(dt.timezone.utc),
                "facts": text, "entries": entries, "digest": fact_row_digest(f.tier, entries)}
        except Exception as exc:  # noqa: BLE001 - one bad row never aborts the build
            rep.skipped += 1
            rep.notes.append(f"skipped facts {ref!r}: {exc}")
    return rows


async def _persist_facts(conn, out: BuildOutput, rows: dict[str, dict[str, Any]], rep: BuildReport) -> None:
    """Replace this source's ``reach_node_facts`` rows. ``rep.facts_changed`` counts rows added,
    removed or whose digest (meaning, timestamps excluded) changed, plus rows whose ``observed_at``
    moved BACKWARDS (freshness only ever shrinks then, and the evaluation that relied on the newer
    stamp must not outlive it). A forward refresh rewrites the row and counts nothing."""
    existing = {r["node_ref"]: r for r in await conn.fetch(
        "SELECT id, node_ref, tier, observed_at, digest, facts::text AS facts FROM reach_node_facts "
        "WHERE source = $1", out.source)}
    to_write: list[dict[str, Any]] = []
    for ref, new in rows.items():
        old = existing.get(ref)
        if old is None:
            rep.facts_changed += 1
            to_write.append(new)
            continue
        if old["digest"] != new["digest"] or old["tier"] != new["tier"]:
            rep.facts_changed += 1
        elif new["observed_at"] < old["observed_at"]:
            rep.facts_changed += 1
        elif old["observed_at"] == new["observed_at"] and \
                _json(json.loads(old["facts"] or "{}")) == new["facts"]:
            continue                                   # identical, nothing to write
        to_write.append(new)
    gone = [r for k, r in existing.items() if k not in rows]
    rep.facts_changed += len(gone)
    for part in _chunks(to_write, 500):
        await conn.execute(
            "INSERT INTO reach_node_facts (node_ref, source, tier, observed_at, digest, facts) "
            "SELECT t.n, $6::text, t.tr, t.o, t.d, t.f::jsonb "
            "FROM unnest($1::text[], $2::text[], $3::timestamptz[], $4::text[], $5::text[]) "
            "AS t(n, tr, o, d, f) "
            "ON CONFLICT (tenant_id, node_ref, source) DO UPDATE SET tier = EXCLUDED.tier, "
            "observed_at = EXCLUDED.observed_at, digest = EXCLUDED.digest, facts = EXCLUDED.facts",
            [r["node_ref"] for r in part], [r["tier"] for r in part], [r["observed_at"] for r in part],
            [r["digest"] for r in part], [r["facts"] for r in part], out.source)
    for part in _chunks([r["id"] for r in gone]):
        await conn.execute("DELETE FROM reach_node_facts WHERE id = ANY($1::uuid[])", list(part))
    rep.facts_stored = len(rows)
    rep.facts_digest = hashlib.sha256(
        "\n".join(f"{ref}:{rows[ref]['digest']}" for ref in sorted(rows)).encode()).hexdigest() if rows else ""


async def _lock_source(conn, source: str) -> None:
    """Serialise persists for one (tenant, source). Replicas/pods racing the same builder
    would otherwise diff against each other's half-applied state."""
    await conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended("
        "coalesce(current_setting('app.tenant_id', true), '') || ':assurance:' || $1, 0))", source)


async def _persist_nodes(conn, nodes: dict[str, dict[str, Any]], now: dt.datetime,
                         source: str, rep: BuildReport) -> None:
    if not nodes:
        return
    refs = sorted(nodes)
    existing: dict[str, str] = {}
    for part in _chunks(refs):
        for r in await conn.fetch(
                "SELECT node_ref, kind FROM reach_nodes WHERE node_ref = ANY($1::text[])", list(part)):
            existing[r["node_ref"]] = r["kind"]
    for ref in refs:
        old = existing.get(ref)
        new = nodes[ref]["kind"]
        if old is None or _KIND_RANK.get(new, 1) > _KIND_RANK.get(old, 1):
            rep.nodes_added += 1   # new node, or a more specific kind (selectors see it)
    for part in _chunks(refs):
        rows = [nodes[r] for r in part]
        await conn.execute(
            "INSERT INTO reach_nodes (node_ref, kind, label, asset_id, attrs, source, first_seen, last_seen) "
            "SELECT t.ref, t.kind, t.label, t.asset_id, t.attrs::jsonb, $6::text, $7::timestamptz, $7::timestamptz "
            "FROM unnest($1::text[], $2::text[], $3::text[], $4::uuid[], $5::text[]) "
            "AS t(ref, kind, label, asset_id, attrs) "
            "ON CONFLICT (tenant_id, node_ref) DO UPDATE SET "
            f"kind = CASE WHEN {_KIND_RANK_SQL.format(c='EXCLUDED.kind')} > "
            f"{_KIND_RANK_SQL.format(c='reach_nodes.kind')} THEN EXCLUDED.kind ELSE reach_nodes.kind END, "
            "label = EXCLUDED.label, "
            "asset_id = COALESCE(EXCLUDED.asset_id, reach_nodes.asset_id), "
            "attrs = EXCLUDED.attrs, source = EXCLUDED.source, "
            "last_seen = GREATEST(reach_nodes.last_seen, EXCLUDED.last_seen)",
            [r["ref"] for r in rows], [r["kind"] for r in rows], [r["label"] for r in rows],
            [r["asset_id"] for r in rows], [r["attrs"] for r in rows], source, now)
    rep.nodes_upserted = len(refs)


async def _persist_edges(conn, out: BuildOutput, edges: dict[tuple, dict[str, Any]],
                         now: dt.datetime, rep: BuildReport) -> None:
    existing = {
        (r["src_ref"], r["dst_ref"], r["proto"], r["port_lo"], r["port_hi"]): r
        for r in await conn.fetch(
            "SELECT id, src_ref, dst_ref, proto, port_lo, port_hi, basis, confidence, last_seen, "
            "evidence::text AS evidence FROM reach_edges WHERE source = $1", out.source)}
    to_write: list[dict[str, Any]] = []
    gone: list[Any] = []
    for key, new in edges.items():
        old = existing.get(key)
        if old is None:
            rep.edges_added += 1
            to_write.append(new)
            continue
        if old["basis"] != new["basis"]:
            rep.edges_added += 1      # (src,dst,proto,lo,hi,basis) is a different member of the set
            rep.edges_removed += 1
        if (old["basis"] != new["basis"] or old["confidence"] != new["confidence"]
                or new["last"] > old["last_seen"]
                or _json(json.loads(old["evidence"] or "{}")) != new["evidence"]):
            to_write.append(new)
    if out.mode == "replace":
        gone = [r for k, r in existing.items() if k not in edges]
    else:
        cutoff = now - (out.window or dt.timedelta(0))
        gone = [r for k, r in existing.items() if k not in edges and r["last_seen"] < cutoff]
    rep.edges_removed += len(gone)
    for part in _chunks(to_write):
        await conn.execute(
            "INSERT INTO reach_edges (src_ref, dst_ref, proto, port_lo, port_hi, basis, source, "
            "confidence, first_seen, last_seen, evidence) "
            "SELECT t.s, t.d, t.p, t.lo, t.hi, t.b, $11::text, t.c, t.f, t.l, t.e::jsonb "
            "FROM unnest($1::text[], $2::text[], $3::text[], $4::int[], $5::int[], $6::text[], "
            "$7::smallint[], $8::timestamptz[], $9::timestamptz[], $10::text[]) "
            "AS t(s, d, p, lo, hi, b, c, f, l, e) "
            "ON CONFLICT (tenant_id, source, src_ref, dst_ref, proto, port_lo, port_hi) DO UPDATE SET "
            "basis = EXCLUDED.basis, confidence = EXCLUDED.confidence, evidence = EXCLUDED.evidence, "
            "first_seen = LEAST(reach_edges.first_seen, EXCLUDED.first_seen), "
            "last_seen = GREATEST(reach_edges.last_seen, EXCLUDED.last_seen)",
            [e["key"][0] for e in part], [e["key"][1] for e in part], [e["key"][2] for e in part],
            [e["key"][3] for e in part], [e["key"][4] for e in part], [e["basis"] for e in part],
            [e["confidence"] for e in part], [e["first"] for e in part], [e["last"] for e in part],
            [e["evidence"] for e in part], out.source)
    for part in _chunks([r["id"] for r in gone]):
        await conn.execute("DELETE FROM reach_edges WHERE id = ANY($1::uuid[])", list(part))


async def _persist_coverage(conn, out: BuildOutput, cov: dict[tuple, dict[str, Any]],
                            rep: BuildReport) -> None:
    existing = {(r["node_ref"], r["direction"]): r for r in await conn.fetch(
        "SELECT id, node_ref, direction, tier FROM reach_coverage WHERE source = $1", out.source)}
    for key, new in cov.items():
        old = existing.get(key)
        if old is None or old["tier"] != new["tier"]:
            rep.coverage_changed += 1
    gone = [r for k, r in existing.items() if k not in cov]
    rep.coverage_changed += len(gone)
    rows = list(cov.values())
    for part in _chunks(rows):
        await conn.execute(
            "INSERT INTO reach_coverage (node_ref, direction, source, tier, observed_at, detail) "
            "SELECT t.n, t.d, $6::text, t.t, t.o, t.x::jsonb "
            "FROM unnest($1::text[], $2::text[], $3::text[], $4::timestamptz[], $5::text[]) "
            "AS t(n, d, t, o, x) "
            "ON CONFLICT (tenant_id, node_ref, direction, source) DO UPDATE SET "
            "tier = EXCLUDED.tier, observed_at = EXCLUDED.observed_at, detail = EXCLUDED.detail",
            [r["key"][0] for r in part], [r["key"][1] for r in part], [r["tier"] for r in part],
            [r["observed_at"] for r in part], [r["detail"] for r in part], out.source)
    for part in _chunks([r["id"] for r in gone]):
        await conn.execute("DELETE FROM reach_coverage WHERE id = ANY($1::uuid[])", list(part))


async def _prune_nodes(conn, out: BuildOutput, emitted: list[str], now: dt.datetime) -> int:
    grace = max(NODE_GRACE, out.window or dt.timedelta(0))
    rows = await conn.fetch(
        "DELETE FROM reach_nodes n WHERE n.source = $1 AND n.node_ref <> 'internet' "
        "AND n.node_ref <> ALL($2::text[]) AND n.last_seen < $3 "
        "AND NOT EXISTS (SELECT 1 FROM reach_edges e WHERE e.src_ref = n.node_ref OR e.dst_ref = n.node_ref) "
        "AND NOT EXISTS (SELECT 1 FROM reach_coverage c WHERE c.node_ref = n.node_ref) "
        "AND NOT EXISTS (SELECT 1 FROM reach_node_facts f WHERE f.node_ref = n.node_ref) "
        "RETURNING n.node_ref", out.source, emitted, now - grace)
    return len(rows)


async def persist_build(conn, out: BuildOutput, now: dt.datetime) -> BuildReport:
    """Apply one builder's output to the tenant's persistent graph, in one transaction.

    ``replace``: the source owns its edges; whatever it does not re-emit is deleted.
    ``window``:  edges persist until ``last_seen`` ages past ``out.window``.
    Coverage and host-fact rows of ``out.source`` are always replaced wholesale.
    A change (the graph version bumps) is a different SET of edges / coverage facts / nodes or a
    changed host fact (``fact_row_digest``); refreshing ``last_seen`` or ``observed_at`` (or
    re-signing identical facts under a new ``seq``) is not. Invalid rows are skipped and counted.
    """
    now = _aware(now)
    if not isinstance(out.source, str) or not out.source or len(out.source) > 64:
        raise ValueError("BuildOutput.source is required")
    if out.mode not in ("replace", "window"):
        raise ValueError(f"unknown mode {out.mode!r}")
    if out.mode == "window" and (out.window is None or out.window <= dt.timedelta(0)):
        raise ValueError("window mode needs a positive window")
    rep = BuildReport(notes=list(out.notes))
    nodes = _clean_nodes(out, rep)
    edges = _clean_edges(out, now, rep)
    cov = _clean_coverage(out, rep)
    fact_rows = _clean_facts(out, rep)
    async with conn.transaction():
        await _lock_source(conn, out.source)
        await _persist_nodes(conn, nodes, now, out.source, rep)
        await _persist_edges(conn, out, edges, now, rep)
        await _persist_coverage(conn, out, cov, rep)
        await _persist_facts(conn, out, fact_rows, rep)
        rep.nodes_removed = await _prune_nodes(conn, out, sorted(nodes), now)
        rep.changed = bool(rep.edges_added or rep.edges_removed or rep.coverage_changed
                           or rep.nodes_added or rep.nodes_removed or rep.facts_changed)
        if rep.changed:
            rep.graph_version = await bump_graph_version(conn)
        else:
            rep.graph_version = (await get_state(conn)).graph_version
    if rep.skipped:
        logger.warning("assurance_build_rows_skipped",
                       extra={"source": out.source, "skipped": rep.skipped})
    return rep


# --------------------------------------------------------------------------------------------
# Flow observation retention
# --------------------------------------------------------------------------------------------

async def prune_flow_obs(conn, older_than: dt.datetime) -> int:
    """Delete aggregated flow rows last seen before ``older_than``; returns the count."""
    older_than = _aware(older_than, "older_than")
    row = await conn.fetchval(
        "WITH d AS (DELETE FROM reach_flow_obs WHERE last_seen < $1 RETURNING 1) SELECT count(*) FROM d",
        older_than)
    return int(row or 0)


# --------------------------------------------------------------------------------------------
# Zones
# --------------------------------------------------------------------------------------------

def validate_zone_cidrs(cidrs: Iterable[str]) -> tuple[str, ...]:
    """Canonical, de-duplicated, sorted CIDR strings. Raises ``ValueError`` on anything odd.

    Rejects ``/0`` (a zone must not be "everything") and non-network text. Host bits are
    normalised away so ``10.0.0.5/24`` and ``10.0.0.0/24`` are the same zone range.
    """
    out: set[str] = set()
    for c in cidrs:
        if not isinstance(c, str) or not c.strip() or "/" not in c:
            raise ValueError(f"bad CIDR {c!r} (a prefix length is required)")
        try:
            net = ipaddress.ip_network(c.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"bad CIDR {c!r}") from exc
        if net.prefixlen == 0:
            raise ValueError(f"CIDR {c!r} is too broad for a zone")
        out.add(net.compressed.lower())
    if not out:
        raise ValueError("a zone needs at least one CIDR")
    if len(out) > _MAX_ZONE_CIDRS:
        raise ValueError(f"too many CIDRs (max {_MAX_ZONE_CIDRS})")
    return tuple(sorted(out, key=lambda s: (ipaddress.ip_network(s).version, ipaddress.ip_network(s))))


def validate_zone_name(name: str) -> str:
    if not isinstance(name, str) or not ZONE_NAME_RE.match(name):
        raise ValueError("zone names match ^[a-z][a-z0-9-]{0,31}$")
    if name in RESERVED_ZONES:
        raise ValueError(f"zone name {name!r} is reserved")
    return name


def _as_net(addr_or_net: str) -> Optional["ipaddress.IPv4Network | ipaddress.IPv6Network"]:
    try:
        return ipaddress.ip_network(str(addr_or_net).strip(), strict=False)
    except ValueError:
        return None


class ZoneIndex:
    """Declared zone CIDRs, parsed ONCE, answering "which zones contain this address/network".

    The loader resolves a zone for every node address. Re-parsing every zone CIDR per address
    (the old ``zone_matches`` loop) is O(nodes x zone CIDRs) calls to ``ipaddress.ip_network``:
    seconds of event-loop stall for a few thousand nodes and 1000 zone CIDRs. Here the CIDRs are
    bucketed by (IP version, prefix length) as network-address integers, so a lookup costs one
    dict probe per DISTINCT prefix length (at most 33 or 129), whatever the number of CIDRs.
    """

    def __init__(self, zones: Iterable[Zone]) -> None:
        # version -> prefixlen -> network address (int) -> zone names
        self._buckets: dict[int, dict[int, dict[int, set[str]]]] = {4: {}, 6: {}}
        for z in zones:
            for c in z.cidrs:
                net = _as_net(c)
                if net is None:
                    continue
                self._buckets[net.version].setdefault(net.prefixlen, {}) \
                    .setdefault(int(net.network_address), set()).add(z.name)

    def matches(self, addr_or_net: str) -> list[tuple[str, int]]:
        """Same contract as ``zone_matches``: ``(zone, prefixlen)`` for every zone CIDR containing
        the address (or wholly containing the network), most specific first, then by name."""
        target = _as_net(addr_or_net)
        if target is None:
            return []
        bits = target.max_prefixlen
        base = int(target.network_address)
        hits: set[tuple[str, int]] = set()
        for plen, table in self._buckets[target.version].items():
            if plen > target.prefixlen:        # a zone CIDR narrower than the target cannot contain it
                continue
            masked = (base >> (bits - plen)) << (bits - plen)
            for name in table.get(masked, ()):
                hits.add((name, plen))
        return sorted(hits, key=lambda h: (-h[1], h[0]))

    def resolve(self, addrs: Iterable[str]) -> tuple[Optional[str], list[str]]:
        """Zone of a node reachable at ``addrs``: each address resolves to its most specific zone;
        several addresses in different zones is a *conflict* (returned so it can be surfaced) and
        the winner is the most specific, then alphabetical (deterministic)."""
        winners: list[tuple[str, int]] = []
        for a in addrs:
            m = self.matches(a)
            if m:
                winners.append(m[0])
        if not winners:
            return None, []
        best = sorted(winners, key=lambda h: (-h[1], h[0]))[0][0]
        names = sorted({w[0] for w in winners})
        return best, (names if len(names) > 1 else [])


def zone_matches(zones: Iterable[Zone], addr_or_net: str) -> list[tuple[str, int]]:
    """``(zone name, prefix length)`` for every declared zone CIDR that CONTAINS ``addr_or_net``
    (an address, or a network wholly inside the zone range). Sorted most specific first, then
    by name, so the first entry is the deterministic winner. One-shot helper: a caller resolving
    many addresses must build a ``ZoneIndex`` once instead."""
    return ZoneIndex(zones).matches(addr_or_net)


def resolve_zone(zones: Iterable[Zone], addrs: Iterable[str]) -> tuple[Optional[str], list[str]]:
    """One-shot ``ZoneIndex(zones).resolve(addrs)`` (see there)."""
    return ZoneIndex(zones).resolve(addrs)


def _zone(r: Any) -> Zone:
    return Zone(id=str(r["id"]), name=r["name"], kind=r["kind"], cidrs=tuple(r["cidrs"] or ()),
                description=r["description"], source=r["source"], created_by=r["created_by"],
                created_at=r["created_at"], updated_at=r["updated_at"])


async def list_zones(conn) -> list[Zone]:
    rows = await conn.fetch("SELECT * FROM zones ORDER BY name")
    return [_zone(r) for r in rows]


async def upsert_zone(conn, name: str, cidrs: Iterable[str], *, kind: str = "custom",
                      description: str = "", set_by: str, justification: str,
                      now: Optional[dt.datetime] = None) -> ZoneChange:
    """Create or update a declared zone. Bumps ``graph_version`` iff the CIDR set changed (or
    the zone is new): zones decide which node is in ``guest`` vs ``pos``, i.e. verdicts.
    ``justification`` is required (the caller audits it; the zones table has no column for it)."""
    validate_zone_name(name)
    by, _why = _require_provenance(set_by, justification)
    canon = validate_zone_cidrs(cidrs)
    if not _ZONE_KIND_RE.match(kind or ""):
        raise ValueError("zone kind must match ^[a-z][a-z0-9_-]{0,31}$")
    now = _aware(now or dt.datetime.now(dt.timezone.utc))
    async with conn.transaction():
        await conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended("
            "coalesce(current_setting('app.tenant_id', true), '') || ':zones', 0))")
        prev = await conn.fetchrow("SELECT cidrs FROM zones WHERE name = $1 FOR UPDATE", name)
        await conn.execute(
            "INSERT INTO zones (name, kind, cidrs, description, source, created_by, created_at, updated_at) "
            "VALUES ($1, $2, $3::text[], $4, 'declared', $5, $6, $6) "
            "ON CONFLICT (tenant_id, name) DO UPDATE SET kind = EXCLUDED.kind, cidrs = EXCLUDED.cidrs, "
            "description = EXCLUDED.description, updated_at = EXCLUDED.updated_at",
            name, kind, list(canon), (description or "")[:1000], by, now)
        created = prev is None
        changed = created or tuple(sorted(prev["cidrs"] or ())) != tuple(sorted(canon))
        zones = await list_zones(conn)
        others = [z for z in zones if z.name != name]
        overlaps = sorted({z.name for z in others for c in canon if zone_matches([z], c)}
                          | {z.name for z in others for zc in z.cidrs
                             if zone_matches([Zone("", name, kind, canon)], zc)})
        version = await bump_graph_version(conn) if changed else None
    return ZoneChange(changed=changed, created=created, cidrs=canon,
                      overlaps=tuple(overlaps), graph_version=version)


async def delete_zone(conn, name: str, *, set_by: str, justification: str) -> Optional[int]:
    """Delete a zone. Returns the new graph version, or ``None`` if there was no such zone.
    Nodes that were in it lose their zone (invariants over that zone then select nothing, which
    the library reports as UNKNOWN, never HOLDS)."""
    _require_provenance(set_by, justification)
    async with conn.transaction():
        res = await conn.execute("DELETE FROM zones WHERE name = $1", name)
        if not res.endswith(" 1"):
            return None
        return await bump_graph_version(conn)


# --------------------------------------------------------------------------------------------
# Labels
# --------------------------------------------------------------------------------------------

def validate_label(node_ref: str, tag: str, value: str) -> tuple[str, str, str]:
    """Normalised ``(node_ref, tag, value)`` or ``ValueError``. The internet cannot be labelled
    (its zone and lack of coverage are fixed facts, not tenant opinions)."""
    try:
        parse_ref(node_ref)
    except RefError as exc:
        raise ValueError(str(exc)) from exc
    if node_ref == INTERNET:
        raise ValueError("the internet node cannot be labelled")
    if not is_valid_tag(tag):
        raise ValueError("tags match ^[a-z][a-z0-9_-]{0,47}$")
    value = (value or "").strip()
    if len(value) > _MAX_LABEL_VALUE:
        raise ValueError("label value too long")
    if tag == "zone":
        validate_zone_name(value)
    if tag == "kind" and value not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    return node_ref, tag, value


async def set_label(conn, node_ref: str, tag: str, value: str, *, set_by: str,
                    justification: str, now: Optional[dt.datetime] = None) -> LabelChange:
    """Declare a label with provenance. Bumps ``graph_version`` when the value changes or the
    label is new (zone / class / app-tier / crown-jewel all change verdicts). Re-declaring the
    same value only refreshes who/why/when."""
    node_ref, tag, value = validate_label(node_ref, tag, value)
    by, why = _require_provenance(set_by, justification)
    now = _aware(now or dt.datetime.now(dt.timezone.utc))
    async with conn.transaction():
        await conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended("
            "coalesce(current_setting('app.tenant_id', true), '') || ':labels', 0))")
        prev = await conn.fetchrow(
            "SELECT value, source FROM asset_labels WHERE node_ref = $1 AND tag = $2 FOR UPDATE",
            node_ref, tag)
        await conn.execute(
            "INSERT INTO asset_labels (node_ref, tag, value, source, set_by, justification, set_at) "
            "VALUES ($1, $2, $3, 'declared', $4, $5, $6) "
            "ON CONFLICT (tenant_id, node_ref, tag) DO UPDATE SET value = EXCLUDED.value, "
            "source = 'declared', set_by = EXCLUDED.set_by, justification = EXCLUDED.justification, "
            "set_at = EXCLUDED.set_at",
            node_ref, tag, value, by, why, now)
        changed = prev is None or prev["value"] != value
        version = await bump_graph_version(conn) if changed else None
    return LabelChange(changed=changed, previous=None if prev is None else prev["value"],
                       graph_version=version)


async def delete_label(conn, node_ref: str, tag: str, *, set_by: str,
                       justification: str) -> LabelChange:
    """Remove a label (any source). Bumps ``graph_version`` if a row was deleted."""
    try:
        parse_ref(node_ref)
    except RefError as exc:
        raise ValueError(str(exc)) from exc
    if not is_valid_tag(tag):
        raise ValueError("tags match ^[a-z][a-z0-9_-]{0,47}$")
    _require_provenance(set_by, justification)
    async with conn.transaction():
        prev = await conn.fetchrow(
            "DELETE FROM asset_labels WHERE node_ref = $1 AND tag = $2 RETURNING value", node_ref, tag)
        version = await bump_graph_version(conn) if prev is not None else None
    return LabelChange(changed=prev is not None, previous=None if prev is None else prev["value"],
                       graph_version=version)


async def list_labels(conn, node_ref: Optional[str] = None) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        "SELECT node_ref, tag, value, source, set_by, justification, set_at FROM asset_labels "
        "WHERE ($1::text IS NULL OR node_ref = $1) ORDER BY node_ref, tag", node_ref)
    return [dict(r) for r in rows]
