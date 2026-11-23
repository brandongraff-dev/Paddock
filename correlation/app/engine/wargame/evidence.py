"""Stored boundary evidence for the twin: observed flows and probe results
(schema/044_wargame_evidence.sql).

The twin (``twin_store``) holds config + topology, which can only ever prove a
pair closed *on paper* (``proved_config``). This module holds the two other
sources of the three-way agreement (``agreement.py``, docs/WARGAME.md §2.2):

* **Observed flows** — parsed from firewall / Zeek / generic logs the customer
  already has (``ingest.parse_flows``). A *real* flow (``impossible.flow_is_real``)
  from an entry segment to a crown jewel the config proves closed makes that
  pair ``fail_open``, and one that crosses a still-valid certificate raises an
  impossible-traffic alert.
* **Probe results** — RECORDED facts submitted by the customer's own probe or
  scanner (``crossed`` / ``blocked`` / ``error`` from a src segment to a dst
  segment on a proto/port). Paddock sends no packets here: it stores what it
  is told and maps it onto pairs, conservatively.

Two layers, like ``twin_store``: pure ser/de + mapping rules (unit-tested, no
I/O), then async persistence. Every statement is RLS-scoped to the current
tenant.

Rules (also in docs/WARGAME_ENGINE.md §15):

* **Pair mapping.** A probe counts for an ``(entry, jewel)`` pair only if it
  was run from the entry segment TO the jewel segment (``src == entry`` and
  ``dst == jewel``). A probe between intermediate segments (a hop) is stored
  but never inferred into a pair verdict: hop results do not compose into an
  end-to-end test.
* **Latest per port, then any-crossed.** Per ``(src, dst, proto, port)`` only
  the newest counting result is kept. The pair reads *crossed* if any port's
  latest result crossed, else *blocked* if at least one did, else not probed.
* **Staleness.** A result older than the certificate TTL
  (:data:`PROBE_MAX_AGE_HOURS`, 24 h — a certificate it backs could not
  outlive it) or dated in the future (beyond :data:`CLOCK_SKEW`) does not
  count. ``error`` results never count (an error is no probe).
* **Bounded storage.** Flows: a rolling :data:`FLOW_WINDOW_DAYS`-day window by
  ``observed_at`` (the flow's own timestamp when it parses, else the ingest
  time) and at most :data:`MAX_FLOWS_PER_TENANT` rows, newest kept. Probes:
  :data:`PROBE_RETENTION_DAYS` days and :data:`MAX_PROBES_PER_TENANT` rows.
  Pruning runs on every ingest.

DEFENSIVE: data handling only. Nothing here opens a socket, probes, or
executes anything.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Optional, Sequence

from ...db import Database
from .environment import Environment
from .impossible import ClosedBoundary, classify_flow
from .model import Flow, ImpossibleTrafficAlert, NodeRole, Proto

#: Rolling window of stored observed flows, in days.
FLOW_WINDOW_DAYS = 30
#: Hard cap on stored flows per tenant (the newest are kept).
MAX_FLOWS_PER_TENANT = 100_000
#: How long probe results are kept (history; only fresh ones count).
PROBE_RETENTION_DAYS = 30
#: Hard cap on stored probe results per tenant (the newest are kept).
MAX_PROBES_PER_TENANT = 50_000
#: A probe result older than this does not count. Equal to the certificate
#: TTL (``assess.CERT_TTL_HOURS``): a ``pass`` certificate never outlives the
#: probe behind it.
PROBE_MAX_AGE_HOURS = 24
#: Tolerated clock skew for a timestamp "from the future".
CLOCK_SKEW = timedelta(minutes=5)
#: Probe result vocabulary (schema 044 CHECK).
PROBE_RESULTS: tuple[str, ...] = ("crossed", "blocked", "error")
#: How many impossible-traffic alerts are kept verbatim in assessment metadata.
ALERT_SAMPLE = 5


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Probe results (pure)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProbeResult:
    """One recorded probe result: did a connect from ``src`` reach ``dst``?"""

    src: str
    dst: str
    proto: str
    port: int
    result: str            # one of PROBE_RESULTS
    observed_at: datetime
    source: str = ""


def probe_counts(p: ProbeResult, *, now: datetime,
                 max_age_hours: int = PROBE_MAX_AGE_HOURS) -> bool:
    """True iff ``p`` is evidence at ``now``: not ``error``, not older than
    ``max_age_hours`` and not dated in the future (beyond :data:`CLOCK_SKEW`)."""
    if p.result not in ("crossed", "blocked"):
        return False
    at, now = _utc(p.observed_at), _utc(now)
    return now - timedelta(hours=max_age_hours) <= at <= now + CLOCK_SKEW


def pair_probes(
    results: Iterable[ProbeResult],
    *,
    now: datetime,
    entries: Optional[Iterable[str]] = None,
    jewels: Optional[Iterable[str]] = None,
    max_age_hours: int = PROBE_MAX_AGE_HOURS,
) -> dict[tuple[str, str], bool]:
    """Map recorded probe results onto ``(entry, jewel)`` pairs for
    ``assess_environment(probes=...)``: ``True`` = crossed, ``False`` = blocked.

    Only a probe run from the entry segment to the jewel segment counts for
    that pair (``src == entry``, ``dst == jewel``); with ``entries`` /
    ``jewels`` given, any other (src, dst) is dropped. Stale, future-dated and
    ``error`` results are ignored (:func:`probe_counts`). Per
    ``(src, dst, proto, port)`` the newest result wins; a pair is crossed if
    any port's newest result crossed, else blocked if any was blocked.
    """
    ent = set(entries) if entries is not None else None
    jew = set(jewels) if jewels is not None else None
    latest: dict[tuple[str, str, str, int], ProbeResult] = {}
    for p in results:
        if not probe_counts(p, now=now, max_age_hours=max_age_hours):
            continue
        if ent is not None and p.src not in ent:
            continue
        if jew is not None and p.dst not in jew:
            continue
        key = (p.src, p.dst, p.proto, int(p.port))
        cur = latest.get(key)
        # Newest wins; on an exact tie, "crossed" wins (fail loud).
        if cur is None or (_utc(p.observed_at), p.result == "crossed") > (
            _utc(cur.observed_at), cur.result == "crossed"
        ):
            latest[key] = p
    out: dict[tuple[str, str], bool] = {}
    for (src, dst, _proto, _port), p in sorted(latest.items()):
        crossed = p.result == "crossed"
        out[(src, dst)] = out.get((src, dst), False) or crossed
    return out


def env_entries_and_jewels(env: Environment) -> tuple[set[str], set[str]]:
    """The entry and crown-jewel node ids of ``env``."""
    entries = {n.id for n in env.nodes.values() if n.role is NodeRole.ENTRY}
    jewels = {n.id for n in env.nodes.values() if n.role is NodeRole.CROWN_JEWEL}
    return entries, jewels


# ---------------------------------------------------------------------------
# Observed flows (pure)
# ---------------------------------------------------------------------------

def flow_observed_at(ts: str, *, ingested_at: datetime) -> datetime:
    """When a flow was seen: its own timestamp (epoch seconds or ISO-8601)
    when that parses and is not in the future, else ``ingested_at``."""
    ingested_at = _utc(ingested_at)
    s = (ts or "").strip()
    at: Optional[datetime] = None
    if s:
        try:
            v = float(s)
            if math.isfinite(v):
                at = datetime.fromtimestamp(v, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            try:
                at = _utc(datetime.fromisoformat(s.replace("Z", "+00:00")))
            except ValueError:
                at = None
    if at is None or at > ingested_at + CLOCK_SKEW:
        return ingested_at
    return at


def flow_to_row(flow: Flow, *, observed_at: datetime, source: str = "") -> dict[str, Any]:
    """A :class:`Flow` as a ``wargame_observed_flows`` row."""
    return {
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "proto": flow.proto.value,
        "dst_port": int(flow.dst_port),
        "handshake_completed": bool(flow.handshake_completed),
        "dst_side_observed": bool(flow.dst_side_observed),
        "firewall_allow_logged": bool(flow.firewall_allow_logged),
        "is_broadcast": bool(flow.is_broadcast),
        "kind": flow.kind or "",
        "ts": flow.ts or "",
        "observed_at": _utc(observed_at),
        "source": source or "",
    }


def row_to_flow(row: Mapping[str, Any]) -> Flow:
    """Inverse of :func:`flow_to_row` (round-trip exact on the Flow fields)."""
    return Flow(
        src_ip=row["src_ip"],
        dst_ip=row["dst_ip"],
        proto=Proto(row["proto"]),
        dst_port=int(row["dst_port"]),
        handshake_completed=bool(row["handshake_completed"]),
        dst_side_observed=bool(row["dst_side_observed"]),
        firewall_allow_logged=bool(row["firewall_allow_logged"]),
        is_broadcast=bool(row["is_broadcast"]),
        kind=row.get("kind", "") or "",
        ts=row.get("ts", "") or "",
    )


def observation_window_days(oldest: Optional[datetime], *, now: datetime) -> int:
    """Whole days the loaded flows span (1..FLOW_WINDOW_DAYS), 0 for none."""
    if oldest is None:
        return 0
    span = (_utc(now) - _utc(oldest)).total_seconds() / 86400.0
    return max(1, min(FLOW_WINDOW_DAYS, math.ceil(span)))


# ---------------------------------------------------------------------------
# Impossible traffic (pure)
# ---------------------------------------------------------------------------

def closed_boundaries(
    env: Environment, certs: Iterable[Mapping[str, Any]], *, now: datetime
) -> list[ClosedBoundary]:
    """:class:`ClosedBoundary` objects for certificates still standing at
    ``now`` (status ``valid``, not expired), with CIDRs from ``env``. A cert
    whose segments are no longer modelled is skipped (it cannot be placed).
    Each cert dict needs ``boundary_src``, ``boundary_dst``, ``fingerprint``
    and optionally ``status`` / ``expires_at`` (datetime or ISO string)."""
    now = _utc(now)
    out: list[ClosedBoundary] = []
    seen: set[str] = set()
    for c in certs:
        if (c.get("status") or "valid") != "valid":
            continue
        exp = c.get("expires_at")
        if isinstance(exp, str) and exp:
            exp = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        if isinstance(exp, datetime) and _utc(exp) <= now:
            continue
        fp = str(c.get("fingerprint") or "")
        if not fp or fp in seen:
            continue
        src = env.nodes.get(c["boundary_src"])
        dst = env.nodes.get(c["boundary_dst"])
        if src is None or dst is None or not src.cidrs or not dst.cidrs:
            continue
        seen.add(fp)
        out.append(ClosedBoundary(
            src_cidrs=tuple(src.cidrs),
            dst_cidrs=tuple(dst.cidrs),
            port=None,               # pair certificates cover every port
            certificate_fingerprint=fp,
            boundary_src=src.id,
            boundary_dst=dst.id,
        ))
    return out


def impossible_alerts(
    flows: Sequence[Flow], boundaries: Sequence[ClosedBoundary]
) -> list[ImpossibleTrafficAlert]:
    """Every real flow that crosses a closed boundary, as a critical alert
    (``impossible.classify_flow``). Deterministic order."""
    if not boundaries:
        return []
    bl = list(boundaries)
    alerts = [a for a in (classify_flow(f, bl) for f in flows) if a is not None]
    alerts.sort(key=lambda a: (a.boundary_src, a.boundary_dst, a.flow.ts,
                               a.flow.src_ip, a.flow.dst_ip, a.flow.dst_port))
    return alerts


def alert_dict(a: ImpossibleTrafficAlert) -> dict[str, Any]:
    """A JSON-ready summary of an alert (for assessment metadata)."""
    f = a.flow
    return {
        "boundary_src": a.boundary_src,
        "boundary_dst": a.boundary_dst,
        "contradicts_certificate": a.contradicts_certificate,
        "severity": a.severity,
        "src_ip": f.src_ip,
        "dst_ip": f.dst_ip,
        "proto": f.proto.value,
        "dst_port": f.dst_port,
        "ts": f.ts,
        "note": a.note,
    }


# ---------------------------------------------------------------------------
# Async persistence (RLS-scoped to the current tenant)
# ---------------------------------------------------------------------------

_FLOW_COLS = (
    "src_ip, dst_ip, proto, dst_port, handshake_completed, dst_side_observed, "
    "firewall_allow_logged, is_broadcast, kind, ts, observed_at, source"
)


async def persist_flows(
    db: Database, rows: Sequence[Mapping[str, Any]], *, now: datetime
) -> dict[str, int]:
    """Insert flow rows, then prune the tenant's flows to the rolling window
    and the row cap. Returns ``{"stored", "pruned"}``. One transaction."""
    now = _utc(now)
    cutoff = now - timedelta(days=FLOW_WINDOW_DAYS)
    keep = [r for r in rows if _utc(r["observed_at"]) >= cutoff]
    keep.sort(key=lambda r: r["observed_at"], reverse=True)
    keep = keep[:MAX_FLOWS_PER_TENANT]
    async with db.acquire() as conn:
        async with conn.transaction():
            if keep:
                await conn.executemany(
                    f"INSERT INTO wargame_observed_flows ({_FLOW_COLS}) "
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                    [
                        (r["src_ip"], r["dst_ip"], r["proto"], r["dst_port"],
                         r["handshake_completed"], r["dst_side_observed"],
                         r["firewall_allow_logged"], r["is_broadcast"], r["kind"],
                         r["ts"], r["observed_at"], r["source"])
                        for r in keep
                    ],
                )
            pruned = _count(await conn.execute(
                "DELETE FROM wargame_observed_flows WHERE observed_at < $1", cutoff))
            pruned += _count(await conn.execute(
                "DELETE FROM wargame_observed_flows WHERE id IN ("
                "  SELECT id FROM wargame_observed_flows"
                "   ORDER BY observed_at DESC, ingested_at DESC, id OFFSET $1)",
                MAX_FLOWS_PER_TENANT))
    return {"stored": len(keep), "pruned": pruned + (len(rows) - len(keep))}


async def load_flows(db: Database, *, now: datetime) -> tuple[list[Flow], int]:
    """The tenant's stored flows inside the rolling window (newest first,
    capped) and the observation window they span in days (0 = none)."""
    now = _utc(now)
    rows = await db.fetch(
        f"SELECT {_FLOW_COLS} FROM wargame_observed_flows "
        "WHERE observed_at >= $1 ORDER BY observed_at DESC, id LIMIT $2",
        now - timedelta(days=FLOW_WINDOW_DAYS),
        MAX_FLOWS_PER_TENANT,
    )
    flows = [row_to_flow(dict(r)) for r in rows]
    oldest = min((r["observed_at"] for r in rows), default=None)
    return flows, observation_window_days(oldest, now=now)


async def segment_keys(db: Database) -> set[str]:
    """The tenant's declared topology segment ids."""
    rows = await db.fetch("SELECT seg_key FROM wargame_segments")
    return {r["seg_key"] for r in rows}


async def persist_probes(
    db: Database, results: Sequence[ProbeResult], *, now: datetime
) -> dict[str, int]:
    """Insert probe results, then prune to the retention window and row cap.
    Returns ``{"stored", "pruned"}``. One transaction."""
    now = _utc(now)
    cutoff = now - timedelta(days=PROBE_RETENTION_DAYS)
    keep = [p for p in results if _utc(p.observed_at) >= cutoff]
    async with db.acquire() as conn:
        async with conn.transaction():
            if keep:
                await conn.executemany(
                    "INSERT INTO wargame_probe_results "
                    "(src_segment, dst_segment, proto, port, result, observed_at, source) "
                    "VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    [(p.src, p.dst, p.proto, int(p.port), p.result,
                      _utc(p.observed_at), p.source or "") for p in keep],
                )
            pruned = _count(await conn.execute(
                "DELETE FROM wargame_probe_results WHERE observed_at < $1", cutoff))
            pruned += _count(await conn.execute(
                "DELETE FROM wargame_probe_results WHERE id IN ("
                "  SELECT id FROM wargame_probe_results"
                "   ORDER BY observed_at DESC, ingested_at DESC, id OFFSET $1)",
                MAX_PROBES_PER_TENANT))
    return {"stored": len(keep), "pruned": pruned + (len(results) - len(keep))}


async def load_probes(
    db: Database, *, now: datetime, max_age_hours: int = PROBE_MAX_AGE_HOURS
) -> list[ProbeResult]:
    """The tenant's probe results young enough to count at ``now`` (the pure
    :func:`pair_probes` re-applies the same rule)."""
    now = _utc(now)
    rows = await db.fetch(
        "SELECT src_segment, dst_segment, proto, port, result, observed_at, source "
        "FROM wargame_probe_results "
        "WHERE observed_at >= $1 AND observed_at <= $2 AND result <> 'error' "
        "ORDER BY observed_at DESC, id",
        now - timedelta(hours=max_age_hours),
        now + CLOCK_SKEW,
    )
    return [
        ProbeResult(src=r["src_segment"], dst=r["dst_segment"], proto=r["proto"],
                    port=int(r["port"]), result=r["result"],
                    observed_at=r["observed_at"], source=r["source"])
        for r in rows
    ]


async def standing_certificates(db: Database, *, now: datetime) -> list[dict[str, Any]]:
    """Certificates of the tenant's most recent ``twin`` assessment that are
    still valid at ``now``: what the customer may currently be relying on, and
    what a newly observed crossing contradicts."""
    rows = await db.fetch(
        "SELECT c.boundary_src, c.boundary_dst, c.status, c.expires_at, c.fingerprint "
        "FROM wargame_certificates c "
        "WHERE c.assessment_id = ("
        "  SELECT id FROM wargame_assessments WHERE label = 'twin' "
        "   ORDER BY computed_at DESC, id LIMIT 1) "
        "  AND c.status = 'valid' AND (c.expires_at IS NULL OR c.expires_at > $1) "
        "ORDER BY c.fingerprint",
        _utc(now),
    )
    return [dict(r) for r in rows]


def _count(status: str) -> int:
    """Row count from an asyncpg status string such as ``"DELETE 3"``."""
    try:
        return int(str(status).rsplit(" ", 1)[-1])
    except (ValueError, IndexError):
        return 0
