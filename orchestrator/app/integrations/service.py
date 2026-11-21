"""Integrations core: fan-out (``emit``), the stream mapper and the delivery engine.

Public API other modules import:

* ``await emit(pool, event)`` -- persist one ``integration_deliveries`` row
  per enabled integration whose subscription matches ``event``. Idempotent on
  ``(integration_id, event_id)``; never raises (a notification problem must not
  fail the business operation that produced the event).

Everything else here is used by the worker (``app.integrations.worker``) and
the REST API (``app.routers.integrations``):

* ``event_from_stream(pool, fields, stream_id)`` maps a ``stream:events`` entry
  (``finding_opened``, ``finding_closed``, ``chain_detected``,
  ``attack_path_found``, ``asset_added``, ``scan_completed``, ``scan_failed``)
  to a normalized ``Event`` enriched from the database.
* ``process_due(pool)`` claims due deliveries (lease + ``SKIP LOCKED`` so
  several workers can run), calls ``connector.deliver`` and records
  sent / failed (exponential backoff) / dead (after N attempts).
* ``send_now(pool, integration, event)`` is the synchronous path behind the
  "Test" button.

Secrets are decrypted only inside ``build_connector`` and live only on the
connector instance for the duration of one batch.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import random
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional

import httpx

from . import connectors as _connectors
from . import secrets as secrets_mod
from .base import EVENT_TYPES, REGISTRY, SEVERITIES, Connector, DeliveryResult, Event
from .outbound import make_client
from .settings import isettings

log = logging.getLogger(__name__)

_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_EVENT_NS = uuid.UUID("6a1f3f0e-5d0b-4b8e-9a51-7d0f1c1e2a10")

# filter key -> the Event.data attribute it constrains (all AND-ed).
FILTER_KEYS: dict[str, str] = {
    "asset_kinds": "asset_kind",     # e.g. ["domain", "subdomain"]
    "rule_sources": "rule_source",   # e.g. ["nuclei", "cve_match"]
    "owners": "owner",               # team / assignee names
    "tags": "tags",                  # any overlap with the asset's tags
    "assets": "asset",               # shell-style globs, e.g. ["*.prod.example.com"]
}


def load_connectors() -> None:
    """Import every connector module (idempotent)."""
    _connectors.load_all()


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #

def _as_json(v: Any, default: Any) -> Any:
    if v is None:
        return default
    if isinstance(v, (dict, list)):
        return v
    try:
        return json.loads(v)
    except (TypeError, ValueError):
        return default


def severity_passes(event_severity: Optional[str], min_severity: Optional[str]) -> bool:
    """The severity gate only applies to events that carry a severity
    (asset/scan lifecycle events have none and are gated by subscription)."""
    if event_severity is None:
        return True
    return _SEV_RANK.get(event_severity, 0) >= _SEV_RANK.get(min_severity or "info", 0)


def filters_pass(filters: Mapping[str, Any] | None, data: Mapping[str, Any]) -> bool:
    """Filters NARROW. An event lacking a filtered attribute does not match."""
    for key, want in (filters or {}).items():
        attr = FILTER_KEYS.get(key)
        if attr is None or not want:
            continue
        have = data.get(attr)
        if have is None or have == "" or have == []:
            return False
        wanted = [str(w).lower() for w in (want if isinstance(want, list) else [want])]
        if key == "tags":
            have_set = {str(t).lower() for t in (have if isinstance(have, list) else [have])}
            if not have_set.intersection(wanted):
                return False
        elif key == "assets":
            if not any(fnmatch.fnmatch(str(have).lower(), pat) for pat in wanted):
                return False
        elif str(have).lower() not in wanted:
            return False
    return True


def matches(integration: Mapping[str, Any], event: Event) -> bool:
    if not integration.get("enabled", True):
        return False
    if event.type not in (integration.get("events") or ()):
        return False
    if not severity_passes(event.severity, integration.get("min_severity")):
        return False
    return filters_pass(_as_json(integration.get("filters"), {}), event.data)


# --------------------------------------------------------------------------- #
# Event (de)serialization
# --------------------------------------------------------------------------- #

def event_payload(event: Event) -> str:
    return json.dumps(event.as_dict(), default=str)


def event_from_dict(d: Mapping[str, Any]) -> Event:
    occurred = d.get("occurred_at")
    kwargs: dict[str, Any] = {}
    if occurred:
        try:
            kwargs["occurred_at"] = datetime.fromisoformat(str(occurred))
        except ValueError:
            pass
    return Event(
        type=d["type"],
        title=d.get("title") or d["type"],
        summary=d.get("summary") or "",
        severity=d.get("severity"),
        data=dict(d.get("data") or {}),
        url=d.get("url"),
        tenant_id=d.get("tenant_id"),
        id=str(d.get("id") or uuid.uuid4()),
        **kwargs,
    )


def stable_event_id(key: str) -> str:
    """Deterministic id for a lifecycle fact, so the same fact arriving twice
    (stream redelivery, two publishers) is delivered once."""
    return str(uuid.uuid5(_EVENT_NS, key))


# --------------------------------------------------------------------------- #
# emit: the fan-out every producer calls
# --------------------------------------------------------------------------- #

_MATCH_SQL = """
SELECT id, kind, enabled, events, min_severity, filters
  FROM integrations
 WHERE enabled AND events @> ARRAY[$1]::text[]
"""

_INSERT_SQL = """
INSERT INTO integration_deliveries
       (integration_id, event_id, event_type, status, attempts, next_attempt_at, payload)
VALUES ($1, $2, $3, 'pending', 0, NOW(), $4::jsonb)
ON CONFLICT (integration_id, event_id) DO NOTHING
RETURNING id
"""


async def fan_out(pool: Any, event: Event) -> list[int]:
    """Like ``emit`` but raises on DB errors and returns the new delivery ids.
    ``pool`` may be an asyncpg Pool or Connection."""
    rows = await pool.fetch(_MATCH_SQL, event.type)
    payload = event_payload(event)
    created: list[int] = []
    for row in rows:
        if not matches(dict(row), event):
            continue
        did = await pool.fetchval(_INSERT_SQL, row["id"], event.id, event.type, payload)
        if did is not None:
            created.append(did)
    if created:
        log.info("integration_event_queued", extra={"event_type": event.type, "event_id": event.id,
                                                    "deliveries": len(created)})
    return created


async def emit(pool: Any, event: Event) -> None:
    """Queue ``event`` for every matching enabled integration. Never raises."""
    try:
        await fan_out(pool, event)
    except Exception:  # noqa: BLE001 -- best-effort by contract
        log.exception("integration_emit_failed", extra={"event_type": event.type, "event_id": event.id})


# --------------------------------------------------------------------------- #
# stream:events -> Event
# --------------------------------------------------------------------------- #

def dashboard_url(path: str) -> str:
    return isettings.paddock_dashboard_url.rstrip("/") + path


def decode_stream_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Two encodings exist on stream:events: the orchestrator writes
    ``{"event": "<json object>"}``; some workers write flat fields
    (``{"event": "scan_completed", "scan_id": ...}``)."""
    for key in ("event", "json", "data"):
        raw = fields.get(key)
        if isinstance(raw, str) and raw.lstrip().startswith("{"):
            try:
                obj = json.loads(raw)
            except ValueError:
                continue
            if isinstance(obj, dict):
                return obj
    return dict(fields)


def _parse_ts(v: Any) -> Optional[datetime]:
    if v in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(float(v), tz=timezone.utc)
    except (TypeError, ValueError):
        pass
    try:
        dt = datetime.fromisoformat(str(v))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _sev(v: Any) -> Optional[str]:
    return v if v in _SEV_RANK else None


def _short(text: Any, n: int = 500) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _uuid_or_none(v: Any) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(v))
    except (TypeError, ValueError):
        return None


def _tags(metadata: Any) -> list[str]:
    md = _as_json(metadata, {})
    tags = md.get("tags") if isinstance(md, dict) else None
    if isinstance(tags, list):
        return [str(t) for t in tags]
    if isinstance(tags, str):
        return [t.strip() for t in tags.split(",") if t.strip()]
    return []


_FINDING_SQL = """
SELECT f.id, f.title, f.severity, f.description, f.impact, f.remediation, f.rule_id, f.rule_source,
       f.status, f.assigned_to, f.cvss, f.epss, f.evidence, f.metadata AS f_metadata,
       a.id AS asset_id, a.kind AS asset_kind, a.value AS asset_value, a.metadata AS a_metadata
  FROM findings f JOIN assets a ON a.id = f.asset_id
 WHERE f.id = $1
"""


async def _finding_context(pool: Any, finding_id: Any) -> Optional[dict[str, Any]]:
    fid = _uuid_or_none(finding_id)
    if fid is None:
        return None
    row = await pool.fetchrow(_FINDING_SQL, fid)
    if row is None:
        return None
    fmd = _as_json(row["f_metadata"], {})
    amd = _as_json(row["a_metadata"], {})
    owner = row["assigned_to"] or (fmd.get("owner") if isinstance(fmd, dict) else None) \
        or (amd.get("owner") if isinstance(amd, dict) else None)
    return {
        "title": row["title"],
        "severity": row["severity"],
        "summary": _short(row["impact"] or row["description"]),
        "data": {
            "finding_id": str(row["id"]),
            "asset_id": str(row["asset_id"]),
            "asset": row["asset_value"],
            "asset_kind": row["asset_kind"],
            "rule_id": row["rule_id"],
            "rule_source": row["rule_source"],
            "status": row["status"],
            "owner": owner,
            "tags": _tags(row["a_metadata"]),
            "cvss": float(row["cvss"]) if row["cvss"] is not None else None,
            "epss": float(row["epss"]) if row["epss"] is not None else None,
            # Full finding for structured consumers (OCSF/SIEM, ticketing).
            "finding": {
                "id": str(row["id"]), "title": row["title"], "severity": row["severity"],
                "description": row["description"], "impact": row["impact"],
                "remediation": row["remediation"], "rule_id": row["rule_id"],
                "rule_source": row["rule_source"], "status": row["status"],
                "cvss": float(row["cvss"]) if row["cvss"] is not None else None,
                "epss": float(row["epss"]) if row["epss"] is not None else None,
                "evidence": _evidence_identifiers(row["evidence"]),
            },
        },
    }


# Evidence can hold response bodies/snippets: only identifiers leave Paddock.
_EVIDENCE_KEYS = ("cve", "cve_id", "cve_ids", "cves", "cwe", "cwe_id", "cwe_ids", "cwes",
                  "kev", "file", "path", "line", "start_line", "end_line", "package",
                  "ecosystem", "version", "fixed_version", "purl", "port", "protocol", "detector")


def _evidence_identifiers(raw: Any) -> dict[str, Any]:
    ev = _as_json(raw, {})
    if not isinstance(ev, dict):
        return {}
    return {k: ev[k] for k in _EVIDENCE_KEYS if k in ev}


async def _asset_label(pool: Any, asset_id: Any) -> tuple[Optional[str], Optional[str], list[str]]:
    aid = _uuid_or_none(asset_id)
    if aid is None:
        return None, None, []
    row = await pool.fetchrow("SELECT kind, value, metadata FROM assets WHERE id = $1", aid)
    if row is None:
        return None, None, []
    return row["value"], row["kind"], _tags(row["metadata"])


async def event_from_stream(pool: Any, fields: Mapping[str, Any], stream_id: Optional[str] = None) -> Optional[Event]:
    """Map one ``stream:events`` entry to an ``Event`` (or ``None`` to ignore)."""
    p = decode_stream_fields(fields)
    name = p.get("event")
    ts = _parse_ts(p.get("ts"))
    extra: dict[str, Any] = {"occurred_at": ts} if ts else {}
    sid = stream_id or str(uuid.uuid4())

    if name == "finding_opened":
        ctx = await _finding_context(pool, p.get("finding_id"))
        if ctx is None:
            ctx = {"title": f"New finding: {p.get('rule_id') or 'unknown rule'}",
                   "severity": p.get("severity"), "summary": "",
                   "data": {"finding_id": p.get("finding_id"), "asset_id": p.get("asset_id"),
                            "rule_id": p.get("rule_id"), "rule_source": p.get("rule_source")}}
        return Event(
            type="finding.opened", title=ctx["title"], summary=ctx["summary"],
            severity=_sev(ctx["severity"]), data=ctx["data"],
            url=dashboard_url(f"/findings?focus={p.get('finding_id')}"),
            id=stable_event_id(f"finding.opened:{p.get('finding_id')}"), **extra,
        )

    if name == "finding_closed":
        status = p.get("status")
        etype = "finding.resolved" if status == "fixed" else "finding.accepted"
        ctx = await _finding_context(pool, p.get("finding_id"))
        if ctx is None:
            ctx = {"title": f"Finding {p.get('finding_id')}", "severity": None, "summary": "",
                   "data": {"finding_id": p.get("finding_id")}}
        verb = {"fixed": "Resolved", "false_positive": "Marked false positive",
                "accepted": "Risk accepted", "accepted_risk": "Risk accepted",
                "wontfix": "Won't fix"}.get(status, "Closed")
        data = {**ctx["data"], "status": status}
        return Event(
            type=etype, title=f"{verb}: {ctx['title']}", summary=ctx["summary"],
            severity=_sev(ctx["severity"]), data=data,
            url=dashboard_url(f"/findings?focus={p.get('finding_id')}"),
            id=stable_event_id(f"{etype}:{p.get('finding_id')}:{sid}"), **extra,
        )

    if name in ("finding_reopened", "finding_updated"):
        # Reopened by a human, an expired acceptance (lifecycle sweep), or a
        # regression; "updated" covers severity/owner/status edits.
        etype = "finding.reopened" if name == "finding_reopened" else "finding.updated"
        ctx = await _finding_context(pool, p.get("finding_id"))
        if ctx is None:
            ctx = {"title": f"Finding {p.get('finding_id')}", "severity": p.get("severity"),
                   "summary": "", "data": {"finding_id": p.get("finding_id")}}
        verb = "Reopened" if name == "finding_reopened" else "Updated"
        data = {**ctx["data"], "status": p.get("status") or ctx["data"].get("status"),
                "reason": p.get("reason")}
        return Event(
            type=etype, title=f"{verb}: {ctx['title']}", summary=ctx["summary"],
            severity=_sev(ctx["severity"]), data=data,
            url=dashboard_url(f"/findings?focus={p.get('finding_id')}"),
            id=stable_event_id(f"{etype}:{p.get('finding_id')}:{sid}"), **extra,
        )

    if name == "chain_detected":
        cid = _uuid_or_none(p.get("chain_id"))
        row = await pool.fetchrow(
            "SELECT c.title, c.description, c.impact_narrative, c.severity, c.finding_ids, "
            "       a.id AS asset_id, a.kind AS asset_kind, a.value AS asset_value, a.metadata AS a_md "
            "  FROM finding_chains c LEFT JOIN assets a ON a.id = c.anchor_asset_id WHERE c.id = $1",
            cid,
        ) if cid else None
        title = row["title"] if row else f"Attack chain detected ({p.get('chain_rule_id')})"
        data = {
            "chain_id": p.get("chain_id"),
            "finding_kind": "chain",
            "rule_id": p.get("chain_rule_id"),
            "rule_source": "chain",
            "finding_count": p.get("finding_count") or (len(row["finding_ids"]) if row else None),
            "asset_id": str(row["asset_id"]) if row and row["asset_id"] else p.get("anchor_asset_id"),
            "asset": row["asset_value"] if row else None,
            "asset_kind": row["asset_kind"] if row else None,
            "tags": _tags(row["a_md"]) if row else [],
        }
        return Event(
            type="finding.opened", title=title,
            summary=_short((row["impact_narrative"] or row["description"]) if row else ""),
            severity=_sev(row["severity"] if row else p.get("severity")), data=data,
            url=dashboard_url("/chains"),
            id=stable_event_id(f"chain:{p.get('chain_id')}"), **extra,
        )

    if name == "attack_path_found":
        src, _sk, _ = await _asset_label(pool, p.get("source_asset_id"))
        dst, dkind, dtags = await _asset_label(pool, p.get("target_asset_id"))
        narrative = None
        pid = _uuid_or_none(p.get("path_id"))
        if pid:
            narrative = await pool.fetchval("SELECT narrative FROM attack_paths WHERE id = $1", pid)
        data = {
            "attack_path_id": p.get("path_id"),
            "fingerprint": p.get("fingerprint"),
            "source_asset_id": p.get("source_asset_id"),
            "target_asset_id": p.get("target_asset_id"),
            "source_asset": src,
            "target_asset": dst,
            "asset": f"{src or '?'} → {dst or '?'}",
            "asset_kind": dkind,
            "exploitability": p.get("exploitability"),
            "kev_on_path": p.get("kev_on_path"),
            "tags": dtags,
        }
        return Event(
            type="attack_path.opened", title=p.get("title") or "New attack path to a crown jewel",
            summary=_short(narrative or ""), severity=_sev(p.get("severity")), data=data,
            url=dashboard_url("/attack-paths"),
            id=stable_event_id(f"attack_path:{p.get('fingerprint') or p.get('path_id')}"), **extra,
        )

    if name == "asset_added":
        kind, value = p.get("kind"), p.get("value") or p.get("canonical")
        return Event(
            type="asset.discovered", title=f"New {kind or 'asset'} discovered: {value}",
            summary=f"Source: {p.get('source')}" if p.get("source") else "",
            data={"asset_id": p.get("asset_id"), "asset": value, "asset_kind": kind,
                  "source": p.get("source")},
            url=dashboard_url("/graph"),
            id=stable_event_id(f"asset:{p.get('asset_id')}"), **extra,
        )

    if name in ("scan_completed", "scan_failed"):
        etype = "scan.completed" if name == "scan_completed" else "scan.failed"
        kind, target = p.get("kind") or "scan", p.get("target") or ""
        verb = "completed" if etype == "scan.completed" else "failed"
        data = {"scan_id": p.get("scan_id"), "scan_kind": kind, "target": target, "asset": target or None}
        if etype == "scan.failed":
            data["error"] = _short(p.get("error"), 300)
        return Event(
            type=etype, title=f"Scan {kind} on {target} {verb}".replace(" on  ", " "),
            summary=data.get("error") or "", data=data, url=dashboard_url("/scans"),
            id=stable_event_id(f"{etype}:{p.get('scan_id') or sid}"), **extra,
        )

    return None


# --------------------------------------------------------------------------- #
# Connectors from rows
# --------------------------------------------------------------------------- #

class SecretsUnavailable(RuntimeError):
    """The stored secret blob cannot be decrypted (key rotated away / dev key lost)."""


def build_connector(row: Mapping[str, Any], http: Any, pool: Any = None) -> Connector:
    """Instantiate the connector for an ``integrations`` row. Secrets are
    decrypted here, in memory only."""
    load_connectors()
    cls = REGISTRY.get(row["kind"])
    if cls is None:
        raise KeyError(f"unknown integration kind {row['kind']!r}")
    try:
        secret_values = secrets_mod.decrypt_secrets(row.get("secrets"))
    except Exception as exc:  # noqa: BLE001
        raise SecretsUnavailable(
            "stored credentials cannot be decrypted with the configured PADDOCK_SECRET_KEY; re-enter them"
        ) from exc
    conn = cls(_as_json(row.get("config"), {}), secret_values, http)
    # Connectors that open their own sockets (SIEM syslog, LAN controllers)
    # read this per-integration opt-in directly.
    conn.allow_private = bool(row.get("allow_private", False))
    # TICKET connectors persist finding<->ticket links and suppress echo loops;
    # they need to know which integration row they are and the DB pool.
    bind = getattr(conn, "bind", None)
    if callable(bind) and pool is not None:
        bind(integration_id=row["id"], pool=pool, allow_private=bool(row.get("allow_private", False)))
    return conn


# --------------------------------------------------------------------------- #
# Delivery engine
# --------------------------------------------------------------------------- #

def backoff_seconds(attempt: int, *, rng: random.Random | None = None) -> float:
    """Delay before retry number ``attempt`` (1 = first retry): exponential,
    capped, with +-10% jitter so a recovering endpoint isn't stampeded."""
    base = isettings.integrations_backoff_base_sec * (2 ** max(0, attempt - 1))
    delay = min(base, isettings.integrations_backoff_max_sec)
    r = (rng or random).uniform(0.9, 1.1)
    return max(1.0, delay * r)


_CLAIM_SQL = """
WITH due AS (
  SELECT id FROM integration_deliveries
   WHERE status IN ('pending', 'failed')
     AND next_attempt_at IS NOT NULL
     AND next_attempt_at <= NOW()
   ORDER BY next_attempt_at
   LIMIT $1
   FOR UPDATE SKIP LOCKED
)
UPDATE integration_deliveries d
   SET next_attempt_at = NOW() + make_interval(secs => $2), updated_at = NOW()
  FROM due
 WHERE d.id = due.id
RETURNING d.id, d.integration_id, d.event_id, d.event_type, d.attempts, d.payload
"""

_INTEGRATION_SQL = """
SELECT id, kind, name, enabled, config, secrets, events, min_severity, filters, allow_private
  FROM integrations WHERE id = $1
"""


async def claim_due(pool: Any, limit: int | None = None) -> list[dict[str, Any]]:
    rows = await pool.fetch(_CLAIM_SQL, limit or isettings.integrations_batch,
                            float(isettings.integrations_lease_sec))
    return [dict(r) for r in rows]


async def record_result(pool: Any, delivery_id: int, integration_id: Any, attempts_before: int,
                        result: DeliveryResult, *, final: bool = False) -> str:
    """Persist the outcome of one attempt; returns the new status.

    ``final=True`` (the synchronous Test send) never schedules a retry."""
    attempts = attempts_before + 1
    detail = (result.detail or "")[:1000]
    if result.ok:
        status, next_at = "sent", None
    elif final:
        status, next_at = "failed", None
    elif result.retryable and attempts < isettings.integrations_max_attempts:
        status, next_at = "failed", backoff_seconds(attempts)
    else:
        status, next_at = "dead", None
        if result.retryable:
            detail = f"{detail} (gave up after {attempts} attempts)"[:1000]
    await pool.execute(
        """
        UPDATE integration_deliveries
           SET status = $2, attempts = $3, status_code = $4, detail = $5,
               next_attempt_at = CASE WHEN $6::float8 IS NULL THEN NULL
                                      ELSE NOW() + make_interval(secs => $6::float8) END,
               updated_at = NOW()
         WHERE id = $1
        """,
        delivery_id, status, attempts, result.status_code, detail, next_at,
    )
    await mark_integration(pool, integration_id, result)
    return status


async def mark_integration(pool: Any, integration_id: Any, result: DeliveryResult) -> None:
    if result.ok:
        await pool.execute("UPDATE integrations SET last_ok_at = NOW() WHERE id = $1", integration_id)
    else:
        await pool.execute(
            "UPDATE integrations SET last_error = $2, last_error_at = NOW() WHERE id = $1",
            integration_id, (result.detail or "delivery failed")[:500],
        )


async def _skip(pool: Any, delivery_id: int, detail: str) -> None:
    await pool.execute(
        "UPDATE integration_deliveries SET status = 'skipped', detail = $2, next_attempt_at = NULL, "
        "updated_at = NOW() WHERE id = $1", delivery_id, detail,
    )


async def _attempt(connector: Connector, event: Event) -> DeliveryResult:
    try:
        res = await connector.deliver(event)
    except NotImplementedError:
        return DeliveryResult(ok=False, retryable=False, detail="this integration cannot deliver events")
    except Exception as exc:  # noqa: BLE001 -- never echo the message (may hold secrets)
        log.warning("connector_deliver_raised", extra={"kind": connector.kind, "exc": type(exc).__name__})
        return DeliveryResult(ok=False, retryable=True, detail=f"connector error ({type(exc).__name__})")
    if not isinstance(res, DeliveryResult):
        return DeliveryResult(ok=False, retryable=False, detail="connector returned no result")
    return res


async def process_due(pool: Any, *, transport: Optional[httpx.AsyncBaseTransport] = None,
                      limit: int | None = None) -> int:
    """Deliver one batch of due deliveries. Returns how many were attempted."""
    claimed = await claim_due(pool, limit)
    if not claimed:
        return 0
    by_integration: dict[Any, list[dict[str, Any]]] = {}
    for d in claimed:
        by_integration.setdefault(d["integration_id"], []).append(d)

    for integration_id, items in by_integration.items():
        row = await pool.fetchrow(_INTEGRATION_SQL, integration_id)
        if row is None:
            continue                           # cascade-deleted meanwhile
        row = dict(row)
        if not row["enabled"]:
            for d in items:
                await _skip(pool, d["id"], "integration disabled")
            continue
        async with make_client(allow_private=bool(row["allow_private"]), transport=transport) as http:
            try:
                connector = build_connector(row, http, pool)
            except (KeyError, SecretsUnavailable) as exc:
                res = DeliveryResult(ok=False, retryable=False, detail=str(exc).strip("'\""))
                for d in items:
                    await record_result(pool, d["id"], integration_id, d["attempts"], res)
                continue
            for d in items:
                try:
                    event = event_from_dict(_as_json(d["payload"], {}))
                except Exception:  # noqa: BLE001
                    await record_result(pool, d["id"], integration_id, d["attempts"],
                                        DeliveryResult(ok=False, retryable=False, detail="stored event is malformed"))
                    continue
                res = await _attempt(connector, event)
                status = await record_result(pool, d["id"], integration_id, d["attempts"], res)
                log.info("integration_delivery", extra={
                    "integration_id": str(integration_id), "kind": row["kind"], "delivery_id": d["id"],
                    "event_type": d["event_type"], "status": status, "status_code": res.status_code,
                })
            del connector                      # drop decrypted secrets promptly
    return len(claimed)


async def send_now(pool: Any, row: Mapping[str, Any], event: Event, *,
                   transport: Optional[httpx.AsyncBaseTransport] = None) -> tuple[DeliveryResult, Optional[int]]:
    """Synchronous single delivery (the Test button). Recorded in the
    delivery log like any other, but never retried."""
    did = await pool.fetchval(
        "INSERT INTO integration_deliveries (integration_id, event_id, event_type, status, attempts, payload) "
        "VALUES ($1, $2, $3, 'pending', 0, $4::jsonb) "
        "ON CONFLICT (integration_id, event_id) DO NOTHING RETURNING id",
        row["id"], event.id, event.type, event_payload(event),
    )
    async with make_client(allow_private=bool(row.get("allow_private")), transport=transport) as http:
        try:
            connector = build_connector(row, http)
        except (KeyError, SecretsUnavailable) as exc:
            res = DeliveryResult(ok=False, retryable=False, detail=str(exc).strip("'\""))
        else:
            res = await _attempt(connector, event)
    if did is not None:
        await record_result(pool, did, row["id"], 0, res, final=True)
    else:
        await mark_integration(pool, row["id"], res)
    return res, did


async def health_check(row: Mapping[str, Any], *, transport: Optional[httpx.AsyncBaseTransport] = None):
    """Run ``connector.test()`` (no event, no delivery row)."""
    from .base import HealthResult

    async with make_client(allow_private=bool(row.get("allow_private")), transport=transport) as http:
        try:
            connector = build_connector(row, http)
            return await connector.test()
        except (KeyError, SecretsUnavailable) as exc:
            return HealthResult(ok=False, detail=str(exc).strip("'\""))
        except Exception as exc:  # noqa: BLE001
            return HealthResult(ok=False, detail=f"connector error ({type(exc).__name__})")


def make_test_event(row: Mapping[str, Any]) -> Event:
    return Event(
        type="integration.test",
        title="Paddock test event",
        summary=f"If you can read this, the '{row.get('name')}' integration is wired up correctly.",
        severity="info",
        data={"integration_id": str(row.get("id")), "integration_name": row.get("name"),
              "asset": "paddock.example", "asset_kind": "domain"},
        url=dashboard_url("/integrations"),
    )


def known_event_types() -> Iterable[str]:
    return EVENT_TYPES.keys()
