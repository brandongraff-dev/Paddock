"""Change detection: diff the asset/finding graph against the cursor.

Each detector method returns a list of *candidate* ``surface_change`` dicts
(``change_type``, ``asset_id``, ``asset_kind``, ``asset_value``, ``severity``,
``summary``, ``detail``). ``ChangeDetector.run`` inserts them (deduped) and
returns the rows that were actually written — those are the "new this run"
changes the alerter matches against.

This module only ever reads the database. It sends packets to nothing.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Optional

from .config import Config
from .db import Database

log = logging.getLogger("changewatch.detect")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# kind -> (change_type, severity) for newly-seen assets (contract §Detection loop).
NEW_ASSET_MAP: dict[str, tuple[str, str]] = {
    "subdomain": ("subdomain_discovered", "low"),
    "endpoint": ("endpoint_discovered", "low"),
    "ipv4": ("ip_discovered", "low"),
    "ipv6": ("ip_discovered", "low"),
    "port": ("port_opened", "medium"),
    "technology": ("tech_detected", "medium"),
    "certificate": ("cert_added", "info"),
    "secret_candidate": ("secret_found", "high"),
    "repository": ("repository_found", "low"),
}

# NOW()-based change types dedupe forever (they would otherwise re-fire every
# pass); cursor-based types dedupe within a finite window.
_FOREVER_DEDUPE = {"asset_removed", "cert_expiring"}


class ChangeDetector:
    def __init__(self, db: Database, cfg: Config) -> None:
        self.db = db
        self.cfg = cfg

    # ------------------------------------------------------------------
    # orchestration
    # ------------------------------------------------------------------
    async def detect(self, since: datetime) -> list[dict[str, Any]]:
        """Produce all candidate changes since ``since`` (no writes)."""
        changes: list[dict[str, Any]] = []
        changes += await self.new_assets(since)
        changes += await self.new_findings(since)
        changes += await self.resolved_findings(since)
        changes += await self.stale_assets()
        changes += await self.expiring_certs()
        changes += await self.exposure_increased(since)
        return changes

    async def run(self, since: datetime) -> list[dict[str, Any]]:
        """Detect + insert; return the rows actually written (deduped)."""
        inserted: list[dict[str, Any]] = []
        window = timedelta(hours=self.cfg.dedupe_window_hours)
        for cand in await self.detect(since):
            dedupe_window = None if cand["change_type"] in _FOREVER_DEDUPE else window
            row = await self.db.insert_change(cand, dedupe_window=dedupe_window)
            if row is not None:
                inserted.append(row)
        return inserted

    # ------------------------------------------------------------------
    # detectors
    # ------------------------------------------------------------------
    async def new_assets(self, since: datetime) -> list[dict[str, Any]]:
        rows = await self.db.fetch(
            """
            SELECT id::text, kind, value, first_seen, metadata
              FROM assets
             WHERE first_seen > $1
               AND kind = ANY($2::text[])
             ORDER BY first_seen
            """,
            since, list(NEW_ASSET_MAP.keys()),
        )
        out: list[dict[str, Any]] = []
        for r in rows:
            change_type, severity = NEW_ASSET_MAP[r["kind"]]
            label = change_type.replace("_", " ")
            out.append({
                "change_type": change_type,
                "asset_id": r["id"],
                "asset_kind": r["kind"],
                "asset_value": r["value"],
                "severity": severity,
                "summary": f"{label}: {r['value']}",
                "detail": {
                    "kind": r["kind"],
                    "first_seen": r["first_seen"],
                    "metadata": r["metadata"],
                    "dedupe": f"{change_type}:{r['id']}",
                },
            })
        return out

    async def new_findings(self, since: datetime) -> list[dict[str, Any]]:
        rows = await self.db.fetch(
            """
            SELECT f.id::text AS finding_id, f.asset_id::text, f.severity,
                   f.title, f.rule_id, f.rule_source, f.first_seen,
                   a.kind AS asset_kind, a.value AS asset_value
              FROM findings f
              JOIN assets a ON a.id = f.asset_id
             WHERE f.first_seen > $1
             ORDER BY f.first_seen
            """,
            since,
        )
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append({
                "change_type": "finding_opened",
                "asset_id": r["asset_id"],
                "asset_kind": r["asset_kind"],
                "asset_value": r["asset_value"],
                # finding_opened inherits the finding's severity.
                "severity": r["severity"],
                "summary": f"Finding opened ({r['severity']}): {r['title']} on {r['asset_value']}",
                "detail": {
                    "finding_id": r["finding_id"],
                    "rule_id": r["rule_id"],
                    "rule_source": r["rule_source"],
                    "severity": r["severity"],
                    "dedupe": f"finding_opened:{r['finding_id']}",
                },
            })
        return out

    async def resolved_findings(self, since: datetime) -> list[dict[str, Any]]:
        # No status-change timestamp exists, so last_seen is the best proxy for
        # "moved to fixed/false_positive since the cursor".
        rows = await self.db.fetch(
            """
            SELECT f.id::text AS finding_id, f.asset_id::text, f.severity,
                   f.title, f.status, f.last_seen,
                   a.kind AS asset_kind, a.value AS asset_value
              FROM findings f
              JOIN assets a ON a.id = f.asset_id
             WHERE f.status IN ('fixed', 'false_positive')
               AND f.last_seen > $1
             ORDER BY f.last_seen
            """,
            since,
        )
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append({
                "change_type": "finding_resolved",
                "asset_id": r["asset_id"],
                "asset_kind": r["asset_kind"],
                "asset_value": r["asset_value"],
                "severity": "info",
                "summary": f"Finding resolved ({r['status']}): {r['title']} on {r['asset_value']}",
                "detail": {
                    "finding_id": r["finding_id"],
                    "status": r["status"],
                    "dedupe": f"finding_resolved:{r['finding_id']}",
                },
            })
        return out

    async def stale_assets(self) -> list[dict[str, Any]]:
        rows = await self.db.fetch(
            """
            SELECT id::text, kind, value, last_seen, metadata
              FROM assets
             WHERE last_seen < NOW() - make_interval(days => $1)
             ORDER BY last_seen
            """,
            self.cfg.stale_days,
        )
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append({
                "change_type": "asset_removed",
                "asset_id": r["id"],
                "asset_kind": r["kind"],
                "asset_value": r["value"],
                "severity": "low",
                "summary": f"Asset no longer seen (stale >{self.cfg.stale_days}d): {r['value']}",
                "detail": {
                    "kind": r["kind"],
                    "last_seen": r["last_seen"],
                    "stale_days": self.cfg.stale_days,
                    "dedupe": f"asset_removed:{r['id']}",
                },
            })
        return out

    async def expiring_certs(self) -> list[dict[str, Any]]:
        rows = await self.db.fetch(
            """
            SELECT id::text, kind, value, metadata,
                   (metadata->>'not_after')::timestamptz AS not_after
              FROM assets
             WHERE kind = 'certificate'
               AND metadata ? 'not_after'
               AND metadata->>'not_after' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
               AND (metadata->>'not_after')::timestamptz < NOW() + make_interval(days => $1)
             ORDER BY not_after
            """,
            self.cfg.cert_expiry_days,
        )
        out: list[dict[str, Any]] = []
        for r in rows:
            na = r["not_after"]
            out.append({
                "change_type": "cert_expiring",
                "asset_id": r["id"],
                "asset_kind": r["kind"],
                "asset_value": r["value"],
                "severity": "medium",
                "summary": f"Certificate expiring {na:%Y-%m-%d}: {r['value']}",
                "detail": {
                    "not_after": na,
                    "expiry_days": self.cfg.cert_expiry_days,
                    "dedupe": f"cert_expiring:{r['id']}",
                },
            })
        return out

    async def exposure_increased(self, since: datetime) -> list[dict[str, Any]]:
        # A host (subdomain/ip) that gained a new open port OR a new public
        # endpoint since the cursor — detected either by a new edge or a newly
        # first_seen port/public-endpoint neighbour.
        rows = await self.db.fetch(
            """
            SELECT DISTINCT
                   h.id::text    AS host_id,
                   h.kind        AS host_kind,
                   h.value       AS host_value,
                   other.id::text AS gained_id,
                   other.kind    AS gained_kind,
                   other.value   AS gained_value
              FROM assets h
              JOIN asset_edges e
                ON (e.src_id = h.id OR e.dst_id = h.id)
              JOIN assets other
                ON other.id = CASE WHEN e.src_id = h.id THEN e.dst_id ELSE e.src_id END
             WHERE h.kind IN ('subdomain', 'ipv4', 'ipv6')
               AND (
                     other.kind = 'port'
                  OR (other.kind = 'endpoint' AND other.metadata @> '{"public": true}'::jsonb)
               )
               AND (e.first_seen > $1 OR other.first_seen > $1)
            """,
            since,
        )
        out: list[dict[str, Any]] = []
        for r in rows:
            gained = "open port" if r["gained_kind"] == "port" else "public endpoint"
            out.append({
                "change_type": "exposure_increased",
                "asset_id": r["host_id"],
                "asset_kind": r["host_kind"],
                "asset_value": r["host_value"],
                "severity": "high",
                "summary": f"Exposure increased: {r['host_value']} gained {gained} {r['gained_value']}",
                "detail": {
                    "gained_kind": r["gained_kind"],
                    "gained_value": r["gained_value"],
                    "gained_asset_id": r["gained_id"],
                    "dedupe": f"exposure_increased:{r['host_id']}:{r['gained_id']}",
                },
            })
        return out
