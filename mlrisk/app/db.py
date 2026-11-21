"""Asyncpg connection pool + helpers for the mlrisk tables.

We OWN writes to ``ml_models``, ``ml_risk_scores`` and ``anomalies``. We READ
findings / assets / attack_paths / tickets / sbom_component_vulns /
surface_changes / cves and the ``ml_training_labels`` view to build features and
labels. No HTTP, no external calls — everything is the platform's own data.

Mirrors ``intel/app/db.py``: same JSON codec install + pool lifecycle.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import asyncpg

log = logging.getLogger("mlrisk.db")


async def _init_connection(conn: asyncpg.Connection) -> None:
    """Install JSON codecs so we can pass dicts/lists directly."""
    await conn.set_type_codec(
        "jsonb",
        encoder=lambda v: json.dumps(v, default=str),
        decoder=json.loads,
        schema="pg_catalog",
    )
    await conn.set_type_codec(
        "json",
        encoder=lambda v: json.dumps(v, default=str),
        decoder=json.loads,
        schema="pg_catalog",
    )


# ---------------------------------------------------------------------------
# Feature SQL. Produces one raw dict per finding with every input the feature
# builder needs. Used for both the open-findings scan and (joined to the
# ml_training_labels view) the labeled training set.
# ---------------------------------------------------------------------------
_FEATURE_CTE = """
WITH feat AS (
  SELECT
    f.id                                             AS finding_id,
    f.severity                                       AS severity,
    COALESCE(f.cvss, c.cvss_v3)                      AS cvss,
    COALESCE(f.epss, c.epss)                         AS epss,
    f.rule_source                                    AS rule_source,
    f.status                                         AS status,
    f.first_seen                                     AS first_seen,
    COALESCE(
      (f.metadata->>'blast_score')::float,
      (a.metadata->>'blast_score')::float,
      0
    )                                                AS blast_score,
    COALESCE(
      (f.metadata->>'kev')::boolean,
      c.known_exploited,
      false
    )                                                AS kev,
    COALESCE(
      NULLIF(f.metadata->>'reachability', ''),
      scv.reachability,
      'unknown'
    )                                                AS reachability,
    COALESCE(ap.on_path, false)                      AS on_attack_path,
    COALESCE(ap.max_exploit, 0)                      AS max_path_exploitability,
    COALESCE(
      (a.metadata->>'internet_exposed')::boolean,
      (a.metadata->>'exposure') IN ('internet', 'external', 'public'),
      (a.metadata->>'env') = 'internet',
      false
    )                                                AS internet_exposed,
    COALESCE(
      (a.metadata->>'env') IN ('prod', 'production'),
      false
    )                                                AS prod_env
  FROM findings f
  JOIN assets a ON a.id = f.asset_id
  LEFT JOIN cves c
         ON c.id = f.rule_id AND f.rule_source = 'cve_match'
  LEFT JOIN LATERAL (
    SELECT scv2.reachability
      FROM sbom_component_vulns scv2
     WHERE scv2.cve_id = f.rule_id OR scv2.osv_id = f.rule_id
     ORDER BY CASE scv2.reachability
                WHEN 'reachable'   THEN 3
                WHEN 'potential'   THEN 2
                WHEN 'unreachable' THEN 1
                ELSE 0 END DESC
     LIMIT 1
  ) scv ON TRUE
  LEFT JOIN LATERAL (
    SELECT (COUNT(*) > 0) AS on_path, MAX(p.exploitability) AS max_exploit
      FROM attack_paths p
     WHERE p.source_asset_id = f.asset_id
        OR p.target_asset_id = f.asset_id
        OR p.hops @> jsonb_build_array(jsonb_build_object('asset_id', f.asset_id::text))
  ) ap ON TRUE
)
"""


class Database:
    """Thin wrapper around an asyncpg pool."""

    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 8) -> None:
        self.dsn = dsn
        self._min = min_size
        self._max = max_size
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            dsn=self.dsn,
            min_size=self._min,
            max_size=self._max,
            init=_init_connection,
            command_timeout=60,
        )
        log.info("db: pool connected (%s/%s)", self._min, self._max)

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("db pool not initialised; call connect()")
        return self._pool

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[asyncpg.Connection]:
        async with self.pool.acquire() as conn:
            yield conn

    async def ping(self) -> bool:
        try:
            async with self.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("db ping failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # feature reads
    # ------------------------------------------------------------------
    async def fetch_open_feature_rows(self) -> list[dict[str, Any]]:
        """Raw feature rows for every OPEN finding (scored into ml_risk_scores)."""
        sql = _FEATURE_CTE + "SELECT * FROM feat WHERE status = 'open'"
        async with self.acquire() as conn:
            rows = await conn.fetch(sql)
        return [dict(r) for r in rows]

    async def fetch_labeled_feature_rows(self) -> list[dict[str, Any]]:
        """Raw feature rows + label for findings the analysts have triaged.

        Labels come from the ``ml_training_labels`` view (1 acted-on, 0 dismissed,
        NULL unlabeled). Only non-NULL labels are returned.
        """
        sql = _FEATURE_CTE + """
        SELECT feat.*, l.label
          FROM feat
          JOIN ml_training_labels l ON l.finding_id = feat.finding_id
         WHERE l.label IS NOT NULL
        """
        async with self.acquire() as conn:
            rows = await conn.fetch(sql)
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # anomaly feature reads
    # ------------------------------------------------------------------
    async def fetch_host_subject_rows(self) -> list[dict[str, Any]]:
        """Per-host feature vectors for the subject anomaly detector.

        A "host" here is a subdomain/ipv4/ipv6 asset. Ports/techs/findings are
        rolled up from the asset graph + findings tables.
        """
        sql = """
        SELECT
          h.id   AS subject_id,
          h.value AS subject_label,
          COALESCE(ports.n, 0)              AS open_port_count,
          COALESCE(techs.n, 0)              AS tech_count,
          COALESCE(find.crit_high, 0)       AS crit_high_count,
          COALESCE(find.total, 0)           AS finding_count,
          COALESCE((h.metadata->>'blast_score')::float, 0) AS blast_score,
          COALESCE(chg.n, 0)                AS recent_change_count
        FROM assets h
        LEFT JOIN LATERAL (
          SELECT COUNT(*) AS n FROM asset_edges e
            JOIN assets p ON p.id = e.dst_id AND p.kind = 'port'
           WHERE e.src_id = h.id
        ) ports ON TRUE
        LEFT JOIN LATERAL (
          SELECT COUNT(*) AS n FROM asset_edges e
            JOIN assets t ON t.id = e.dst_id AND t.kind = 'technology'
           WHERE e.src_id = h.id
        ) techs ON TRUE
        LEFT JOIN LATERAL (
          SELECT COUNT(*) AS total,
                 COUNT(*) FILTER (WHERE f.severity IN ('high', 'critical')) AS crit_high
            FROM findings f
           WHERE f.asset_id = h.id AND f.status = 'open'
        ) find ON TRUE
        LEFT JOIN LATERAL (
          SELECT COUNT(*) AS n FROM surface_changes sc
           WHERE sc.asset_id = h.id
             AND sc.detected_at > NOW() - INTERVAL '14 days'
        ) chg ON TRUE
        WHERE h.kind IN ('subdomain', 'ipv4', 'ipv6')
        """
        async with self.acquire() as conn:
            rows = await conn.fetch(sql)
        out = []
        for r in rows:
            d = dict(r)
            d["subject_type"] = "host"
            out.append(d)
        return out

    async def fetch_velocity_rows(
        self, window_h: int = 24, baseline_days: int = 14
    ) -> list[dict[str, Any]]:
        """Recent vs trailing change rate, per host, for velocity anomalies."""
        sql = """
        SELECT
          h.id    AS subject_id,
          h.value AS subject_label,
          COALESCE(r.recent, 0)                                   AS recent_count,
          COALESCE(r.recent, 0)::float / ($1::float / 24.0)       AS recent_rate,
          COALESCE(b.base, 0)::float / $2::float                  AS baseline_rate
        FROM assets h
        LEFT JOIN LATERAL (
          SELECT COUNT(*) AS recent FROM surface_changes sc
           WHERE sc.asset_id = h.id
             AND sc.detected_at > NOW() - make_interval(hours => $1)
        ) r ON TRUE
        LEFT JOIN LATERAL (
          SELECT COUNT(*) AS base FROM surface_changes sc
           WHERE sc.asset_id = h.id
             AND sc.detected_at <= NOW() - make_interval(hours => $1)
             AND sc.detected_at >  NOW() - make_interval(days => $2)
        ) b ON TRUE
        WHERE h.kind IN ('subdomain', 'ipv4', 'ipv6')
        """
        async with self.acquire() as conn:
            rows = await conn.fetch(sql, window_h, baseline_days)
        out = []
        for r in rows:
            d = dict(r)
            d["subject_type"] = "change_velocity"
            out.append(d)
        return out

    # ------------------------------------------------------------------
    # ml_models
    # ------------------------------------------------------------------
    async def next_version(self, kind: str) -> int:
        async with self.acquire() as conn:
            val = await conn.fetchval(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM ml_models WHERE kind = $1", kind
            )
        return int(val or 1)

    async def insert_model(
        self,
        kind: str,
        version: int,
        algo: str,
        n_samples: int,
        metrics: dict[str, Any],
        feature_importance: dict[str, Any],
        cold_start: bool,
        notes: str = "",
    ) -> str:
        """Insert a model row and make it the sole active row for its kind."""
        async with self.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "UPDATE ml_models SET active = FALSE WHERE kind = $1", kind
                )
                row = await conn.fetchrow(
                    """
                    INSERT INTO ml_models
                      (version, kind, algo, n_samples, metrics,
                       feature_importance, cold_start, active, notes)
                    VALUES ($1,$2,$3,$4,$5,$6,$7, TRUE, $8)
                    RETURNING id
                    """,
                    version, kind, algo, n_samples, metrics,
                    feature_importance, cold_start, notes,
                )
        return str(row["id"])

    async def active_model(self, kind: str) -> dict[str, Any] | None:
        async with self.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM ml_models WHERE kind = $1 AND active ORDER BY version DESC LIMIT 1",
                kind,
            )
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # ml_risk_scores
    # ------------------------------------------------------------------
    async def upsert_risk_scores(
        self, scores: list[dict[str, Any]], model_version: int
    ) -> int:
        if not scores:
            return 0
        sql = """
        INSERT INTO ml_risk_scores (finding_id, ml_risk, model_version, features, rationale)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (finding_id) DO UPDATE SET
            ml_risk       = EXCLUDED.ml_risk,
            model_version = EXCLUDED.model_version,
            features      = EXCLUDED.features,
            rationale     = EXCLUDED.rationale,
            scored_at     = NOW()
        """
        n = 0
        async with self.acquire() as conn:
            async with conn.transaction():
                for s in scores:
                    if not s.get("finding_id"):
                        continue
                    await conn.execute(
                        sql,
                        s["finding_id"],
                        float(s["ml_risk"]),
                        model_version,
                        s.get("features", {}),
                        s.get("rationale", []),
                    )
                    n += 1
        return n

    # ------------------------------------------------------------------
    # anomalies
    # ------------------------------------------------------------------
    async def insert_anomalies(
        self, anomalies: list[dict[str, Any]], model_version: int
    ) -> int:
        if not anomalies:
            return 0
        sql = """
        INSERT INTO anomalies
          (subject_type, subject_id, subject_label, score, severity,
           reason, features, model_version)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        ON CONFLICT (subject_type, subject_label, detected_at) DO NOTHING
        """
        n = 0
        async with self.acquire() as conn:
            async with conn.transaction():
                for a in anomalies:
                    await conn.execute(
                        sql,
                        a["subject_type"],
                        a.get("subject_id"),
                        a["subject_label"],
                        float(a["score"]),
                        a.get("severity", "medium"),
                        a["reason"],
                        a.get("features", {}),
                        model_version,
                    )
                    n += 1
        return n

    # ------------------------------------------------------------------
    # stats
    # ------------------------------------------------------------------
    async def counters(self) -> dict[str, int]:
        async with self.acquire() as conn:
            scored = await conn.fetchval("SELECT COUNT(*) FROM ml_risk_scores")
            anomalies = await conn.fetchval(
                "SELECT COUNT(*) FROM anomalies WHERE NOT acknowledged"
            )
            labels = await conn.fetchval(
                "SELECT COUNT(*) FROM ml_training_labels WHERE label IS NOT NULL"
            )
        return {
            "risk_scores": int(scored or 0),
            "anomalies_open": int(anomalies or 0),
            "labeled_samples": int(labels or 0),
        }
