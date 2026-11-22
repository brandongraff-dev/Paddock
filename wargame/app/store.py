"""Persistence for the Proving Ground: scenario catalogue, runs, proofs.

All writes go through the tenant-scoped connection (RLS fills tenant_id). Proof
entries are append-only (the immutability trigger blocks UPDATE); a re-run of
the same fingerprint replaces the run's proofs by DELETE+INSERT inside one
transaction, which the trigger permits.
"""
from __future__ import annotations

from typing import Any, Optional

from . import tenancy
from .db import Database
from .engine.prover import ProverResult
from .scenarios.base import ScenarioCtx


class WargameStore:
    def __init__(self, db: Database) -> None:
        self._db = db

    # -- catalogue (global) ------------------------------------------------- #

    async def sync_catalog(self, rows: list[dict[str, Any]]) -> int:
        """Upsert the scenario catalogue. wargame_scenarios is a global
        catalogue, so writes run as the platform tenant."""
        n = 0
        async with self._db.acquire_platform() as conn:
            for r in rows:
                await conn.execute(
                    """
                    INSERT INTO wargame_scenarios (id, title, description, category,
                        technique, enabled, spec, updated_at)
                    VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,NOW())
                    ON CONFLICT (id) DO UPDATE SET
                        title=EXCLUDED.title, description=EXCLUDED.description,
                        category=EXCLUDED.category, technique=EXCLUDED.technique,
                        enabled=EXCLUDED.enabled, spec=EXCLUDED.spec, updated_at=NOW()
                    """,
                    r["id"], r["title"], r.get("description", ""), r["category"],
                    r.get("technique"), bool(r.get("enabled", True)), r.get("spec") or {},
                )
                n += 1
        return n

    async def scenarios(self) -> list[dict[str, Any]]:
        rows = await self._db.fetch(
            "SELECT id, title, description, category, technique, enabled, spec "
            "FROM wargame_scenarios ORDER BY id"
        )
        return [dict(r) for r in rows]

    # -- runs + proofs ------------------------------------------------------ #

    async def record(self, result: ProverResult, ctx: ScenarioCtx) -> str:
        """Persist a prover result and its proof chain. Returns the run id."""
        completed = result.status in ("done", "refused", "error")
        async with self._db.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO wargame_runs (attack_path_id, target_asset_id, scenario_id,
                    component, status, phase, before_verdict, after_verdict, outcome,
                    fix_ref, isolation, requested_by, reason, fingerprint,
                    completed_at, metadata)
                VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,
                    CASE WHEN $15 THEN NOW() ELSE NULL END, $16::jsonb)
                ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
                    attack_path_id=EXCLUDED.attack_path_id,
                    target_asset_id=EXCLUDED.target_asset_id,
                    scenario_id=EXCLUDED.scenario_id, component=EXCLUDED.component,
                    status=EXCLUDED.status, phase=EXCLUDED.phase,
                    before_verdict=EXCLUDED.before_verdict,
                    after_verdict=EXCLUDED.after_verdict, outcome=EXCLUDED.outcome,
                    fix_ref=EXCLUDED.fix_ref, isolation=EXCLUDED.isolation,
                    reason=EXCLUDED.reason, completed_at=EXCLUDED.completed_at,
                    metadata=EXCLUDED.metadata, started_at=NOW()
                RETURNING id::text AS id
                """,
                _uuid_or_none(ctx.path.get("attack_path_id")),
                _uuid_or_none(ctx.path.get("target_asset_id")),
                result.scenario_id,
                result.component,
                result.status,
                _phase(result),
                result.before_verdict,
                result.after_verdict,
                result.outcome,
                result.fix_ref or None,
                result.isolation,
                ctx.path.get("requested_by") or "system:wargame",
                result.reason,
                result.fingerprint,
                completed,
                {},
            )
            run_id = row["id"]
            # Replace any prior proof chain for this run (append-only forbids
            # UPDATE, but DELETE+INSERT of a fresh chain is allowed).
            await conn.execute(
                "DELETE FROM wargame_proofs WHERE run_id = $1::uuid", run_id
            )
            for entry in result.proofs:
                r = entry.as_row()
                await conn.execute(
                    """
                    INSERT INTO wargame_proofs (run_id, seq, phase, prev_hash,
                        payload_hash, entry_hash, signature, key_id, payload)
                    VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
                    """,
                    run_id, r["seq"], r["phase"], r["prev_hash"], r["payload_hash"],
                    r["entry_hash"], r["signature"], r["key_id"], r["payload"],
                )
        return run_id

    async def get_run(self, run_id: str) -> Optional[dict[str, Any]]:
        row = await self._db.fetchrow(
            "SELECT id::text AS id, attack_path_id::text AS attack_path_id, "
            "target_asset_id::text AS target_asset_id, scenario_id, component, status, "
            "phase, before_verdict, after_verdict, outcome, fix_ref, isolation, "
            "reason, fingerprint, started_at, completed_at "
            "FROM wargame_runs WHERE id = $1::uuid",
            run_id,
        )
        return dict(row) if row else None

    async def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = await self._db.fetch(
            "SELECT id::text AS id, scenario_id, outcome, status, before_verdict, "
            "after_verdict, fix_ref, started_at, completed_at "
            "FROM wargame_runs ORDER BY started_at DESC LIMIT $1",
            max(1, min(int(limit), 500)),
        )
        return [dict(r) for r in rows]

    async def get_proofs(self, run_id: str) -> list[dict[str, Any]]:
        rows = await self._db.fetch(
            "SELECT seq, phase, prev_hash, payload_hash, entry_hash, signature, "
            "key_id, payload, created_at FROM wargame_proofs "
            "WHERE run_id = $1::uuid ORDER BY seq",
            run_id,
        )
        return [dict(r) for r in rows]

    async def count_runs(self) -> int:
        return int(await self._db.fetchval("SELECT COUNT(*) FROM wargame_runs") or 0)


def _phase(result: ProverResult) -> str:
    return result.status if result.status != "done" else (result.outcome or "done")


def _uuid_or_none(v: Any) -> Optional[str]:
    try:
        return tenancy.norm(v)
    except Exception:
        return None
