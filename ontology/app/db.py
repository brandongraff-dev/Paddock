"""Asyncpg connection pool + the projection engine.

We own writes to the ``ontology_*`` tables ONLY. Every other table
(assets, asset_edges, findings, attack_paths, tickets, sbom_components,
sca_projects) is read strictly read-only.

The projection is a single idempotent pass:
  1. seed the type system (upsert object/link types)
  2. bulk-load every backing source (no N+1)
  3. map rows -> typed objects, bulk-upsert, read back ids
  4. derive links from edges/findings/paths/tickets/sbom, bulk-upsert
  5. prune objects/links whose backing source vanished -- all in one txn
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import asyncpg

from . import types as T

log = logging.getLogger(__name__)


async def _init_connection(conn: asyncpg.Connection) -> None:
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


class Database:
    """Thin wrapper around an asyncpg pool + the projector."""

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
            command_timeout=120,
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

    # ------------------------------------------------------------------ #
    # Type-system seed (idempotent)
    # ------------------------------------------------------------------ #
    async def seed_types(self) -> dict[str, int]:
        async with self.acquire() as conn:
            async with conn.transaction():
                for name, spec in T.OBJECT_TYPES.items():
                    await conn.execute(
                        """
                        INSERT INTO ontology_object_types
                            (name, display, icon, color, property_schema, source, enabled)
                        VALUES ($1,$2,$3,$4,$5::jsonb,$6,TRUE)
                        ON CONFLICT (name) DO UPDATE SET
                            display = EXCLUDED.display,
                            icon = EXCLUDED.icon,
                            color = EXCLUDED.color,
                            property_schema = EXCLUDED.property_schema,
                            source = EXCLUDED.source,
                            enabled = TRUE
                        """,
                        name, spec["display"], spec["icon"], spec["color"],
                        json.dumps(spec["property_schema"]), spec["source"],
                    )
                for name, spec in T.LINK_TYPES.items():
                    await conn.execute(
                        """
                        INSERT INTO ontology_link_types
                            (name, display, from_type, to_type, cardinality)
                        VALUES ($1,$2,$3,$4,$5)
                        ON CONFLICT (name) DO UPDATE SET
                            display = EXCLUDED.display,
                            from_type = EXCLUDED.from_type,
                            to_type = EXCLUDED.to_type,
                            cardinality = EXCLUDED.cardinality
                        """,
                        name, spec["display"], spec["from_type"],
                        spec["to_type"], spec["cardinality"],
                    )
        return {"object_types": len(T.OBJECT_TYPES), "link_types": len(T.LINK_TYPES)}

    # ------------------------------------------------------------------ #
    # Projection
    # ------------------------------------------------------------------ #
    async def project(self) -> dict[str, Any]:
        """Run a full projection pass. Returns counts."""
        await self.seed_types()
        async with self.acquire() as conn:
            async with conn.transaction():
                return await self._project_txn(conn)

    async def _project_txn(self, conn: asyncpg.Connection) -> dict[str, Any]:
        # --- 1. bulk-load sources ------------------------------------- #
        asset_rows = await conn.fetch(
            "SELECT id, kind, value, canonical, confidence, source, metadata, "
            "classification FROM assets"
        )
        finding_rows = await conn.fetch(
            "SELECT id, asset_id, rule_id, rule_source, severity, status, title, "
            "cvss, epss, classification FROM findings"
        )
        edge_rows = await conn.fetch(
            "SELECT e.src_id, e.dst_id, e.kind, s.kind AS src_kind, d.kind AS dst_kind "
            "FROM asset_edges e "
            "JOIN assets s ON s.id = e.src_id "
            "JOIN assets d ON d.id = e.dst_id"
        )
        ticket_rows = await conn.fetch(
            "SELECT id, finding_id, title, status, severity, system, owner_team, "
            "sla_due, breached FROM tickets"
        )
        path_rows = await conn.fetch(
            "SELECT id, source_asset_id, target_asset_id, hops, length, severity, "
            "exploitability, kev_on_path, title FROM attack_paths"
        )
        component_rows = await conn.fetch(
            "SELECT id, project_id, ecosystem, name, version, purl, direct, depth "
            "FROM sbom_components"
        )
        project_rows = await conn.fetch(
            "SELECT id, asset_id FROM sca_projects"
        )
        project_asset = {str(r["id"]): r["asset_id"] for r in project_rows}

        # --- 2. map rows -> objects ----------------------------------- #
        objects: dict[tuple[str, str], dict[str, Any]] = {}

        def _add_obj(obj: dict[str, Any] | None) -> None:
            if obj is None:
                return
            key = (obj["backing_table"], obj["backing_id"])
            objects[key] = obj

        for r in asset_rows:
            _add_obj(T.asset_to_object(dict(r)))
        for r in finding_rows:
            _add_obj(T.finding_to_object(dict(r)))
        for r in component_rows:
            _add_obj(T.package_to_object(dict(r)))
        for r in ticket_rows:
            _add_obj(T.ticket_to_object(dict(r)))
            team = r["owner_team"]
            if team:
                _add_obj(T.team_to_object(team))
        for r in path_rows:
            _add_obj(T.attackpath_to_object(dict(r)))

        # --- 3. bulk-upsert objects, read back ids -------------------- #
        id_by_backing: dict[tuple[str, str], str] = {}
        live_object_ids: list[str] = []
        if objects:
            vals = list(objects.values())
            rows = await conn.fetch(
                """
                INSERT INTO ontology_objects AS o
                    (object_type, title, properties, backing_table, backing_id, classification)
                SELECT ot, ti, pr::jsonb, bt, bi, cl
                  FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[])
                       AS t(ot, ti, pr, bt, bi, cl)
                ON CONFLICT (object_type, backing_table, backing_id) DO UPDATE SET
                    title = EXCLUDED.title,
                    properties = EXCLUDED.properties,
                    classification = EXCLUDED.classification,
                    last_seen = NOW()
                RETURNING id, backing_table, backing_id
                """,
                [v["object_type"] for v in vals],
                [v["title"] for v in vals],
                [json.dumps(v["properties"]) for v in vals],
                [v["backing_table"] for v in vals],
                [v["backing_id"] for v in vals],
                [v["classification"] for v in vals],
            )
            for row in rows:
                oid = str(row["id"])
                id_by_backing[(row["backing_table"], row["backing_id"])] = oid
                live_object_ids.append(oid)

        def _oid_asset(asset_id: Any) -> str | None:
            return id_by_backing.get(("assets", str(asset_id))) if asset_id else None

        # --- 4. derive links ------------------------------------------ #
        # keyed by (link_type, from, to) to dedup; value = properties dict
        links: dict[tuple[str, str, str], dict[str, Any]] = {}

        def _add_link(link_type: str, frm: str | None, to: str | None,
                      props: dict[str, Any] | None = None) -> None:
            if not frm or not to or frm == to:
                return
            links[(link_type, frm, to)] = props or {}

        # object_type lookup by asset id (for edge orientation)
        asset_type = {str(r["id"]): T.ASSET_KIND_TO_TYPE.get(r["kind"]) for r in asset_rows}

        # 4a. edges -> RESOLVES_TO / RUNS / SECURES / CONTAINS
        for e in edge_rows:
            st = T.ASSET_KIND_TO_TYPE.get(e["src_kind"])
            dt = T.ASSET_KIND_TO_TYPE.get(e["dst_kind"])
            verdict = T.classify_edge(st, dt, e["kind"])
            if verdict is None:
                continue
            link_type, from_type = verdict
            src_oid = _oid_asset(e["src_id"])
            dst_oid = _oid_asset(e["dst_id"])
            if from_type is None or st == from_type:
                _add_link(link_type, src_oid, dst_oid, {"edge_kind": e["kind"]})
            else:
                _add_link(link_type, dst_oid, src_oid, {"edge_kind": e["kind"]})

        # 4b. findings -> AFFECTS (Vulnerability -> asset object)
        for r in finding_rows:
            v_oid = id_by_backing.get(("findings", str(r["id"])))
            a_oid = _oid_asset(r["asset_id"])
            _add_link("AFFECTS", v_oid, a_oid, {"severity": r["severity"]})

        # 4c. attack paths -> ON_PATH (Host -> AttackPath) for each hop host
        for r in path_rows:
            p_oid = id_by_backing.get(("attack_paths", str(r["id"])))
            if not p_oid:
                continue
            hop_ids: list[Any] = []
            hops = r["hops"]
            if isinstance(hops, str):
                try:
                    hops = json.loads(hops)
                except json.JSONDecodeError:
                    hops = []
            for h in hops or []:
                if isinstance(h, dict) and h.get("asset_id"):
                    hop_ids.append(h["asset_id"])
            if r["source_asset_id"]:
                hop_ids.append(r["source_asset_id"])
            if r["target_asset_id"]:
                hop_ids.append(r["target_asset_id"])
            for aid in hop_ids:
                if asset_type.get(str(aid)) == "Host":
                    _add_link("ON_PATH", _oid_asset(aid), p_oid)

        # 4d. tickets -> TRACKS (Ticket -> Vulnerability) + OWNED_BY (Host -> Team)
        finding_asset = {str(r["id"]): r["asset_id"] for r in finding_rows}
        for r in ticket_rows:
            t_oid = id_by_backing.get(("tickets", str(r["id"])))
            if r["finding_id"]:
                v_oid = id_by_backing.get(("findings", str(r["finding_id"])))
                _add_link("TRACKS", t_oid, v_oid)
                team = r["owner_team"]
                if team:
                    team_oid = id_by_backing.get(("team", team))
                    aid = finding_asset.get(str(r["finding_id"]))
                    if aid and asset_type.get(str(aid)) == "Host":
                        _add_link("OWNED_BY", _oid_asset(aid), team_oid,
                                  {"team": team})

        # 4e. sbom -> DECLARES (Repository -> Package)
        for r in component_rows:
            pkg_oid = id_by_backing.get(("sbom_components", str(r["id"])))
            repo_asset = project_asset.get(str(r["project_id"]))
            if repo_asset and asset_type.get(str(repo_asset)) == "Repository":
                _add_link("DECLARES", _oid_asset(repo_asset), pkg_oid)

        # --- 5. bulk-upsert links ------------------------------------- #
        live_link_ids: list[str] = []
        if links:
            keys = list(links.keys())
            rows = await conn.fetch(
                """
                INSERT INTO ontology_links AS l
                    (link_type, from_object, to_object, properties)
                SELECT lt, fo::uuid, too::uuid, pr::jsonb
                  FROM unnest($1::text[], $2::text[], $3::text[], $4::text[])
                       AS t(lt, fo, too, pr)
                ON CONFLICT (link_type, from_object, to_object) DO UPDATE SET
                    properties = EXCLUDED.properties
                RETURNING id
                """,
                [k[0] for k in keys],
                [k[1] for k in keys],
                [k[2] for k in keys],
                [json.dumps(links[k]) for k in keys],
            )
            live_link_ids = [str(row["id"]) for row in rows]

        # --- 6. prune vanished rows (links first, then objects) ------- #
        pruned_links = await conn.fetchval(
            "WITH d AS (DELETE FROM ontology_links WHERE id <> ALL($1::uuid[]) "
            "RETURNING 1) SELECT COUNT(*) FROM d",
            live_link_ids,
        )
        pruned_objects = await conn.fetchval(
            "WITH d AS (DELETE FROM ontology_objects WHERE id <> ALL($1::uuid[]) "
            "RETURNING 1) SELECT COUNT(*) FROM d",
            live_object_ids,
        )

        return {
            "objects": len(live_object_ids),
            "links": len(live_link_ids),
            "pruned_objects": int(pruned_objects or 0),
            "pruned_links": int(pruned_links or 0),
        }

    # ------------------------------------------------------------------ #
    # Stats
    # ------------------------------------------------------------------ #
    async def stats(self) -> dict[str, Any]:
        async with self.acquire() as conn:
            obj_rows = await conn.fetch(
                "SELECT object_type, COUNT(*) AS n FROM ontology_objects "
                "GROUP BY object_type ORDER BY object_type"
            )
            link_rows = await conn.fetch(
                "SELECT link_type, COUNT(*) AS n FROM ontology_links "
                "GROUP BY link_type ORDER BY link_type"
            )
            total_obj = await conn.fetchval("SELECT COUNT(*) FROM ontology_objects")
            total_link = await conn.fetchval("SELECT COUNT(*) FROM ontology_links")
        return {
            "objects": int(total_obj or 0),
            "links": int(total_link or 0),
            "objects_by_type": {r["object_type"]: int(r["n"]) for r in obj_rows},
            "links_by_type": {r["link_type"]: int(r["n"]) for r in link_rows},
        }
