"""Ontology / semantic-layer read API.

The ontology service (`ontology/`) projects the raw tables into a typed object
+ link model (ontology_object_types / ontology_link_types / ontology_objects /
ontology_links). This router is *read-only*: it serves the type system, paged
typed objects, the per-object "object view" (an entity plus its neighbours
grouped by link type and direction -- the ontology pivot), and a cross-type
title search.

- `GET /v1/ontology/types`          object types (+ live object counts) + link types.
- `GET /v1/ontology/objects`        paged typed objects; filter `type`, `q`.
- `GET /v1/ontology/objects/{id}`   the object + its linked objects grouped by link type.
- `GET /v1/ontology/search?q=`      objects across all types by title.

Every read applies the same ABAC classification filter as the findings router
(`classification_rank_sql`): objects above the caller's clearance never leave
the DB. When the auth layer is absent (e.g. a build without governance) the
dependency resolves a dev principal with full clearance, so the filter is a
no-op. Nothing here writes; projection is the ontology service's job.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..auth import Principal, classification_rank_sql, current_principal
from ..db import get_pool

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/ontology", tags=["ontology"])

# ABAC: an object's classification rank must be <= the caller's clearance rank.
_ABAC = f"{classification_rank_sql('o.classification')} <= "


# --------------------------------------------------------------------------- #
# Response models (defined here to avoid touching the shared models.py)
# --------------------------------------------------------------------------- #

class OntologyObjectTypeOut(BaseModel):
    name: str
    display: str
    icon: str | None = None
    color: str | None = None
    property_schema: dict[str, Any] = Field(default_factory=dict)
    source: str
    enabled: bool = True
    count: int = 0


class OntologyLinkTypeOut(BaseModel):
    name: str
    display: str
    from_type: str
    to_type: str
    cardinality: str


class OntologyTypesOut(BaseModel):
    object_types: list[OntologyObjectTypeOut]
    link_types: list[OntologyLinkTypeOut]


class OntologyObjectOut(BaseModel):
    id: UUID
    object_type: str
    title: str
    properties: dict[str, Any] = Field(default_factory=dict)
    backing_table: str
    backing_id: str
    classification: str
    first_seen: Any | None = None
    last_seen: Any | None = None


class OntologyObjectPage(BaseModel):
    items: list[OntologyObjectOut]
    total: int
    limit: int
    offset: int


class OntologyLinkGroup(BaseModel):
    """Neighbours reached from the focus object over one link type + direction."""
    link_type: str
    display: str
    direction: str  # 'out' (focus -> neighbour) | 'in' (neighbour -> focus)
    objects: list[OntologyObjectOut]


class OntologyObjectView(BaseModel):
    object: OntologyObjectOut
    groups: list[OntologyLinkGroup]


# --------------------------------------------------------------------------- #
# Row coercion
# --------------------------------------------------------------------------- #

def _coerce_obj(row) -> dict[str, Any]:
    d = dict(row)
    p = d.get("properties")
    if isinstance(p, str):
        d["properties"] = json.loads(p) if p else {}
    elif p is None:
        d["properties"] = {}
    return d


# --------------------------------------------------------------------------- #
# GET /types
# --------------------------------------------------------------------------- #

@router.get("/types", response_model=OntologyTypesOut)
async def get_types(
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Object types with live (ABAC-filtered) object counts + all link types."""
    async with pool.acquire() as con:
        obj_rows = await con.fetch(
            f"""
            SELECT t.name, t.display, t.icon, t.color, t.property_schema,
                   t.source, t.enabled, COALESCE(c.n, 0) AS count
              FROM ontology_object_types t
              LEFT JOIN (
                   SELECT object_type, COUNT(*) AS n
                     FROM ontology_objects o
                    WHERE {_ABAC}$1
                    GROUP BY object_type
              ) c ON c.object_type = t.name
             ORDER BY t.name
            """,
            principal.clearance_rank,
        )
        link_rows = await con.fetch(
            "SELECT name, display, from_type, to_type, cardinality "
            "FROM ontology_link_types ORDER BY name"
        )

    def _as_dict(v: Any) -> dict:
        # jsonb may come back as a str (no codec) or even double-encoded; coerce.
        for _ in range(3):
            if isinstance(v, dict):
                return v
            if isinstance(v, str) and v:
                try:
                    v = json.loads(v)
                except (ValueError, TypeError):
                    return {}
            else:
                return {}
        return v if isinstance(v, dict) else {}

    object_types = []
    for r in obj_rows:
        d = dict(r)
        d["property_schema"] = _as_dict(d.get("property_schema"))
        object_types.append(OntologyObjectTypeOut.model_validate(d))
    link_types = [OntologyLinkTypeOut.model_validate(dict(r)) for r in link_rows]
    return OntologyTypesOut(object_types=object_types, link_types=link_types)


# --------------------------------------------------------------------------- #
# GET /objects (paged, typed)
# --------------------------------------------------------------------------- #

_OBJ_COLS = (
    "o.id, o.object_type, o.title, o.properties, o.backing_table, "
    "o.backing_id, o.classification, o.first_seen, o.last_seen"
)


@router.get("/objects", response_model=OntologyObjectPage)
async def list_objects(
    type: str | None = Query(None, max_length=64),
    q: str | None = Query(None, max_length=256),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    clauses: list[str] = []
    args: list[Any] = []
    if type is not None:
        args.append(type)
        clauses.append(f"o.object_type = ${len(args)}")
    if q:
        args.append(f"%{q}%")
        clauses.append(f"o.title ILIKE ${len(args)}")
    args.append(principal.clearance_rank)
    clauses.append(f"{_ABAC}${len(args)}")
    where = "WHERE " + " AND ".join(clauses)

    sql_count = f"SELECT COUNT(*) FROM ontology_objects o {where}"
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT {_OBJ_COLS}
          FROM ontology_objects o
          {where}
         ORDER BY o.object_type, o.title
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count, *args)
        rows = await con.fetch(sql, *args_list)
    items = [OntologyObjectOut.model_validate(_coerce_obj(r)) for r in rows]
    return OntologyObjectPage(items=items, total=int(total or 0), limit=limit, offset=offset)


# --------------------------------------------------------------------------- #
# GET /search (cross-type by title)
# --------------------------------------------------------------------------- #

@router.get("/search", response_model=OntologyObjectPage)
async def search_objects(
    q: str = Query(..., min_length=1, max_length=256),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Objects across all types whose title matches `q` (ABAC-filtered)."""
    args: list[Any] = [f"%{q}%", principal.clearance_rank]
    where = f"WHERE o.title ILIKE $1 AND {_ABAC}$2"
    sql_count = f"SELECT COUNT(*) FROM ontology_objects o {where}"
    args_list = [*args, limit, offset]
    sql = f"""
        SELECT {_OBJ_COLS}
          FROM ontology_objects o
          {where}
         ORDER BY o.title
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count, *args)
        rows = await con.fetch(sql, *args_list)
    items = [OntologyObjectOut.model_validate(_coerce_obj(r)) for r in rows]
    return OntologyObjectPage(items=items, total=int(total or 0), limit=limit, offset=offset)


# --------------------------------------------------------------------------- #
# GET /objects/{id} (object view: entity + neighbours grouped by link type)
# --------------------------------------------------------------------------- #

@router.get("/objects/{object_id}", response_model=OntologyObjectView)
async def get_object(
    object_id: UUID,
    request: Request,
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """The object plus its linked objects, grouped by (link_type, direction).

    Neighbours above the caller's clearance are filtered out; a focus object
    above clearance 404s (existence of over-classified objects is not
    disclosed), matching the findings router's pattern.
    """
    async with pool.acquire() as con:
        focus = await con.fetchrow(
            f"""
            SELECT {_OBJ_COLS}
              FROM ontology_objects o
             WHERE o.id = $1 AND {_ABAC}$2
            """,
            object_id,
            principal.clearance_rank,
        )
        if focus is None:
            raise HTTPException(status_code=404, detail="object not found")
        if focus["classification"] == "restricted":
            request.state.audit_restricted = True
            request.state.audit_classification = "restricted"

        # Outgoing + incoming neighbours in one pass. The ABAC filter is
        # applied to the NEIGHBOUR object (aliased `o`) in both legs.
        neighbours = await con.fetch(
            f"""
            SELECT l.link_type, lt.display AS link_display, 'out' AS direction,
                   l.properties AS link_properties, {_OBJ_COLS}
              FROM ontology_links l
              JOIN ontology_objects o ON o.id = l.to_object
              LEFT JOIN ontology_link_types lt ON lt.name = l.link_type
             WHERE l.from_object = $1 AND {_ABAC}$2
            UNION ALL
            SELECT l.link_type, lt.display AS link_display, 'in' AS direction,
                   l.properties AS link_properties, {_OBJ_COLS}
              FROM ontology_links l
              JOIN ontology_objects o ON o.id = l.from_object
              LEFT JOIN ontology_link_types lt ON lt.name = l.link_type
             WHERE l.to_object = $1 AND {_ABAC}$2
             ORDER BY link_type, direction, title
            """,
            object_id,
            principal.clearance_rank,
        )

    grouped: dict[tuple[str, str], OntologyLinkGroup] = {}
    order: list[tuple[str, str]] = []
    for r in neighbours:
        key = (r["link_type"], r["direction"])
        if key not in grouped:
            grouped[key] = OntologyLinkGroup(
                link_type=r["link_type"],
                display=r["link_display"] or r["link_type"],
                direction=r["direction"],
                objects=[],
            )
            order.append(key)
        grouped[key].objects.append(OntologyObjectOut.model_validate(_coerce_obj(r)))

    return OntologyObjectView(
        object=OntologyObjectOut.model_validate(_coerce_obj(focus)),
        groups=[grouped[k] for k in order],
    )
