"""Ontology read-API tests.

The ontology service writes the ontology_* tables; here we seed them directly
and exercise the orchestrator's read surface: the type system (+ counts), paged
typed objects, the per-object "object view" (neighbours grouped by link type +
direction), cross-type search, and the ABAC classification filter.

The ontology router is wired by the integrator (not in app.main yet), so the
`ont_client` fixture mounts it on the test app explicitly.
"""
from __future__ import annotations

import json
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import auth as auth_svc
from app.config import settings
from app.routers import ontology as ontology_router


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest_asyncio.fixture
async def ont_client(app):
    """A client against the test app with the ontology router mounted."""
    app.include_router(ontology_router.router)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


# --------------------------------------------------------------------------- #
# Seed helpers
# --------------------------------------------------------------------------- #

async def _seed_types(con):
    otypes = [
        ("Host", "Host", "server", "#4ea3ff", "assets"),
        ("Service", "Service", "plug", "#ffb86b", "assets"),
        ("Vulnerability", "Vulnerability", "alert", "#ff4d6d", "findings"),
        ("Team", "Team", "users", "#c084fc", "tickets"),
        ("Ticket", "Ticket", "ticket", "#f0b429", "tickets"),
    ]
    for name, display, icon, color, source in otypes:
        await con.execute(
            "INSERT INTO ontology_object_types (name, display, icon, color, "
            "property_schema, source) VALUES ($1,$2,$3,$4,'{}'::jsonb,$5) "
            "ON CONFLICT (name) DO NOTHING",
            name, display, icon, color, source,
        )
    ltypes = [
        ("AFFECTS", "affects", "Vulnerability", "Host"),
        ("RUNS", "runs", "Host", "Service"),
        ("OWNED_BY", "owned by", "Host", "Team"),
        ("TRACKS", "tracks", "Ticket", "Vulnerability"),
    ]
    for name, display, ft, tt in ltypes:
        await con.execute(
            "INSERT INTO ontology_link_types (name, display, from_type, to_type) "
            "VALUES ($1,$2,$3,$4) ON CONFLICT (name) DO NOTHING",
            name, display, ft, tt,
        )


async def _obj(con, object_type, title, *, classification="internal", props=None,
               backing_table=None, backing_id=None):
    return str(
        await con.fetchval(
            "INSERT INTO ontology_objects (object_type, title, properties, "
            "backing_table, backing_id, classification) "
            "VALUES ($1,$2,$3::jsonb,$4,$5,$6) RETURNING id",
            object_type, title, json.dumps(props or {}),
            backing_table or object_type.lower(),
            backing_id or str(uuid.uuid4()), classification,
        )
    )


async def _link(con, link_type, frm, to, props=None):
    await con.execute(
        "INSERT INTO ontology_links (link_type, from_object, to_object, properties) "
        "VALUES ($1,$2,$3,$4::jsonb) ON CONFLICT DO NOTHING",
        link_type, frm, to, json.dumps(props or {}),
    )


async def _seed_user_with_key(pool, username, role, clearance, scopes=("read",)):
    async with pool.acquire() as con:
        uid = await con.fetchval(
            "INSERT INTO app_users (username, role, clearance, pw_hash) "
            "VALUES ($1,$2,$3,NULL) RETURNING id",
            username, role, clearance,
        )
        full, prefix, key_hash = auth_svc.generate_api_key()
        await con.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes) "
            "VALUES ($1,$2,$3,$4,$5::text[])",
            uid, f"key-{prefix}", prefix, key_hash, list(scopes),
        )
    return full


def _hdr(key):
    return {"Authorization": f"Bearer {key}"}


# --------------------------------------------------------------------------- #
# /types
# --------------------------------------------------------------------------- #

async def test_types_lists_object_and_link_types_with_counts(ont_client, db_pool):
    async with db_pool.acquire() as con:
        await _seed_types(con)
        await _obj(con, "Host", "a.example.com")
        await _obj(con, "Host", "b.example.com")
        await _obj(con, "Vulnerability", "RCE")

    r = await ont_client.get("/v1/ontology/types")
    assert r.status_code == 200, r.text
    body = r.json()
    counts = {t["name"]: t["count"] for t in body["object_types"]}
    assert counts["Host"] == 2
    assert counts["Vulnerability"] == 1
    assert counts["Service"] == 0
    link_names = {lt["name"] for lt in body["link_types"]}
    assert {"AFFECTS", "RUNS", "OWNED_BY", "TRACKS"} <= link_names
    affects = next(lt for lt in body["link_types"] if lt["name"] == "AFFECTS")
    assert affects["from_type"] == "Vulnerability" and affects["to_type"] == "Host"


# --------------------------------------------------------------------------- #
# /objects
# --------------------------------------------------------------------------- #

async def test_objects_paged_and_filtered(ont_client, db_pool):
    async with db_pool.acquire() as con:
        await _seed_types(con)
        await _obj(con, "Host", "api.example.com", props={"kind": "subdomain"})
        await _obj(con, "Host", "web.example.com")
        await _obj(con, "Service", "tcp/443")

    r = await ont_client.get("/v1/ontology/objects", params={"type": "Host"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"items", "total", "limit", "offset"}
    assert body["total"] == 2
    assert all(it["object_type"] == "Host" for it in body["items"])
    # properties round-trips as a dict.
    api = next(it for it in body["items"] if it["title"] == "api.example.com")
    assert api["properties"]["kind"] == "subdomain"

    # q filter
    r2 = await ont_client.get("/v1/ontology/objects", params={"q": "api"})
    assert r2.json()["total"] == 1

    # paging
    r3 = await ont_client.get("/v1/ontology/objects", params={"type": "Host", "limit": 1})
    assert len(r3.json()["items"]) == 1
    assert r3.json()["total"] == 2


# --------------------------------------------------------------------------- #
# object view (neighbours grouped by link type + direction)
# --------------------------------------------------------------------------- #

async def test_object_view_groups_neighbours_bidirectionally(ont_client, db_pool):
    async with db_pool.acquire() as con:
        await _seed_types(con)
        host = await _obj(con, "Host", "api.example.com")
        svc = await _obj(con, "Service", "tcp/443")
        vuln = await _obj(con, "Vulnerability", "RCE")
        await _link(con, "RUNS", host, svc)        # host -> service (out from host)
        await _link(con, "AFFECTS", vuln, host)    # vuln -> host (in to host)

    # Host view: RUNS outgoing (-> Service), AFFECTS incoming (<- Vulnerability)
    r = await ont_client.get(f"/v1/ontology/objects/{host}")
    assert r.status_code == 200, r.text
    view = r.json()
    assert view["object"]["title"] == "api.example.com"
    groups = {(g["link_type"], g["direction"]): g for g in view["groups"]}
    assert ("RUNS", "out") in groups
    assert groups[("RUNS", "out")]["objects"][0]["title"] == "tcp/443"
    assert ("AFFECTS", "in") in groups
    assert groups[("AFFECTS", "in")]["objects"][0]["id"] == vuln

    # Pivot to the Vulnerability: AFFECTS now outgoing, pointing back to the Host.
    r2 = await ont_client.get(f"/v1/ontology/objects/{vuln}")
    v2 = r2.json()
    g2 = {(g["link_type"], g["direction"]): g for g in v2["groups"]}
    assert ("AFFECTS", "out") in g2
    assert g2[("AFFECTS", "out")]["objects"][0]["id"] == host


async def test_object_view_404_for_missing(ont_client, db_pool):
    async with db_pool.acquire() as con:
        await _seed_types(con)
    r = await ont_client.get(f"/v1/ontology/objects/{uuid.uuid4()}")
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# /search
# --------------------------------------------------------------------------- #

async def test_search_across_types(ont_client, db_pool):
    async with db_pool.acquire() as con:
        await _seed_types(con)
        await _obj(con, "Host", "payments.example.com")
        await _obj(con, "Vulnerability", "payments service RCE")
        await _obj(con, "Service", "ssh")

    r = await ont_client.get("/v1/ontology/search", params={"q": "payments"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 2
    types = {it["object_type"] for it in body["items"]}
    assert types == {"Host", "Vulnerability"}


# --------------------------------------------------------------------------- #
# ABAC classification filter (enforce mode)
# --------------------------------------------------------------------------- #

async def test_classification_filter_hides_over_clearance(enforce, ont_client, db_pool):
    async with db_pool.acquire() as con:
        await _seed_types(con)
        pub = await _obj(con, "Host", "open.example.com", classification="public")
        conf = await _obj(con, "Host", "secret.example.com", classification="confidential")
        vuln = await _obj(con, "Vulnerability", "leak", classification="public")
        # the vuln affects the confidential host (neighbour must be filtered)
        await _link(con, "AFFECTS", vuln, conf)

    key = await _seed_user_with_key(db_pool, "intern", "analyst", "internal")

    # /objects: confidential host hidden
    r = await ont_client.get("/v1/ontology/objects", params={"type": "Host"}, headers=_hdr(key))
    titles = {it["title"] for it in r.json()["items"]}
    assert "open.example.com" in titles
    assert "secret.example.com" not in titles

    # type counts respect ABAC
    r_types = await ont_client.get("/v1/ontology/types", headers=_hdr(key))
    host_count = next(t["count"] for t in r_types.json()["object_types"] if t["name"] == "Host")
    assert host_count == 1

    # search hides it too
    r_s = await ont_client.get("/v1/ontology/search", params={"q": "example"}, headers=_hdr(key))
    s_titles = {it["title"] for it in r_s.json()["items"]}
    assert "secret.example.com" not in s_titles

    # object view of the confidential host 404s
    r_v = await ont_client.get(f"/v1/ontology/objects/{conf}", headers=_hdr(key))
    assert r_v.status_code == 404

    # the confidential host does not leak as a neighbour of the public vuln
    r_vv = await ont_client.get(f"/v1/ontology/objects/{vuln}", headers=_hdr(key))
    assert r_vv.status_code == 200
    neighbour_ids = {o["id"] for g in r_vv.json()["groups"] for o in g["objects"]}
    assert conf not in neighbour_ids
