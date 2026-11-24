"""Provable containment API (app/routers/assurance.py, docs/ASSURANCE_P1.md section 7).

Real Postgres, the real router, the real store and the real library. What is covered here and why:

* invariants: parse + compile through the library (422 with its problem list), digest-addressed
  version rows, the std copy, disable-and-archive that keeps every row, and that a re-enabled or
  edited invariant is never shown as a trusted HOLDS (soundness);
* zones and labels: validation, mandatory justification, graph_version bumps only when the meaning
  changes, semantic audit rows;
* reads: nodes, edges, coverage (directional), state;
* evaluate: always 200, degraded runs say so, an empty selection is never "everything";
* RBAC (enforce mode), the billing gate, and tenant isolation of every route with identical 404s.

Isolation tests serve the app through ``app_pool`` (the non-superuser role, RLS enforced); the rest
use the default pool and the synthetic dev admin.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import types
import uuid

import pytest
import pytest_asyncio

from app import audit as audit_svc
from app import tenancy
from app.billing import config as bcfg
from app.billing import service as billing_service
from app.billing import status as bstatus
from app.config import settings

from .test_governance import _hdr, _seed_user_with_key
from .test_tenancy import _seed_admin

TENANT_A = tenancy.DEFAULT_TENANT_ID
TENANT_B = "00000000-0000-0000-0000-0000000000b9"

NOW = lambda: dt.datetime.now(dt.timezone.utc)  # noqa: E731


def inv_yaml(inv_id: str = "acme:guest-cannot-reach-pos", title: str = "Guests cannot reach the POS",
             severity: str = "high", to_zone: str = "pos") -> str:
    return f"""apiVersion: paddock.dev/invariant/v1
id: {inv_id}
title: {title}
severity: {severity}
subjects:
  from: {{ zone: guest }}
  to: {{ zone: {to_zone} }}
assert: unreachable
"""


@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


async def _create(client, inv_id="acme:guest-cannot-reach-pos", **kw):
    r = await client.post("/v1/invariants", json={"yaml": inv_yaml(inv_id, **kw)})
    assert r.status_code == 201, r.text
    return r.json()["invariant"]


async def _audit_rows(db_pool, action: str) -> list[dict]:
    async with db_pool.acquire() as con:
        rows = await con.fetch("SELECT actor, resource_type, resource_id, justification, details "
                               "FROM audit_log WHERE action = $1 ORDER BY ts, id", action)
    out = []
    for r in rows:
        d = dict(r)
        d["details"] = json.loads(d["details"]) if isinstance(d["details"], str) else d["details"]
        out.append(d)
    return out


async def _graph_version(client) -> int:
    return (await client.get("/v1/assurance/state")).json()["graph_version"]


async def _seed_node(db_pool, ref, kind="host", tenant=TENANT_A, source="test", label=""):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO reach_nodes (tenant_id, node_ref, kind, label, source) VALUES ($1,$2,$3,$4,$5)",
            tenant, ref, kind, label, source)


async def _seed_cov(db_pool, ref, direction, tier="observed", source="sentry_flow", age_h=0.0,
                    tenant=TENANT_A):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO reach_coverage (tenant_id, node_ref, direction, tier, source, observed_at) "
            "VALUES ($1,$2,$3,$4,$5,$6)", tenant, ref, direction, tier, source,
            NOW() - dt.timedelta(hours=age_h))


async def _seed_edge(db_pool, src, dst, *, port=443, source="aws_sg", basis="configured",
                     proto="tcp", tenant=TENANT_A, evidence=None):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO reach_edges (tenant_id, src_ref, dst_ref, proto, port_lo, port_hi, basis, source, "
            "evidence) VALUES ($1,$2,$3,$4,$5,$5,$6,$7,$8::jsonb)", tenant, src, dst, proto, port, basis,
            source, json.dumps(evidence or {"sg": ["sg-1"]}))


async def _seed_asset(db_pool, tenant=TENANT_A, value="i-0abc") -> str:
    async with db_pool.acquire() as con:
        return str(await con.fetchval(
            "INSERT INTO assets (tenant_id, kind, value, canonical, source) VALUES ($1,'domain',$2,$2,'test') "
            "RETURNING id", tenant, value))


# ============================================================================================
# Invariants: create / validate
# ============================================================================================

async def test_create_get_list_invariant_roundtrip(client, db_pool):
    inv = await _create(client)
    assert inv["invariant_id"] == "acme:guest-cannot-reach-pos"
    assert inv["source"] == "custom" and inv["enabled"] is True and inv["version"] == 1
    assert inv["digest"].startswith("sha256:") and inv["status"] == "PENDING"

    got = (await client.get(f"/v1/invariants/{inv['id']}")).json()
    assert got["yaml"].startswith("apiVersion: paddock.dev/invariant/v1")
    assert [v["digest"] for v in got["versions"]] == [inv["digest"]]

    page = (await client.get("/v1/invariants")).json()
    assert set(page) == {"items", "total", "limit", "offset"}
    assert page["total"] == 1 and page["items"][0]["id"] == inv["id"]
    # the version ledger row exists and is digest-addressed
    async with db_pool.acquire() as con:
        n = await con.fetchval("SELECT count(*) FROM invariant_versions WHERE invariant_id = $1 AND digest = $2",
                               inv["invariant_id"], inv["digest"])
    assert n == 1


async def test_invalid_yaml_is_422_with_the_librarys_problem_list(client):
    r = await client.post("/v1/invariants", json={"yaml": "id: [unclosed"})
    assert r.status_code == 422
    d = r.json()["detail"]
    assert d["error"] == "invalid_invariant" and d["problems"] and all(isinstance(p, str) for p in d["problems"])

    # a structurally valid document that violates the schema reports each problem with its path
    bad = inv_yaml(severity="catastrophic").replace("assert: unreachable", "assert: nonsense")
    r = await client.post("/v1/invariants", json={"yaml": bad})
    assert r.status_code == 422
    problems = r.json()["detail"]["problems"]
    assert any("severity" in p for p in problems) and any("assert" in p for p in problems)

    # nothing was stored
    assert (await client.get("/v1/invariants")).json()["total"] == 0


async def test_yaml_bomb_and_oversize_are_rejected_not_crashed(client):
    bomb = "a: &a [x, x]\nb: *a\n"
    r = await client.post("/v1/invariants", json={"yaml": bomb})
    assert r.status_code == 422 and "alias" in json.dumps(r.json()).lower()
    assert (await client.post("/v1/invariants", json={"yaml": "x" * 70_000})).status_code == 422
    assert (await client.post("/v1/invariants", json={"yaml": ""})).status_code == 422
    assert (await client.post("/v1/invariants", json={})).status_code == 422


async def test_std_namespace_is_reserved_for_the_shipped_library(client):
    r = await client.post("/v1/invariants", json={"yaml": inv_yaml("std:my-own-copy")})
    assert r.status_code == 422
    assert any("reserved" in p for p in r.json()["detail"]["problems"])
    assert (await client.get("/v1/invariants")).json()["total"] == 0


async def test_duplicate_id_is_409_and_does_not_overwrite(client):
    first = await _create(client)
    r = await client.post("/v1/invariants", json={"yaml": inv_yaml(title="A different title")})
    assert r.status_code == 409
    again = (await client.get(f"/v1/invariants/{first['id']}")).json()
    assert again["title"] == first["title"] and again["digest"] == first["digest"]


# ============================================================================================
# Invariants: update / disable / re-enable
# ============================================================================================

async def test_put_new_definition_makes_a_new_version_and_same_definition_does_not(client, db_pool):
    inv = await _create(client)
    same = await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": inv_yaml()})
    assert same.status_code == 200 and same.json()["changed"] is False and same.json()["new_version"] is False
    assert same.json()["invariant"]["version"] == 1

    r = await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": inv_yaml(title="Renamed rule")})
    body = r.json()
    assert r.status_code == 200 and body["changed"] and body["new_version"]
    assert body["invariant"]["version"] == 2 and body["invariant"]["digest"] != inv["digest"]
    assert body["invariant"]["title"] == "Renamed rule"

    detail = (await client.get(f"/v1/invariants/{inv['id']}")).json()
    assert {v["version"] for v in detail["versions"]} == {1, 2}
    async with db_pool.acquire() as con:
        rows = await con.fetch("SELECT digest, yaml FROM invariant_versions WHERE invariant_id = $1",
                               inv["invariant_id"])
    assert len(rows) == 2  # both definitions are kept, addressed by digest


async def test_put_rejects_id_change_bad_yaml_and_empty_body(client):
    inv = await _create(client)
    r = await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": inv_yaml("acme:other-id")})
    assert r.status_code == 422 and "cannot change" in json.dumps(r.json())
    r = await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": "not: [valid"})
    assert r.status_code == 422 and r.json()["detail"]["problems"]
    assert (await client.put(f"/v1/invariants/{inv['id']}", json={})).status_code == 422
    assert (await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": None, "enabled": None})
            ).status_code == 422
    still = (await client.get(f"/v1/invariants/{inv['id']}")).json()
    assert still["digest"] == inv["digest"] and still["version"] == 1


async def test_delete_disables_and_archives_but_keeps_every_row(client, db_pool):
    inv = await _create(client)
    await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": inv_yaml(title="Second version")})
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO invariant_runs (invariant_id, digest, verdict) VALUES ($1, 'sha256:x', "
                          "'VIOLATED')", inv["invariant_id"])
    r = await client.delete(f"/v1/invariants/{inv['id']}")
    assert r.status_code == 200
    out = r.json()
    assert out["changed"] and out["invariant"]["enabled"] is False and out["invariant"]["status"] == "DISABLED"

    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM invariants") == 1
        assert await con.fetchval("SELECT count(*) FROM invariant_versions WHERE invariant_id = $1",
                                  inv["invariant_id"]) == 2
        assert await con.fetchval("SELECT count(*) FROM invariant_runs WHERE invariant_id = $1",
                                  inv["invariant_id"]) == 1
    # idempotent
    again = (await client.delete(f"/v1/invariants/{inv['id']}")).json()
    assert again["changed"] is False
    # its ledger is still readable
    runs = (await client.get(f"/v1/invariants/{inv['id']}/runs")).json()
    assert runs["total"] == 1


async def test_reenabling_never_shows_the_old_holds_as_current(client, db_pool):
    """Soundness: a HOLDS recorded before an invariant was switched off says nothing about the
    graph of today. Re-enabling must clear it from view and make the runner treat it as due."""
    inv = await _create(client)
    async with db_pool.acquire() as con:
        await con.execute(
            "UPDATE invariants SET last_verdict='HOLDS', last_graph_version=3, last_evaluated_at=NOW(), "
            "valid_until=NOW() + interval '5 hours', last_result=$2::jsonb WHERE id=$1",
            uuid.UUID(inv["id"]), json.dumps({"verdict": "HOLDS", "reasons": ["no_path"],
                                              "coverage": {"universe": 4, "covered": 4, "ratio": 1.0}}))
    assert (await client.get(f"/v1/invariants/{inv['id']}")).json()["status"] == "HOLDS"
    await client.put(f"/v1/invariants/{inv['id']}", json={"enabled": False})
    assert (await client.get(f"/v1/invariants/{inv['id']}")).json()["status"] == "DISABLED"

    r = await client.put(f"/v1/invariants/{inv['id']}", json={"enabled": True})
    assert r.json()["invariant"]["status"] == "PENDING"
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT last_graph_version, valid_until FROM invariants WHERE id=$1",
                                 uuid.UUID(inv["id"]))
    assert row["last_graph_version"] is None and row["valid_until"] is None   # => runner._is_due


async def test_editing_the_definition_discards_the_old_verdict(client, db_pool):
    inv = await _create(client)
    async with db_pool.acquire() as con:
        await con.execute("UPDATE invariants SET last_verdict='HOLDS', last_graph_version=9, "
                          "valid_until=NOW() + interval '5 hours' WHERE id=$1", uuid.UUID(inv["id"]))
    r = await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": inv_yaml(to_zone="dmz")})
    assert r.json()["invariant"]["status"] == "PENDING"
    # a no-op PUT must not erase a verdict that is still valid
    async with db_pool.acquire() as con:
        await con.execute("UPDATE invariants SET last_graph_version=9, valid_until=NOW() + interval '5 hours' "
                          "WHERE id=$1", uuid.UUID(inv["id"]))
    r = await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": inv_yaml(to_zone="dmz")})
    assert r.json()["changed"] is False and r.json()["invariant"]["status"] == "HOLDS"


async def test_status_is_derived_honestly(client, db_pool):
    a = await _create(client, "acme:a-rule")
    b = await _create(client, "acme:b-rule")
    c = await _create(client, "acme:c-rule")
    d = await _create(client, "acme:d-rule")
    async with db_pool.acquire() as con:
        await con.execute("UPDATE assurance_state SET graph_version = graph_version")  # no row yet: no-op
        await con.execute("INSERT INTO assurance_state (graph_version) VALUES (7) "
                          "ON CONFLICT (tenant_id) DO UPDATE SET graph_version = 7")
        # a: HOLDS that outlived its evidence; b: fresh HOLDS at the current version;
        # c: VIOLATED at an older version; d: UNKNOWN
        await con.execute("UPDATE invariants SET last_verdict='HOLDS', last_graph_version=7, "
                          "valid_until=NOW() - interval '1 minute' WHERE id=$1", uuid.UUID(a["id"]))
        await con.execute("UPDATE invariants SET last_verdict='HOLDS', last_graph_version=7, "
                          "valid_until=NOW() + interval '1 hour' WHERE id=$1", uuid.UUID(b["id"]))
        await con.execute("UPDATE invariants SET last_verdict='VIOLATED', last_graph_version=5, "
                          "last_result=$2::jsonb WHERE id=$1", uuid.UUID(c["id"]),
                          json.dumps({"violation_count": 3, "reasons": ["witness_found"],
                                      "evidence_tier": "observed",
                                      "coverage": {"universe": 10, "covered": 8, "ratio": 0.8}}))
        await con.execute("UPDATE invariants SET last_verdict='UNKNOWN', last_graph_version=7 WHERE id=$1",
                          uuid.UUID(d["id"]))
    items = {i["invariant_id"]: i for i in (await client.get("/v1/invariants")).json()["items"]}
    assert items["acme:a-rule"]["status"] == "EXPIRED"
    assert items["acme:b-rule"]["status"] == "HOLDS" and items["acme:b-rule"]["stale"] is False
    cc = items["acme:c-rule"]
    assert cc["status"] == "VIOLATED" and cc["stale"] is True and cc["violation_count"] == 3
    assert cc["evidence_tier"] == "observed" and cc["coverage"]["ratio"] == 0.8
    assert items["acme:d-rule"]["status"] == "UNKNOWN"
    # filter by derived status
    exp = (await client.get("/v1/invariants?status=expired")).json()
    assert [i["invariant_id"] for i in exp["items"]] == ["acme:a-rule"] and exp["total"] == 1
    # other filters + paging envelope
    p = (await client.get("/v1/invariants?limit=2&offset=1")).json()
    assert p["total"] == 4 and len(p["items"]) == 2 and p["limit"] == 2 and p["offset"] == 1
    assert (await client.get("/v1/invariants?source=std")).json()["total"] == 0
    assert (await client.get("/v1/invariants?enabled=false")).json()["total"] == 0
    assert (await client.get("/v1/invariants?limit=0")).status_code == 422
    assert (await client.get("/v1/invariants?limit=501")).status_code == 422


# ============================================================================================
# Std invariants
# ============================================================================================

async def test_std_listing_and_enable(client, db_pool):
    lst = (await client.get("/v1/invariants/std")).json()
    ids = [s["id"] for s in lst]
    assert ids == sorted(ids) and "std:no-internet-to-datastore" in ids and "std:coverage-complete" in ids
    assert len(ids) == 4 and not any(s["installed"] or s["enabled"] for s in lst)
    assert all(s["digest"].startswith("sha256:") and s["assertion"] for s in lst)

    r = await client.post("/v1/invariants/std/std:no-internet-to-datastore/enable")
    assert r.status_code == 201
    body = r.json()
    assert body["created"] and body["invariant"]["source"] == "std" and body["invariant"]["enabled"]
    after = {s["id"]: s for s in (await client.get("/v1/invariants/std")).json()}
    assert after["std:no-internet-to-datastore"]["enabled"] and after["std:no-internet-to-datastore"]["up_to_date"]
    assert not after["std:coverage-complete"]["installed"]
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT yaml, digest FROM invariants WHERE invariant_id = 'std:no-internet-to-datastore'")
        vers = await con.fetchval("SELECT count(*) FROM invariant_versions WHERE invariant_id = "
                                  "'std:no-internet-to-datastore' AND digest = $1", row["digest"])
    assert "assert: unreachable" in row["yaml"] and vers == 1   # a copy of the shipped text

    # idempotent: a second enable changes nothing and creates no second row
    r2 = await client.post("/v1/invariants/std/std:no-internet-to-datastore/enable")
    assert r2.status_code == 200 and r2.json()["changed"] is False and r2.json()["created"] is False
    assert (await client.get("/v1/invariants?source=std")).json()["total"] == 1


async def test_std_enable_accepts_the_short_name_and_404s_unknown(client):
    r = await client.post("/v1/invariants/std/coverage-complete/enable")
    assert r.status_code == 201 and r.json()["invariant"]["invariant_id"] == "std:coverage-complete"
    for bad in ("std:does-not-exist", "nope", "std:..", "std:"):
        r = await client.post(f"/v1/invariants/std/{bad}/enable")
        assert r.status_code in (404,), (bad, r.status_code)


async def test_std_reenable_after_disable_and_refresh_of_a_stale_copy(client, db_pool):
    r = await client.post("/v1/invariants/std/std:coverage-complete/enable")
    inv = r.json()["invariant"]
    await client.delete(f"/v1/invariants/{inv['id']}")
    # simulate a copy from an older library release plus a verdict recorded back then
    async with db_pool.acquire() as con:
        await con.execute("UPDATE invariants SET digest='sha256:old', yaml='stale', last_verdict='HOLDS', "
                          "last_graph_version=1, valid_until=NOW() + interval '1 day' WHERE id=$1",
                          uuid.UUID(inv["id"]))
    r = await client.post("/v1/invariants/std/std:coverage-complete/enable")
    out = r.json()
    assert r.status_code == 200 and out["changed"] and out["new_version"]
    cur = out["invariant"]
    assert cur["enabled"] and cur["version"] == 2 and cur["digest"] != "sha256:old"
    assert cur["status"] == "PENDING"          # the old verdict is gone from view
    async with db_pool.acquire() as con:
        y = await con.fetchval("SELECT yaml FROM invariants WHERE id=$1", uuid.UUID(inv["id"]))
    assert "assert: covered" in y


async def test_std_definition_cannot_be_edited_but_can_be_toggled(client):
    inv = (await client.post("/v1/invariants/std/std:coverage-complete/enable")).json()["invariant"]
    r = await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": inv_yaml("std:coverage-complete")})
    assert r.status_code == 422
    r = await client.put(f"/v1/invariants/{inv['id']}", json={"enabled": False})
    assert r.status_code == 200 and r.json()["invariant"]["enabled"] is False


# ============================================================================================
# Runs
# ============================================================================================

async def test_runs_are_paged_filtered_and_newest_first(client, db_pool):
    inv = await _create(client)
    other = await _create(client, "acme:other-rule")
    base = NOW() - dt.timedelta(days=3)
    async with db_pool.acquire() as con:
        for i, v in enumerate(["UNKNOWN", "HOLDS", "VIOLATED", "HOLDS"]):
            await con.execute(
                "INSERT INTO invariant_runs (invariant_id, digest, verdict, reasons, result, graph_version, "
                "violation_count, coverage_covered, coverage_universe, evaluated_at) VALUES "
                "($1,'sha256:d',$2,$3::jsonb,$4::jsonb,$5,$6,3,4,$7)", inv["invariant_id"], v,
                json.dumps(["r"]), json.dumps({"witnesses": [{"n": i}]}), i, 2 if v == "VIOLATED" else 0,
                base + dt.timedelta(hours=i))
        await con.execute("INSERT INTO invariant_runs (invariant_id, digest, verdict) VALUES ($1,'sha256:z',"
                          "'HOLDS')", other["invariant_id"])
    page = (await client.get(f"/v1/invariants/{inv['id']}/runs?limit=3")).json()
    assert page["total"] == 4 and [r["graph_version"] for r in page["items"]] == [3, 2, 1]
    assert all(r["result"] is None for r in page["items"])          # heavy payload is opt-in
    assert page["items"][0]["coverage_covered"] == 3 and page["items"][0]["reasons"] == ["r"]
    nxt = (await client.get(f"/v1/invariants/{inv['id']}/runs?limit=3&offset=3")).json()
    assert [r["graph_version"] for r in nxt["items"]] == [0]
    v = (await client.get(f"/v1/invariants/{inv['id']}/runs?verdict=VIOLATED&include_result=true")).json()
    assert v["total"] == 1 and v["items"][0]["result"] == {"witnesses": [{"n": 2}]}
    assert (await client.get(f"/v1/invariants/{inv['id']}/runs?verdict=BOGUS")).status_code == 422
    assert (await client.get(f"/v1/invariants/{uuid.uuid4()}/runs")).status_code == 404
    assert (await client.get("/v1/invariants/not-a-uuid/runs")).status_code == 422


# ============================================================================================
# Zones
# ============================================================================================

async def test_zone_crud_validation_and_graph_version(client, db_pool):
    v0 = await _graph_version(client)
    r = await client.post("/v1/zones", json={"name": "guest", "cidrs": ["10.20.0.0/16", "10.20.5.7/24"],
                                              "kind": "network", "justification": "guest wifi VLAN"})
    assert r.status_code == 201, r.text
    z = r.json()
    assert z["created"] and z["changed"] and z["zone"]["name"] == "guest"
    assert z["zone"]["cidrs"] == ["10.20.0.0/16", "10.20.5.0/24"]       # canonicalised
    assert z["graph_version"] == v0 + 1 and await _graph_version(client) == v0 + 1
    zid = z["zone"]["id"]

    assert (await client.get("/v1/zones")).json()["total"] == 1
    assert (await client.get(f"/v1/zones/{zid}")).json()["name"] == "guest"

    # a different, overlapping zone reports the overlap (most specific wins) and bumps again
    r = await client.post("/v1/zones", json={"name": "pos", "cidrs": ["10.20.5.0/24"],
                                              "justification": "register LAN"})
    assert r.status_code == 201 and r.json()["overlaps"] == ["guest"]

    # PUT: change CIDRs bumps; resubmitting the same CIDRs does not
    v1 = await _graph_version(client)
    r = await client.put(f"/v1/zones/{zid}", json={"cidrs": ["10.30.0.0/16"], "justification": "moved"})
    assert r.status_code == 200 and r.json()["changed"] and r.json()["zone"]["cidrs"] == ["10.30.0.0/16"]
    assert await _graph_version(client) == v1 + 1
    r = await client.put(f"/v1/zones/{zid}", json={"cidrs": ["10.30.0.0/16"], "description": "d",
                                                    "justification": "typo fix"})
    assert r.json()["changed"] is False and r.json()["graph_version"] is None
    assert r.json()["zone"]["description"] == "d" and await _graph_version(client) == v1 + 1

    # DELETE bumps and removes
    r = await client.delete(f"/v1/zones/{zid}?justification=decommissioned")
    assert r.status_code == 200 and r.json()["graph_version"] == v1 + 2
    assert (await client.get(f"/v1/zones/{zid}")).status_code == 404
    assert (await client.delete(f"/v1/zones/{zid}")).status_code == 404

    # every mutation left a semantic audit row naming the zone and the reason
    created = await _audit_rows(db_pool, "assurance_zone_create")
    assert {a["details"]["name"] for a in created} == {"guest", "pos"}
    assert created[0]["justification"] == "guest wifi VLAN" and created[0]["details"]["cidrs"]
    upd = await _audit_rows(db_pool, "assurance_zone_update")
    assert upd[0]["details"]["previous_cidrs"] == ["10.20.0.0/16", "10.20.5.0/24"]
    assert (await _audit_rows(db_pool, "assurance_zone_delete"))[0]["justification"] == "decommissioned"


@pytest.mark.parametrize("body", [
    {"name": "Guest", "cidrs": ["10.0.0.0/8"]},                 # uppercase
    {"name": "1guest", "cidrs": ["10.0.0.0/8"]},                # leading digit
    {"name": "a" * 33, "cidrs": ["10.0.0.0/8"]},                # too long
    {"name": "internet", "cidrs": ["10.0.0.0/8"]},              # reserved
    {"name": "guest", "cidrs": ["not-a-cidr"]},
    {"name": "guest", "cidrs": ["10.0.0.0/33"]},
    {"name": "guest", "cidrs": []},                             # a zone with no address space
    {"name": "guest", "cidrs": ["10.0.0.0/8"], "kind": "Bad Kind!"},
])
async def test_zone_validation_rejects_bad_input(client, body):
    r = await client.post("/v1/zones", json={**body, "justification": "because"})
    assert r.status_code == 422, r.text
    assert (await client.get("/v1/zones")).json()["total"] == 0


async def test_zone_needs_justification_and_unique_name(client):
    ok = {"name": "guest", "cidrs": ["10.0.0.0/8"]}
    assert (await client.post("/v1/zones", json=ok)).status_code == 422
    assert (await client.post("/v1/zones", json={**ok, "justification": "   "})).status_code == 422
    assert (await client.post("/v1/zones", json={**ok, "justification": "x"})).status_code == 201
    r = await client.post("/v1/zones", json={**ok, "cidrs": ["192.168.0.0/16"], "justification": "x"})
    assert r.status_code == 409
    assert (await client.get("/v1/zones")).json()["items"][0]["cidrs"] == ["10.0.0.0/8"]   # untouched


async def test_zone_put_body_rules(client):
    z = (await client.post("/v1/zones", json={"name": "guest", "cidrs": ["10.0.0.0/8"],
                                              "justification": "j"})).json()["zone"]
    assert (await client.put(f"/v1/zones/{z['id']}", json={})).status_code == 422
    assert (await client.put(f"/v1/zones/{z['id']}", json={"cidrs": ["10.1.0.0/16"]})).status_code == 422
    assert (await client.put(f"/v1/zones/{z['id']}", json={"justification": "j"})).status_code == 422
    r = await client.put(f"/v1/zones/{z['id']}", json={"cidrs": ["bogus"], "justification": "j"})
    assert r.status_code == 422
    assert (await client.get(f"/v1/zones/{z['id']}")).json()["cidrs"] == ["10.0.0.0/8"]
    # a name in the body cannot rename: the zone's identity is its name
    r = await client.put(f"/v1/zones/{z['id']}", json={"name": "renamed", "description": "x", "justification": "j"})
    assert r.status_code == 200 and r.json()["zone"]["name"] == "guest"


async def test_zone_delete_reports_labels_still_naming_it(client, db_pool):
    z = (await client.post("/v1/zones", json={"name": "guest", "cidrs": ["10.0.0.0/8"],
                                              "justification": "j"})).json()["zone"]
    asset = await _seed_asset(db_pool)
    assert (await client.put("/v1/labels", json={"node_ref": f"asset:{asset}", "tag": "zone", "value": "guest",
                                                 "justification": "j"})).status_code == 200
    r = await client.delete(f"/v1/zones/{z['id']}")
    assert r.json()["labels_still_naming_it"] == 1


# ============================================================================================
# Labels
# ============================================================================================

async def test_label_requires_a_real_justification(client, db_pool):
    asset = await _seed_asset(db_pool)
    base = {"node_ref": f"asset:{asset}", "tag": "crown-jewel", "value": "true"}
    for j in (None, "", "   ", "\n\t"):
        body = dict(base) if j is None else {**base, "justification": j}
        r = await client.put("/v1/labels", json=body)
        assert r.status_code == 422, (j, r.text)
    assert (await client.get("/v1/labels")).json()["total"] == 0
    assert await _graph_version(client) == 0


async def test_label_set_bumps_only_when_the_meaning_changes(client, db_pool):
    asset = await _seed_asset(db_pool)
    ref = f"asset:{asset}"
    r = await client.put("/v1/labels", json={"node_ref": ref, "tag": "app-tier", "value": "web",
                                             "justification": "front-end tier"})
    assert r.status_code == 200
    out = r.json()
    assert out["changed"] and out["previous"] is None and out["graph_version"] == 1
    lab = out["label"]
    assert lab["source"] == "declared" and lab["set_by"] == "dev-admin" and lab["justification"] == "front-end tier"

    # same value again: provenance refreshes, verdicts cannot move, version stays
    r = await client.put("/v1/labels", json={"node_ref": ref, "tag": "app-tier", "value": "web",
                                             "justification": "re-confirmed in review"})
    assert r.json()["changed"] is False and r.json()["graph_version"] is None
    assert r.json()["label"]["justification"] == "re-confirmed in review"
    assert await _graph_version(client) == 1

    r = await client.put("/v1/labels", json={"node_ref": ref, "tag": "app-tier", "value": "data",
                                             "justification": "actually the db tier"})
    assert r.json()["changed"] and r.json()["previous"] == "web" and r.json()["graph_version"] == 2

    aud = await _audit_rows(db_pool, "assurance_label_set")
    assert [a["details"]["value"] for a in aud] == ["web", "web", "data"]
    assert aud[2]["details"]["previous"] == "web" and aud[2]["justification"] == "actually the db tier"


@pytest.mark.parametrize("patch,why", [
    ({"node_ref": "internet"}, "the internet cannot be labelled"),
    ({"node_ref": "host-1"}, "bad ref"),
    ({"node_ref": "ip:999.1.1.1"}, "bad ip"),
    ({"node_ref": "ip:10.0.0.1/24"}, "bad ip"),
    ({"node_ref": "asset:not-a-uuid"}, "bad asset id"),
    ({"node_ref": "ip:010.0.0.1"}, "bad ip"),
    ({"tag": "Bad Tag"}, "tag"),
    ({"tag": ""}, "tag"),
    ({"tag": "a" * 49}, "tag"),
    ({"value": "x" * 129}, "value"),
    ({"tag": "zone", "value": "Not A Zone"}, "zone"),
    ({"tag": "zone", "value": "internet"}, "reserved"),
    ({"tag": "kind", "value": "toaster"}, "kind"),
])
async def test_label_validation(client, patch, why):
    body = {"node_ref": "ip:10.0.0.5", "tag": "class", "value": "data_store", "justification": "j", **patch}
    r = await client.put("/v1/labels", json=body)
    assert r.status_code == 422, (patch, r.status_code, r.text)
    assert (await client.get("/v1/labels")).json()["total"] == 0 and await _graph_version(client) == 0


async def test_label_on_unknown_asset_is_refused_but_ip_nodes_are_fine(client):
    r = await client.put("/v1/labels", json={"node_ref": f"asset:{uuid.uuid4()}", "tag": "class",
                                             "value": "data_store", "justification": "j"})
    assert r.status_code == 422 and "no such asset" in r.text
    r = await client.put("/v1/labels", json={"node_ref": "ip:10.0.0.5", "tag": "class", "value": "data_store",
                                             "justification": "j"})
    assert r.status_code == 200


async def test_zone_label_warns_when_zone_is_undeclared(client):
    r = await client.put("/v1/labels", json={"node_ref": "ip:10.0.0.5", "tag": "zone", "value": "pos",
                                             "justification": "j"})
    assert r.status_code == 200 and r.json()["warnings"] and "not declared" in r.json()["warnings"][0]
    await client.post("/v1/zones", json={"name": "pos", "cidrs": ["10.9.0.0/16"], "justification": "j"})
    r = await client.put("/v1/labels", json={"node_ref": "ip:10.0.0.6", "tag": "zone", "value": "pos",
                                             "justification": "j"})
    assert r.json()["warnings"] == []


async def test_label_list_filters_paging_and_delete(client, db_pool):
    for i in range(3):
        await client.put("/v1/labels", json={"node_ref": f"ip:10.0.0.{i + 1}", "tag": "class",
                                             "value": "data_store", "justification": "j"})
    await client.put("/v1/labels", json={"node_ref": "ip:10.0.0.1", "tag": "crown-jewel", "value": "true",
                                         "justification": "j"})
    page = (await client.get("/v1/labels?limit=2")).json()
    assert page["total"] == 4 and len(page["items"]) == 2
    assert (await client.get("/v1/labels?tag=crown-jewel")).json()["total"] == 1
    one = (await client.get("/v1/labels?node_ref=ip:10.0.0.1")).json()
    assert one["total"] == 2
    assert (await client.get("/v1/labels?source=metadata")).json()["total"] == 0
    assert (await client.get("/v1/labels?source=bogus")).status_code == 422

    v = await _graph_version(client)
    lid = one["items"][0]["id"]
    r = await client.delete(f"/v1/labels/{lid}?justification=no%20longer%20true")
    assert r.status_code == 200 and r.json()["graph_version"] == v + 1 and r.json()["deleted"]
    assert (await client.get("/v1/labels")).json()["total"] == 3
    assert (await client.delete(f"/v1/labels/{lid}")).status_code == 404
    assert await _graph_version(client) == v + 1            # a second delete is not a change
    aud = await _audit_rows(db_pool, "assurance_label_delete")
    assert len(aud) == 1 and aud[0]["justification"] == "no longer true"
    # a delete without a justification is still attributed (and says so)
    lid2 = (await client.get("/v1/labels")).json()["items"][0]["id"]
    assert (await client.delete(f"/v1/labels/{lid2}")).status_code == 200
    assert "no justification" in (await _audit_rows(db_pool, "assurance_label_delete"))[-1]["justification"]


# ============================================================================================
# Reach graph reads, coverage, state
# ============================================================================================

async def test_reach_nodes_and_edges_are_paged_and_filterable(client, db_pool):
    a, b, c = (f"asset:{uuid.uuid4()}" for _ in range(3))
    await _seed_node(db_pool, "internet", "internet", source="builtin")
    await _seed_node(db_pool, a, "cloud_db", label="orders-db")
    await _seed_node(db_pool, b, "cloud_instance", source="aws_sg")
    await _seed_node(db_pool, c, "device", source="sentry_flow")
    await _seed_cov(db_pool, a, "in", "configured", "aws_sg")
    await _seed_edge(db_pool, "internet", a, port=5432, evidence={"sg": ["sg-secret-ish"]})
    await _seed_edge(db_pool, b, a, port=5432, source="aws_sg")
    await _seed_edge(db_pool, c, b, port=22, source="sentry_flow", basis="observed")

    nodes = (await client.get("/v1/reach/nodes")).json()
    assert nodes["total"] == 4 and [n["node_ref"] for n in nodes["items"]] == sorted(n["node_ref"] for n in nodes["items"])
    db = next(n for n in nodes["items"] if n["node_ref"] == a)
    assert db["kind"] == "cloud_db" and db["label"] == "orders-db"
    assert db["coverage"] == [{"direction": "in", "tier": "configured", "source": "aws_sg",
                               "observed_at": db["coverage"][0]["observed_at"]}]
    assert (await client.get("/v1/reach/nodes?kind=device")).json()["total"] == 1
    assert (await client.get("/v1/reach/nodes?source=aws_sg")).json()["total"] == 1
    assert (await client.get("/v1/reach/nodes?q=orders")).json()["total"] == 1
    assert len((await client.get("/v1/reach/nodes?limit=2&offset=3")).json()["items"]) == 1

    edges = (await client.get("/v1/reach/edges")).json()
    assert edges["total"] == 3 and "evidence" not in edges["items"][0]            # opt-in
    assert (await client.get("/v1/reach/edges?source=sentry_flow")).json()["total"] == 1
    assert (await client.get("/v1/reach/edges?basis=observed")).json()["total"] == 1
    assert (await client.get(f"/v1/reach/edges?node={a}")).json()["total"] == 2
    assert (await client.get(f"/v1/reach/edges?src=internet&dst={a}")).json()["total"] == 1
    assert (await client.get("/v1/reach/edges?proto=udp")).json()["total"] == 0
    ev = (await client.get("/v1/reach/edges?include_evidence=true&src=internet")).json()["items"][0]
    assert ev["evidence"] == {"sg": ["sg-secret-ish"]} and ev["port_lo"] == ev["port_hi"] == 5432
    assert (await client.get("/v1/reach/edges?basis=bogus")).status_code == 422
    assert (await client.get("/v1/reach/edges?limit=9999")).status_code == 422
    # ordering is deterministic across pages
    p1 = (await client.get("/v1/reach/edges?limit=2")).json()["items"]
    p2 = (await client.get("/v1/reach/edges?limit=2&offset=2")).json()["items"]
    assert len({e["id"] for e in p1 + p2}) == 3


async def test_coverage_is_directional_and_uses_the_librarys_rule(client, db_pool):
    n = {k: f"asset:{uuid.uuid4()}" for k in "abcde"}
    await _seed_node(db_pool, "internet", "internet")
    for ref in n.values():
        await _seed_node(db_pool, ref, "cloud_instance")
    await _seed_cov(db_pool, n["a"], "in", "observed", "sentry_flow")                 # covered both
    await _seed_cov(db_pool, n["a"], "out", "observed", "sentry_flow")
    await _seed_cov(db_pool, n["b"], "in", "configured", "aws_sg")                    # inbound only
    await _seed_cov(db_pool, n["d"], "in", "observed", "sentry_flow", age_h=72)      # stale
    await _seed_cov(db_pool, n["d"], "out", "observed", "sentry_flow", age_h=72)
    await _seed_cov(db_pool, n["e"], "in", "declared", "declared")                    # below min tier
    r = (await client.get("/v1/assurance/coverage")).json()
    s = r["summary"]
    assert s["nodes"] == 5 and s["covered"] == 1 and s["blind"] == 4              # internet excluded
    assert s["covered_in_only"] == 1 and s["covered_out_only"] == 0 and s["ratio"] == 0.2
    by = {x["node_ref"]: x for x in r["nodes"]["items"]}
    assert by[n["a"]]["covered"] and by[n["a"]]["reason_in"] is None
    assert by[n["b"]]["covered_in"] and not by[n["b"]]["covered_out"] and by[n["b"]]["reason_out"] == "no_sensor"
    assert by[n["c"]]["reason_in"] == "no_sensor" and by[n["c"]]["reason_out"] == "no_sensor"
    assert by[n["d"]]["reason_in"] == "stale" and by[n["d"]]["reason_out"] == "stale"
    assert by[n["e"]]["reason_in"] == "tier_below_min"
    assert r["blind_spots"]["nodes_by_reason"]["out"]["no_sensor"] == 3     # b, c, e
    assert r["blind_spots"]["nodes_by_reason"]["in"] == {"no_sensor": 1, "stale": 1, "tier_below_min": 1}
    src = {(x["source"], x["direction"]): x for x in r["by_source"]}
    assert src[("sentry_flow", "in")]["facts"] == 2 and src[("sentry_flow", "in")]["fresh"] == 1
    assert src[("sentry_flow", "in")]["stale"] == 1 and src[("aws_sg", "in")]["nodes"] == 1

    # the thresholds are the caller's: a weaker tier / longer window covers more
    r2 = (await client.get("/v1/assurance/coverage?min_tier=declared&max_age_h=100")).json()
    assert r2["summary"]["covered"] == 2 and r2["summary"]["covered_in_only"] == 2   # a, d both; b, e in only
    # stronger tier covers fewer: nobody has 'tested'
    r3 = (await client.get("/v1/assurance/coverage?min_tier=tested")).json()
    assert r3["summary"]["covered"] == 0

    blind = (await client.get("/v1/assurance/coverage?only_blind=true&limit=2")).json()["nodes"]
    assert blind["total"] == 4 and len(blind["items"]) == 2 and all(not x["covered"] for x in blind["items"])
    assert (await client.get(f"/v1/assurance/coverage?q={n['c']}")).json()["nodes"]["total"] == 1
    assert (await client.get("/v1/assurance/coverage?min_tier=bogus")).status_code == 422
    assert (await client.get("/v1/assurance/coverage?max_age_h=0")).status_code == 422


async def test_coverage_reports_stale_and_silent_sensors(client, db_pool):
    async with db_pool.acquire() as con:
        for name, online, upload in (("fresh", True, NOW()), ("silent", False, NOW() - dt.timedelta(days=2)),
                                     ("never", True, None), ("old-but-online", True, NOW() - dt.timedelta(days=3))):
            await con.execute(
                "INSERT INTO sensors (name, site, cred_prefix, cred_hash, online, last_upload_at) "
                "VALUES ($1,'hq',$2,'h',$3,$4)", name, f"pfx-{name}", online, upload)
        await con.execute("INSERT INTO sensors (name, site, cred_prefix, cred_hash, status, online) "
                          "VALUES ('revoked','hq','pfx-r','h','revoked', FALSE)")
    names = [s["name"] for s in (await client.get("/v1/assurance/coverage")).json()["stale_sensors"]]
    assert names == ["never", "old-but-online", "silent"]       # revoked sensors are not "stale", they are gone


async def test_coverage_includes_what_the_last_evaluations_found_blind(client, db_pool):
    inv = await _create(client)
    async with db_pool.acquire() as con:
        await con.execute("UPDATE invariants SET last_result=$2::jsonb WHERE id=$1", uuid.UUID(inv["id"]),
                          json.dumps({"blind_spot_summary": {"total": 5, "by_reason": {"no_sensor": 4, "stale": 1}}}))
    bs = (await client.get("/v1/assurance/coverage")).json()["blind_spots"]
    assert bs["evaluated_by_reason"] == {"no_sensor": 4, "stale": 1}
    assert bs["invariants"] == [{"invariant_id": inv["invariant_id"], "total": 5,
                                 "by_reason": {"no_sensor": 4, "stale": 1}}]


async def test_state_endpoint(client, db_pool):
    s = (await client.get("/v1/assurance/state")).json()
    assert s["graph_version"] == 0 and s["last_eval_version"] == -1 and s["evaluation_pending"] is True
    assert s["counts"]["nodes"] == 0 and s["invariants"] == {"total": 0, "by_status": {}}
    assert s["library_version"] and s["builders"] == {} and s["evaluation_in_progress"] is False
    await client.post("/v1/zones", json={"name": "guest", "cidrs": ["10.0.0.0/8"], "justification": "j"})
    await _create(client)
    await _seed_edge(db_pool, "internet", f"asset:{uuid.uuid4()}")
    s = (await client.get("/v1/assurance/state")).json()
    assert s["graph_version"] == 1 and s["counts"]["zones"] == 1 and s["counts"]["edges"] == 1
    assert s["edges_by_source"] == {"aws_sg": 1} and s["invariants"]["by_status"] == {"PENDING": 1}
    assert "lease_owner" not in s            # process identity stays internal


# ============================================================================================
# Evaluate
# ============================================================================================

async def test_evaluate_passes_force_and_only_to_the_runner_and_returns_its_summary(client, monkeypatch):
    from app.assurance import runner

    inv = await _create(client)
    calls = []

    async def fake(pool, tenant_id, *, force=False, only=None, rebuild=False, redis=None):
        calls.append({"tenant": tenant_id, "force": force, "only": only, "rebuild": rebuild,
                      "redis": redis is not None})
        return {"ok": True, "tenant_id": tenant_id, "skipped": None, "built": rebuild, "graph_version": 4,
                "evaluated": 1, "results": [{"invariant_id": inv["invariant_id"], "verdict": "HOLDS"}],
                "errors": [], "builders": {"aws_sg": {"ok": True}}}

    monkeypatch.setattr(runner, "evaluate_tenant", fake)
    r = await client.post("/v1/assurance/evaluate", json={"invariant_ids": [inv["id"]], "rebuild": True})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["ok"] and out["evaluated"] == 1 and out["graph_version"] == 4 and out["built"]
    assert out["results"] == [{"invariant_id": inv["invariant_id"], "verdict": "HOLDS"}]
    # a row UUID is resolved to the text id the runner selects by; the tenant is the caller's
    assert calls == [{"tenant": TENANT_A, "force": True, "only": [inv["invariant_id"]], "rebuild": True,
                      "redis": True}]
    await client.post("/v1/assurance/evaluate")                     # no body at all is fine
    assert calls[-1]["only"] is None and calls[-1]["rebuild"] is False


async def test_evaluate_is_200_when_the_runner_degrades_raises_or_hangs(client, monkeypatch):
    from app.assurance import runner
    from app.routers import assurance as api

    async def degraded(pool, tenant_id, **kw):
        return {"ok": False, "skipped": "lease_held", "errors": ["another evaluation holds the lease"],
                "evaluated": 0, "results": []}

    async def boom(pool, tenant_id, **kw):
        raise RuntimeError("database exploded " + "x" * 1000)

    async def hang(pool, tenant_id, **kw):
        await asyncio.sleep(30)

    monkeypatch.setattr(api, "EVALUATE_TIMEOUT_S", 0.2)
    for fake, skipped in ((degraded, "lease_held"), (boom, "error"), (hang, "timeout")):
        monkeypatch.setattr(runner, "evaluate_tenant", fake)
        r = await client.post("/v1/assurance/evaluate")
        assert r.status_code == 200, (skipped, r.text)
        out = r.json()
        assert out["ok"] is False and out["degraded"] is True and out["skipped"] == skipped and out["errors"]
        assert out["evaluated"] == 0 and all(len(e) <= 320 for e in out["errors"])


async def test_evaluate_never_widens_an_empty_selection_to_everything(client, monkeypatch):
    """The runner reads ``only=[]`` as "all". Naming only disabled invariants must not run them (or
    anything else)."""
    from app.assurance import runner

    inv = await _create(client)
    await _create(client, "acme:another")
    await client.put(f"/v1/invariants/{inv['id']}", json={"enabled": False})
    called = []

    async def fake(pool, tenant_id, **kw):
        called.append(kw)
        return {"ok": True, "evaluated": 0, "results": []}

    monkeypatch.setattr(runner, "evaluate_tenant", fake)
    r = await client.post("/v1/assurance/evaluate", json={"invariant_ids": [inv["invariant_id"]]})
    out = r.json()
    assert r.status_code == 200 and out["ok"] and out["skipped"] == "none_enabled"
    assert out["ignored_disabled"] == [inv["invariant_id"]] and called == []
    # mixed: the disabled one is reported, the enabled one is what runs
    r = await client.post("/v1/assurance/evaluate",
                          json={"invariant_ids": [inv["invariant_id"], "acme:another"]})
    assert called[-1]["only"] == ["acme:another"] and r.json()["ignored_disabled"] == [inv["invariant_id"]]


async def test_evaluate_unknown_id_is_404_and_input_is_validated(client):
    assert (await client.post("/v1/assurance/evaluate", json={"invariant_ids": ["acme:nope"]})).status_code == 404
    assert (await client.post("/v1/assurance/evaluate", json={"invariant_ids": [str(uuid.uuid4())]})).status_code == 404
    assert (await client.post("/v1/assurance/evaluate", json={"invariant_ids": [""]})).status_code == 422
    assert (await client.post("/v1/assurance/evaluate", json={"invariant_ids": ["x"] * 101})).status_code == 422
    assert (await client.post("/v1/assurance/evaluate", json={"invariant_ids": "acme:x"})).status_code == 422


async def test_evaluate_with_nothing_enabled_is_ok_and_empty(client):
    r = await client.post("/v1/assurance/evaluate")
    assert r.status_code == 200 and r.json()["ok"] is True and r.json()["evaluated"] == 0
    assert r.json()["skipped"] == "no_invariants"


async def test_evaluate_end_to_end_with_the_real_runner(client, db_pool):
    """Real runner, real library: an uncovered host violates std:coverage-complete, and the list
    shows the verdict afterwards."""
    ref = f"asset:{uuid.uuid4()}"
    await _seed_node(db_pool, ref, "cloud_instance")          # no coverage at all => blind
    inv = (await client.post("/v1/invariants/std/std:coverage-complete/enable")).json()["invariant"]
    r = await client.post("/v1/assurance/evaluate", json={"invariant_ids": [inv["invariant_id"]]})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["evaluated"] == 1, out
    assert out["results"][0]["verdict"] == "VIOLATED"
    got = (await client.get(f"/v1/invariants/{inv['id']}")).json()
    assert got["status"] == "VIOLATED" and got["violation_count"] == 1 and got["last_evaluated_at"]
    assert got["last_result"]["witnesses"][0]["detail"]["node"] == ref
    runs = (await client.get(f"/v1/invariants/{inv['id']}/runs")).json()
    assert runs["total"] == 1 and runs["items"][0]["verdict"] == "VIOLATED"
    # cover the node in both directions and evaluate again: the verdict flips to HOLDS
    await _seed_cov(db_pool, ref, "in", "configured", "aws_sg")
    await _seed_cov(db_pool, ref, "out", "observed", "sentry_flow")
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO assurance_state (graph_version) VALUES (1) "
                          "ON CONFLICT (tenant_id) DO UPDATE SET graph_version = assurance_state.graph_version + 1")
    r = await client.post("/v1/assurance/evaluate", json={"invariant_ids": [inv["invariant_id"]]})
    assert r.json()["results"][0]["verdict"] == "HOLDS", r.text
    assert (await client.get(f"/v1/invariants/{inv['id']}")).json()["status"] == "HOLDS"
    assert (await client.get(f"/v1/invariants/{inv['id']}/runs")).json()["total"] == 2


# ============================================================================================
# Audit is best effort
# ============================================================================================

async def test_an_audit_failure_never_fails_the_mutation(client, monkeypatch):
    from app.routers import assurance as api

    async def broken(*a, **kw):
        raise RuntimeError("audit store down")

    # only this router's audit calls break (the governance middleware writes its own rows)
    monkeypatch.setattr(api, "audit", types.SimpleNamespace(record=broken))
    r = await client.post("/v1/zones", json={"name": "guest", "cidrs": ["10.0.0.0/8"], "justification": "j"})
    assert r.status_code == 201
    inv = await _create(client)
    assert (await client.delete(f"/v1/invariants/{inv['id']}")).status_code == 200


async def test_invariant_mutations_are_audited_with_semantic_detail(client, db_pool):
    inv = await _create(client)
    await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": inv_yaml(title="Renamed rule")})
    await client.delete(f"/v1/invariants/{inv['id']}")
    await client.post("/v1/invariants/std/std:coverage-complete/enable")
    c = (await _audit_rows(db_pool, "assurance_invariant_create"))[0]["details"]
    assert c["invariant_id"] == inv["invariant_id"] and c["digest"] == inv["digest"] and c["assertion"] == "unreachable"
    u = (await _audit_rows(db_pool, "assurance_invariant_update"))[0]["details"]
    assert u["previous"]["digest"] == inv["digest"] and u["new_version"] is True and u["version"] == 2
    d = (await _audit_rows(db_pool, "assurance_invariant_archive"))[0]["details"]
    assert d["was_enabled"] is True and d["rows_kept"] is True
    assert (await _audit_rows(db_pool, "assurance_std_enable"))[0]["details"]["invariant_id"] == "std:coverage-complete"


# ============================================================================================
# RBAC (enforce mode)
# ============================================================================================

async def test_rbac_reads_need_read_and_every_mutation_needs_admin(enforce, client, db_pool):
    admin = await _seed_admin(db_pool, TENANT_A, "ada-admin")
    _, viewer = await _seed_user_with_key(db_pool, "vera", "viewer", "public")
    inv = (await client.post("/v1/invariants", headers=_hdr(admin), json={"yaml": inv_yaml()})).json()["invariant"]
    zone = (await client.post("/v1/zones", headers=_hdr(admin), json={
        "name": "guest", "cidrs": ["10.0.0.0/8"], "justification": "j"})).json()["zone"]
    lab = (await client.put("/v1/labels", headers=_hdr(admin), json={
        "node_ref": "ip:10.0.0.5", "tag": "class", "value": "data_store", "justification": "j"})).json()["label"]

    reads = ["/v1/invariants", "/v1/invariants/std", f"/v1/invariants/{inv['id']}",
             f"/v1/invariants/{inv['id']}/runs", "/v1/assurance/coverage", "/v1/assurance/state",
             "/v1/reach/nodes", "/v1/reach/edges", "/v1/zones", f"/v1/zones/{zone['id']}", "/v1/labels"]
    muts = [("POST", "/v1/invariants", {"yaml": inv_yaml("acme:x")}),
            ("PUT", f"/v1/invariants/{inv['id']}", {"enabled": False}),
            ("DELETE", f"/v1/invariants/{inv['id']}", None),
            ("POST", "/v1/invariants/std/std:coverage-complete/enable", None),
            ("POST", "/v1/assurance/evaluate", {}),
            ("POST", "/v1/zones", {"name": "pos", "cidrs": ["10.1.0.0/16"], "justification": "j"}),
            ("PUT", f"/v1/zones/{zone['id']}", {"cidrs": ["10.2.0.0/16"], "justification": "j"}),
            ("DELETE", f"/v1/zones/{zone['id']}", None),
            ("PUT", "/v1/labels", {"node_ref": "ip:10.0.0.6", "tag": "class", "value": "x", "justification": "j"}),
            ("DELETE", f"/v1/labels/{lab['id']}", None)]

    for path in reads:
        assert (await client.get(path)).status_code == 401, path                          # anonymous
        assert (await client.get(path, headers=_hdr(viewer))).status_code == 200, path    # read-only key
        assert (await client.get(path, headers=_hdr(admin))).status_code == 200, path
    before = await _fingerprint(db_pool)
    for method, path, body in muts:
        kw = {} if body is None else {"json": body}
        assert (await client.request(method, path, **kw)).status_code == 401, (method, path)
        r = await client.request(method, path, headers=_hdr(viewer), **kw)
        assert r.status_code == 403, (method, path, r.status_code)
    assert await _fingerprint(db_pool) == before          # the refused calls changed nothing
    # ... and the admin can do all of it
    for method, path, body in muts[:4] + muts[5:6] + muts[8:9]:
        kw = {} if body is None else {"json": body}
        r = await client.request(method, path, headers=_hdr(admin), **kw)
        assert r.status_code in (200, 201), (method, path, r.status_code, r.text)


async def _fingerprint(db_pool, tenant=None) -> str:
    parts = []
    async with db_pool.acquire() as con:
        for t in ("invariants", "invariant_versions", "invariant_runs", "zones", "asset_labels",
                  "assurance_state", "reach_nodes", "reach_edges", "reach_coverage"):
            q = f"SELECT md5(COALESCE(string_agg(x::text, '|' ORDER BY x::text), '')) FROM public.\"{t}\" x"
            if tenant:
                q += " WHERE x.tenant_id = $1"
                parts.append(await con.fetchval(q, tenant))
            else:
                parts.append(await con.fetchval(q))
    return "".join(parts)


# ============================================================================================
# Billing gate
# ============================================================================================

@pytest.fixture
def billing(monkeypatch):
    s = bcfg.settings
    monkeypatch.setattr(s, "stripe_secret_key", "sk_test_not_a_real_key")
    monkeypatch.setattr(s, "stripe_webhook_secret", "whsec_x")
    monkeypatch.setattr(s, "stripe_price_team", "price_team_placeholder")
    monkeypatch.setattr(s, "stripe_price_enterprise", "price_ent_placeholder")
    monkeypatch.setattr(s, "billing_public_url", "https://app.example.test")
    monkeypatch.setattr(s, "billing_cache_ttl_sec", 0.0)
    monkeypatch.setattr(s, "enforce_editions", "auto")
    billing_service.invalidate()
    bstatus.reset_cache()
    yield s
    billing_service.invalidate()
    bstatus.reset_cache()


async def _lapse_trial(db_pool):
    async with db_pool.acquire() as con:
        await con.execute("UPDATE tenants SET created_at = NOW() - make_interval(days => 60) WHERE id = $1::uuid",
                          TENANT_A)


async def test_billing_gate_refuses_paid_mutations_but_never_reads_or_cleanup(client, db_pool, billing):
    # inside the trial a Team feature is available
    inv = await _create(client)
    zone = (await client.post("/v1/zones", json={"name": "guest", "cidrs": ["10.0.0.0/8"],
                                                 "justification": "j"})).json()["zone"]
    lab = (await client.put("/v1/labels", json={"node_ref": "ip:10.0.0.5", "tag": "class", "value": "x",
                                                "justification": "j"})).json()["label"]
    await _lapse_trial(db_pool)
    before = await _fingerprint(db_pool)
    gated = [("POST", "/v1/invariants", {"yaml": inv_yaml("acme:new")}),
             ("PUT", f"/v1/invariants/{inv['id']}", {"enabled": False}),
             ("POST", "/v1/invariants/std/std:coverage-complete/enable", None),
             ("POST", "/v1/assurance/evaluate", {}),
             ("POST", "/v1/zones", {"name": "pos", "cidrs": ["10.1.0.0/16"], "justification": "j"}),
             ("PUT", f"/v1/zones/{zone['id']}", {"cidrs": ["10.2.0.0/16"], "justification": "j"}),
             ("PUT", "/v1/labels", {"node_ref": "ip:10.0.0.6", "tag": "class", "value": "x", "justification": "j"})]
    for method, path, body in gated:
        kw = {} if body is None else {"json": body}
        r = await client.request(method, path, **kw)
        assert r.status_code == 402, (method, path, r.status_code)
        assert r.json()["feature"] == "assurance" and r.json()["error"] == "payment_required"
    assert await _fingerprint(db_pool) == before          # a refused paid action changed nothing

    # reads are never gated
    for path in ("/v1/invariants", "/v1/invariants/std", f"/v1/invariants/{inv['id']}",
                 f"/v1/invariants/{inv['id']}/runs", "/v1/assurance/coverage", "/v1/assurance/state",
                 "/v1/reach/nodes", "/v1/reach/edges", "/v1/zones", "/v1/labels"):
        assert (await client.get(path)).status_code == 200, path
    # clean-up is never a paid action: a downgraded tenant can switch things off and remove them
    assert (await client.delete(f"/v1/labels/{lab['id']}")).status_code == 200
    assert (await client.delete(f"/v1/zones/{zone['id']}")).status_code == 200
    assert (await client.delete(f"/v1/invariants/{inv['id']}")).status_code == 200


async def test_gates_are_open_when_billing_is_off(client):
    assert (await client.post("/v1/invariants", json={"yaml": inv_yaml()})).status_code == 201


# ============================================================================================
# Tenant isolation
# ============================================================================================

@pytest_asyncio.fixture
async def two(enforce, app, app_pool, db_pool, client):
    """Tenant A (default) and B, each with an admin key, served through the RLS role."""
    app.state.pool = app_pool
    await tenancy.create_tenant(db_pool, slug="bravo-assurance", name="Bravo", tenant_id=TENANT_B)
    ka = await _seed_admin(db_pool, TENANT_A, "alice-admin")
    kb = await _seed_admin(db_pool, TENANT_B, "bob-admin")
    return {"a": _hdr(ka), "b": _hdr(kb)}


async def _seed_tenant_a(client, db_pool, h) -> dict:
    inv = (await client.post("/v1/invariants", headers=h, json={"yaml": inv_yaml()})).json()["invariant"]
    std = (await client.post("/v1/invariants/std/std:coverage-complete/enable", headers=h)).json()["invariant"]
    zone = (await client.post("/v1/zones", headers=h, json={"name": "guest", "cidrs": ["10.0.0.0/8"],
                                                            "justification": "alpha zone"})).json()["zone"]
    asset = await _seed_asset(db_pool, TENANT_A, "alpha-only.example")
    lab = (await client.put("/v1/labels", headers=h, json={
        "node_ref": f"asset:{asset}", "tag": "crown-jewel", "value": "true",
        "justification": "alpha secret reason"})).json()["label"]
    ref = f"asset:{asset}"
    await _seed_node(db_pool, ref, "cloud_db", TENANT_A, label="alpha-orders-db")
    await _seed_edge(db_pool, "internet", ref, tenant=TENANT_A)
    await _seed_cov(db_pool, ref, "in", tenant=TENANT_A)
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO invariant_runs (tenant_id, invariant_id, digest, verdict) "
                          "VALUES ($1, $2, 'sha256:a', 'VIOLATED')", TENANT_A, inv["invariant_id"])
    return {"inv": inv, "std": std, "zone": zone, "label": lab, "asset": asset, "ref": ref}


def _norm(text: str, ids: list[str]) -> str:
    for i in ids:
        text = text.replace(i, "<id>")
    return text


async def test_tenant_b_sees_nothing_of_a_on_any_read(two, client, db_pool):
    a = await _seed_tenant_a(client, db_pool, two["a"])
    for path in ("/v1/invariants", "/v1/zones", "/v1/labels", "/v1/reach/nodes", "/v1/reach/edges"):
        body = (await client.get(path, headers=two["b"])).json()
        assert body["total"] == 0 and body["items"] == [], path
    assert (await client.get("/v1/invariants/std", headers=two["b"])).json()[0]["installed"] is False
    assert not any(s["installed"] for s in (await client.get("/v1/invariants/std", headers=two["b"])).json())
    cov = (await client.get("/v1/assurance/coverage", headers=two["b"])).json()
    assert cov["summary"]["nodes"] == 0 and cov["by_source"] == [] and cov["nodes"]["items"] == []
    state = (await client.get("/v1/assurance/state", headers=two["b"])).json()
    assert state["graph_version"] == 0 and state["counts"]["nodes"] == 0 and state["invariants"]["total"] == 0
    # and the data really is there for its owner
    assert (await client.get("/v1/invariants", headers=two["a"])).json()["total"] == 2
    assert (await client.get("/v1/reach/nodes", headers=two["a"])).json()["total"] == 1
    # nothing about A leaks through any response B can get
    blob = json.dumps([(await client.get(p, headers=two["b"])).json() for p in (
        "/v1/invariants", "/v1/zones", "/v1/labels", "/v1/reach/nodes", "/v1/assurance/coverage",
        "/v1/assurance/state")])
    for needle in (a["asset"], "alpha", "guest"):
        assert needle not in blob


async def test_foreign_ids_answer_exactly_like_unknown_ids_on_every_id_route(two, client, db_pool):
    a = await _seed_tenant_a(client, db_pool, two["a"])
    before_a = await _fingerprint(db_pool, TENANT_A)
    victim = {"invariant": [a["inv"]["id"], a["std"]["id"]], "zone": [a["zone"]["id"]],
              "label": [a["label"]["id"]]}
    # (method, template, id kind, body)
    routes = [
        ("GET", "/v1/invariants/{}", "invariant", None),
        ("PUT", "/v1/invariants/{}", "invariant", {"enabled": False}),
        ("PUT", "/v1/invariants/{}", "invariant", {"yaml": inv_yaml(title="pwned by bravo")}),
        ("DELETE", "/v1/invariants/{}", "invariant", None),
        ("GET", "/v1/invariants/{}/runs", "invariant", None),
        ("GET", "/v1/zones/{}", "zone", None),
        ("PUT", "/v1/zones/{}", "zone", {"cidrs": ["192.168.0.0/16"], "justification": "pwned"}),
        ("DELETE", "/v1/zones/{}", "zone", None),
        ("DELETE", "/v1/labels/{}", "label", None),
    ]
    for method, tmpl, kind, body in routes:
        for vid in victim[kind]:
            rid = str(uuid.uuid4())
            kw = {} if body is None else {"json": body}
            foreign = await client.request(method, tmpl.format(vid), headers=two["b"], **kw)
            random_ = await client.request(method, tmpl.format(rid), headers=two["b"], **kw)
            assert foreign.status_code == random_.status_code == 404, (method, tmpl, foreign.status_code,
                                                                         random_.status_code)
            assert _norm(foreign.text, [vid]) == _norm(random_.text, [rid]), (method, tmpl)
    # B's attempts changed none of A's rows
    assert await _fingerprint(db_pool, TENANT_A) == before_a
    # evaluate by id: A's invariant is as unknown to B as a random one
    ids = [a["inv"]["id"], a["inv"]["invariant_id"], a["std"]["invariant_id"]]
    for i in ids:
        r = await client.post("/v1/assurance/evaluate", headers=two["b"], json={"invariant_ids": [i]})
        assert r.status_code == 404 and r.json() == {"detail": "invariant not found"}, i
    r0 = await client.post("/v1/assurance/evaluate", headers=two["b"], json={"invariant_ids": ["acme:zz"]})
    assert r0.status_code == 404 and r0.json() == {"detail": "invariant not found"}
    assert await _fingerprint(db_pool, TENANT_A) == before_a
    # and B's evaluate (a real run, nothing enabled) touches only B
    r = await client.post("/v1/assurance/evaluate", headers=two["b"])
    assert r.status_code == 200 and r.json()["evaluated"] == 0
    assert await _fingerprint(db_pool, TENANT_A) == before_a


async def test_same_names_in_two_tenants_do_not_collide(two, client, db_pool):
    await _seed_tenant_a(client, db_pool, two["a"])
    r = await client.post("/v1/invariants", headers=two["b"], json={"yaml": inv_yaml()})
    assert r.status_code == 201                                  # not a 409 against A's identical id
    assert (await client.post("/v1/zones", headers=two["b"], json={
        "name": "guest", "cidrs": ["172.16.0.0/12"], "justification": "bravo"})).status_code == 201
    assert (await client.post("/v1/invariants/std/std:coverage-complete/enable", headers=two["b"])).status_code == 201
    za = (await client.get("/v1/zones", headers=two["a"])).json()["items"]
    zb = (await client.get("/v1/zones", headers=two["b"])).json()["items"]
    assert za[0]["cidrs"] == ["10.0.0.0/8"] and zb[0]["cidrs"] == ["172.16.0.0/12"]
    # graph versions are per tenant
    assert (await client.get("/v1/assurance/state", headers=two["a"])).json()["graph_version"] == 2   # zone + label
    assert (await client.get("/v1/assurance/state", headers=two["b"])).json()["graph_version"] == 1   # zone only
    # B labelling an asset id that only exists in A is "no such asset", not a leak and not a write
    asset_a = await _seed_asset(db_pool, TENANT_A, "alpha-two.example")
    r = await client.put("/v1/labels", headers=two["b"], json={
        "node_ref": f"asset:{asset_a}", "tag": "class", "value": "data_store", "justification": "j"})
    assert r.status_code == 422 and "no such asset" in r.text
    assert (await client.get("/v1/labels", headers=two["a"])).json()["total"] == 1


# ============================================================================================
# Sweep safety
# ============================================================================================

async def test_empty_and_hostile_bodies_never_500(client):
    """What the generic API sweep sends: {} and a body of unrelated fields, to every id route (random
    ids) and every id-less PUT. 422 or 404 are fine; a 500 is not."""
    junk = {"name": "pwned", "title": "pwned", "status": "closed", "enabled": False, "note": "pwned",
            "reason": "pwned", "label": "pwned", "role": "admin", "severity": "info"}
    rid = uuid.uuid4()
    targets = [(f"/v1/invariants/{rid}", ("put", "patch")), (f"/v1/zones/{rid}", ("put", "patch")),
               ("/v1/labels", ("put", "patch")), (f"/v1/invariants/{rid}", ("delete",)),
               (f"/v1/zones/{rid}", ("delete",)), (f"/v1/labels/{rid}", ("delete",))]
    for path, methods in targets:
        for m in methods:
            for body in ({}, junk, [], "x", None):
                r = await client.request(m.upper(), path, json=body)
                assert r.status_code in (404, 405, 422), (m, path, body, r.status_code, r.text[:200])
    for path in ("/v1/invariants/not-a-uuid", "/v1/zones/%00", "/v1/labels/1", "/v1/invariants/" + "9" * 400):
        for m in ("get", "put", "delete"):
            r = await client.request(m.upper(), path, json={})
            assert r.status_code in (404, 405, 422), (m, path, r.status_code)
