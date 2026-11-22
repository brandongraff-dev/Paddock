"""A multi-tenant world for the isolation / concurrency stress suites.

Tenants: ``a`` and ``b`` (plain), ``m`` (an MSP org) and ``c1`` (an MSP
customer, created through the MSP API). Every tenant gets

* an admin user + full-scope API key (``key``),
* coherent data written THROUGH the API (scope, assets, findings, suppliers,
  trust links, ingest sources, sensor tokens ...) whose text carries the
  tenant's ``marker``, and
* one generated row (marker in every text column) in every other tenant table.

Every response a tenant gets must therefore never contain another tenant's
marker.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from app import auth as auth_svc
from app import tenancy
from app.config import settings

from .test_isolation_sweep import _make_row, _relations

SERVICE_KEY = "svc-key-for-stress-tests-0123456789"

MARKERS = {"a": "zqamark", "b": "zqbmark", "m": "zqmmark", "c1": "zqcmark"}
T_A = "00000000-0000-0000-0000-0000000000a1"
T_B = "00000000-0000-0000-0000-0000000000b1"
T_M = "00000000-0000-0000-0000-0000000000c1"

#: tables that must not get a generated row (they would corrupt a hash chain /
#: the MSP relationship the world builds through the API).
NO_GENERIC = {"audit_log", "msp_orgs", "msp_children", "msp_grants", "msp_invites",
              "msp_child_health", "msp_templates", "msp_template_applications", "msp_usage_snapshots"}


def h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@dataclass
class Tenant:
    name: str
    id: str
    marker: str
    key: str | None = None
    token: str | None = None          # bearer: API key or session/switch JWT
    ids: dict[str, list] = field(default_factory=dict)   # table -> pk values (superuser view)
    api: dict[str, list] = field(default_factory=dict)   # kind -> ids created through the API

    def headers(self) -> dict[str, str]:
        return h(self.token or self.key or "")


async def seed_admin(db_pool, tenant_id: str, username: str) -> str:
    full, prefix, key_hash = auth_svc.generate_api_key()
    async with db_pool.acquire() as con:
        uid = await con.fetchval(
            "INSERT INTO app_users (username, role, clearance, pw_hash, tenant_id) "
            "VALUES ($1, 'admin', 'restricted', $2, $3) RETURNING id",
            username, auth_svc.hash_password("pw-" + username), tenant_id,
        )
        await con.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes, tenant_id) "
            "VALUES ($1, 'k', $2, $3, $4::text[], $5)",
            uid, prefix, key_hash, sorted(auth_svc.ROLE_CAPABILITIES["admin"]), tenant_id,
        )
    return full


async def seed_api_data(client, t: Tenant) -> None:
    """Coherent data through the real API, so list/detail routes have rows."""
    hd = t.headers()
    m = t.marker
    dom = f"{m}.example"
    r = await client.post("/v1/scope", headers=hd, json={"kind": "domain", "value": dom, "added_by": "t"})
    assert r.status_code == 201, r.text
    t.api["scope"] = [r.json()["id"]]
    r = await client.post("/v1/assets/bulk", headers=hd, json={"items": [
        {"kind": "domain", "value": dom, "source": "test"},
        {"kind": "domain", "value": f"www.{dom}", "source": "test"}]})
    assert r.status_code in (200, 201), r.text
    t.api["assets"] = [i["id"] for i in r.json()["items"]]
    r = await client.post("/v1/findings/bulk", headers=hd, json={"items": [
        {"asset_value": dom, "asset_kind": "domain", "rule_id": f"{m}-rule-{i}", "rule_source": "policy",
         "severity": sev, "title": f"{m} finding {i}", "description": f"{m} desc"}
        for i, sev in enumerate(("high", "medium", "critical", "low"))]})
    assert r.status_code in (200, 201), r.text
    t.api["findings"] = [i["id"] for i in r.json()["items"]]
    r = await client.post("/v1/suppliers", headers=hd, json={"domain": f"sup.{dom}", "name": f"{m} supplier"})
    if r.status_code in (200, 201):
        t.api["suppliers"] = [r.json()["id"]]
    r = await client.post("/v1/trust-links", headers=hd, json={"label": f"{m} link"})
    if r.status_code in (200, 201):
        t.api["trust_links"] = [r.json().get("id")]
    r = await client.post("/v1/ingest/sources", headers=hd, json={"name": f"{m}-source", "description": f"{m} source"})
    if r.status_code in (200, 201):
        t.api["ingest_sources"] = [r.json().get("id")]
    r = await client.post("/v1/sensors/tokens", headers=hd, json={"site": f"{m}-site", "label": f"{m} sensor"})
    if r.status_code in (200, 201):
        t.api["sensor_tokens"] = [r.json().get("id")]


async def seed_generic(db_pool, t: Tenant) -> dict[str, list]:
    """One generated row (marker text) in every tenant table; returns pk values."""
    async with db_pool.acquire() as con:
        rels = await _relations(con)
    tables = [r["relname"] for r in rels if r["relkind"] in ("r", "p") and r["has_tenant"]]
    for table in tables:
        if table in NO_GENERIC:
            continue
        async with db_pool.acquire() as su:
            await su.execute("SET session_replication_role = replica")
            try:
                await _make_row(su, table, t.id, t.marker)
            finally:
                await su.execute("SET session_replication_role = DEFAULT")
    return await collect_ids(db_pool, t.id, tables)


async def collect_ids(db_pool, tenant_id: str, tables: list[str]) -> dict[str, list]:
    """Every value of every uuid / int / text column named ``id`` or ``*_id`` per table."""
    out: dict[str, list] = {}
    async with db_pool.acquire() as con:
        for table in tables:
            cols = await con.fetch(
                "SELECT a.attname FROM pg_attribute a WHERE a.attrelid = ('public.' || quote_ident($1))::regclass "
                "AND a.attnum > 0 AND NOT a.attisdropped AND (a.attname = 'id' OR a.attname = 'slug')",
                table,
            )
            vals: list = []
            for c in cols:
                rows = await con.fetch(
                    f'SELECT "{c["attname"]}" AS v FROM public."{table}" WHERE tenant_id = $1 LIMIT 20',
                    tenant_id,
                )
                vals += [r["v"] for r in rows if r["v"] is not None]
            if vals:
                out[table] = vals
    return out


@dataclass
class World:
    t: dict[str, Tenant]
    db_pool: object
    client: object

    def __getitem__(self, k: str) -> Tenant:
        return self.t[k]


async def build_world(*, db_pool, app_pool, app, client, generic: bool = True) -> World:
    """Create the four tenants, log the MSP user in, switch into the customer."""
    app.state.pool = app_pool
    settings.auth_mode = "enforce"
    settings.service_api_key = SERVICE_KEY
    w = World(t={}, db_pool=db_pool, client=client)
    for name, tid in (("a", T_A), ("b", T_B), ("m", T_M)):
        await tenancy.create_tenant(db_pool, slug=f"stress-{name}", name=f"Stress {name}", tenant_id=tid)
        w.t[name] = Tenant(name=name, id=tid, marker=MARKERS[name])
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO msp_orgs (tenant_id, name, created_by) VALUES ($1, 'Stress MSP', 'test')", T_M
        )
    for name in ("a", "b"):
        w.t[name].key = await seed_admin(db_pool, w.t[name].id, f"admin-{name}")
        w.t[name].token = w.t[name].key
    # MSP root: an admin user that signs in (session JWT) and creates the customer.
    await seed_admin(db_pool, T_M, "admin-m")
    r = await client.post("/v1/auth/login", json={"username": "admin-m", "password": "pw-admin-m"})
    assert r.status_code == 200, r.text
    w.t["m"].token = r.json()["access_token"]
    r = await client.post("/v1/msp/customers", headers=w.t["m"].headers(),
                          json={"slug": "stress-c1", "name": "Stress customer one"})
    assert r.status_code == 201, r.text
    c1 = Tenant(name="c1", id=r.json()["id"], marker=MARKERS["c1"])
    w.t["c1"] = c1
    r = await client.post(f"/v1/msp/customers/{c1.id}/switch", headers=w.t["m"].headers())
    assert r.status_code == 200, r.text
    c1.token = r.json()["access_token"]

    for t in w.t.values():
        await seed_api_data(client, t)
    if generic:
        for t in w.t.values():
            t.ids = await seed_generic(db_pool, t)
    return w


def new_uuid() -> str:
    return str(uuid.uuid4())
