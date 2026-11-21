"""Tenant isolation for otdiscovery: per-tenant engines, tenant-bound sensor
tokens, tenant-stamped orchestrator calls, and the CVE read under a real
``paddock_svc_otdiscovery`` role."""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import tenant_testkit as kit  # noqa: E402

from app import tenancy  # noqa: E402
from app.config import Config  # noqa: E402
from app.db import Database  # noqa: E402
from app.main import OtDiscoveryService  # noqa: E402

A, B = kit.TENANT_A, kit.TENANT_B
pytestmark = pytest.mark.asyncio


class FakeOrch:
    """Records the tenant context each orchestrator call is made under."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None, int]] = []

    async def bulk_assets(self, assets):
        self.calls.append(("assets", tenancy.requested_tenant(), len(assets)))
        return {"inserted": len(assets)}

    async def bulk_edges(self, edges):
        self.calls.append(("edges", tenancy.requested_tenant(), len(edges)))
        return {}

    async def bulk_findings(self, findings):
        self.calls.append(("findings", tenancy.requested_tenant(), len(findings)))
        return {"inserted": len(findings)}


def _obs(ip: str) -> dict:
    return {"kind": "flow", "src": ip, "dst": "10.9.9.9", "dst_port": 502, "proto": "tcp",
            "first_seen": 1000, "last_seen": 1000}


@pytest.fixture
async def http():
    cfg = dataclasses.replace(
        Config(), enable_db=False, sentry_tokens=(f"{A}=tok-a", f"{B}=tok-b", "tok-default"))
    svc = OtDiscoveryService(cfg)
    svc.orch = FakeOrch()
    client = TestClient(TestServer(svc.make_app()))
    await client.start_server()
    yield svc, client
    await client.close()


async def _ingest(client, token, ip, sensor):
    return await client.post(
        "/ingest", headers={"Authorization": f"Bearer {token}"},
        json={"observations": [_obs(ip)], "sensor": {"id": sensor, "site": "s"}})


async def test_a_sensor_token_only_feeds_its_own_tenant(http):
    svc, client = http
    assert (await _ingest(client, "tok-a", "10.1.1.1", "sensor-a")).status == 200
    assert (await _ingest(client, "tok-b", "10.2.2.2", "sensor-b")).status == 200
    assert (await _ingest(client, "nope", "10.3.3.3", "x")).status == 401
    ea, eb = svc.engines[A], svc.engines[B]
    assert [o["src"] for o in ea.observations] == ["10.1.1.1"]
    assert [o["src"] for o in eb.observations] == ["10.2.2.2"]
    assert set(ea.sensors) == {"sensor-a"} and set(eb.sensors) == {"sensor-b"}
    # every orchestrator write ran under the sensor's tenant, never another's
    by_tenant = {t for _, t, _ in svc.orch.calls}
    assert by_tenant == {A, B}


async def test_unbound_token_is_default_tenant_and_refused_in_strict_mode(http, monkeypatch):
    svc, client = http
    assert (await _ingest(client, "tok-default", "10.4.4.4", "d")).status == 200
    assert [o["src"] for o in svc.engines[tenancy.DEFAULT_TENANT_ID].observations] == ["10.4.4.4"]
    monkeypatch.setenv("TENANCY_STRICT", "true")
    r = await _ingest(client, "tok-default", "10.4.4.5", "d")
    assert r.status == 403 and (await r.json())["error"] == "tenant_required"


async def test_stats_are_per_tenant_and_need_the_service_key_to_pick_one(http, monkeypatch):
    svc, client = http
    await _ingest(client, "tok-a", "10.1.1.1", "sensor-a")
    # no header: the default tenant's (empty) view -- A's data is not visible
    stats = await (await client.get("/stats")).json()
    assert stats["observations_stored"] == 0 and "sensor-a" not in stats["sensors"]
    # naming a tenant without the service key is refused once a key is configured
    monkeypatch.setenv("SERVICE_API_KEY", "svc-key")
    r = await client.get("/stats", headers={tenancy.TENANT_HEADER: A})
    assert r.status == 403
    r = await client.get("/stats", headers={tenancy.TENANT_HEADER: A, "X-API-Key": "svc-key"})
    assert r.status == 200 and (await r.json())["observations_stored"] == 1


async def test_cve_catalogue_read_as_the_service_role():
    tdb = await kit.make_db(roles=("paddock_svc_otdiscovery",))
    db = Database(tdb.role_dsn("paddock_svc_otdiscovery"))
    await db.connect()
    try:
        info = await tenancy.check_role(db.pool, require=True)
        assert not info["superuser"] and not info["bypassrls"]
        await tdb.raw(
            "INSERT INTO cves (id, cpe_affected) VALUES ('CVE-2099-1', "
            "'[{\"vendor\":\"acme\",\"product\":\"plc\"}]'::jsonb)")
        with tenancy.tenant_context(A):
            assert [r["id"] for r in await db.cve_candidates({"acme"})] == ["CVE-2099-1"]
            async with db.acquire() as con:
                await kit.expect_denied(con.fetch("SELECT * FROM findings"), what="findings read")
    finally:
        await db.close()
        await tdb.drop()
