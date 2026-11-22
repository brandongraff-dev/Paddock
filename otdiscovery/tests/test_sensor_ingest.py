"""Managed-sensor ingest: per-sensor credentials, idempotent batches, tenant
separation and the enrollment / heartbeat proxy (orchestrator faked)."""
from __future__ import annotations

import asyncio
import dataclasses
import gzip
import json

import pytest
from aiohttp.test_utils import TestClient, TestServer

from app.config import Config
from app import tenancy
from app.main import OtDiscoveryService
from app.pipeline import DiscoveryEngine
from app.sensorapi import SensorGateway

CRED = "pst_11223344_" + "C" * 32
TENANT_A = "00000000-0000-0000-0000-00000000000a"
TENANT_B = "00000000-0000-0000-0000-00000000000b"


class FakeOrch:
    """Stands in for the orchestrator HTTP API (sensor bracket + bulk writes)."""

    def __init__(self) -> None:
        self.claims: dict[str, str] = {}      # batch id -> state
        self.done_calls: list[tuple[str, bool, int]] = []
        self.sensor = {"sensor_id": "5e5e5e5e-0000-0000-0000-000000000001", "tenant_id": TENANT_A,
                       "name": "pi-1", "site": "store-42"}
        self.revoked = False
        self.down = False
        self.bulk_error = False
        self.forwarded_ips: list[str | None] = []
        self.enroll_answer: tuple[int, dict] = (201, {"credential": CRED})
        self.tenants_seen: list[str | None] = []
        self.assets_posted = 0

    # -- gateway surface ---------------------------------------------------
    async def request(self, method, path, *, json_body=None, headers=None):
        headers = headers or {}
        if self.down:
            return 503, {"detail": "orchestrator unavailable"}
        self.forwarded_ips.append(headers.get("X-Sensor-Client-IP"))
        if path == "/v1/sensors/enroll":
            return self.enroll_answer
        if headers.get("X-Sensor-Token") != CRED:
            return 401, {"detail": "invalid sensor credential"}
        if self.revoked:
            return 403, {"detail": "sensor revoked"}
        if path == "/v1/sensors/heartbeat":
            return 200, {"ok": True}
        if path == "/v1/sensors/ingest/claim":
            bid = json_body["batch_id"]
            state = self.claims.get(bid)
            if state == "done":
                return 200, {"state": "duplicate", **self.sensor}
            if state == "claimed":
                return 200, {"state": "in_progress", **self.sensor}
            self.claims[bid] = "claimed"
            return 200, {"state": "new", **self.sensor}
        if path == "/v1/sensors/ingest/done":
            self.done_calls.append((json_body["batch_id"], json_body["ok"], json_body["flows"]))
            if json_body["ok"]:
                self.claims[json_body["batch_id"]] = "done"
            else:
                self.claims.pop(json_body["batch_id"], None)
            return 200, {"ok": True}
        return 404, {}

    # -- OrchestratorClient surface (used by the tenant engines) -------------
    def for_tenant(self, tenant):
        outer = self

        class View:
            async def bulk_assets(self, assets):
                outer.tenants_seen.append(tenant)
                outer.assets_posted += len(assets)
                return {"error": "boom"} if outer.bulk_error else {"inserted": len(assets), "updated": 0}

            async def bulk_edges(self, edges):
                return {"edges_inserted": len(edges)}

            async def bulk_findings(self, findings):
                return {"inserted": len(findings), "updated": 0}

        return View()


def _flows(n=5, base="10.9.0"):
    return [{"kind": "flow", "proto": "tcp", "src_ip": f"{base}.{i + 10}", "dst_ip": f"{base}.200",
             "src_mac": f"02:00:00:00:00:{i:02x}", "dst_port": 443, "packets": 3, "bytes": 300,
             "first_seen": 1000.0 + i, "last_seen": 1001.0 + i, "tcp_syn": True} for i in range(n)]


@pytest.fixture
async def env():
    fake = FakeOrch()
    cfg = dataclasses.replace(Config(), enable_db=False, require_sentry_token=True, sentry_tokens=(),
                              managed_analyze_interval_s=0.0)
    svc = OtDiscoveryService(cfg)
    svc.engine = DiscoveryEngine(cfg, db=None, orch=None)
    svc.orch = fake  # type: ignore[assignment]
    svc.gateway = SensorGateway(fake)  # type: ignore[arg-type]
    client = TestClient(TestServer(svc.make_app()))
    await client.start_server()
    yield svc, fake, client
    await client.close()


def _h(key="batch-0000001", cred=CRED):
    return {"Authorization": f"Bearer {cred}", "Idempotency-Key": key}


def _env(obs=None, **kw):
    return {"observations": obs if obs is not None else _flows(),
            "sensor": {"id": "pi-1", "version": "0.2.0", "window": {"packets": 9}}, **kw}


async def test_managed_credential_ingests_without_any_shared_token(env, monkeypatch):
    monkeypatch.setenv("SERVICE_API_KEY", "svc-key")
    svc, fake, client = env
    r = await client.post("/ingest", json=_env(), headers=_h())
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["batch_id"] == "batch-0000001" and body["observations_ingested"] == 5
    assert fake.done_calls == [("batch-0000001", True, 5)]
    # data went to the sensor's tenant engine, not the legacy default engine
    assert svc.engine.observations == []
    assert len(svc.engines[TENANT_A].observations) == 5
    assert set(fake.tenants_seen) == {TENANT_A}
    # /stats is per tenant: the default view doesn't show A's sensor; A's view does
    stats = await (await client.get("/stats", headers={"X-API-Key": "svc-key"})).json()
    assert "pi-1@5e5e5e5e" not in stats["sensors"]
    stats = await (await client.get("/stats", headers={tenancy.TENANT_HEADER: TENANT_A, "X-API-Key": "svc-key"})).json()
    assert stats["sensors"]["pi-1@5e5e5e5e"]["site"] == "store-42"


async def test_replayed_batch_is_acknowledged_but_not_ingested_again(env):
    svc, fake, client = env
    assert (await client.post("/ingest", json=_env(), headers=_h())).status == 200
    before = len(svc.engines[TENANT_A].observations)
    for _ in range(3):
        r = await client.post("/ingest", json=_env(), headers=_h())
        assert r.status == 200 and (await r.json())["duplicate"] is True
    assert len(svc.engines[TENANT_A].observations) == before
    assert len(fake.done_calls) == 1


async def test_concurrent_retry_gets_409(env):
    _, fake, client = env
    fake.claims["batch-0000001"] = "claimed"
    r = await client.post("/ingest", json=_env(), headers=_h())
    assert r.status == 409 and r.headers["Retry-After"]


async def test_revoked_or_wrong_credential_is_refused_immediately(env):
    svc, fake, client = env
    assert (await client.post("/ingest", json=_env(), headers=_h())).status == 200
    fake.revoked = True
    r = await client.post("/ingest", json=_env(), headers=_h("batch-0000002"))
    assert r.status == 403
    r = await client.post("/ingest", json=_env(), headers=_h("batch-0000003", cred="pst_deadbeef_" + "z" * 32))
    assert r.status in (401, 403)
    assert len(svc.engines[TENANT_A].observations) == 5


async def test_missing_idempotency_key_is_rejected(env):
    _, _, client = env
    r = await client.post("/ingest", json=_env(), headers={"Authorization": f"Bearer {CRED}"})
    assert r.status == 400


async def test_orchestrator_down_means_retry_not_loss(env):
    _, fake, client = env
    fake.down = True
    r = await client.post("/ingest", json=_env(), headers=_h())
    assert r.status == 503 and r.headers["Retry-After"]
    assert fake.done_calls == []


async def test_bad_body_releases_the_claim_so_the_retry_is_accepted(env):
    _, fake, client = env
    r = await client.post("/ingest", data=b"{not json", headers={**_h(), "Content-Type": "application/json"})
    assert r.status == 400
    assert fake.done_calls == [("batch-0000001", False, 0)]
    assert (await client.post("/ingest", json=_env(), headers=_h())).status == 200


async def test_failed_store_is_not_marked_done(env):
    _, fake, client = env
    fake.bulk_error = True
    r = await client.post("/ingest", json=_env(), headers=_h())
    assert r.status == 503
    assert fake.done_calls == [("batch-0000001", False, 5)]
    fake.bulk_error = False
    r = await client.post("/ingest", json=_env(), headers=_h())  # same batch id, now accepted
    assert r.status == 200 and "duplicate" not in await r.json()


async def test_gzip_compressed_upload_is_accepted(env):
    _, fake, client = env
    body = gzip.compress(json.dumps(_env(_flows(50))).encode())
    r = await client.post("/ingest", data=body, headers={**_h(), "Content-Type": "application/json",
                                                         "Content-Encoding": "gzip"})
    assert r.status == 200 and (await r.json())["observations_ingested"] == 50
    assert fake.done_calls[-1][2] == 50


async def test_tenants_never_mix(env, monkeypatch):
    monkeypatch.setenv("SERVICE_API_KEY", "svc-key")
    svc, fake, client = env
    await client.post("/ingest", json=_env(), headers=_h("batch-a-00001"))
    fake.sensor = {**fake.sensor, "tenant_id": TENANT_B, "name": "pi-2",
                   "sensor_id": "5e5e5e5e-0000-0000-0000-000000000002"}
    await client.post("/ingest", json=_env(_flows(2, "10.7.0")), headers=_h("batch-b-00001"))
    assert len(svc.engines[TENANT_A].observations) == 5
    assert len(svc.engines[TENANT_B].observations) == 2
    assert svc.engine.observations == []
    assert set(fake.tenants_seen) == {TENANT_A, TENANT_B}
    a = await (await client.get("/stats", headers={tenancy.TENANT_HEADER: TENANT_A, "X-API-Key": "svc-key"})).text()
    b = await (await client.get("/stats", headers={tenancy.TENANT_HEADER: TENANT_B, "X-API-Key": "svc-key"})).text()
    assert "pi-1@" in a and "pi-2@" not in a
    assert "pi-2@" in b and "pi-1@" not in b


async def test_legacy_shared_tokens_still_work_alongside_managed(env):
    svc, fake, client = env
    svc.cfg = dataclasses.replace(svc.cfg, sentry_tokens=("legacy",))
    r = await client.post("/ingest", json=_env(), headers={"Authorization": "Bearer legacy"})
    assert r.status == 200
    assert len(svc.engine.observations) == 5 and fake.claims == {}
    assert (await client.post("/ingest", json=_env(), headers={"Authorization": "Bearer nope"})).status == 401


async def test_managed_disabled_falls_back_to_shared_tokens(env):
    svc, fake, client = env
    svc.cfg = dataclasses.replace(svc.cfg, managed_sensors=False)
    r = await client.post("/ingest", json=_env(), headers=_h())
    assert r.status == 503  # require_sentry_token with no shared tokens: fail closed


async def test_enroll_proxy_passes_status_and_client_ip(env):
    _, fake, client = env
    r = await client.post("/enroll", json={"token": "pet_x"})
    assert r.status == 201 and (await r.json())["credential"] == CRED
    assert fake.forwarded_ips[-1] == "127.0.0.1"
    fake.enroll_answer = (429, {"detail": "slow down"})
    r = await client.post("/enroll", json={"token": "pet_x"})
    assert r.status == 429 and r.headers["Retry-After"] == "60"
    assert (await client.post("/enroll", data=b"zzz")).status == 400
    assert (await client.post("/enroll", data=b"x" * 70_000)).status == 413


async def test_heartbeat_proxy_needs_a_sensor_credential(env):
    _, fake, client = env
    assert (await client.post("/heartbeat", json={})).status == 401
    assert (await client.post("/heartbeat", json={}, headers={"Authorization": "Bearer legacy"})).status == 401
    assert (await client.post("/heartbeat", json={"health": {}}, headers=_h())).status == 200
    fake.revoked = True
    assert (await client.post("/heartbeat", json={}, headers=_h())).status == 403


async def test_x_forwarded_for_only_when_trusted(env):
    svc, fake, client = env
    await client.post("/enroll", json={"token": "t"}, headers={"X-Forwarded-For": "198.51.100.7"})
    assert fake.forwarded_ips[-1] == "127.0.0.1"
    svc.cfg = dataclasses.replace(svc.cfg, trust_proxy=True)
    await client.post("/enroll", json={"token": "t"}, headers={"X-Forwarded-For": "198.51.100.7, 10.0.0.1"})
    assert fake.forwarded_ips[-1] == "198.51.100.7"


async def test_deferred_analysis_coalesces_many_uploads_into_one_run(env):
    svc, fake, client = env
    svc.cfg = dataclasses.replace(svc.cfg, managed_analyze_interval_s=0.2)
    for i in range(6):
        r = await client.post("/ingest", json=_env(_flows(3)), headers=_h(f"batch-co-{i:04d}"))
        assert r.status == 200 and (await r.json())["analysis"] == "scheduled"
    eng = svc.engines[TENANT_A]
    await eng.flush()
    await asyncio.sleep(0.4)
    await eng.flush()
    assert 1 <= len(fake.tenants_seen) <= 3 and set(fake.tenants_seen) == {TENANT_A}   # not one per upload
    assert eng.stats["ingests"] == 6 and fake.assets_posted > 0
    assert len(fake.done_calls) == 6 and all(ok for _, ok, _ in fake.done_calls)


async def test_repeated_flows_are_merged_not_stored_again(env):
    svc, _, client = env
    for i in range(5):
        await client.post("/ingest", json=_env(_flows(4)), headers=_h(f"batch-mg-{i:04d}"))
    eng = svc.engines[TENANT_A]
    flows = [o for o in eng.observations if o["kind"] == "flow"]
    assert len(flows) == 4 and all(f["packets"] == 15 for f in flows)   # 5 uploads x 3 packets
