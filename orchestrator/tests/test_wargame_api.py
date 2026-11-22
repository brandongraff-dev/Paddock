"""Wargame API: tenant isolation (RLS), input caps, error handling, and the
change-impact proxy. Correlation is mocked (no network)."""
from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import pytest
import pytest_asyncio

from app import auth as auth_svc
from app import tenancy
from app.config import settings
from app.routers import wargame as wg

TENANT_A = tenancy.DEFAULT_TENANT_ID
TENANT_B = "00000000-0000-0000-0000-0000000000b2"
MISSING = "00000000-0000-0000-0000-00000000dead"


# --------------------------------------------------------------------------- #
# Fake correlation (patches httpx.AsyncClient used inside the router)
# --------------------------------------------------------------------------- #

class _Resp:
    def __init__(self, status: int, body: Any):
        self.status_code = status
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class _Corr:
    """Programmable stand-in for the correlation service."""

    def __init__(self):
        self.calls: list[dict[str, Any]] = []
        self.status = 200
        self.body: Any = {}
        self.exc: Exception | None = None

    def install(self, monkeypatch):
        corr = self

        class _Client:
            def __init__(self, *a, **k):
                corr.timeout = k.get("timeout")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, url, json=None, headers=None):
                corr.calls.append({"url": url, "json": json, "headers": headers or {}})
                if corr.exc is not None:
                    raise corr.exc
                return _Resp(corr.status, corr.body)

        monkeypatch.setattr(httpx, "AsyncClient", _Client)


@pytest.fixture
def corr(monkeypatch):
    c = _Corr()
    c.install(monkeypatch)
    monkeypatch.setattr(settings, "correlation_url", "http://correlation.test")
    monkeypatch.setattr(settings, "service_api_key", "svc-key")
    return c


IMPACT = {
    "verdict": "opens_and_breaks",
    "routes_opened": [{"entry": "internet", "jewel": "db"}],
    "routes_closed": [],
    "newly_denied_flows": [{"src_ip": "10.9.0.5", "dst_ip": "10.1.0.9", "proto": "tcp",
                            "dst_port": 5432, "ruleset_id": "sg-db"}],
    "newly_allowed_flows": [],
    "summary": "Change impact for x: verdict opens_and_breaks.",
    "warnings": ["skipped aws_instance.web: unhandled resource type 'aws_instance'"],
    "change_title": "x",
    "affected_boundaries": ["sg-db"],
    "complete": True,
    "flows_parsed": 1,
    "flows_skipped": 0,
}


# --------------------------------------------------------------------------- #
# change-impact
# --------------------------------------------------------------------------- #

async def test_change_impact_proxies_and_shapes(client, corr):
    corr.body = IMPACT
    plan = {"resource_changes": []}
    r = await client.post("/v1/wargame/change-impact",
                          json={"plan": plan, "flows": "[]", "flows_format": "zeek"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) >= {"verdict", "routes_opened", "routes_closed", "newly_denied_flows",
                         "newly_allowed_flows", "summary", "warnings"}
    assert body["verdict"] == "opens_and_breaks"
    assert body["routes_opened"] == [{"entry": "internet", "jewel": "db"}]
    assert body["newly_denied_flows"][0]["dst_port"] == 5432
    assert body["complete"] is True and body["affected_boundaries"] == ["sg-db"]

    (call,) = corr.calls
    assert call["url"] == "http://correlation.test/change-impact"
    assert call["json"] == {"plan": plan, "flows": "[]", "flows_format": "zeek"}
    # same auth + tenant headers the other proxied calls carry
    assert call["headers"]["X-API-Key"] == "svc-key"
    assert call["headers"][tenancy.TENANT_HEADER] == TENANT_A


async def test_change_impact_omits_absent_flows(client, corr):
    corr.body = IMPACT
    r = await client.post("/v1/wargame/change-impact", json={"plan": {}})
    assert r.status_code == 200
    assert corr.calls[0]["json"] == {"plan": {}, "flows_format": "auto"}


@pytest.mark.parametrize("status,detail,expect", [
    (409, "no twin for this tenant", 409),
    (422, "not a terraform show -json plan", 422),
    (413, "request body too large", 413),
])
async def test_change_impact_passes_client_errors_through(client, corr, status, detail, expect):
    corr.status, corr.body = status, {"detail": detail}
    r = await client.post("/v1/wargame/change-impact", json={"plan": {}})
    assert r.status_code == expect
    assert r.json()["detail"] == detail


async def test_change_impact_server_errors_do_not_leak(client, corr):
    corr.status, corr.body = 500, {"detail": "asyncpg.PostgresError at /srv/app/x.py", "trace": "boom"}
    r = await client.post("/v1/wargame/change-impact", json={"plan": {}})
    assert r.status_code == 503
    assert "asyncpg" not in r.text and "/srv" not in r.text

    corr.exc = httpx.ConnectError("connect to 10.0.0.7:8080 failed")
    r = await client.post("/v1/wargame/change-impact", json={"plan": {}})
    assert r.status_code == 503
    assert "10.0.0.7" not in r.text

    corr.exc = None
    corr.status, corr.body = 200, {"verdict": ["not", "a", "string"]}
    r = await client.post("/v1/wargame/change-impact", json={"plan": {}})
    assert r.status_code == 502


async def test_change_impact_validation_and_size_cap(client, corr):
    assert (await client.post("/v1/wargame/change-impact", json={})).status_code == 422
    assert (await client.post("/v1/wargame/change-impact", json={"plan": []})).status_code == 422
    assert (await client.post("/v1/wargame/change-impact",
                              json={"plan": {}, "flows_format": "pcap"})).status_code == 422
    big = {"plan": {}, "flows": "x" * (wg_models().WARGAME_MAX_FLOWS_CHARS + 1)}
    assert (await client.post("/v1/wargame/change-impact", json=big)).status_code == 422

    # Byte cap, enforced before parsing: declared and streamed.
    cap = wg._BODY_CAPS["/v1/wargame/change-impact"]
    r = await client.post("/v1/wargame/change-impact", content=b"{" + b" " * cap + b"}",
                          headers={"content-type": "application/json"})
    assert r.status_code == 413

    async def chunks():
        for _ in range(cap // (1024 * 1024) + 2):
            yield b" " * (1024 * 1024)
    r = await client.post("/v1/wargame/change-impact", content=chunks(),
                          headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert corr.calls == []          # nothing was forwarded


def wg_models():
    from app import models
    return models


# --------------------------------------------------------------------------- #
# twin config / topology / recompute: caps, allowlist, no poison, no leaks
# --------------------------------------------------------------------------- #

async def test_twin_config_vendor_allowlist_and_caps(client, corr, fake_redis):
    r = await client.post("/v1/wargame/twin/config", json={"vendor": "evil", "raw": "x"})
    assert r.status_code == 422
    r = await client.post("/v1/wargame/twin/config", json={"vendor": "aws", "raw": ""})
    assert r.status_code == 422
    r = await client.post("/v1/wargame/twin/config", json={
        "vendor": "aws", "raw": "x" * (wg_models().WARGAME_MAX_CONFIG_CHARS + 1)})
    assert r.status_code == 422
    cap = wg._BODY_CAPS["/v1/wargame/twin/config"]
    r = await client.post("/v1/wargame/twin/config", headers={"content-type": "application/json"},
                          content=b'{"vendor":"aws","raw":"' + b"x" * cap + b'"}')
    assert r.status_code == 413
    assert corr.calls == [] and await fake_redis.xlen("queue:correlate") == 0


async def test_twin_config_ok_and_rejection_is_not_queued(client, corr, fake_redis):
    corr.body = {"rulesets": 3, "warnings": 1}
    r = await client.post("/v1/wargame/twin/config",
                          json={"vendor": "aws", "raw": "{}", "source": "acct"})
    assert r.status_code == 200
    assert r.json()["status"] == "ingested" and r.json()["rulesets"] == 3

    # Correlation refuses the config (4xx): the caller sees it; no job is queued.
    corr.status, corr.body = 422, {"detail": "could not parse the aws config"}
    r = await client.post("/v1/wargame/twin/config", json={"vendor": "aws", "raw": "{"})
    assert r.status_code == 422
    assert await fake_redis.xlen("queue:correlate") == 0


async def test_twin_config_falls_back_to_queue_when_correlation_down(client, corr, fake_redis):
    corr.exc = httpx.ConnectError("refused")
    r = await client.post("/v1/wargame/twin/config", json={"vendor": "aws", "raw": "{}"})
    assert r.status_code == 200 and r.json()["status"] == "queued"
    (entry,) = await fake_redis.xrange("queue:correlate")
    job = json.loads(entry[1]["job"])
    assert job["op"] == "twin_ingest_config" and job["tenant_id"] == TENANT_A


async def test_unavailable_never_leaks_internals(client, corr, app):
    class _BadRedis:
        async def xadd(self, *a, **k):
            raise RuntimeError("redis://:hunter2@10.0.0.5:6379 refused")
    corr.exc = httpx.ConnectError("refused")
    app.state.redis = _BadRedis()
    for path, body in (("/v1/wargame/recompute", None),
                       ("/v1/wargame/twin/config", {"vendor": "aws", "raw": "{}"}),
                       ("/v1/wargame/twin/topology", {"segments": [], "edges": []})):
        r = await client.post(path, json=body)
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "unavailable"
        assert "hunter2" not in r.text and "10.0.0.5" not in r.text


async def test_recompute_reports_assessments_and_uses_long_read_timeout(client, corr):
    corr.body = {"assessments": 2, "routes": 5, "elapsed_ms": 1.0}
    r = await client.post("/v1/wargame/recompute")
    assert r.json() == {"status": "computed", "detail": "correlation computed 2 assessment(s)"}
    assert corr.timeout.read >= 20 and corr.timeout.connect <= 5


async def test_topology_caps(client, corr):
    n = wg_models().WARGAME_MAX_TOPOLOGY_SEGMENTS + 1
    r = await client.post("/v1/wargame/twin/topology",
                          json={"segments": [{"id": str(i)} for i in range(n)], "edges": []})
    assert r.status_code == 422


# --------------------------------------------------------------------------- #
# reads: validation + 404
# --------------------------------------------------------------------------- #

async def test_read_validation_and_404(client):
    for tail in ("", "/routes", "/boundaries", "/certificates", "/fix-set", "/evidence"):
        assert (await client.get(f"/v1/wargame/assessments/not-a-uuid{tail}")).status_code == 422
        assert (await client.get(f"/v1/wargame/assessments/{MISSING}{tail}")).status_code == 404
    assert (await client.get("/v1/wargame/assessments?limit=501")).status_code == 422
    assert (await client.get("/v1/wargame/assessments?limit=0")).status_code == 422
    assert (await client.get("/v1/wargame/assessments?offset=-1")).status_code == 422
    for tail in ("routes", "boundaries", "certificates", "evidence"):
        assert (await client.get(f"/v1/wargame/assessments/{MISSING}/{tail}?limit=5001")).status_code == 422
    assert (await client.get(f"/v1/wargame/assessments/{MISSING}/evidence?framework={'x' * 65}")).status_code == 422


# --------------------------------------------------------------------------- #
# tenant isolation (RLS via the non-superuser app role)
# --------------------------------------------------------------------------- #

@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


async def _seed_user(db_pool, tenant_id: str, username: str, role: str = "admin") -> str:
    full, prefix, key_hash = auth_svc.generate_api_key()
    async with db_pool.acquire() as con:
        uid = await con.fetchval(
            "INSERT INTO app_users (username, role, clearance, pw_hash, tenant_id) "
            "VALUES ($1, $2, 'restricted', $3, $4) RETURNING id",
            username, role, auth_svc.hash_password("pw-" + username), tenant_id)
        await con.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes, tenant_id) "
            "VALUES ($1, 'k', $2, $3, $4::text[], $5)",
            uid, prefix, key_hash, sorted(auth_svc.ROLE_CAPABILITIES[role]), tenant_id)
    return full


def _h(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def _seed_assessment(db_pool, tenant_id: str, label: str) -> str:
    async with db_pool.acquire() as con:
        aid = await con.fetchval(
            "INSERT INTO wargame_assessments (label, tenant_id) VALUES ($1, $2) RETURNING id::text",
            label, tenant_id)
        await con.execute(
            "INSERT INTO wargame_routes (assessment_id, entry, jewel, tenant_id) "
            "VALUES ($1::uuid, 'e', $2, $3)", aid, f"jewel-{label}", tenant_id)
        await con.execute(
            "INSERT INTO wargame_boundaries (assessment_id, boundary_src, boundary_dst, verdict, tenant_id) "
            "VALUES ($1::uuid, 's', 'd', 'pass', $2)", aid, tenant_id)
        await con.execute(
            "INSERT INTO wargame_fix_sets (assessment_id, tenant_id) VALUES ($1::uuid, $2)", aid, tenant_id)
        await con.execute(
            "INSERT INTO wargame_evidence (assessment_id, framework, control_id, tenant_id) "
            "VALUES ($1::uuid, 'pci', 'c1', $2)", aid, tenant_id)
        await con.execute(
            "INSERT INTO wargame_rulesets (ruleset_key, tenant_id) VALUES ($1, $2)", f"rs-{label}", tenant_id)
        await con.execute(
            "INSERT INTO wargame_segments (seg_key, tenant_id) VALUES ($1, $2)", f"seg-{label}", tenant_id)
    return aid


@pytest_asyncio.fixture
async def two(enforce, app, app_pool, db_pool):
    app.state.pool = app_pool
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo", tenant_id=TENANT_B)
    ka = await _seed_user(db_pool, TENANT_A, "alice")
    kb = await _seed_user(db_pool, TENANT_B, "bob")
    aa = await _seed_assessment(db_pool, TENANT_A, "alpha")
    ab = await _seed_assessment(db_pool, TENANT_B, "bravo")
    return {"ka": ka, "kb": kb, "aa": aa, "ab": ab}


async def test_assessment_reads_never_cross_tenants(client, two):
    ka, kb, aa, ab = two["ka"], two["kb"], two["aa"], two["ab"]
    page = (await client.get("/v1/wargame/assessments", headers=_h(kb))).json()
    assert page["total"] == 1 and page["items"][0]["id"] == ab
    page = (await client.get("/v1/wargame/assessments", headers=_h(ka))).json()
    assert page["total"] == 1 and page["items"][0]["id"] == aa

    # B asking for A's id gets exactly what a missing id gets: a 404, for every artifact.
    for tail in ("", "/routes", "/boundaries", "/certificates", "/fix-set", "/evidence"):
        r = await client.get(f"/v1/wargame/assessments/{aa}{tail}", headers=_h(kb))
        assert r.status_code == 404, (tail, r.text)
        r = await client.get(f"/v1/wargame/assessments/{ab}{tail}", headers=_h(kb))
        assert r.status_code == 200, (tail, r.text)
    routes = (await client.get(f"/v1/wargame/assessments/{ab}/routes", headers=_h(kb))).json()
    assert [x["jewel"] for x in routes["items"]] == ["jewel-bravo"]


async def test_twin_summary_is_per_tenant(client, two):
    a = (await client.get("/v1/wargame/twin", headers=_h(two["ka"]))).json()
    b = (await client.get("/v1/wargame/twin", headers=_h(two["kb"]))).json()
    assert a["ruleset_count"] == 1 and a["segment_count"] == 1 and a["has_twin"] is True
    assert b["ruleset_count"] == 1 and b["segment_count"] == 1
    # app role cannot see the other tenant's rows even by direct SQL
    async with client._transport.app.state.pool.acquire() as con:
        n = await con.fetchval("SELECT COUNT(*) FROM wargame_rulesets WHERE ruleset_key = 'rs-bravo'")
    assert n == 0   # the default-tenant context of the helper connection


async def test_change_impact_forwards_the_callers_tenant(client, two, corr):
    corr.body = IMPACT
    r = await client.post("/v1/wargame/change-impact", headers=_h(two["kb"]), json={"plan": {}})
    assert r.status_code == 200, r.text
    assert corr.calls[0]["headers"][tenancy.TENANT_HEADER] == TENANT_B


async def test_change_impact_rbac(client, two, db_pool, corr):
    corr.body = IMPACT
    viewer = await _seed_user(db_pool, TENANT_A, "vera", role="viewer")
    analyst = await _seed_user(db_pool, TENANT_A, "ana", role="analyst")
    r = await client.post("/v1/wargame/change-impact", headers=_h(viewer), json={"plan": {}})
    assert r.status_code == 403
    r = await client.post("/v1/wargame/change-impact", headers=_h(analyst), json={"plan": {}})
    assert r.status_code == 200
    # twin ingest stays admin-only
    r = await client.post("/v1/wargame/twin/config", headers=_h(analyst),
                          json={"vendor": "aws", "raw": "{}"})
    assert r.status_code == 403
    # unauthenticated
    assert (await client.post("/v1/wargame/change-impact", json={"plan": {}})).status_code == 401


# --------------------------------------------------------------------------- #
# twin evidence: flows + recorded probe results
# --------------------------------------------------------------------------- #

PROBE = {"src": "guest", "dst": "db", "port": 5432, "result": "blocked",
         "observed_at": "2026-11-22T10:00:00Z", "source": "scanner-1"}


async def test_twin_flows_proxies_and_shapes(client, corr, fake_redis):
    corr.body = {"flows_parsed": 3, "flows_skipped": 1, "flows_stored": 3,
                 "warnings": ["row 3: missing or invalid destination port"]}
    r = await client.post("/v1/wargame/twin/flows",
                          json={"raw": "[]", "format": "zeek", "source": "zeek-1"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ingested" and body["flows_stored"] == 3
    assert body["flows_parsed"] == 3 and body["flows_skipped"] == 1
    assert body["warnings"] == ["row 3: missing or invalid destination port"]
    assert body["detail"] == "correlation stored 3 flow(s)"
    (call,) = corr.calls
    assert call["url"] == "http://correlation.test/ingest-flows"
    assert call["json"] == {"raw": "[]", "format": "zeek", "source": "zeek-1"}
    assert call["headers"][tenancy.TENANT_HEADER] == TENANT_A
    assert await fake_redis.xlen("queue:correlate") == 0


async def test_twin_probes_proxies_and_shapes(client, corr):
    corr.body = {"stored": 1, "rejected": 1, "warnings": ["result 1: segment 'x' is not in the twin"]}
    r = await client.post("/v1/wargame/twin/probes",
                          json={"results": [PROBE, {**PROBE, "src": "x"}]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {"status": "ingested", "detail": "correlation stored 1 probe result(s)",
                    "stored": 1, "rejected": 1,
                    "warnings": ["result 1: segment 'x' is not in the twin"]}
    (call,) = corr.calls
    assert call["url"] == "http://correlation.test/ingest-probes"
    sent = call["json"]["results"][0]
    # datetimes are forwarded as ISO strings (JSON-serialisable for the queue too)
    assert sent["observed_at"].startswith("2026-11-22T10:00:00")
    assert sent["proto"] == "tcp" and sent["result"] == "blocked"


@pytest.mark.parametrize("body", [
    {}, {"results": []},
    {"results": [{**PROBE, "result": "open"}]},
    {"results": [{**PROBE, "port": -1}]},
    {"results": [{**PROBE, "proto": "sctp"}]},
    {"results": [{**PROBE, "observed_at": "yesterday"}]},
])
async def test_twin_probes_validation(client, corr, body):
    assert (await client.post("/v1/wargame/twin/probes", json=body)).status_code == 422
    assert corr.calls == []


async def test_twin_evidence_caps(client, corr, fake_redis):
    m = wg_models()
    r = await client.post("/v1/wargame/twin/flows", json={"raw": ""})
    assert r.status_code == 422
    r = await client.post("/v1/wargame/twin/flows", json={"raw": "[]", "format": "pcap"})
    assert r.status_code == 422
    r = await client.post("/v1/wargame/twin/flows",
                          json={"raw": "x" * (m.WARGAME_MAX_FLOWS_CHARS + 1)})
    assert r.status_code == 422
    r = await client.post("/v1/wargame/twin/probes",
                          json={"results": [PROBE] * (m.WARGAME_MAX_PROBE_RESULTS + 1)})
    assert r.status_code in (413, 422)
    for path in ("/v1/wargame/twin/flows", "/v1/wargame/twin/probes"):
        cap = wg._BODY_CAPS[path]
        r = await client.post(path, headers={"content-type": "application/json"},
                              content=b'{"raw":"' + b"x" * cap + b'"}')
        assert r.status_code == 413, path
    assert corr.calls == [] and await fake_redis.xlen("queue:correlate") == 0


@pytest.mark.parametrize("path,body,status,detail", [
    ("/v1/wargame/twin/probes", {"results": [PROBE]}, 409, "no twin topology for this tenant"),
    ("/v1/wargame/twin/flows", {"raw": "[]"}, 422, "bad flows"),
])
async def test_twin_evidence_client_errors_pass_through_unqueued(
        client, corr, fake_redis, path, body, status, detail):
    corr.status, corr.body = status, {"detail": detail}
    r = await client.post(path, json=body)
    assert r.status_code == status and r.json()["detail"] == detail
    assert await fake_redis.xlen("queue:correlate") == 0


@pytest.mark.parametrize("path,body,op", [
    ("/v1/wargame/twin/flows", {"raw": "[]"}, "twin_ingest_flows"),
    ("/v1/wargame/twin/probes", {"results": [PROBE]}, "twin_ingest_probes"),
])
async def test_twin_evidence_falls_back_to_queue(client, corr, fake_redis, path, body, op):
    corr.exc = httpx.ConnectError("refused")
    r = await client.post(path, json=body)
    assert r.status_code == 200 and r.json()["status"] == "queued"
    assert r.json()["warnings"] == []
    (entry,) = await fake_redis.xrange("queue:correlate")
    job = json.loads(entry[1]["job"])
    assert job["op"] == op and job["kind"] == f"correlate_{op}"
    assert job["tenant_id"] == TENANT_A
    assert job["payload"]["raw" if "flows" in path else "results"]


async def test_twin_evidence_unavailable_never_leaks(client, corr, app):
    class _BadRedis:
        async def xadd(self, *a, **k):
            raise RuntimeError("redis://:hunter2@10.0.0.5:6379 refused")
    corr.exc = httpx.ConnectError("refused")
    app.state.redis = _BadRedis()
    for path, body in (("/v1/wargame/twin/flows", {"raw": "[]"}),
                       ("/v1/wargame/twin/probes", {"results": [PROBE]})):
        r = await client.post(path, json=body)
        assert r.status_code == 200 and r.json()["status"] == "unavailable"
        assert "hunter2" not in r.text and "10.0.0.5" not in r.text


async def test_twin_summary_counts_evidence_per_tenant(client, two, db_pool):
    async with db_pool.acquire() as con:
        for t, n in ((TENANT_A, 2), (TENANT_B, 1)):
            for i in range(n):
                await con.execute(
                    "INSERT INTO wargame_observed_flows (src_ip, dst_ip, proto, dst_port, "
                    "observed_at, tenant_id) VALUES ('10.0.0.1', '10.0.0.2', 'tcp', $1, NOW(), $2)",
                    i, t)
        for result, age in (("blocked", "1 hour"), ("error", "1 hour"), ("crossed", "3 days")):
            await con.execute(
                "INSERT INTO wargame_probe_results (src_segment, dst_segment, port, result, "
                "observed_at, tenant_id) VALUES ('a', 'b', 443, $1, NOW() - $2::text::interval, $3)",
                result, age, TENANT_A)
    a = (await client.get("/v1/wargame/twin", headers=_h(two["ka"]))).json()
    b = (await client.get("/v1/wargame/twin", headers=_h(two["kb"]))).json()
    assert (a["flow_count"], a["probe_count"], a["probe_fresh_count"]) == (2, 3, 1)
    assert (b["flow_count"], b["probe_count"], b["probe_fresh_count"]) == (1, 0, 0)


async def test_twin_evidence_rbac(client, two, db_pool, corr):
    corr.body = {"stored": 1, "rejected": 0, "warnings": []}
    analyst = await _seed_user(db_pool, TENANT_A, "ana2", role="analyst")
    for path, body in (("/v1/wargame/twin/flows", {"raw": "[]"}),
                       ("/v1/wargame/twin/probes", {"results": [PROBE]})):
        assert (await client.post(path, headers=_h(analyst), json=body)).status_code == 403
        assert (await client.post(path, json=body)).status_code == 401
        r = await client.post(path, headers=_h(two["ka"]), json=body)
        assert r.status_code == 200, r.text
    assert corr.calls[0]["headers"][tenancy.TENANT_HEADER] == TENANT_A
    assert auth_svc.required_capability("POST", "/v1/wargame/twin/probes") == "admin"
    assert auth_svc.required_capability("POST", "/v1/wargame/twin/flows") == "admin"
