"""POST /v1/ingest + /v1/ingest/sources against a real Postgres.

Served through ``app_pool`` (the non-superuser ``paddock_app`` role with the
production tenant-stamping pool hook) in ENFORCE auth mode, so RLS and the
token scoping are exercised the way production runs them.
"""
from __future__ import annotations

import gzip
import json
import uuid

import pytest
import pytest_asyncio

from app import auth as auth_svc
from app import tenancy
from app.config import settings
from app.routers import ingest as ingest_router

from . import ingest_samples as S

TENANT_A = tenancy.DEFAULT_TENANT_ID
TENANT_B = "00000000-0000-0000-0000-0000000000b2"


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    ingest_router.rate_limiter.reset()
    ingest_router.failure_limiter.reset()
    yield
    settings.auth_mode = prev
    ingest_router.rate_limiter.reset()
    ingest_router.failure_limiter.reset()


async def _key(db_pool, tenant_id: str, username: str, role: str) -> str:
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
    return {"X-API-Key": key}


@pytest_asyncio.fixture
async def env(app, app_pool, db_pool, client):
    app.state.pool = app_pool
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo", tenant_id=TENANT_B)
    return {
        "admin": await _key(db_pool, TENANT_A, "alice", "admin"),
        "admin_b": await _key(db_pool, TENANT_B, "bob", "admin"),
        "analyst": await _key(db_pool, TENANT_A, "ann", "analyst"),
        "viewer": await _key(db_pool, TENANT_A, "vic", "viewer"),
    }


async def _source(client, key, name="ci-trivy", **kw):
    r = await client.post("/v1/ingest/sources", headers=_h(key), json={"name": name, **kw})
    assert r.status_code == 201, r.text
    return r.json()


def _tok(t: str) -> dict[str, str]:
    return {"X-Paddock-Ingest-Token": t}


async def _count(db_pool, sql, *args):
    async with db_pool.acquire() as con:
        return await con.fetchval(sql, *args)


# --------------------------------------------------------------------------- #
# source management
# --------------------------------------------------------------------------- #

async def test_source_lifecycle_and_secrecy(client, env, db_pool):
    src = await _source(client, env["admin"], description="CI", default_project="acme/web")
    assert src["token"].startswith("pdi_") and src["url"].endswith("/v1/ingest")
    secret = src["token"].rsplit("_", 1)[-1]
    # only the hash is stored; listings never echo the token
    row = await db_pool.fetchrow("SELECT token_hash FROM ingest_sources WHERE id = $1", uuid.UUID(src["id"]))
    assert row["token_hash"] != src["token"] and secret not in row["token_hash"]
    lst = (await client.get("/v1/ingest/sources", headers=_h(env["admin"]))).json()["items"]
    assert [s["name"] for s in lst] == ["ci-trivy"] and "token" not in lst[0] and "token_hash" not in lst[0]
    assert (await client.post("/v1/ingest/sources", headers=_h(env["admin"]), json={"name": "CI-TRIVY"})).status_code == 409
    for bad in ("../etc", "a b", "", "x" * 65, "-lead"):
        r = await client.post("/v1/ingest/sources", headers=_h(env["admin"]), json={"name": bad})
        assert r.status_code == 422, bad
    r = await client.post("/v1/ingest/sources", headers=_h(env["admin"]),
                          json={"name": "z", "allowed_formats": ["nessus"]})
    assert r.status_code == 422
    r = await client.patch(f"/v1/ingest/sources/{src['id']}", headers=_h(env["admin"]),
                           json={"rate_limit_per_min": 5, "allowed_formats": ["sarif", "trivy"]})
    assert r.json()["rate_limit_per_min"] == 5 and r.json()["allowed_formats"] == ["sarif", "trivy"]


async def test_management_is_admin_only(client, env):
    for key in (env["analyst"], env["viewer"]):
        assert (await client.post("/v1/ingest/sources", headers=_h(key), json={"name": "x"})).status_code == 403
        assert (await client.get("/v1/ingest/sources", headers=_h(key))).status_code == 403
    assert (await client.post("/v1/ingest/sources", json={"name": "x"})).status_code == 401


# --------------------------------------------------------------------------- #
# ingest, every format
# --------------------------------------------------------------------------- #

CASES = [
    ("sarif", S.jbytes(S.SARIF), 2, 0),
    ("trivy", S.jbytes(S.TRIVY), 4, 1),
    ("grype", S.jbytes(S.GRYPE), 2, 2),
    ("semgrep", S.jbytes(S.SEMGREP), 2, 0),
    ("nuclei", S.NUCLEI.encode(), 2, 0),
    ("zap", S.jbytes(S.ZAP), 2, 0),
    ("ocsf", "\n".join(json.dumps(e) for e in S.OCSF).encode(), 2, 0),
    ("csv", S.CSV.encode(), 3, 0),
    ("cyclonedx", S.jbytes(S.CYCLONEDX), 0, 2),
    ("spdx", S.jbytes(S.SPDX), 0, 1),
]


@pytest.mark.parametrize("fmt,body,n_findings,n_components", CASES)
async def test_ingest_each_format(client, env, db_pool, fmt, body, n_findings, n_components):
    src = await _source(client, env["admin"], name=f"src-{fmt}")
    r = await client.post("/v1/ingest", headers=_tok(src["token"]), content=body)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["format"] == fmt and j["source"] == f"src-{fmt}"
    assert j["findings_new"] == n_findings and j["components"] == n_components
    if n_findings:
        n = await _count(db_pool, "SELECT count(*) FROM findings WHERE metadata->'ingest'->>'source' = $1",
                         f"src-{fmt}")
        assert n == n_findings                                      # source attribution on every row
        assert (await _count(db_pool, "SELECT count(*) FROM assets WHERE source = 'ingest'")) >= 1
    # idempotent: the same upload again updates, never duplicates
    r2 = await client.post("/v1/ingest", headers=_tok(src["token"]), content=body)
    assert r2.json()["findings_new"] == 0 and r2.json()["findings_updated"] == n_findings
    log = (await client.get("/v1/ingest/log", headers=_h(env["admin"]))).json()["items"]
    assert log[0]["format"] == fmt and log[0]["status"] in ("ok", "partial") and log[1]["findings_new"] == n_findings


async def test_sbom_goes_to_components_and_links_asset(client, env, db_pool):
    src = await _source(client, env["admin"], name="sbom")
    r = await client.post("/v1/ingest", headers=_tok(src["token"]), content=S.jbytes(S.CYCLONEDX))
    assert r.json()["project"] == "acme-web" and r.json()["vulnerabilities"] == 1
    row = await db_pool.fetchrow("SELECT p.asset_id, count(c.*) AS n FROM sca_projects p "
                                 "JOIN sbom_components c ON c.project_id = p.id WHERE p.name = 'acme-web' "
                                 "GROUP BY p.asset_id")
    assert row["n"] == 2 and row["asset_id"] is not None


async def test_cross_engine_dedupe_uses_lifecycle_fingerprint(client, env, db_pool):
    src = await _source(client, env["admin"], name="dedupe")
    nuc = json.dumps(S.NUCLEI_LINES[0]).encode()
    a = (await client.post("/v1/ingest", headers=_tok(src["token"]), content=nuc)).json()
    assert a["findings_new"] == 1 and a["duplicates"] == 0
    csv = b"asset,title,severity,cve\napp.example.com,Widget RCE,critical,CVE-2023-1234\n"
    b = (await client.post("/v1/ingest", headers=_tok(src["token"]), content=csv)).json()
    assert b["findings_new"] == 1 and b["duplicates"] == 1           # same host + same CVE -> collapsed
    dup = await _count(db_pool, "SELECT count(*) FROM findings WHERE duplicate_of IS NOT NULL")
    assert dup == 1


async def test_asset_and_project_overrides(client, env, db_pool):
    src = await _source(client, env["admin"], name="over", default_project="from-source")
    await client.post("/v1/ingest", headers=_tok(src["token"]), content=S.jbytes(S.SEMGREP))
    assert await _count(db_pool, "SELECT count(*) FROM assets WHERE kind='repository' AND value='from-source'") == 1
    await client.post("/v1/ingest?project=explicit&asset=host9.example.com&asset_kind=subdomain",
                      headers=_tok(src["token"]), content=S.jbytes(S.SEMGREP))
    assert await _count(db_pool, "SELECT count(*) FROM assets WHERE value='host9.example.com'") == 1


# --------------------------------------------------------------------------- #
# token scoping, revocation, rate limits
# --------------------------------------------------------------------------- #

async def test_token_is_ingest_only(client, env):
    src = await _source(client, env["admin"], name="scoped")
    for hdrs in (_tok(src["token"]), {"Authorization": f"Bearer {src['token']}"}):
        for method, path in (("GET", "/v1/findings"), ("GET", "/v1/scope"), ("GET", "/v1/ingest/sources"),
                             ("POST", "/v1/findings/bulk"), ("POST", "/v1/ingest/sources"), ("POST", "/v1/scans")):
            r = await client.request(method, path, headers=hdrs, json={} if method == "POST" else None)
            assert r.status_code in (401, 403), (method, path, r.status_code)
    # ...but the Bearer form does work on the ingest route
    r = await client.post("/v1/ingest", headers={"Authorization": f"Bearer {src['token']}"}, content=S.CSV.encode())
    assert r.status_code == 200
    # and the query-string form
    r = await client.post(f"/v1/ingest?token={src['token']}", content=S.CSV.encode())
    assert r.status_code == 200


async def test_bad_tokens(client, env):
    src = await _source(client, env["admin"], name="real")
    t = src["token"]
    forged = [
        "pdi_garbage", "pdi_" + "0" * 32 + "_" + "1" * 32 + "_" + "A" * 43,
        t[:-1] + ("A" if t[-1] != "A" else "B"),                            # wrong secret
        t.replace(t.split("_")[1], TENANT_B.replace("-", "")),               # wrong tenant, right source+secret
        "pak_notaningestkey",
    ]
    for tok in forged:
        r = await client.post("/v1/ingest", headers=_tok(tok), content=S.CSV.encode())
        assert r.status_code == 401, tok
    assert (await client.post("/v1/ingest", content=S.CSV.encode())).status_code == 401


async def test_revoke_disable_rotate(client, env):
    src = await _source(client, env["admin"], name="rv")
    body = S.CSV.encode()
    assert (await client.post("/v1/ingest", headers=_tok(src["token"]), content=body)).status_code == 200
    # disable
    await client.patch(f"/v1/ingest/sources/{src['id']}", headers=_h(env["admin"]), json={"enabled": False})
    assert (await client.post("/v1/ingest", headers=_tok(src["token"]), content=body)).status_code == 401
    await client.patch(f"/v1/ingest/sources/{src['id']}", headers=_h(env["admin"]), json={"enabled": True})
    assert (await client.post("/v1/ingest", headers=_tok(src["token"]), content=body)).status_code == 200
    # rotate: old token dies, new works
    new = (await client.post(f"/v1/ingest/sources/{src['id']}/rotate", headers=_h(env["admin"]))).json()
    assert new["token"] != src["token"]
    assert (await client.post("/v1/ingest", headers=_tok(src["token"]), content=body)).status_code == 401
    assert (await client.post("/v1/ingest", headers=_tok(new["token"]), content=body)).status_code == 200
    # revoke
    assert (await client.delete(f"/v1/ingest/sources/{src['id']}", headers=_h(env["admin"]))).status_code == 200
    assert (await client.post("/v1/ingest", headers=_tok(new["token"]), content=body)).status_code == 401
    assert (await client.post(f"/v1/ingest/sources/{src['id']}/rotate", headers=_h(env["admin"]))).status_code == 404
    # a revoked name can be reused
    await _source(client, env["admin"], name="rv")


async def test_rate_limit_per_source(client, env):
    a = await _source(client, env["admin"], name="slow", rate_limit_per_min=2)
    b = await _source(client, env["admin"], name="other")
    body = S.CSV.encode()
    codes = [(await client.post("/v1/ingest", headers=_tok(a["token"]), content=body)).status_code for _ in range(4)]
    assert codes == [200, 200, 429, 429]
    r = await client.post("/v1/ingest", headers=_tok(a["token"]), content=body)
    assert r.headers["retry-after"] == "60"
    assert (await client.post("/v1/ingest", headers=_tok(b["token"]), content=body)).status_code == 200


async def test_failed_token_guessing_is_throttled(client, env):
    bad = "pdi_" + "0" * 32 + "_" + "1" * 32 + "_" + "A" * 43
    codes = {(await client.post("/v1/ingest", headers=_tok(bad), content=b"x")).status_code for _ in range(40)}
    assert codes == {401, 429}


async def test_allowed_formats(client, env):
    src = await _source(client, env["admin"], name="csvonly", allowed_formats=["csv"])
    assert (await client.post("/v1/ingest", headers=_tok(src["token"]), content=S.jbytes(S.SARIF))).status_code == 403
    assert (await client.post("/v1/ingest", headers=_tok(src["token"]), content=S.CSV.encode())).status_code == 200


# --------------------------------------------------------------------------- #
# API-key callers
# --------------------------------------------------------------------------- #

async def test_api_key_callers_need_scan(client, env):
    body = S.CSV.encode()
    r = await client.post("/v1/ingest?source=ci", headers=_h(env["analyst"]), content=body)
    assert r.status_code == 200 and r.json()["source"] == "ci"
    assert (await client.post("/v1/ingest", headers=_h(env["viewer"]), content=body)).status_code == 403
    assert (await client.post("/v1/ingest?source=../x", headers=_h(env["analyst"]), content=body)).status_code == 422


# --------------------------------------------------------------------------- #
# tenancy
# --------------------------------------------------------------------------- #

async def test_token_writes_only_into_its_own_tenant(client, env, db_pool):
    sa = await _source(client, env["admin"], name="same-name")
    sb = await _source(client, env["admin_b"], name="same-name")        # per-tenant namespace
    assert sa["token"].split("_")[1] != sb["token"].split("_")[1]
    await client.post("/v1/ingest", headers=_tok(sb["token"]), content=S.jbytes(S.SEMGREP))
    ta = await _count(db_pool, "SELECT count(*) FROM findings WHERE tenant_id = $1", TENANT_A)
    tb = await _count(db_pool, "SELECT count(*) FROM findings WHERE tenant_id = $1", TENANT_B)
    assert (ta, tb) == (0, 2)
    # tenant A's admin sees none of it and cannot list B's sources
    assert (await client.get("/v1/ingest/sources", headers=_h(env["admin"]))).json()["items"][0]["id"] == sa["id"]
    log_a = (await client.get("/v1/ingest/log", headers=_h(env["admin"]))).json()["items"]
    assert log_a == []
    # B's token cannot be pointed at A's source id
    t = sb["token"].split("_")
    swapped = "_".join([t[0], t[1], sa["id"].replace("-", ""), t[3]])
    assert (await client.post("/v1/ingest", headers=_tok(swapped), content=S.CSV.encode())).status_code == 401


# --------------------------------------------------------------------------- #
# audit + log
# --------------------------------------------------------------------------- #

async def test_audit_and_ingest_log(client, env, db_pool):
    src = await _source(client, env["admin"], name="audited")
    await client.post("/v1/ingest", headers=_tok(src["token"]), content=S.jbytes(S.SEMGREP))
    await client.post("/v1/ingest", headers=_tok(src["token"]), content=b"<xml/>")
    n = await _count(db_pool, "SELECT count(*) FROM audit_log WHERE action = 'ingest' AND actor = 'ingest:audited'")
    assert n == 1
    det = await db_pool.fetchval("SELECT details FROM audit_log WHERE action = 'ingest' LIMIT 1")
    assert "SECRET" not in str(det) and src["token"] not in str(det)
    log = (await client.get("/v1/ingest/log", headers=_h(env["admin"]))).json()["items"]
    assert [l["status"] for l in log] == ["rejected", "partial"]
    assert log[1]["findings_new"] == 2 and log[1]["errors"] and log[1]["sha256"] and log[1]["bytes"] > 0
    assert log[0]["http_status"] == 415 and "XML" in log[0]["errors"][0]["message"]
    only = (await client.get(f"/v1/ingest/log?source_id={src['id']}&status=rejected", headers=_h(env["admin"]))).json()
    assert len(only["items"]) == 1
    # chain still verifies after public-route audit rows
    v = await client.get("/v1/audit/verify", headers=_h(env["admin"]))
    assert v.status_code == 200 and v.json().get("ok", v.json().get("valid", True)) is not False


# --------------------------------------------------------------------------- #
# hostile bodies over HTTP
# --------------------------------------------------------------------------- #

async def test_size_limits(client, env, monkeypatch, db_pool):
    monkeypatch.setenv("PADDOCK_INGEST_MAX_BYTES", "4096")
    src = await _source(client, env["admin"], name="limits")
    big = b'{"results": [' + b'{"check_id":"a","path":"b"},' * 400 + b"]}"
    r = await client.post("/v1/ingest", headers=_tok(src["token"]), content=big)
    assert r.status_code == 413
    bomb = gzip.compress(b"0" * (20 * 1024 * 1024))
    r = await client.post("/v1/ingest", headers={**_tok(src["token"]), "Content-Encoding": "gzip"}, content=bomb)
    assert r.status_code == 413
    assert await _count(db_pool, "SELECT count(*) FROM ingest_log WHERE status='rejected' AND http_status=413") == 2
    assert await _count(db_pool, "SELECT count(*) FROM findings") == 0
    monkeypatch.setenv("PADDOCK_INGEST_MAX_BYTES", str(25 * 1024 * 1024))
    ok = gzip.compress(S.CSV.encode())
    r = await client.post("/v1/ingest", headers={**_tok(src["token"]), "Content-Encoding": "gzip"}, content=ok)
    assert r.status_code == 200 and r.json()["findings_new"] == 3


async def test_hostile_and_malformed_bodies(client, env, db_pool):
    src = await _source(client, env["admin"], name="hostile")
    xml = b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><r>&b;</r>'
    for body, code in ((xml, 415), (b"[" * 100_000, 422), (b"", 400), (b"\xff\xfe\x00", 415), (b'{"x": 1}', 415),
                       (b"asset,title\nh,t\n", 415)):
        r = await client.post("/v1/ingest", headers=_tok(src["token"]), content=body)
        assert r.status_code == code, (body[:20], r.status_code, r.text)
    assert await _count(db_pool, "SELECT count(*) FROM findings") == 0


async def test_dry_run_and_strict(client, env, db_pool):
    src = await _source(client, env["admin"], name="dry")
    r = await client.post("/v1/ingest?dry_run=true", headers=_tok(src["token"]), content=S.jbytes(S.TRIVY))
    assert r.status_code == 200 and r.json()["dry_run"] and r.json()["findings_new"] == 4
    assert await _count(db_pool, "SELECT count(*) FROM findings") == 0
    r = await client.post("/v1/ingest?strict=true", headers=_tok(src["token"]), content=S.jbytes(S.TRIVY))
    assert r.status_code == 422 and "strict" in r.json()["detail"]
    assert await _count(db_pool, "SELECT count(*) FROM findings") == 0
    r = await client.post("/v1/ingest?format=trivy", headers=_tok(src["token"]), content=S.jbytes(S.SARIF))
    assert r.status_code == 422
    r = await client.post("/v1/ingest?asset_kind=../x", headers=_tok(src["token"]), content=S.CSV.encode())
    assert r.status_code == 422


async def test_path_traversal_in_names_is_neutralised(client, env, db_pool):
    src = await _source(client, env["admin"], name="trav")
    r = await client.post("/v1/ingest", headers=_tok(src["token"]), content=S.jbytes(S.SEMGREP))
    assert r.status_code == 200
    rows = await db_pool.fetch("SELECT rule_id, evidence FROM findings")
    for row in rows:
        ev = json.loads(row["evidence"]) if isinstance(row["evidence"], str) else row["evidence"]
        assert ".." not in row["rule_id"] and not str(ev.get("file", "")).startswith("/") and ".." not in str(ev.get("file", ""))


async def test_formats_reference(client, env):
    j = (await client.get("/v1/ingest/formats", headers=_h(env["viewer"]))).json()
    assert "sarif" in j["formats"] and j["csv_columns"]["asset"].startswith("REQUIRED")
