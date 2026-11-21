"""Auto-remediation router (schema 014): list + detail reads with verifier /
injection summaries, and the propose proxy degrading when the remediation
service is down.

The remediation service owns the writes in production; here we seed
``remediations`` directly and exercise the orchestrator's read + proxy surface.
The propose proxy is driven against a dead upstream and must DEGRADE to
{ok:false, note:...} — never raise, never 5xx.
"""
from __future__ import annotations

import json
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# A port nothing listens on: the proxy call fails immediately and must degrade.
_DEAD_URL = "http://127.0.0.1:59997"


@pytest_asyncio.fixture
async def rem_client(app):
    from app.routers import remediation

    app.include_router(remediation.router)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# --------------------------------------------------------------------------- #
# Seed helpers
# --------------------------------------------------------------------------- #

async def _mk_finding(con) -> str:
    aid = await con.fetchval(
        "INSERT INTO assets (kind, value, canonical, source) "
        "VALUES ('repository','example/repo','example/repo','seed') RETURNING id"
    )
    return str(await con.fetchval(
        "INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, "
        "description) VALUES ($1,'osv:GHSA-1','sca','high','flask vuln','desc') "
        "RETURNING id",
        aid,
    ))


async def _mk_remediation(con, *, kind="dependency_bump", status="verified",
                          summary="bump flask 1.0.0 -> 1.1.4", diff="--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-flask==1.0.0\n+flask==1.1.4\n",
                          finding_id=None, verifier_report=None, injection_checks=None,
                          pr_url=None, pr_number=None, repo="example/repo") -> str:
    verifier_report = verifier_report if verifier_report is not None else {
        "gate": {"ok": True, "files": ["requirements.txt"]},
        "verify": {"ok": True, "verdict": "addresses_finding",
                   "summary": "addresses the finding; no out-of-scope changes"},
        "pr": {"opened": False, "reason": "REMEDIATION_OPEN_PR is false (default); PR not pushed"},
    }
    injection_checks = injection_checks if injection_checks is not None else {
        "finding": {"flagged": False, "blocked": False, "categories": [],
                    "summary": "no injection detected"},
        "pr": {"flagged": False, "blocked": False, "categories": [],
               "summary": "no injection detected"},
    }
    return str(await con.fetchval(
        """
        INSERT INTO remediations
            (finding_id, repo, kind, summary, base_branch, head_branch, diff,
             status, verifier_report, injection_checks, pr_url, pr_number, created_by)
        VALUES ($1,$2,$3,$4,'main','auto/x',$5,$6,$7::jsonb,$8::jsonb,$9,$10,'test')
        RETURNING id
        """,
        finding_id, repo, kind, summary, diff, status,
        json.dumps(verifier_report), json.dumps(injection_checks), pr_url, pr_number,
    ))


# --------------------------------------------------------------------------- #
# list + detail
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_list_remediations_with_summaries(rem_client, db_pool):
    async with db_pool.acquire() as con:
        fid = await _mk_finding(con)
        await _mk_remediation(con, status="verified", finding_id=fid)
        await _mk_remediation(con, kind="security_header", status="verified",
                              summary="add hsts header",
                              diff="--- a/nginx.conf\n+++ b/nginx.conf\n")

    r = await rem_client.get("/v1/remediation")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 2
    assert {"items", "total", "limit", "offset"} <= set(body)
    first = body["items"][0]
    # summaries are present; the full diff is NOT in the list payload
    assert "diff" not in first
    assert first["injection"]["blocked"] is False
    assert first["injection"]["summary"] == "no injection detected"
    assert first["verifier"]["gate_ok"] is True
    assert first["verifier"]["verify_ok"] is True


@pytest.mark.asyncio
async def test_list_filter_by_status(rem_client, db_pool):
    async with db_pool.acquire() as con:
        await _mk_remediation(con, status="verified")
        await _mk_remediation(con, status="rejected",
                              summary="[rejected] injected finding",
                              verifier_report={"rejection_reason": "prompt-injection detected in finding fields"},
                              injection_checks={"finding": {"flagged": True, "blocked": True,
                                                            "categories": ["instruction_override", "action_exfil"],
                                                            "summary": "blocked: action_exfil, instruction_override"}})

    r = await rem_client.get("/v1/remediation", params={"status": "rejected"})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    row = body["items"][0]
    assert row["status"] == "rejected"
    assert row["injection"]["blocked"] is True
    assert "instruction_override" in row["injection"]["categories"]
    assert "prompt-injection" in (row["verifier"]["rejection_reason"] or "")


@pytest.mark.asyncio
async def test_detail_returns_full_diff_and_reports(rem_client, db_pool):
    async with db_pool.acquire() as con:
        rid = await _mk_remediation(con, status="verified")

    r = await rem_client.get(f"/v1/remediation/{rid}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "flask==1.1.4" in body["diff"]
    assert body["verifier_report"]["gate"]["ok"] is True
    assert body["injection_checks"]["finding"]["blocked"] is False
    assert body["verifier"]["verdict"] == "addresses_finding"


@pytest.mark.asyncio
async def test_detail_unknown_is_404(rem_client):
    r = await rem_client.get(f"/v1/remediation/{uuid.uuid4()}")
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# propose proxy degradation (remediation service down)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_propose_degrades_when_service_down(rem_client, monkeypatch):
    from app.routers import remediation
    monkeypatch.setattr(remediation, "_remediation_url", lambda: _DEAD_URL)

    r = await rem_client.post("/v1/remediation/propose",
                              json={"finding_id": str(uuid.uuid4())})
    assert r.status_code == 200  # never a 5xx
    body = r.json()
    assert body["ok"] is False
    assert "not reachable" in body["note"]


@pytest.mark.asyncio
async def test_propose_requires_finding_id(rem_client):
    r = await rem_client.post("/v1/remediation/propose", json={})
    assert r.status_code == 422  # pydantic validation
