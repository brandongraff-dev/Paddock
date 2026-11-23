"""First-run wizard state + optional-service status (schema 021)."""
from __future__ import annotations

import pytest

from app.config import settings
from app.routers import onboarding as onboarding_mod


async def test_fresh_workspace_needs_setup(client):
    r = await client.get("/v1/onboarding")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["available"] is True
    assert d["needs_setup"] is True
    assert d["current_step"] == "workspace"
    assert d["steps_done"] == []
    assert d["has_verified_scope"] is False
    assert d["counts"] == {"assets": 0, "findings": 0, "domain_assets": 0, "domain_findings": 0}
    assert d["require_scope_proof"] is False


async def test_progress_is_persisted(client):
    r = await client.put("/v1/onboarding", json={
        "workspace_name": "  Acme Security ", "current_step": "domain", "step_done": "workspace"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["workspace_name"] == "Acme Security"
    assert d["current_step"] == "domain"
    assert d["steps_done"] == ["workspace"]
    # step_done is idempotent
    d = (await client.put("/v1/onboarding", json={"step_done": "workspace"})).json()
    assert d["steps_done"] == ["workspace"]
    d = (await client.get("/v1/onboarding")).json()
    assert d["workspace_name"] == "Acme Security"


async def test_scope_entry_scan_and_domain_counts(client, db_pool):
    e = (await client.post("/v1/scope", json={
        "kind": "subdomain_wildcard", "value": "acme-demo.example", "added_by": "t"})).json()
    async with db_pool.acquire() as con:
        await con.execute(
            """INSERT INTO assets (kind, value, canonical, source) VALUES
               ('domain','acme-demo.example','acme-demo.example','t'),
               ('subdomain','api.acme-demo.example','api.acme-demo.example','t'),
               ('subdomain','notacme-demo.example','notacme-demo.example','t')"""
        )
        aid = await con.fetchval("SELECT id FROM assets WHERE canonical='api.acme-demo.example'")
        await con.execute(
            "INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description)"
            " VALUES ($1,'r','manual','high','t','d')", aid)
        scan_id = await con.fetchval(
            "INSERT INTO scans (kind, target, status) VALUES "
            "('passive_full','acme-demo.example','queued') RETURNING id")
    d = (await client.put("/v1/onboarding", json={
        "scope_entry_id": e["id"], "first_scan_id": str(scan_id)})).json()
    assert d["scope_entry"]["id"] == e["id"]
    assert d["scope_entry"]["proof"]["status"] == "pending"
    assert d["first_scan"]["status"] == "queued"
    assert d["counts"] == {"assets": 3, "findings": 1, "domain_assets": 2, "domain_findings": 1}


async def test_unknown_scope_entry_404(client):
    r = await client.put("/v1/onboarding", json={"scope_entry_id": 4242})
    assert r.status_code == 404


async def test_verified_scope_or_dismiss_or_complete_ends_setup(client):
    assert (await client.get("/v1/onboarding")).json()["needs_setup"] is True
    d = (await client.put("/v1/onboarding", json={"dismissed": True})).json()
    assert d["needs_setup"] is False
    d = (await client.put("/v1/onboarding", json={"dismissed": False})).json()
    assert d["needs_setup"] is True
    d = (await client.put("/v1/onboarding", json={"completed": True, "current_step": "done"})).json()
    assert d["completed_at"] is not None and d["needs_setup"] is False
    d = (await client.put("/v1/onboarding", json={"completed": False})).json()
    assert d["needs_setup"] is True

    e = (await client.post("/v1/scope", json={
        "kind": "ipv4_cidr", "value": "198.51.100.0/24", "added_by": "t"})).json()
    await client.post(f"/v1/scope/{e['id']}/verify", json={"loa_ref": "L", "approver": "A"})
    d = (await client.get("/v1/onboarding")).json()
    assert d["has_verified_scope"] is True and d["needs_setup"] is False


async def test_invalid_step_rejected(client):
    r = await client.put("/v1/onboarding", json={"current_step": "hack"})
    assert r.status_code == 422


@pytest.fixture
def lite():
    prev = settings.deployment_mode
    settings.deployment_mode = "lite"
    onboarding_mod._cache = None
    try:
        yield
    finally:
        settings.deployment_mode = prev
        onboarding_mod._cache = None


async def test_services_not_enabled_in_lite(client, lite, monkeypatch):
    probed = []

    async def probe(url):
        probed.append(url)
        return "brain" in url

    monkeypatch.setattr(onboarding_mod, "_probe", probe)
    r = await client.get("/v1/system/services")
    assert r.status_code == 200
    d = r.json()
    assert d["mode"] == "lite"
    names = {s["name"]: s for s in d["services"]}
    # brain is part of the lite stack (AI triage + Ask) and is probed like in full mode ...
    assert names["brain"]["enabled"] is True and names["brain"]["status"] == "ok"
    assert len(probed) == 1 and "brain" in probed[0]
    # ... everything else the lite file leaves out is "not enabled" and never probed
    assert names["graphsync"]["enabled"] is False
    assert all(s["status"] == "not_enabled" for s in d["services"] if s["name"] != "brain")


async def test_lite_brain_down_is_reported_not_raised(client, lite, monkeypatch):
    async def probe(_url):
        return False

    monkeypatch.setattr(onboarding_mod, "_probe", probe)
    names = {s["name"]: s for s in (await client.get("/v1/system/services")).json()["services"]}
    assert names["brain"]["status"] == "down" and names["brain"]["enabled"] is True


async def test_services_down_in_full_mode_never_errors(client, monkeypatch):
    onboarding_mod._cache = None

    async def probe(url):
        return "brain" in url

    monkeypatch.setattr(onboarding_mod, "_probe", probe)
    d = (await client.get("/v1/system/services")).json()
    onboarding_mod._cache = None
    names = {s["name"]: s for s in d["services"]}
    assert d["mode"] == "full"
    assert names["brain"]["status"] == "ok"
    assert names["mlrisk"]["status"] == "down"
