"""The active worker carries a tenant for every job: callbacks echo it (with the
job's scan id), concurrent jobs of different tenants never mix, and the scope
cache is per tenant."""
from __future__ import annotations

import asyncio

import httpx
import pytest

from app import tenancy
from app.orchestrator import OrchestratorClient
from app.scope_guard import ScopeGuard

A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def _client(seen: list[httpx.Request]) -> OrchestratorClient:
    orch = OrchestratorClient(base_url="http://orch.test", worker_id="w")

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"allow": True, "normalized": "x.example"})

    # keep the REAL event hooks of the production client, swap only the transport
    orch._client = httpx.AsyncClient(
        base_url="http://orch.test", transport=httpx.MockTransport(handler),
        event_hooks=orch._client.event_hooks,
    )
    return orch


async def test_callbacks_echo_the_jobs_tenant_and_scan_even_when_jobs_interleave():
    seen: list[httpx.Request] = []
    orch = _client(seen)

    async def job(tenant: str, scan: str) -> None:
        with tenancy.bind_job({"tenant_id": tenant, "scan_id": scan}):
            await orch.scan_start(scan)
            await asyncio.sleep(0)  # interleave with the other job
            await orch.scope_check("x.example")

    await asyncio.gather(job(A, "11111111-1111-4111-8111-111111111111"),
                         job(B, "22222222-2222-4222-8222-222222222222"))
    pairs = {(r.headers.get("x-paddock-tenant"), r.headers.get("x-paddock-scan")) for r in seen}
    assert pairs == {(A, "11111111-1111-4111-8111-111111111111"),
                     (B, "22222222-2222-4222-8222-222222222222")}
    assert len(seen) == 4


async def test_scope_cache_never_lets_one_tenants_allow_authorise_another():
    calls: list[str | None] = []

    class Orch:
        async def scope_check(self, target):
            calls.append(tenancy.current_tenant_id())
            return {"allow": tenancy.current_tenant_id() == A, "normalized": target}

    guard = ScopeGuard(Orch(), ttl_sec=300)
    with tenancy.tenant_context(A):
        assert (await guard.allow("shared.example")).allow
        assert (await guard.allow("shared.example")).allow  # cached for A
    with tenancy.tenant_context(B):
        with pytest.raises(Exception):  # B asks again and is DENIED -- not served A's allow
            await guard.allow("shared.example")
    assert calls == [A, B]


def test_job_without_a_tenant_is_refused_in_strict_mode(monkeypatch):
    monkeypatch.setenv("TENANCY_STRICT", "true")
    with pytest.raises(tenancy.TenantError):
        with tenancy.bind_job({"scan_id": "s"}):
            pass
    monkeypatch.delenv("TENANCY_STRICT")
    with tenancy.bind_job({"scan_id": "s"}):
        assert tenancy.current_tenant_id() == tenancy.DEFAULT_TENANT_ID
