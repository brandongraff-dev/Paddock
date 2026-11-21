"""The passive worker echoes its job's tenant + scan on every orchestrator
callback and keeps scope decisions per tenant."""
from __future__ import annotations

import asyncio

from aiohttp import web
from aiohttp.test_utils import TestServer

from app import tenancy
from app.config import Settings
from app.orchestrator import OrchestratorClient

A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
SCAN_A = "11111111-1111-4111-8111-111111111111"
SCAN_B = "22222222-2222-4222-8222-222222222222"


async def test_callbacks_carry_the_job_tenant_and_scope_cache_is_per_tenant():
    seen: list[tuple[str, str | None, str | None]] = []

    async def scope(req: web.Request) -> web.Response:
        body = await req.json()
        seen.append(("scope", req.headers.get("X-Paddock-Tenant"), req.headers.get("X-Paddock-Scan")))
        # only tenant A may scan this target
        allow = req.headers.get("X-Paddock-Tenant") == A
        return web.json_response({"allow": allow, "normalized": body["target"], "reason": "t"})

    async def patch_scan(req: web.Request) -> web.Response:
        seen.append(("scan", req.headers.get("X-Paddock-Tenant"), req.headers.get("X-Paddock-Scan")))
        return web.json_response({})

    app = web.Application()
    app.add_routes([web.post("/v1/scope/check", scope), web.patch("/v1/scans/{id}", patch_scan)])
    server = TestServer(app)
    await server.start_server()
    try:
        s = Settings(orchestrator_url=str(server.make_url("")).rstrip("/"))
        async with OrchestratorClient(s) as orc:
            async def job(tenant: str, scan: str) -> bool:
                with tenancy.bind_job({"tenant_id": tenant, "scan_id": scan}):
                    await orc.update_scan_status(scan, "running")
                    await asyncio.sleep(0)
                    return (await orc.scope_check("shared.example")).allow

            ra, rb = await asyncio.gather(job(A, SCAN_A), job(B, SCAN_B))
            assert ra is True and rb is False  # B was not served A's cached allow
            # and the verdicts are cached PER tenant afterwards
            with tenancy.tenant_context(A):
                assert (await orc.scope_check("shared.example")).allow
            with tenancy.tenant_context(B):
                assert not (await orc.scope_check("shared.example")).allow
    finally:
        await server.close()
    assert ("scan", A, SCAN_A) in seen and ("scan", B, SCAN_B) in seen
    assert ("scope", A, SCAN_A) in seen and ("scope", B, SCAN_B) in seen
    assert sum(1 for k, *_ in seen if k == "scope") == 2  # the later checks were cache hits
