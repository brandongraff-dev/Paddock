"""The on-read lifecycle sweep is throttled per tenant (it only sees one tenant's rows)."""
from __future__ import annotations

from app import lifecycle, tenancy

from . import stress_world as sw


async def test_on_read_sweep_throttle_is_per_tenant(monkeypatch):
    calls: list[str | None] = []

    async def fake_sweep(pool, now=None):
        calls.append(tenancy.current_tenant_id())
        return {"reopened": 0, "released": 0}

    monkeypatch.setattr(lifecycle, "sweep_expired", fake_sweep)
    lifecycle.reset_sweep_throttle()
    with tenancy.tenant_context(sw.T_A):
        await lifecycle.maybe_sweep(None)
        await lifecycle.maybe_sweep(None)      # throttled
    with tenancy.tenant_context(sw.T_B):
        await lifecycle.maybe_sweep(None)      # B is NOT starved by A's slot
    assert calls == [sw.T_A, sw.T_B]
    lifecycle.reset_sweep_throttle()
