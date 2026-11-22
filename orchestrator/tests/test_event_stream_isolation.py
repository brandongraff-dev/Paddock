"""SSE event stream tenant filter (found by the API sweep hanging on it)."""
from __future__ import annotations

import json

import pytest

from app import tenancy
from app.config import settings

from . import stress_world as sw


@pytest.fixture
def stress_settings(monkeypatch):
    monkeypatch.setattr(settings, "auth_mode", "enforce")
    monkeypatch.setattr(settings, "service_api_key", sw.SERVICE_KEY)
    yield


async def test_event_stream_is_tenant_filtered(stress_settings, app, app_pool, db_pool, client, fake_redis,
                                               monkeypatch):
    """Regression: GET /v1/events tailed the shared Redis stream for EVERY
    authenticated caller, leaking other tenants' finding events."""
    from app import main as main_mod
    from app import queue

    w = await sw.build_world(db_pool=db_pool, app_pool=app_pool, app=app, client=client, generic=False)
    for n in ("a", "b"):
        with tenancy.tenant_context(w[n].id):
            await queue.publish_event(fake_redis, {"event": "finding_opened", "title": f"secret-{n}"})
    await queue.publish_event(fake_redis, {"event": "legacy_unstamped", "title": "secret-legacy", "tenant_id": ""})

    async def finite(r, since="$", block_ms=15000, count=50):
        # the real reader blocks forever; replay what is in the stream and stop
        for sid, fields in await r.xrange(queue.settings.events_stream):
            yield sid, json.loads(fields["event"])

    monkeypatch.setattr(main_mod, "read_events", finite)
    ra = await client.get("/v1/events?since=0", headers=w["a"].headers())
    rb = await client.get("/v1/events?since=0", headers=w["b"].headers())
    rm = await client.get("/v1/events?since=0", headers=w["m"].headers())
    assert "secret-a" in ra.text and "secret-b" not in ra.text and "secret-legacy" not in ra.text
    assert "secret-b" in rb.text and "secret-a" not in rb.text and "secret-legacy" not in rb.text
    assert "secret-" not in rm.text


def test_event_visibility_rules(monkeypatch):
    d = tenancy.DEFAULT_TENANT_ID
    assert tenancy.event_visible_to({"tenant_id": sw.T_A}, sw.T_A)
    assert not tenancy.event_visible_to({"tenant_id": sw.T_A}, sw.T_B)
    assert not tenancy.event_visible_to({"tenant_id": "not-a-uuid"}, sw.T_A)
    assert not tenancy.event_visible_to({"tenant_id": sw.T_A}, None)
    assert tenancy.event_visible_to({}, d) and not tenancy.event_visible_to({}, sw.T_A)
    monkeypatch.setattr(settings, "tenancy_strict", True)
    assert not tenancy.event_visible_to({}, d)
