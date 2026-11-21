"""GET /metrics: per-sensor Sentry freshness for the "Sentry silent" alert."""
from __future__ import annotations

import dataclasses

from aiohttp.test_utils import make_mocked_request

from app import config as config_module
from app.main import OtDiscoveryService, _render_metrics


def test_render_metrics_per_sensor_and_escaping():
    text = _render_metrics(
        {
            "s1": {"last_seen": "2026-01-01T00:00:00+00:00", "site": 'HQ "north"', "batches": 3},
            "bad": {"last_seen": "not-a-date", "batches": 1},
        },
        1767225600.0,
    )
    assert (
        'paddock_sentry_last_ingest_timestamp_seconds{sensor="s1",site="HQ \\"north\\""} '
        "1767225600.000" in text
    )
    assert 'paddock_sentry_batches_total{sensor="s1"} 3' in text
    assert 'sensor="bad"' not in text  # unparsable timestamp skipped
    assert "paddock_otdiscovery_last_ingest_timestamp_seconds 1767225600.000" in text
    assert "paddock_otdiscovery_sensors 2" in text


def _svc(require_token: bool) -> OtDiscoveryService:
    cfg = dataclasses.replace(config_module.load(), enable_db=False,
                              require_sentry_token=require_token)
    return OtDiscoveryService(cfg)


async def test_metrics_access_control(monkeypatch):
    monkeypatch.delenv("METRICS_TOKEN", raising=False)
    # dev (no sensor token required): open
    r = await _svc(False)._handle_metrics(make_mocked_request("GET", "/metrics"))
    assert r.status == 200 and "paddock_otdiscovery_sensors 0" in r.text
    # hardened without a metrics token: fail closed
    r = await _svc(True)._handle_metrics(make_mocked_request("GET", "/metrics"))
    assert r.status == 404
    # token configured: required
    monkeypatch.setenv("METRICS_TOKEN", "tok")
    svc = _svc(True)
    assert (await svc._handle_metrics(make_mocked_request("GET", "/metrics"))).status == 401
    ok = await svc._handle_metrics(
        make_mocked_request("GET", "/metrics", headers={"Authorization": "Bearer tok"})
    )
    assert ok.status == 200
