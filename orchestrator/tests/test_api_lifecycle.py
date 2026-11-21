"""Deprecation/sunset header helper (docs/API.md)."""
from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from app.api_lifecycle import deprecated, deprecation_headers


def test_headers_shape():
    h = deprecation_headers(sunset="2027-06-30", since="2026-12-01", successor="/v1/findings")
    assert h["Deprecation"].startswith("@")
    assert h["Sunset"] == "Wed, 30 Jun 2027 00:00:00 GMT"
    assert '</v1/findings>; rel="successor-version"' in h["Link"]
    assert 'rel="deprecation"' in h["Link"]
    assert deprecation_headers()["Deprecation"] == "true"


def test_sunset_window_enforced():
    with pytest.raises(ValueError):
        deprecated(since="2027-01-01", sunset="2027-02-01")


async def test_dependency_sets_headers_and_openapi_flag():
    app = FastAPI()

    @app.get(
        "/v1/old",
        deprecated=True,
        dependencies=[Depends(deprecated(sunset="2027-06-30", successor="/v1/new"))],
    )
    async def old():
        return {"ok": True}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/v1/old")
    assert r.status_code == 200
    assert r.headers["deprecation"] == "true"
    assert r.headers["sunset"].endswith("GMT")
    assert app.openapi()["paths"]["/v1/old"]["get"]["deprecated"] is True
