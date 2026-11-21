"""TAXII 2.1 poll tests against a local in-process HTTP server (no real network).

A real aiohttp server (rather than a client-side mock library) keeps these
tests independent of aiohttp's private ClientResponse internals, which
change between releases and broke the previous aioresponses-based mocks.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from app import taxii
from tests.conftest import load_fixture


def test_build_objects_url_from_collection():
    feed = {"url": "https://taxii.example/api1/", "collection": "col-1"}
    assert taxii.build_objects_url(feed) == "https://taxii.example/api1/collections/col-1/objects/"


def test_build_objects_url_already_objects_endpoint():
    feed = {"url": "https://taxii.example/api1/collections/col-1/objects", "collection": None}
    assert taxii.build_objects_url(feed).endswith("/objects/")


@asynccontextmanager
async def serve(routes: dict[str, list[tuple[int, object]]]):
    """Serve canned JSON responses; each path pops its queue in order (the
    last response repeats). Yields (base_url, request_log)."""
    log: list[web.Request] = []

    async def handler(request: web.Request) -> web.Response:
        log.append(request)
        queue = routes.get(request.path)
        if not queue:
            return web.json_response({"error": "no route"}, status=404)
        status, body = queue.pop(0) if len(queue) > 1 else queue[0]
        return web.json_response(body, status=status)

    app = web.Application()
    app.router.add_route("GET", "/{tail:.*}", handler)
    server = TestServer(app)
    await server.start_server()
    try:
        yield str(server.make_url("")).rstrip("/"), log
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_poll_taxii_ingests_indicators(fake_db):
    bundle = load_fixture("stix_bundle.json")
    envelope = {"objects": bundle["objects"], "more": False}
    async with serve({"/api1/collections/col-1/objects/": [(200, envelope)]}) as (base, log):
        feed = {"id": "feed-1", "name": "unit-feed", "kind": "taxii",
                "url": f"{base}/api1", "collection": "col-1"}
        async with aiohttp.ClientSession() as session:
            res = await taxii.poll_feed(fake_db, session, feed, timeout_s=10)

    assert res["status"].startswith("ok")
    assert res["inserted"] >= 8
    # indicators actually landed in the (fake) DB, tagged to the feed
    assert any(i["type"] == "ipv4" and i["value"] == "203.0.113.10"
               for i in fake_db.indicators.values())
    # the poll was recorded, and a TAXII 2.1 Accept header was sent
    assert fake_db.feed_polls and fake_db.feed_polls[-1]["feed_id"] == "feed-1"
    assert "taxii" in log[0].headers.get("Accept", "")


@pytest.mark.asyncio
async def test_poll_taxii_pages_through_more_cursor(fake_db):
    page1 = {
        "objects": [{
            "type": "indicator", "id": "indicator--p1",
            "pattern": "[ipv4-addr:value = '1.1.1.1']", "pattern_type": "stix",
        }],
        "more": True, "next": "CURSOR2",
    }
    page2 = {
        "objects": [{
            "type": "indicator", "id": "indicator--p2",
            "pattern": "[ipv4-addr:value = '2.2.2.2']", "pattern_type": "stix",
        }],
        "more": False,
    }
    async with serve({"/api1/collections/c/objects/": [(200, page1), (200, page2)]}) as (base, log):
        feed = {"id": "feed-2", "name": "paged", "kind": "taxii",
                "url": f"{base}/api1", "collection": "c"}
        async with aiohttp.ClientSession() as session:
            res = await taxii.poll_feed(fake_db, session, feed, timeout_s=10, max_pages=5)

    assert res["pages"] == 2
    assert res["inserted"] == 2
    vals = {i["value"] for i in fake_db.indicators.values()}
    assert {"1.1.1.1", "2.2.2.2"} <= vals
    assert log[1].query.get("next") == "CURSOR2"   # the cursor was followed


@pytest.mark.asyncio
async def test_poll_stix_url_single_bundle(fake_db):
    bundle = load_fixture("stix_bundle.json")
    async with serve({"/bundle.json": [(200, bundle)]}) as (base, _):
        feed = {"id": "feed-3", "name": "bundle-url", "kind": "stix_url",
                "url": f"{base}/bundle.json", "collection": None}
        async with aiohttp.ClientSession() as session:
            res = await taxii.poll_feed(fake_db, session, feed, timeout_s=10)
    assert res["status"].startswith("ok")
    assert res["inserted"] >= 8


@pytest.mark.asyncio
async def test_poll_records_error_and_never_raises(fake_db):
    async with serve({"/api1/collections/c/objects/": [(500, {"error": "boom"})]}) as (base, _):
        feed = {"id": "feed-4", "name": "broken", "kind": "taxii",
                "url": f"{base}/api1", "collection": "c"}
        async with aiohttp.ClientSession() as session:
            res = await taxii.poll_feed(fake_db, session, feed, timeout_s=10)
    assert res["status"].startswith("error")
    assert res["inserted"] == 0
    assert fake_db.feed_polls[-1]["status"].startswith("error")


@pytest.mark.asyncio
async def test_poll_unsupported_kind(fake_db):
    feed = {"id": "feed-5", "name": "manual", "kind": "manual", "url": None, "collection": None}
    async with aiohttp.ClientSession() as session:
        res = await taxii.poll_feed(fake_db, session, feed, timeout_s=10)
    assert "unsupported" in res["status"]
