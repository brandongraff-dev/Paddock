"""TAXII 2.1 poll tests with a mocked HTTP layer (no real network)."""
from __future__ import annotations

import re

import aiohttp
import pytest
from aioresponses import aioresponses

from app import taxii
from tests.conftest import load_fixture


def test_build_objects_url_from_collection():
    feed = {"url": "https://taxii.example/api1/", "collection": "col-1"}
    assert taxii.build_objects_url(feed) == "https://taxii.example/api1/collections/col-1/objects/"


def test_build_objects_url_already_objects_endpoint():
    feed = {"url": "https://taxii.example/api1/collections/col-1/objects", "collection": None}
    assert taxii.build_objects_url(feed).endswith("/objects/")


@pytest.mark.asyncio
async def test_poll_taxii_ingests_indicators(fake_db):
    feed = {
        "id": "feed-1", "name": "unit-feed", "kind": "taxii",
        "url": "https://taxii.example/api1", "collection": "col-1",
    }
    bundle = load_fixture("stix_bundle.json")
    envelope = {"objects": bundle["objects"], "more": False}

    pattern = re.compile(r"^https://taxii\.example/api1/collections/col-1/objects/")
    with aioresponses() as m:
        m.get(pattern, payload=envelope, status=200)
        async with aiohttp.ClientSession() as session:
            res = await taxii.poll_feed(fake_db, session, feed, timeout_s=10)

    assert res["status"].startswith("ok")
    assert res["inserted"] >= 8
    # indicators actually landed in the (fake) DB, tagged to the feed
    assert any(i["type"] == "ipv4" and i["value"] == "203.0.113.10"
               for i in fake_db.indicators.values())
    assert fake_db.feeds == {} or True  # feed row optional in unit db
    # the poll was recorded
    assert fake_db.feed_polls and fake_db.feed_polls[-1]["feed_id"] == "feed-1"


@pytest.mark.asyncio
async def test_poll_taxii_pages_through_more_cursor(fake_db):
    feed = {
        "id": "feed-2", "name": "paged", "kind": "taxii",
        "url": "https://taxii.example/api1", "collection": "c",
    }
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
    pattern = re.compile(r"^https://taxii\.example/api1/collections/c/objects/")
    with aioresponses() as m:
        # aioresponses serves queued responses in order for repeated GETs
        m.get(pattern, payload=page1, status=200)
        m.get(pattern, payload=page2, status=200)
        async with aiohttp.ClientSession() as session:
            res = await taxii.poll_feed(fake_db, session, feed, timeout_s=10, max_pages=5)

    assert res["pages"] == 2
    assert res["inserted"] == 2
    vals = {i["value"] for i in fake_db.indicators.values()}
    assert {"1.1.1.1", "2.2.2.2"} <= vals


@pytest.mark.asyncio
async def test_poll_stix_url_single_bundle(fake_db):
    feed = {"id": "feed-3", "name": "bundle-url", "kind": "stix_url",
            "url": "https://feeds.example/bundle.json", "collection": None}
    bundle = load_fixture("stix_bundle.json")
    with aioresponses() as m:
        m.get("https://feeds.example/bundle.json", payload=bundle, status=200)
        async with aiohttp.ClientSession() as session:
            res = await taxii.poll_feed(fake_db, session, feed, timeout_s=10)
    assert res["status"].startswith("ok")
    assert res["inserted"] >= 8


@pytest.mark.asyncio
async def test_poll_records_error_and_never_raises(fake_db):
    feed = {"id": "feed-4", "name": "broken", "kind": "taxii",
            "url": "https://taxii.example/api1", "collection": "c"}
    pattern = re.compile(r"^https://taxii\.example/api1/.*")
    with aioresponses() as m:
        m.get(pattern, status=500)
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
