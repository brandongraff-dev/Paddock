"""Threat-intel router (schema 013): feeds CRUD, indicators + matches paging,
summary shapes, and the poll/ingest proxies degrading when the threatintel
service is down.

The threatintel service owns the writes in production; here we seed `ti_feeds`,
`ti_indicators`, `ti_matches`, `assets`, and `findings` directly and exercise
the orchestrator's read/config + proxy surface. The poll/ingest proxies are
driven against a dead upstream and must DEGRADE to {ok:false, note:...} -- never
raise, never 5xx.
"""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.config import settings

# A port nothing listens on: the proxy call fails immediately and must degrade.
_DEAD_URL = "http://127.0.0.1:59998"


@pytest_asyncio.fixture
async def ti_client(app):
    """The app fixture + our router mounted (main.py wires it in production)."""
    from app.routers import threatintel

    app.include_router(threatintel.router)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# --------------------------------------------------------------------------- #
# Seed helpers
# --------------------------------------------------------------------------- #

async def _mk_asset(con, kind: str, value: str) -> str:
    return str(await con.fetchval(
        "INSERT INTO assets (kind, value, canonical, source) "
        "VALUES ($1,$2,$3,'seed') RETURNING id",
        kind, value, value.lower(),
    ))


async def _mk_finding(con, asset_id: str, title: str, severity: str = "high") -> str:
    return str(await con.fetchval(
        "INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, "
        "description) VALUES ($1,$2,'threat_intel',$3,$4,'desc') RETURNING id",
        asset_id, f"ti:{title}", severity, title,
    ))


async def _mk_feed(con, *, name: str, kind: str = "taxii",
                   url: str | None = "https://taxii.example/api",
                   collection: str | None = "col-1", enabled: bool = True) -> str:
    return str(await con.fetchval(
        "INSERT INTO ti_feeds (name, kind, url, collection, enabled) "
        "VALUES ($1,$2,$3,$4,$5) RETURNING id",
        name, kind, url, collection, enabled,
    ))


async def _mk_indicator(con, *, type: str, value: str, labels=None, malware=None,
                        threat_actor=None, confidence: int = 50,
                        feed_id: str | None = None, stix_id: str | None = None) -> str:
    return str(await con.fetchval(
        """
        INSERT INTO ti_indicators
            (stix_id, type, value, labels, malware, threat_actor, confidence, feed_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id
        """,
        stix_id, type, value, labels or [], malware or [],
        threat_actor, confidence, feed_id,
    ))


async def _mk_match(con, *, indicator_id: str, subject_type: str, subject_id: str,
                    matched_value: str, severity: str = "high",
                    finding_id: str | None = None) -> str:
    return str(await con.fetchval(
        """
        INSERT INTO ti_matches
            (indicator_id, subject_type, subject_id, matched_value, severity, finding_id)
        VALUES ($1,$2,$3,$4,$5,$6) RETURNING id
        """,
        indicator_id, subject_type, subject_id, matched_value, severity, finding_id,
    ))


# --------------------------------------------------------------------------- #
# Feeds CRUD
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_create_list_delete_feed(ti_client):
    r = await ti_client.post("/v1/ti/feeds", json={
        "name": "AlienVault OTX", "kind": "taxii",
        "url": "https://otx.example/taxii2", "collection": "col-abc", "enabled": True,
    })
    assert r.status_code == 201, r.text
    feed = r.json()
    assert feed["name"] == "AlienVault OTX"
    assert feed["kind"] == "taxii"
    assert feed["indicator_count"] == 0
    fid = feed["id"]

    r = await ti_client.get("/v1/ti/feeds")
    assert r.status_code == 200
    assert any(f["id"] == fid for f in r.json())

    r = await ti_client.delete(f"/v1/ti/feeds/{fid}")
    assert r.status_code == 204

    r = await ti_client.delete(f"/v1/ti/feeds/{fid}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_create_feed_rejects_bad_kind(ti_client):
    r = await ti_client.post("/v1/ti/feeds", json={"name": "bad", "kind": "nonsense"})
    assert r.status_code == 422


# --------------------------------------------------------------------------- #
# Indicators (paged + filters)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_list_indicators_paged_and_filtered(ti_client, db_pool):
    async with db_pool.acquire() as con:
        feed = await _mk_feed(con, name="feed-ind")
        await _mk_indicator(con, type="ipv4", value="203.0.113.10",
                            labels=["malicious-activity"], confidence=90, feed_id=feed)
        await _mk_indicator(con, type="domain", value="evil-c2.example",
                            labels=["c2"], malware=["Emotet"], feed_id=feed)
        await _mk_indicator(con, type="domain", value="other.example", labels=["phishing"])

    r = await ti_client.get("/v1/ti/indicators", params={"limit": 50})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert {"items", "total", "limit", "offset"} <= set(body)

    # type filter
    r = await ti_client.get("/v1/ti/indicators", params={"type": "domain"})
    assert r.json()["total"] == 2

    # label filter
    r = await ti_client.get("/v1/ti/indicators", params={"label": "c2"})
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["value"] == "evil-c2.example"
    assert items[0]["malware"] == ["Emotet"]
    assert items[0]["feed_name"] == "feed-ind"

    # q substring on value
    r = await ti_client.get("/v1/ti/indicators", params={"q": "203.0"})
    assert r.json()["total"] == 1


# --------------------------------------------------------------------------- #
# Matches (join indicator + subject)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_list_matches_joins_asset_and_finding_subjects(ti_client, db_pool):
    async with db_pool.acquire() as con:
        asset = await _mk_asset(con, "ipv4", "203.0.113.10")
        host = await _mk_asset(con, "domain", "clean.example")
        finding = await _mk_finding(con, host, "hash hit")
        ind_ip = await _mk_indicator(con, type="ipv4", value="203.0.113.10",
                                     labels=["malicious-activity"], threat_actor="APT-X")
        ind_hash = await _mk_indicator(con, type="file_sha256", value="a" * 64,
                                       malware=["Emotet"])
        # asset-subject match (high) + finding-subject match (critical)
        emitted = await _mk_finding(con, asset, "ti asset finding", "high")
        await _mk_match(con, indicator_id=ind_ip, subject_type="asset",
                        subject_id=asset, matched_value="203.0.113.10",
                        severity="high", finding_id=emitted)
        await _mk_match(con, indicator_id=ind_hash, subject_type="finding",
                        subject_id=finding, matched_value="a" * 64, severity="critical")

    r = await ti_client.get("/v1/ti/matches")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    # worst severity first -> the critical finding-subject match leads
    first = body["items"][0]
    assert first["severity"] == "critical"
    assert first["subject_type"] == "finding"
    assert first["indicator"]["type"] == "file_sha256"
    assert first["indicator"]["malware"] == ["Emotet"]
    assert first["subject"]["finding_title"] == "hash hit"
    assert first["subject"]["asset_value"] == "clean.example"  # the finding's asset

    second = body["items"][1]
    assert second["subject_type"] == "asset"
    assert second["subject"]["asset_value"] == "203.0.113.10"
    assert second["indicator"]["threat_actor"] == "APT-X"
    assert second["finding_id"] is not None


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_summary_counts(ti_client, db_pool):
    async with db_pool.acquire() as con:
        feed = await _mk_feed(con, name="sum-feed")
        asset = await _mk_asset(con, "ipv4", "198.51.100.9")
        ip = await _mk_indicator(con, type="ipv4", value="198.51.100.9", feed_id=feed)
        await _mk_indicator(con, type="ipv4", value="198.51.100.10", feed_id=feed)
        await _mk_indicator(con, type="domain", value="x.example", feed_id=feed)
        await _mk_match(con, indicator_id=ip, subject_type="asset",
                        subject_id=asset, matched_value="198.51.100.9")

    r = await ti_client.get("/v1/ti/summary")
    assert r.status_code == 200
    body = r.json()
    assert body["indicators"] == 3
    assert body["matches"] == 1
    assert body["feeds"] == 1
    assert body["by_type"] == {"ipv4": 2, "domain": 1}


# --------------------------------------------------------------------------- #
# Proxy degradation (threatintel service down)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_poll_degrades_when_service_down(ti_client, db_pool, monkeypatch):
    from app.routers import threatintel
    monkeypatch.setattr(threatintel, "_threatintel_url", lambda: _DEAD_URL)
    async with db_pool.acquire() as con:
        fid = await _mk_feed(con, name="down-feed")

    r = await ti_client.post(f"/v1/ti/feeds/{fid}/poll")
    assert r.status_code == 200  # never a 5xx
    body = r.json()
    assert body["ok"] is False
    assert "not reachable" in body["note"]


@pytest.mark.asyncio
async def test_poll_unknown_feed_is_404(ti_client, monkeypatch):
    from app.routers import threatintel
    monkeypatch.setattr(threatintel, "_threatintel_url", lambda: _DEAD_URL)
    r = await ti_client.post(f"/v1/ti/feeds/{uuid.uuid4()}/poll")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_ingest_degrades_when_service_down(ti_client, monkeypatch):
    from app.routers import threatintel
    monkeypatch.setattr(threatintel, "_threatintel_url", lambda: _DEAD_URL)
    r = await ti_client.post("/v1/ti/ingest", json={"type": "bundle", "objects": []})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "not reachable" in body["note"]
