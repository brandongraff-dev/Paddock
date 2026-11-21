"""IoT/OT device inventory router (/v1/devices).

The router lives in app/routers/devices.py and is included into the app here
(main.py is a fixed wiring surface we don't edit in this test). We seed
iot_device / ot_device / network_segment assets, member_of edges and exposure
findings directly, then assert list/detail/summary + filters.
"""
from __future__ import annotations

import json

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.routers import devices as devices_router


@pytest_asyncio.fixture
async def dev_client(app):
    # Mount the devices router onto the test app (idempotent across tests).
    if not any(getattr(r, "path", "") == "/v1/devices" for r in app.router.routes):
        app.include_router(devices_router.router)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _seed(pool):
    """Insert a small device graph; return the key asset ids."""
    async with pool.acquire() as con:
        async def asset(kind, value, md):
            return await con.fetchval(
                """
                INSERT INTO assets (kind, value, canonical, source, confidence, metadata)
                VALUES ($1, $2, $3, 'otdiscovery', 90, $4::jsonb)
                RETURNING id
                """,
                kind, value, value.lower(), json.dumps(md),
            )

        seg_ot = await asset("network_segment", "10.0.5.0/24",
                             {"classification": "ot", "internet_facing": False,
                              "device_count": 1})
        seg_mixed = await asset("network_segment", "10.0.0.0/24",
                                {"classification": "mixed", "internet_facing": False,
                                 "device_count": 2})

        ot1 = await asset("ot_device", "10.0.5.10",
                          {"vendor": "Siemens", "model": "SIMATIC S7-1200",
                           "type": "plc", "mac": "00:1b:1b:00:00:10",
                           "ips": ["10.0.5.10"], "protocols": ["modbus", "s7comm"],
                           "confidence": 92, "role": "ot", "segment": "10.0.5.0/24"})
        ot2 = await asset("ot_device", "10.0.0.10",
                          {"vendor": "Honeywell", "type": "hvac_controller",
                           "mac": "00:40:84:00:00:20", "ips": ["10.0.0.10"],
                           "protocols": ["bacnet"], "confidence": 92, "role": "ot",
                           "segment": "10.0.0.0/24"})
        iot1 = await asset("iot_device", "10.0.0.60",
                           {"vendor": "Hewlett-Packard", "type": "printer",
                            "mac": "00:1b:78:00:00:60", "ips": ["10.0.0.60"],
                            "protocols": [], "confidence": 60, "role": "iot",
                            "segment": "10.0.0.0/24"})

        async def edge(src, dst):
            await con.execute(
                "INSERT INTO asset_edges (src_id, dst_id, kind) VALUES ($1,$2,'member_of')",
                src, dst,
            )
        await edge(ot1, seg_ot)
        await edge(ot2, seg_mixed)
        await edge(iot1, seg_mixed)

        async def finding(asset_id, rule_id, rule_source, severity, title):
            await con.execute(
                """
                INSERT INTO findings (asset_id, rule_id, rule_source, severity,
                                      title, description)
                VALUES ($1, $2, $3, $4, $5, 'seeded')
                """,
                asset_id, rule_id, rule_source, severity, title,
            )
        # ot1: internet-exposed + a CVE match. ot2: IT/OT segmentation violation.
        await finding(ot1, "ot_public_exposure", "policy", "high", "public OT")
        await finding(ot1, "CVE-2021-0001", "cve_match", "high", "cve on plc")
        await finding(ot2, "ot_it_exposure", "policy", "high", "IT/OT violation")

    return {"ot1": ot1, "ot2": ot2, "iot1": iot1,
            "seg_ot": seg_ot, "seg_mixed": seg_mixed}


# --------------------------------------------------------------------------- #
# List + filters + pagination
# --------------------------------------------------------------------------- #

async def test_list_all_devices(dev_client, db_pool):
    await _seed(db_pool)
    r = await dev_client.get("/v1/devices")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 3
    roles = {d["value"]: d["role"] for d in body["items"]}
    assert roles["10.0.5.10"] == "ot"
    assert roles["10.0.0.60"] == "iot"
    plc = next(d for d in body["items"] if d["value"] == "10.0.5.10")
    assert plc["vendor"] == "Siemens"
    assert "modbus" in plc["protocols"]
    assert plc["open_finding_count"] == 2
    assert plc["exposed"] is True


async def test_filter_by_role(dev_client, db_pool):
    await _seed(db_pool)
    r = await dev_client.get("/v1/devices", params={"role": "ot"})
    body = r.json()
    assert body["total"] == 2
    assert all(d["role"] == "ot" for d in body["items"])


async def test_filter_by_type_and_vendor(dev_client, db_pool):
    await _seed(db_pool)
    r = await dev_client.get("/v1/devices", params={"type": "plc"})
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["value"] == "10.0.5.10"

    r = await dev_client.get("/v1/devices", params={"vendor": "siemens"})
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["vendor"] == "Siemens"


async def test_pagination(dev_client, db_pool):
    await _seed(db_pool)
    r = await dev_client.get("/v1/devices", params={"limit": 1, "offset": 0})
    body = r.json()
    assert body["total"] == 3
    assert len(body["items"]) == 1
    assert body["limit"] == 1


# --------------------------------------------------------------------------- #
# Detail
# --------------------------------------------------------------------------- #

async def test_device_detail_with_findings_and_segment(dev_client, db_pool):
    ids = await _seed(db_pool)
    r = await dev_client.get(f"/v1/devices/{ids['ot1']}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["device"]["vendor"] == "Siemens"
    rule_ids = {f["rule_id"] for f in body["findings"]}
    assert "ot_public_exposure" in rule_ids
    assert "CVE-2021-0001" in rule_ids
    assert body["segment"]["value"] == "10.0.5.0/24"
    assert body["segment"]["classification"] == "ot"


async def test_detail_404_for_non_device_asset(dev_client, db_pool):
    async with db_pool.acquire() as con:
        aid = await con.fetchval(
            "INSERT INTO assets (kind,value,canonical,source) "
            "VALUES ('domain','example.com','example.com','seed') RETURNING id"
        )
    r = await dev_client.get(f"/v1/devices/{aid}")
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

async def test_summary_counts(dev_client, db_pool):
    await _seed(db_pool)
    r = await dev_client.get("/v1/devices/summary")
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["total"] == 3
    assert s["ot_total"] == 2
    assert s["iot_total"] == 1
    assert s["by_role"] == {"ot": 2, "iot": 1}
    assert s["by_type"].get("plc") == 1
    assert s["by_vendor"].get("Siemens") == 1
    assert s["segments"] == 2
    # ot1 (public) + ot2 (it/ot) both exposed
    assert s["exposed_ot"] == 2
    assert s["it_ot_violations"] == 1
    assert s["internet_facing_ot"] == 1
