"""The real OrchestratorClient puts the orchestrator's literal wire shapes on the wire."""
from __future__ import annotations

import json

import httpx
import pytest

from app.orchestrator import OrchestratorClient, OrchestratorError

pytestmark = pytest.mark.asyncio


def _client(handler) -> OrchestratorClient:
    c = OrchestratorClient(base_url="http://orch", worker_id="w")
    c._client = httpx.AsyncClient(base_url="http://orch", transport=httpx.MockTransport(handler))
    return c


async def test_wire_shapes_and_paths():
    seen: list[tuple[str, dict]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        seen.append((req.url.path, body))
        if req.url.path == "/v1/assets/bulk":
            return httpx.Response(200, json={"inserted": len(body["items"]), "updated": 0, "items": []})
        if req.url.path == "/v1/edges/bulk":
            return httpx.Response(200, json={"edges_inserted": 1, "edges_updated": 0,
                                             "edges_skipped_missing_endpoint": 0})
        return httpx.Response(200, json={"inserted": 1, "updated": 0, "items": []})

    c = _client(handler)
    await c.assets_bulk([{"kind": "ipv4", "value": "1.2.3.4", "canonical": "1.2.3.4",
                          "source": "port_scan", "metadata": {}}],
                        [{"src_kind": "ipv4", "src_canonical": "1.2.3.4", "dst_kind": "port",
                          "dst_canonical": "1.2.3.4:22", "kind": "hosts"}])
    await c.findings_bulk([{"target_host": "h", "target_canonical": "2606:4700::1111",
                            "target_kind": "ipv6", "rule_id": "r", "rule_source": "policy",
                            "severity": "info", "title": "t", "description": "d"}])
    assert [p for p, _ in seen] == ["/v1/assets/bulk", "/v1/edges/bulk", "/v1/findings/bulk"]
    assert set(seen[0][1]) == {"items"}
    assert set(seen[1][1]) == {"edges"}
    assert set(seen[2][1]) == {"items"}
    f = seen[2][1]["items"][0]
    assert f["asset_value"] == "2606:4700::1111" and f["asset_kind"] == "ipv6"
    assert not {"target_host", "target_canonical", "target_kind"} & set(f)


async def test_422_raises():
    c = _client(lambda req: httpx.Response(422, json={"detail": "bad"}))
    with pytest.raises(httpx.HTTPStatusError):
        await c.assets_bulk([{"kind": "ipv4", "value": "1.2.3.4", "source": "s"}])
    with pytest.raises(httpx.HTTPStatusError):
        await c.findings_bulk([{"asset_value": "x", "rule_id": "r", "rule_source": "policy",
                                "severity": "info", "title": "t", "description": "d"}])


async def test_partial_accept_raises():
    c = _client(lambda req: httpx.Response(200, json={"inserted": 0, "updated": 0, "items": []}))
    with pytest.raises(OrchestratorError):
        await c.assets_bulk([{"kind": "ipv4", "value": "1.2.3.4", "source": "s"}])


async def test_finding_without_target_raises():
    c = _client(lambda req: httpx.Response(200, json={}))
    with pytest.raises(OrchestratorError):
        await c.findings_bulk([{"rule_id": "r", "rule_source": "policy", "severity": "info",
                                "title": "t", "description": "d"}])


async def test_bulk_is_chunked_at_1000():
    sizes: list[int] = []

    def handler(req: httpx.Request) -> httpx.Response:
        n = len(json.loads(req.content)["items"])
        sizes.append(n)
        return httpx.Response(200, json={"inserted": n, "updated": 0, "items": []})

    c = _client(handler)
    await c.assets_bulk([{"kind": "port", "value": f"1.2.3.4:{i}", "source": "s"} for i in range(1, 2002)])
    assert sizes == [1000, 1000, 1]
