"""Tool behaviour against a fake Paddock API (no network)."""
from __future__ import annotations

import httpx
import pytest

from paddock_mcp import tools
from paddock_mcp.client import PaddockClient, PaddockError

from .fake_paddock import AID, FID, make_app


def make_client(caps=("read",), in_scope=True, key="pak_test"):
    log: list = []
    app = make_app(list(caps), log, in_scope=in_scope)
    c = PaddockClient("http://paddock.test", key, transport=httpx.ASGITransport(app=app))
    return c, log


async def test_list_findings_compact_and_bounded():
    c, log = make_client()
    out = await tools.list_findings(c, severity="critical", limit=9999)
    assert out["total"] == 41 and out["returned"] == 1
    f = out["findings"][0]
    assert f["asset"] == "app.example.com" and f["priority_score"] == 97 and f["kev"] is True
    assert len(f["title"]) < 400                                     # untrusted text is capped
    assert "evidence" not in f and "description" not in f
    q = log[-1][2]["q"]
    assert q["severity"] == "critical" and q["status"] == "open" and q["limit"] == "50"
    assert log[-1][2]["key"] == "pak_test"


async def test_list_findings_validates_args():
    c, _ = make_client()
    for kw in ({"severity": "catastrophic"}, {"status": "x"}, {"sort": "random"}, {"asset_id": "not-a-uuid"}):
        with pytest.raises(ValueError):
            await tools.list_findings(c, **kw)


async def test_search_findings():
    c, log = make_client()
    out = await tools.search_findings(c, "CVE-2021-44228")
    assert out["total"] == 41 and log[-1][2]["q"]["q"] == "CVE-2021-44228"
    for bad in ("", "  ", "x" * 300):
        with pytest.raises(ValueError):
            await tools.search_findings(c, bad)


async def test_get_finding_has_evidence_and_attribution():
    c, _ = make_client()
    out = await tools.get_finding(c, FID)
    assert out["ingest"]["source"] == "ci-trivy" and out["remediation"] == "Upgrade log4j"
    assert len(out["evidence"]) <= tools._EVIDENCE + 20 and "fixed_version" in out["evidence"]
    assert out["chains"][0]["id"] == "c1" and out["history"][0]["by"] == "scanner"
    assert out["asset_detail"]["classification"] == "internal"
    with pytest.raises(ValueError):
        await tools.get_finding(c, "../../etc/passwd")
    with pytest.raises(PaddockError) as e:
        await tools.get_finding(c, "99999999-9999-9999-9999-999999999999")
    assert e.value.status == 404


async def test_explain_priority():
    c, _ = make_client()
    out = await tools.explain_priority(c, FID)
    assert out["priority_score"] == 97 and len(out["factors"]) == 3
    assert "Known exploited" in out["explanation"] and "SLA is breached" in out["explanation"]


async def test_list_assets_and_scope():
    c, log = make_client()
    out = await tools.list_assets(c, query="example", kind="subdomain")
    assert out["assets"][0]["id"] == AID and log[-1][2]["q"]["value"] == "%example%"
    with pytest.raises(ValueError):
        await tools.list_assets(c, kind="x; drop table")
    ok = await tools.check_scope(c, "App.Example.com")
    assert ok["in_scope"] is True and log[-1][2]["body"]["worker"] == "mcp"
    for bad in ("", "a b", "x;rm -rf", "h" * 600):
        with pytest.raises(ValueError):
            await tools.check_scope(c, bad)
    c2, _ = make_client(in_scope=False)
    assert (await tools.check_scope(c2, "evil.example"))["in_scope"] is False


async def test_posture_summary_selects_fields():
    c, log = make_client()
    out = await tools.get_posture_summary(c, "30d")
    assert out["highlights"] == ["3 new critical findings"] and "secret" not in out
    assert len(out["risky_assets"]) == 5 and set(out["open_by_severity"]) == set(tools.SEVERITIES)
    with pytest.raises(ValueError):
        await tools.get_posture_summary(c, "forever")


async def test_suggest_remediation_is_read_only():
    c, log = make_client()
    out = await tools.suggest_remediation(c, FID)
    assert out["guidance"][0] == "Upgrade log4j" and "Upgrade log4j-core from 2.14.1 to 2.17.1." in out["guidance"]
    assert all(m == "GET" for m, _, _ in log)


async def test_trigger_scan_respects_scope():
    c, log = make_client(("read", "scan"))
    out = await tools.trigger_scan(c, "app.example.com", "dns", reason="routine")
    assert out["submitted"] and out["status"] == "queued"
    post = [x for x in log if x[1] == "/v1/scans"][0]
    assert post[2]["body"]["config"]["requested_via"] == "mcp"
    c2, log2 = make_client(("read", "scan"), in_scope=False)
    out2 = await tools.trigger_scan(c2, "evil.example", "dns")
    assert out2["submitted"] is False and out2["in_scope"] is False
    assert not [x for x in log2 if x[1] == "/v1/scans"]              # nothing queued for out-of-scope
    for kind in ("exploit", "brute_force", "../x", ""):
        with pytest.raises(ValueError):
            await tools.trigger_scan(c, "app.example.com", kind)


async def test_propose_remediation_filters_response():
    c, log = make_client(("read", "admin"))
    out = await tools.propose_remediation(c, FID)
    assert out == {"ok": True, "id": 7, "status": "proposed", "summary": "Bump log4j"}
    assert log[-1][2]["body"] == {"finding_id": FID, "created_by": "paddock-mcp"}


async def test_client_errors_are_clean():
    c, _ = make_client(key="wrong")
    with pytest.raises(PaddockError) as e:
        await c.capabilities()
    assert e.value.status == 401 and "invalid API key" in e.value.detail
    dead = PaddockClient("http://127.0.0.1:9", "k", timeout=1)
    with pytest.raises(PaddockError) as e:
        await dead.get("/v1/auth/me")
    assert e.value.status == 0 and "cannot reach" in e.value.detail
    with pytest.raises(ValueError):
        PaddockClient("", "k")
