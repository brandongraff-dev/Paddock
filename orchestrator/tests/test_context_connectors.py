"""Context SOURCE + network ACTION connectors, no database, no real network.

Every vendor API is an ``httpx.MockTransport``; DNS for vendor hosts is a
fake resolver patched into ``netsafety`` so the REAL outbound-URL checks run.
"""
from __future__ import annotations

import json
import types
from urllib.parse import parse_qs

import httpx
import pytest

from app.integrations import REGISTRY, Capability
from app.integrations import netsafety
from app.integrations.connectors import load_all
from app.integrations.connectors._common import (
    SourceError,
    is_unicast_mac,
    merge_hint,
    normalize_mac,
    request_json,
)

load_all()

SECRET = "s3cr3t-DO-NOT-LEAK"


@pytest.fixture
def fake_dns(monkeypatch):
    """Resolve every name to a public address (except names under .internal)."""
    def getaddrinfo(host, port, *a, **k):
        ip = "10.9.9.9" if host.endswith(".internal") else "93.184.216.34"
        return [(2, 1, 6, "", (ip, port))]
    monkeypatch.setattr(netsafety, "socket", types.SimpleNamespace(getaddrinfo=getaddrinfo))


def client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _form(req: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(req.content.decode()).items()}


# --------------------------------------------------------------------------- #
# Registry + helpers
# --------------------------------------------------------------------------- #

def test_registered_with_expected_capabilities():
    for kind in ("aws", "microsoft_defender", "crowdstrike", "servicenow_cmdb"):
        assert REGISTRY[kind].capabilities == frozenset({Capability.SOURCE}), kind
    for kind in ("unifi", "meraki"):
        assert REGISTRY[kind].capabilities == frozenset({Capability.ACTION}), kind
        d = REGISTRY[kind].describe()
        assert "protected_macs" in d["config_schema"]["properties"]
    for kind in ("aws", "microsoft_defender", "crowdstrike", "servicenow_cmdb", "unifi", "meraki"):
        assert REGISTRY[kind].describe()["secret_fields"], kind


def test_mac_normalisation():
    assert normalize_mac("00-1A-2B-3C-4D-5E") == "00:1a:2b:3c:4d:5e"
    assert normalize_mac("001a.2b3c.4d5e") == "00:1a:2b:3c:4d:5e"
    assert normalize_mac("ff:ff:ff:ff:ff:ff") is None
    assert normalize_mac("10.0.0.5") is None
    assert not is_unicast_mac("01:00:5e:00:00:01")
    hint = merge_hint(ips=["10.0.0.5", "127.0.0.1", "bogus"], hostnames=["Host.Corp.", None],
                      macs=["001A2B3C4D5E"])
    assert hint == {"ips": ["10.0.0.5"], "hostnames": ["host.corp"],
                    "macs": ["00:1a:2b:3c:4d:5e"]}


async def test_request_json_never_echoes_body_and_refuses_foreign_redirect(fake_dns):
    def handler(req):
        if req.url.path == "/redirect":
            return httpx.Response(302, headers={"location": "https://evil.example/x"})
        return httpx.Response(401, json={"error": f"bad secret {SECRET}"})

    async with client(handler) as http:
        with pytest.raises(SourceError) as ei:
            await request_json(http, "GET", "https://api.example.com/x", what="probe")
        assert SECRET not in str(ei.value) and "401" in str(ei.value)
        with pytest.raises(SourceError, match="refused redirect"):
            await request_json(http, "GET", "https://api.example.com/redirect", what="r",
                               follow_suffixes=("meraki.com",))


# --------------------------------------------------------------------------- #
# Microsoft Defender + Intune
# --------------------------------------------------------------------------- #

def _ms_handler(seen):
    def handler(req: httpx.Request):
        seen.append((req.method, req.url.host, req.url.path))
        if req.url.host == "login.microsoftonline.com":
            form = _form(req)
            assert form["client_secret"] == SECRET and form["grant_type"] == "client_credentials"
            return httpx.Response(200, json={"access_token": "tok-" + form["scope"].split("/")[2]})
        auth = req.headers["authorization"]
        if req.url.host == "api.securitycenter.microsoft.com":
            assert auth == "Bearer tok-api.securitycenter.microsoft.com"
            if "skiptoken" in str(req.url):
                return httpx.Response(200, json={"value": [{
                    "id": "m2", "computerDnsName": "srv-2.corp.acme.com", "lastIpAddress": "10.1.2.9",
                    "healthStatus": "Inactive", "riskScore": "Low", "exposureLevel": "Low",
                    "ipAddresses": []}],
                    # A nextLink to another host must never be followed.
                    "@odata.nextLink": "https://evil.example/api/machines"})
            return httpx.Response(200, json={
                "value": [{
                    "id": "m1", "computerDnsName": "laptop-1.corp.acme.com", "osPlatform": "Windows11",
                    "osVersion": "10.0", "osBuild": 22631, "lastIpAddress": "10.1.2.3",
                    "lastExternalIpAddress": "52.1.1.1", "healthStatus": "Active",
                    "riskScore": "High", "exposureLevel": "High", "aadDeviceId": "aad-1",
                    "ipAddresses": [
                        {"ipAddress": "10.1.2.3", "macAddress": "001A2B3C4D5E"},
                        {"ipAddress": "172.17.0.1", "macAddress": "0242AC110001"},
                    ]}],
                "@odata.nextLink": "https://api.securitycenter.microsoft.com/api/machines?$skiptoken=2",
            })
        if req.url.host == "graph.microsoft.com":
            assert auth == "Bearer tok-graph.microsoft.com"
            if req.url.params.get("$top") == "1":                 # test()
                return httpx.Response(200, json={"value": []})
            assert "complianceState" in req.url.params["$select"]
            return httpx.Response(200, json={"value": [
                {"id": "i1", "deviceName": "LAPTOP-1", "azureADDeviceId": "aad-1",
                 "complianceState": "noncompliant", "managementState": "managed",
                 "userPrincipalName": "alice@acme.com", "wiFiMacAddress": "001a2b3c4d5f"},
                {"id": "i2", "deviceName": "PHONE-9", "azureADDeviceId": "aad-9",
                 "complianceState": "compliant", "userPrincipalName": "bob@acme.com"},
            ]})
        return httpx.Response(404)
    return handler


async def test_defender_intune_pull(fake_dns):
    seen: list = []
    cls = REGISTRY["microsoft_defender"]
    async with client(_ms_handler(seen)) as http:
        conn = cls({"tenant_id": "contoso-tenant", "client_id": "app-1"},
                   {"client_secret": SECRET}, http)
        assert (await conn.test()).ok
        batch = await conn.pull()
    assert not any(h == "evil.example" for _, h, _ in seen)
    by_host = {a["metadata"].get("hostname"): a for a in batch.assets}
    lap = by_host["laptop-1.corp.acme.com"]
    assert (lap["kind"], lap["value"]) == ("ipv4", "10.1.2.3")
    # merged by the primary NIC only; the docker bridge and external NAT IP are NOT hints
    assert lap["merge_on"]["ips"] == ["10.1.2.3"]
    assert "00:1a:2b:3c:4d:5e" in lap["merge_on"]["macs"]
    assert "02:42:ac:11:00:01" not in lap["merge_on"]["macs"]
    assert lap["metadata"]["owner"] == "alice@acme.com"
    assert lap["metadata"]["managed"] is True and lap["metadata"]["compliant"] is False
    assert lap["metadata"]["mde"]["exposure_level"] == "High"
    phone = by_host["PHONE-9"]
    assert phone.get("merge_only") is True          # no IP, no FQDN: merge or drop
    rules = {(f["rule_id"], f["merge_on"]["ips"][0] if f["merge_on"]["ips"] else None)
             for f in batch.findings}
    assert ("msdefender.device_noncompliant", "10.1.2.3") in rules
    assert ("msdefender.high_exposure", "10.1.2.3") in rules
    assert ("msdefender.high_risk", "10.1.2.3") in rules
    assert ("msdefender.sensor_not_reporting", "10.1.2.9") in rules
    assert all(f["rule_source"] == "policy" for f in batch.findings)
    assert SECRET not in json.dumps([batch.assets, batch.findings], default=str)


async def test_defender_bad_secret_error_is_safe(fake_dns):
    def handler(req):
        return httpx.Response(401, json={"error_description": f"invalid secret {SECRET}"})

    async with client(handler) as http:
        conn = REGISTRY["microsoft_defender"]({"tenant_id": "t", "client_id": "c"},
                                              {"client_secret": SECRET}, http)
        res = await conn.test()
        assert not res.ok and SECRET not in res.detail and "401" in res.detail
        with pytest.raises(SourceError) as ei:
            await conn.pull()
        assert SECRET not in str(ei.value)


async def test_defender_refuses_private_endpoint_override(fake_dns):
    async with client(lambda r: httpx.Response(500)) as http:
        conn = REGISTRY["microsoft_defender"](
            {"tenant_id": "t", "client_id": "c", "login_url": "https://login.corp.internal"},
            {"client_secret": SECRET}, http)
        with pytest.raises(SourceError, match="refused outbound URL"):
            await conn.pull()


# --------------------------------------------------------------------------- #
# CrowdStrike
# --------------------------------------------------------------------------- #

async def test_crowdstrike_pull(fake_dns):
    calls: list[str] = []

    def handler(req: httpx.Request):
        calls.append(req.url.path)
        assert req.url.host == "api.eu-1.crowdstrike.com"
        if req.url.path == "/oauth2/token":
            assert _form(req)["client_secret"] == SECRET
            return httpx.Response(201, json={"access_token": "cs-tok"})
        assert req.headers["authorization"] == "Bearer cs-tok"
        if req.url.path == "/devices/queries/devices-scroll/v1":
            if "offset" not in req.url.params:
                return httpx.Response(200, json={"resources": ["d1"],
                                                 "meta": {"pagination": {"offset": "tok2", "total": 2}}})
            return httpx.Response(200, json={"resources": ["d2"],
                                             "meta": {"pagination": {"offset": "tok3", "total": 2}}})
        if req.url.path == "/devices/entities/devices/v2":
            assert json.loads(req.content)["ids"] == ["d1", "d2"]
            return httpx.Response(200, json={"resources": [
                {"device_id": "d1", "hostname": "web-01", "machine_domain": "corp.acme.com",
                 "local_ip": "10.2.0.5", "external_ip": "52.9.9.9", "mac_address": "00-50-56-aa-bb-cc",
                 "platform_name": "Linux", "os_version": "Ubuntu 22.04", "status": "normal",
                 "device_policies": {"prevention": {"policy_id": "p1", "applied": True}},
                 "reduced_functionality_mode": "yes"},
                {"device_id": "d2", "hostname": "kiosk", "local_ip": "10.2.0.6",
                 "device_policies": {"prevention": {"policy_id": "p2", "applied": True}}},
                {"device_id": "d3", "hostname": "nopolicy", "local_ip": "10.2.0.7",
                 "device_policies": {}},
            ]})
        if req.url.path == "/policy/entities/prevention/v1":
            assert req.url.params.get_list("ids") == ["p1", "p2"]
            return httpx.Response(200, json={"resources": [
                {"id": "p1", "name": "Servers", "enabled": True},
                {"id": "p2", "name": "Kiosks", "enabled": False}]})
        return httpx.Response(404)

    async with client(handler) as http:
        conn = REGISTRY["crowdstrike"]({"client_id": "cid", "cloud": "eu-1"},
                                       {"client_secret": SECRET}, http)
        batch = await conn.pull()
    by_ip = {a["value"]: a for a in batch.assets}
    web = by_ip["10.2.0.5"]
    assert web["merge_on"]["hostnames"] == ["web-01.corp.acme.com", "web-01"]
    assert web["merge_on"]["ips"] == ["10.2.0.5"]          # never the external NAT IP
    assert web["metadata"]["crowdstrike"]["prevention_policy"] == "Servers"
    rules = {(f["asset_value"], f["rule_id"]) for f in batch.findings}
    assert ("10.2.0.5", "crowdstrike.reduced_functionality_mode") in rules
    assert ("10.2.0.6", "crowdstrike.prevention_policy_disabled") in rules
    assert ("10.2.0.7", "crowdstrike.prevention_policy_not_applied") in rules
    assert ("10.2.0.5", "crowdstrike.prevention_policy_not_applied") not in rules


# --------------------------------------------------------------------------- #
# ServiceNow CMDB
# --------------------------------------------------------------------------- #

def _dv(v, d=None):
    return {"value": v, "display_value": d if d is not None else v}


async def test_servicenow_cmdb_pull(fake_dns):
    def handler(req: httpx.Request):
        assert req.headers["authorization"].startswith("Basic ")
        table = req.url.path.rsplit("/", 1)[-1]
        if table == "cmdb_ci_computer":
            if req.url.params.get("sysparm_limit") == "1":       # test()
                return httpx.Response(200, json={"result": []})
            assert req.url.params["sysparm_display_value"] == "all"
            if req.url.params["sysparm_offset"] != "0":
                return httpx.Response(200, json={"result": []})
            return httpx.Response(200, json={"result": [
                {"sys_id": _dv("ci1"), "name": _dv("db01"), "ip_address": _dv("10.3.0.10"),
                 "fqdn": _dv("db01.corp.acme.com"), "mac_address": _dv("00:11:22:33:44:55"),
                 "support_group": _dv("sg1", "DBA Team"), "support_group.email": _dv("dba@acme.com"),
                 "owned_by": _dv("u1", "Carol"), "owned_by.email": _dv("carol@acme.com")},
                {"sys_id": _dv("ci2"), "name": _dv("printer-7"), "ip_address": _dv(""),
                 "support_group": _dv("sg2", "Facilities")},
            ]})
        if table == "cmdb_ci_service":
            return httpx.Response(200, json={"result": [
                {"sys_id": _dv("svc1"), "name": _dv("Payments"),
                 "busines_criticality": _dv("1", "1 - most critical")}]})
        if table == "cmdb_rel_ci":
            assert "cmdb_ci_service" in req.url.params["sysparm_query"]
            return httpx.Response(200, json={"result": [
                {"parent": _dv("svc1", "Payments"), "child": _dv("ci1", "db01")}]})
        return httpx.Response(404)

    async with client(handler) as http:
        conn = REGISTRY["servicenow_cmdb"]({"instance_url": "https://acme.service-now.com",
                                            "page_size": 2},
                                           {"username": "paddock", "password": SECRET}, http)
        assert (await conn.test()).ok
        batch = await conn.pull()
    db = next(a for a in batch.assets if a["value"] == "10.3.0.10")
    assert db["metadata"]["crown_jewel"] is True
    assert db["metadata"]["business_service"] == "Payments"
    assert db["metadata"]["owner"] == "carol@acme.com"
    assert db["metadata"]["owner_team"] == "DBA Team"
    assert db["metadata"]["tags"] == ["owner:DBA Team"]
    printer = next(a for a in batch.assets if a["metadata"]["hostname"] == "printer-7")
    assert printer["merge_only"] is True and "crown_jewel" not in printer["metadata"]
    owners = {o["team"]: o for o in batch.owners}
    assert owners["DBA Team"]["match"]["tag"] == "owner:DBA Team"
    assert owners["DBA Team"]["contact"] == "dba@acme.com"


async def test_servicenow_requires_https_public_unless_opted_in(fake_dns):
    async with client(lambda r: httpx.Response(200, json={"result": []})) as http:
        conn = REGISTRY["servicenow_cmdb"]({"instance_url": "https://cmdb.corp.internal"},
                                           {"oauth_token": SECRET}, http)
        assert not (await conn.test()).ok
        conn = REGISTRY["servicenow_cmdb"]({"instance_url": "https://cmdb.corp.internal",
                                            "allow_private": True}, {"oauth_token": SECRET}, http)
        assert (await conn.test()).ok


# --------------------------------------------------------------------------- #
# UniFi
# --------------------------------------------------------------------------- #

def _unifi_handler(calls, *, known=True):
    def handler(req: httpx.Request):
        body = json.loads(req.content) if req.content else None
        calls.append((req.method, req.url.path, body))
        assert req.headers.get("x-api-key") == SECRET
        p = req.url.path
        if p == "/proxy/network/api/self/sites":
            return httpx.Response(200, json={"meta": {"rc": "ok"},
                                             "data": [{"name": "default", "desc": "HQ"}]})
        if p.startswith("/proxy/network/api/s/default/stat/user/"):
            if not known:
                return httpx.Response(400, json={"meta": {"rc": "error", "msg": "api.err.UnknownUser"}})
            return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": [{
                "_id": "u123", "mac": p.rsplit("/", 1)[-1],
                "virtual_network_override_enabled": False}]})
        if p in ("/proxy/network/api/s/default/cmd/stamgr", "/proxy/network/api/s/default/rest/user/u123"):
            return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": []})
        return httpx.Response(404)
    return handler


def _unifi(http, **cfg):
    base = {"base_url": "https://10.0.0.1", "allow_private": True,
            "protected_macs": ["aa:bb:cc:00:00:01"]}
    return REGISTRY["unifi"]({**base, **cfg}, {"api_key": SECRET}, http)


async def test_unifi_test_reads_site_only():
    calls: list = []
    async with client(_unifi_handler(calls)) as http:
        res = await _unifi(http).test()
    assert res.ok and "HQ" in res.detail
    assert [c[0] for c in calls] == ["GET"]


async def test_unifi_requires_allow_private_for_lan_controller():
    async with client(_unifi_handler([])) as http:
        res = await _unifi(http, allow_private=False).test()
    assert not res.ok and "private" in res.detail


async def test_unifi_block_quarantine_dry_run_real_and_release():
    calls: list = []
    mac = "00:1a:2b:3c:4d:5e"
    async with client(_unifi_handler(calls)) as http:
        conn = _unifi(http)
        dry = await conn.act({"type": "quarantine_device", "mac": mac.upper(), "dry_run": True})
        assert dry.ok and dry.dry_run and "block-sta" in dry.planned[0]
        assert not any(m == "POST" for m, _, _ in calls)      # dry run: reads only
        # dry_run absent -> treated as a dry run (fail safe)
        assert (await conn.act({"type": "quarantine_device", "mac": mac})).dry_run
        real = await conn.act({"type": "quarantine_device", "mac": mac, "dry_run": False})
        assert real.ok and real.revert == {"mode": "block", "mac": mac}
        assert ("POST", "/proxy/network/api/s/default/cmd/stamgr",
                {"cmd": "block-sta", "mac": mac}) in calls
        rel = await conn.act({"type": "release_device", "mac": mac, "dry_run": False,
                              "revert": real.revert})
        assert rel.ok
        assert ("POST", "/proxy/network/api/s/default/cmd/stamgr",
                {"cmd": "unblock-sta", "mac": mac}) in calls


async def test_unifi_network_mode_moves_and_restores():
    calls: list = []
    mac = "00:1a:2b:3c:4d:5e"
    async with client(_unifi_handler(calls)) as http:
        conn = _unifi(http, quarantine_mode="network", quarantine_network_id="net-q")
        real = await conn.act({"type": "quarantine_device", "mac": mac, "dry_run": False})
        assert real.ok and real.revert["user_id"] == "u123"
        assert ("PUT", "/proxy/network/api/s/default/rest/user/u123",
                {"virtual_network_override_enabled": True,
                 "virtual_network_override_id": "net-q"}) in calls
        rel = await conn.act({"type": "release_device", "mac": mac, "dry_run": False,
                              "revert": real.revert})
        assert rel.ok
        assert ("PUT", "/proxy/network/api/s/default/rest/user/u123",
                {"virtual_network_override_enabled": False,
                 "virtual_network_override_id": ""}) in calls


async def test_unifi_refuses_protected_multicast_and_unknown_types():
    calls: list = []
    async with client(_unifi_handler(calls)) as http:
        conn = _unifi(http)
        for action in (
            {"type": "quarantine_device", "mac": "AA:BB:CC:00:00:01", "dry_run": False},
            {"type": "quarantine_device", "mac": "01:00:5e:00:00:01", "dry_run": False},
            {"type": "quarantine_device", "mac": "not-a-mac", "dry_run": False},
            {"type": "wipe_device", "mac": "00:1a:2b:3c:4d:5e", "dry_run": False},
        ):
            res = await conn.act(action)
            assert not res.ok and not res.retryable, action
    assert calls == []


async def test_unifi_password_login_uses_csrf_and_logs_out():
    calls: list = []

    def handler(req: httpx.Request):
        calls.append((req.method, req.url.path, dict(req.headers)))
        if req.url.path == "/api/auth/login":
            assert json.loads(req.content)["password"] == SECRET
            return httpx.Response(200, headers={"x-csrf-token": "csrf-1",
                                                "set-cookie": "TOKEN=abc; Path=/"}, json={})
        if req.url.path == "/api/auth/logout":
            return httpx.Response(200, json={})
        assert req.headers["x-csrf-token"] == "csrf-1"
        return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": [{"name": "default"}]})

    async with client(handler) as http:
        conn = REGISTRY["unifi"]({"base_url": "https://10.0.0.1", "allow_private": True},
                                 {"username": "paddock", "password": SECRET}, http)
        assert (await conn.test()).ok
    assert [c[1] for c in calls] == ["/api/auth/login", "/proxy/network/api/self/sites",
                                     "/api/auth/logout"]


# --------------------------------------------------------------------------- #
# Meraki
# --------------------------------------------------------------------------- #

async def test_meraki_group_policy_quarantine_and_exact_restore(fake_dns):
    calls: list = []
    state = {"devicePolicy": "Allowed"}

    def handler(req: httpx.Request):
        calls.append((req.method, req.url.host, req.url.path,
                      json.loads(req.content) if req.content else None))
        assert req.headers["authorization"] == f"Bearer {SECRET}"
        if req.url.host == "api.meraki.com" and req.url.path.endswith("/policy"):
            # Dashboard sometimes redirects to a shard host.
            return httpx.Response(307, headers={"location": "https://n42.meraki.com" + req.url.path})
        if req.url.path == "/api/v1/networks/L_123":
            return httpx.Response(200, json={"id": "L_123", "name": "Branch 7"})
        if req.url.path == "/api/v1/networks/L_123/clients/00:1a:2b:3c:4d:5e/policy":
            if req.method == "PUT":
                state.clear()
                state.update(json.loads(req.content))
            return httpx.Response(200, json={"mac": "00:1a:2b:3c:4d:5e", **state})
        return httpx.Response(404)

    async with client(handler) as http:
        conn = REGISTRY["meraki"]({"network_id": "L_123", "group_policy_id": "101"},
                                  {"api_key": SECRET}, http)
        assert (await conn.test()).ok
        dry = await conn.act({"type": "quarantine_device", "mac": "00:1a:2b:3c:4d:5e",
                              "dry_run": True})
        assert dry.ok and not any(c[0] == "PUT" for c in calls)
        real = await conn.act({"type": "quarantine_device", "mac": "00:1a:2b:3c:4d:5e",
                               "dry_run": False})
        assert real.ok and real.revert == {"prior": {"devicePolicy": "Allowed"}}
        assert state == {"devicePolicy": "Group policy", "groupPolicyId": "101"}
        rel = await conn.act({"type": "release_device", "mac": "00:1a:2b:3c:4d:5e",
                              "dry_run": False, "revert": real.revert})
        assert rel.ok and state == {"devicePolicy": "Allowed"}
        # Direct release without a plan -> Normal
        await conn.act({"type": "release_device", "mac": "00:1a:2b:3c:4d:5e", "dry_run": False})
        assert state == {"devicePolicy": "Normal"}
    assert any(c[1] == "n42.meraki.com" and c[0] == "PUT" for c in calls)


async def test_meraki_error_detail_never_contains_key(fake_dns):
    def handler(req):
        return httpx.Response(403, json={"errors": [f"key {SECRET} lacks access"]})

    async with client(handler) as http:
        conn = REGISTRY["meraki"]({"network_id": "L_1", "quarantine_policy": "blocked"},
                                  {"api_key": SECRET}, http)
        res = await conn.act({"type": "quarantine_device", "mac": "00:1a:2b:3c:4d:5e",
                              "dry_run": False})
    assert not res.ok and SECRET not in res.detail and "403" in res.detail
