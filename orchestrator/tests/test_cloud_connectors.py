"""GCP + Azure SOURCE connectors and the Google SecOps SIEM connector.

No database, no network: vendor APIs are ``httpx.MockTransport`` fakes shaped
like the real responses (see ``cloud_fixtures``). Covers pagination, auth
failure, throttling/retry, token refresh, partial failure and secret hygiene.
"""
from __future__ import annotations

import json

import httpx
import pytest

from app.integrations import REGISTRY, Capability, Event, SourceBatch
from app.integrations.connectors import azure as azure_mod
from app.integrations.connectors import gcp as gcp_mod
from app.integrations.connectors import load_all
from app.integrations.connectors._common import SourceError
from app.integrations.connectors._gcp_auth import clear_token_cache, parse_key, sign_jwt
from app.integrations.connectors.azure import AzureConnector
from app.integrations.connectors.gcp import GcpConnector
from app.integrations.connectors.google_secops import GoogleSecOpsConnector, ocsf_to_udm
from tests import cloud_fixtures as fx
from tests.cloud_fixtures import SA_SECRET_MARK, client, fake_dns  # noqa: F401 (fixture)

load_all()

CID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture(autouse=True)
def _clean_tokens():
    clear_token_cache()
    azure_mod.clear_token_cache()
    yield
    clear_token_cache()
    azure_mod.clear_token_cache()


def _gcp(handler, **cfg) -> GcpConnector:
    return GcpConnector({"parents": ["projects/acme-prod"], **cfg},
                        {"service_account_json": fx.sa_json()}, client(handler))


def _azure(handler, **cfg) -> AzureConnector:
    return AzureConnector({"tenant_id": "t-1", "client_id": "app-1", **cfg},
                          {"client_secret": "az-secret-VALUE"}, client(handler))


def _find(batch: SourceBatch, rule: str, value: str | None = None):
    return [f for f in batch.findings if f["rule_id"] == rule
            and (value is None or f["asset_value"] == value)]


def _asset(batch: SourceBatch, kind: str, value: str):
    hits = [a for a in batch.assets if a["kind"] == kind and a["value"] == value]
    assert hits, f"no {kind} {value}"
    return hits[0]


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

def test_registered_with_expected_contract():
    for kind in ("gcp", "azure"):
        cls = REGISTRY[kind]
        assert cls.capabilities == frozenset({Capability.SOURCE})
        d = cls.describe()
        assert d["category"] == "cloud" and d["secret_fields"]
        assert d["config_schema"]["type"] == "object"
    assert REGISTRY["gcp"].describe()["secret_fields"] == ["service_account_json"]
    assert REGISTRY["azure"].describe()["secret_fields"] == ["client_secret"]
    sec = REGISTRY["google_secops"].describe()
    assert sec["category"] == "siem" and sec["capabilities"] == ["notify"]
    assert sec["secret_fields"] == ["service_account_json"]


# --------------------------------------------------------------------------- #
# Service-account JWT (no Google SDK)
# --------------------------------------------------------------------------- #

def test_jwt_is_rs256_signed_with_expected_claims():
    key = parse_key(fx.sa_json())
    jwt = sign_jwt(key, "https://www.googleapis.com/auth/cloud-platform",
                   "https://oauth2.googleapis.com/token", now=1_700_000_000)
    claims = fx.verify_assertion(jwt)          # raises if the signature is wrong
    assert claims["iss"] == key["client_email"] and claims["aud"] == "https://oauth2.googleapis.com/token"
    assert claims["exp"] - claims["iat"] == 3600 and claims["scope"].endswith("cloud-platform")
    assert claims["_header"] == {"alg": "RS256", "typ": "JWT", "kid": "kid-1"}


@pytest.mark.parametrize("raw,needle", [
    (None, "required"), ("not json", "not valid JSON"),
    (json.dumps({"type": "authorized_user"}), "not a service-account key"),
    (json.dumps({"type": "service_account", "client_email": "x@y"}), "private_key"),
])
def test_parse_key_rejects_bad_keys(raw, needle):
    with pytest.raises(SourceError, match=needle):
        parse_key(raw)


def test_garbage_private_key_never_echoed():
    key = {"client_email": "a@b", "private_key": f"-----BEGIN PRIVATE KEY-----{SA_SECRET_MARK}"}
    with pytest.raises(SourceError) as ei:
        sign_jwt(key, "s", "u")
    assert SA_SECRET_MARK not in str(ei.value) and ei.value.__cause__ is None


# --------------------------------------------------------------------------- #
# GCP
# --------------------------------------------------------------------------- #

async def test_gcp_pull_paginates_and_builds_the_batch(fake_dns):
    gcp = fx.Gcp(page_size=2)
    batch = await _gcp(gcp).pull()

    # pagination: 3 instances at 2 per page -> 2 requests for that type
    inst_calls = [r for r in gcp.requests if r.url.params.get("assetTypes") == gcp_mod.T_INSTANCE]
    assert len(inst_calls) == 2 and inst_calls[1].url.params["pageToken"] == "2"
    assert gcp.tokens == 1                                       # one token, reused
    # the hostile token_uri in the key file was ignored; the claim audience is Google's
    assert gcp.claims["aud"] == "https://oauth2.googleapis.com/token"
    assert all(r.url.host != "evil.example" for r in gcp.requests)
    # read-only: every Cloud Asset call is a GET
    assert {r.method for r in gcp.requests if r.url.host == "cloudasset.googleapis.com"} == {"GET"}

    web = fx.VM_WEB["name"]
    meta = _asset(batch, "cloud_resource", web)["metadata"]
    assert meta["public"] is True and meta["public_ips"] == ["34.120.10.5"]
    # db-edge: world-open 443 applies (public) but that is not an admin port
    assert _asset(batch, "cloud_resource", fx.VM_NOFW["name"])["metadata"]["public"] is True
    assert not _find(batch, "gcp.compute.admin_port_open_to_internet", fx.VM_NOFW["name"])
    assert "public" not in _asset(batch, "cloud_resource", fx.VM_PRIVATE["name"])["metadata"]
    assert any(e["src_canonical"] == "34.120.10.5" and e["dst_canonical"] == web
               and e["kind"] == "attached_to" for e in batch.edges)

    # findings
    ssh = _find(batch, "gcp.firewall.admin_port_open_to_world")
    assert [f["asset_value"] for f in ssh] == [fx.FW_SSH["name"]]            # disabled rule ignored
    assert ssh[0]["evidence"]["ports"] == [22, 8086] and ssh[0]["rule_source"] == "policy"
    assert [f["asset_value"] for f in _find(batch, "gcp.compute.admin_port_open_to_internet")] == [web]
    assert [f["severity"] for f in _find(batch, "gcp.sql.public_ip_open_to_world")] == ["high"]
    assert _find(batch, "gcp.sql.public_ip") == []
    pub = _find(batch, "gcp.storage.bucket_public")
    assert [f["asset_value"] for f in pub] == [fx.B_PUBLIC["name"]]          # enforced PAP + private are not
    assert _asset(batch, "cloud_resource", fx.B_PUBLIC["name"])["metadata"]["sensitive"] is True

    # LBs: only EXTERNAL schemes
    assert _asset(batch, "cloud_resource", fx.LB["name"])["metadata"]["public"] is True
    assert not [a for a in batch.assets if a["value"] == fx.LB_INTERNAL["name"]]

    # Cloud Run / Functions URLs, but not an internal-ingress service
    assert _asset(batch, "subdomain", "api-abc123-uc.a.run.app")
    assert _asset(batch, "subdomain", "us-central1-acme-prod.cloudfunctions.net")
    assert not [a for a in batch.assets if a["value"] == "job-abc123-uc.a.run.app"]
    # public DNS zone only
    assert _asset(batch, "domain", "acme-test.com")
    assert not [a for a in batch.assets if a["value"] == "corp.internal"]


async def test_gcp_scope_suggestions_are_suggestions_only(fake_dns):
    batch = await _gcp(fx.Gcp()).pull()
    got = {(s["kind"], s["value"]) for s in batch.scope_suggestions}
    assert ("ipv4_cidr", "34.120.10.5/32") in got and ("ipv4_cidr", "35.190.1.1/32") in got
    assert ("ipv4_cidr", "34.70.0.9/32") in got and ("domain", "acme-test.com") in got
    # private / provider-owned names are never suggested (nobody can prove control of run.app)
    assert not [s for s in got if s[1].startswith("10.") or s[1].endswith((".run.app", ".cloudfunctions.net"))]
    assert all(s["evidence"]["cloud"] == "gcp" for s in batch.scope_suggestions)
    # suggestions are data on the batch: the connector has no way to add scope
    off = await _gcp(fx.Gcp(), suggest_scope=False).pull()
    assert off.scope_suggestions == []


async def test_gcp_auth_failure_is_a_hard_error_without_secrets(fake_dns):
    gcp = fx.Gcp(token_status=401)
    conn = _gcp(gcp)
    with pytest.raises(SourceError) as ei:
        await conn.pull()
    assert "HTTP 401" in str(ei.value) and not ei.value.retryable
    assert SA_SECRET_MARK not in str(ei.value) and "BEGIN PRIVATE KEY" not in str(ei.value)
    assert not [r for r in gcp.requests if r.url.host == "cloudasset.googleapis.com"]
    res = await _gcp(fx.Gcp(token_status=401)).test()
    assert res.ok is False and "401" in res.detail and "PRIVATE KEY" not in res.detail


async def test_gcp_throttling_is_retried(fake_dns):
    gcp = fx.Gcp(throttle_once=True)
    batch = await _gcp(gcp).pull()
    assert batch.assets
    assert any(r.url.host == "cloudasset.googleapis.com" for r in gcp.requests)


async def test_gcp_revoked_token_is_refreshed_once(fake_dns):
    gcp = fx.Gcp(revoke_first_token=True)
    conn = _gcp(gcp)
    batch = await conn.pull()
    assert gcp.tokens == 2 and batch.assets and conn.last_warnings == []


async def test_gcp_partial_failure_keeps_the_rest_and_warns(fake_dns):
    gcp = fx.Gcp(fail_types={gcp_mod.T_SQL: 403, gcp_mod.T_DNS: 500})
    conn = _gcp(gcp)
    batch = await conn.pull()
    assert _asset(batch, "cloud_resource", fx.VM_WEB["name"])
    assert not [a for a in batch.assets if a["kind"] == "domain"]
    assert len(conn.last_warnings) == 2
    joined = " ".join(conn.last_warnings)
    assert "sqladmin.googleapis.com/Instance" in joined and "HTTP 403" in joined
    assert SA_SECRET_MARK not in joined


async def test_gcp_every_listing_failing_is_a_failed_sync(fake_dns):
    gcp = fx.Gcp(fail_types={t: 403 for t in gcp_mod.RESOURCE_TYPES})
    with pytest.raises(SourceError, match="403"):
        await _gcp(gcp).pull()


async def test_gcp_parents_validation_and_default_project(fake_dns):
    with pytest.raises(SourceError, match="invalid parent"):
        await _gcp(fx.Gcp(), parents=["../../etc"]).pull()
    conn = GcpConnector({}, {"service_account_json": fx.sa_json("acme-prod")}, client(fx.Gcp()))
    batch = await conn.pull()                       # falls back to the key's project_id
    assert batch.assets
    conn2 = GcpConnector({"parents": "acme-prod, organizations/123"},
                         {"service_account_json": fx.sa_json()}, client(fx.Gcp()))
    assert conn2._parents() == ["projects/acme-prod", "organizations/123"]


async def test_gcp_refuses_private_base_url(fake_dns):
    conn = _gcp(fx.Gcp(), base_url="https://169.254.169.254")
    with pytest.raises(SourceError, match="refused outbound URL"):
        await conn.pull()


async def test_gcp_test_button(fake_dns):
    res = await _gcp(fx.Gcp()).test()
    assert res.ok and "cloudasset" in res.detail


def test_gcp_firewall_helpers():
    assert gcp_mod.firewall_world_ports({"direction": "EGRESS", "sourceRanges": ["0.0.0.0/0"],
                                         "allowed": [{"IPProtocol": "all"}]}) is None
    assert gcp_mod.firewall_world_ports({"sourceRanges": ["10.0.0.0/8"],
                                         "allowed": [{"IPProtocol": "all"}]}) is None
    r = gcp_mod.firewall_world_ports({"sourceRanges": ["::/0"], "allowed": [{"IPProtocol": "all"}]})
    assert r == [("all", 0, 65535)] and gcp_mod.admin_ports_hit(r, (22, 3389)) == [22, 3389]
    icmp = gcp_mod.firewall_world_ports({"sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "icmp"}]})
    assert icmp == [] or icmp is None


# --------------------------------------------------------------------------- #
# Azure
# --------------------------------------------------------------------------- #

async def test_azure_pull_builds_the_batch(fake_dns):
    az = fx.Azure(page_size=2)
    batch = await _azure(az).pull()

    # every Resource Graph call is a read-only query, with a Bearer token and paging
    assert az.tokens == 1
    pips = [b for b in az.bodies if b["query"] == azure_mod.QUERIES["publicips"]]
    assert len(pips) == 2 and pips[1]["options"]["$skipToken"] == "2"      # 4 rows, 2 per page
    assert all(b["options"]["resultFormat"] == "objectArray" for b in az.bodies)

    vm = fx.VM_ID.lower()
    vmm = _asset(batch, "cloud_resource", vm)["metadata"]
    assert vmm["public"] is True and vmm["public_ips"] == ["20.10.0.4"]
    assert any(e["src_canonical"] == "20.10.0.4" and e["dst_canonical"] == vm for e in batch.edges)
    lb = fx.LB_ID.lower()
    assert _asset(batch, "cloud_resource", lb)["metadata"]["public"] is True
    assert any(e["src_canonical"] == "20.10.0.5" and e["dst_canonical"] == lb for e in batch.edges)
    assert "attached_to" not in _asset(batch, "ipv4", "20.10.0.6")["metadata"]   # unattached IP

    nsg = _find(batch, "azure.nsg.admin_port_open_to_internet")
    assert [f["asset_value"] for f in nsg] == [fx.NSG_ID.lower()]
    assert nsg[0]["evidence"]["ports"] == [22]                 # 3389 is corp-only, 80/443 aren't admin
    assert [f["asset_value"] for f in _find(batch, "azure.compute.admin_port_open_to_internet")] == [vm]

    st = _find(batch, "azure.storage.public_blob_access")
    assert [f["asset_value"] for f in st] == [fx.ARG["storage"][0]["id"].lower()]   # firewall-denied + safe: no
    assert _find(batch, "azure.aks.api_server_public")[0]["asset_value"].endswith("/open")
    assert len(_find(batch, "azure.aks.api_server_public")) == 1
    assert [f["asset_value"].endswith("/shop") for f in _find(batch, "azure.appservice.http_allowed")] == [True]

    assert _asset(batch, "subdomain", "shop.azurewebsites.net")
    assert _asset(batch, "subdomain", "www.acme-test.com")
    assert not [a for a in batch.assets if a["value"] == "internal.azurewebsites.net"]
    assert _asset(batch, "domain", "acme-test.com")
    assert _asset(batch, "subdomain", "open-dns-1.hcp.eastus.azmk8s.io")


async def test_azure_scope_suggestions(fake_dns):
    batch = await _azure(fx.Azure()).pull()
    got = {(s["kind"], s["value"]) for s in batch.scope_suggestions}
    assert {("ipv4_cidr", "20.10.0.4/32"), ("ipv4_cidr", "20.10.0.5/32"), ("ipv4_cidr", "20.10.0.6/32"),
            ("domain", "acme-test.com"), ("domain", "www.acme-test.com")} <= got
    assert not [v for _, v in got if v.endswith((".azurewebsites.net", ".azmk8s.io", ".cloudapp.azure.com"))]
    assert (await _azure(fx.Azure(), suggest_scope=False).pull()).scope_suggestions == []


async def test_azure_auth_failure(fake_dns):
    az = fx.Azure(token_status=401)
    with pytest.raises(SourceError) as ei:
        await _azure(az).pull()
    assert "HTTP 401" in str(ei.value) and not ei.value.retryable
    assert "az-secret-VALUE" not in str(ei.value) and SA_SECRET_MARK not in str(ei.value)
    res = await _azure(fx.Azure(token_status=401)).test()
    assert not res.ok and "401" in res.detail


async def test_azure_throttling_is_retried_with_retry_after(fake_dns):
    az = fx.Azure(throttle=2)
    conn = _azure(az)
    batch = await conn.pull()
    assert conn.last_warnings == [] and _asset(batch, "domain", "acme-test.com")
    assert sum(1 for r in az.requests if r.url.host == "management.azure.com") > 2


async def test_azure_persistent_throttling_degrades_not_dies(fake_dns):
    class Flaky(fx.Azure):
        def __call__(self, req):
            if req.url.host == "management.azure.com":
                body = json.loads(req.content)
                if body["query"] == azure_mod.QUERIES["storage"]:
                    self.requests.append(req)
                    return httpx.Response(429, headers={"retry-after": "0"}, json={})
            return super().__call__(req)

    conn = _azure(Flaky())
    batch = await conn.pull()
    assert any("storage" in w and "429" in w for w in conn.last_warnings)
    assert _asset(batch, "domain", "acme-test.com") and not _find(batch, "azure.storage.public_blob_access")


async def test_azure_partial_failure_and_total_failure(fake_dns):
    conn = _azure(fx.Azure(fail={"nsgs": 403, "aks": 500}))
    batch = await conn.pull()
    assert len(conn.last_warnings) == 2 and "nsgs: " in " ".join(conn.last_warnings)
    assert SA_SECRET_MARK not in " ".join(conn.last_warnings)
    assert _asset(batch, "domain", "acme-test.com")
    assert not _find(batch, "azure.nsg.admin_port_open_to_internet")
    with pytest.raises(SourceError, match="403"):
        await _azure(fx.Azure(fail={n: 403 for n in azure_mod.QUERIES})).pull()


async def test_azure_subscription_filter_and_test_button(fake_dns):
    az = fx.Azure()
    await _azure(az, subscriptions=["0000-1111"]).pull()
    assert all(b["subscriptions"] == ["0000-1111"] for b in az.bodies)
    assert (await _azure(fx.Azure()).test()).ok


def test_azure_nsg_helpers():
    world = azure_mod.nsg_world_rules([
        {"name": "a", "properties": {"direction": "Inbound", "access": "Allow", "protocol": "*",
                                     "sourceAddressPrefixes": ["10.0.0.0/8", "0.0.0.0/0"],
                                     "destinationPortRange": "3000-3400"}},
        {"name": "deny", "properties": {"direction": "Inbound", "access": "Deny",
                                        "sourceAddressPrefix": "*", "destinationPortRange": "22"}}])
    assert [w["name"] for w in world] == ["a"]
    assert azure_mod.admin_ports_hit(world, (22, 3306, 3389, 5432)) == [3306, 3389]


# --------------------------------------------------------------------------- #
# Google SecOps
# --------------------------------------------------------------------------- #

def _events(n: int) -> list[Event]:
    return [Event(type="finding.opened", title=f"Exposed admin panel {i}", severity="high",
                  summary="s", url="https://paddock.example/f",
                  data={"finding": {"id": f"f-{i}", "rule_id": "exposed-git", "rule_source": "exposed_file",
                                    "severity": "high", "title": f"Exposed admin panel {i}",
                                    "description": "d", "status": "open",
                                    "asset_value": "a.example.com", "asset_kind": "subdomain"}})
            for i in range(n)]


class SecOps:
    def __init__(self, *, ingest_status: int = 200, token_status: int = 200,
                 revoke_first: bool = False, fail_after: int | None = None) -> None:
        self.ingest_status, self.token_status = ingest_status, token_status
        self.revoke_first, self.fail_after = revoke_first, fail_after
        self.requests: list[httpx.Request] = []
        self.tokens = 0
        self.ingested = 0

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if req.url.host == "oauth2.googleapis.com":
            fx.verify_assertion(fx.form(req)["assertion"])
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": SA_SECRET_MARK})
            self.tokens += 1
            return httpx.Response(200, json={"access_token": f"sec-{self.tokens}", "expires_in": 3600})
        if self.revoke_first and req.headers["authorization"] == "Bearer sec-1":
            return httpx.Response(401, json={})
        if self.fail_after is not None and len(self.bodies()) > self.fail_after:
            return httpx.Response(503, json={"error": "later"})
        if self.ingest_status != 200:
            return httpx.Response(self.ingest_status, json={"error": {"message": f"bad {SA_SECRET_MARK}"}})
        return httpx.Response(200, json={})

    def bodies(self) -> list[dict]:
        return [json.loads(r.content) for r in self.requests if r.url.host != "oauth2.googleapis.com"
                and r.headers.get("authorization")]


def _secops(handler, **cfg) -> GoogleSecOpsConnector:
    return GoogleSecOpsConnector({"customer_id": CID, **cfg},
                                 {"service_account_json": fx.sa_json()}, client(handler))


async def test_secops_sends_udm_events_with_service_account_auth(fake_dns):
    s = SecOps()
    res = await _secops(s).deliver_batch(_events(3))
    assert res.ok, res.detail
    ingest = [r for r in s.requests if r.url.host != "oauth2.googleapis.com"]
    assert len(ingest) == 1 and ingest[0].url == "https://malachiteingestion-pa.googleapis.com/v2/udmevents:batchCreate"
    assert ingest[0].headers["authorization"] == "Bearer sec-1"
    body = json.loads(ingest[0].content)
    assert body["customer_id"] == CID and len(body["events"]) == 3
    ev = body["events"][0]
    assert ev["metadata"]["event_type"] == "GENERIC_EVENT" and ev["metadata"]["vendor_name"] == "Paddock"
    assert ev["security_result"][0]["severity"] == "HIGH"
    assert ev["target"]["hostname"] == "a.example.com"
    assert ev["additional"]["ocsf"]["class_uid"] in (2004, 2002)          # the _siem OCSF mapping is reused
    assert ev["metadata"]["product_log_id"] == ev["additional"]["paddock_event_id"]


async def test_secops_regions_batching_and_oversize_split(fake_dns):
    s = SecOps()
    c = _secops(s, region="europe-west2")
    assert c.endpoint() == "https://europe-west2-malachiteingestion-pa.googleapis.com/v2/udmevents:batchCreate"
    res = await c.deliver_batch(_events(450))          # 200 per request cap
    assert res.ok and len([b for b in s.bodies()]) == 3
    # a body is never over 1 MB: big events force an extra split
    big = _events(30)
    for e in big:
        e.data["finding"]["description"] = "x" * 60_000
    s2 = SecOps()
    ok = await _secops(s2).deliver_batch(big)
    assert ok.ok and len(s2.bodies()) >= 2
    assert all(len(r.content) <= 1_000_000 for r in s2.requests if r.url.host != "oauth2.googleapis.com")


async def test_secops_ocsf_log_mode(fake_dns):
    s = SecOps()
    res = await _secops(s, format="ocsf", log_type="PADDOCK_OCSF").deliver_batch(_events(2))
    assert res.ok
    req = [r for r in s.requests if r.url.host != "oauth2.googleapis.com"][0]
    assert req.url.path == "/v2/unstructuredlogs:batchCreate"
    body = json.loads(req.content)
    assert body["log_type"] == "PADDOCK_OCSF" and len(body["entries"]) == 2
    assert json.loads(body["entries"][0]["log_text"])["metadata"]["product"]["name"] == "Paddock"
    assert isinstance(body["entries"][0]["ts_epoch_microseconds"], int)


async def test_secops_error_classification_and_secret_hygiene(fake_dns):
    for status, retry in ((400, False), (403, False), (404, False), (429, True), (500, True)):
        res = await _secops(SecOps(ingest_status=status)).deliver_batch(_events(1))
        assert not res.ok and res.retryable is retry and res.status_code == status, status
    clear_token_cache()
    bad = await _secops(SecOps(token_status=401)).deliver_batch(_events(1))
    assert not bad.ok and not bad.retryable and "401" in bad.detail
    assert SA_SECRET_MARK not in bad.detail and "PRIVATE KEY" not in bad.detail
    clear_token_cache()
    throttled_tok = await _secops(SecOps(token_status=429)).deliver_batch(_events(1))
    assert not throttled_tok.ok and throttled_tok.retryable


async def test_secops_validates_config_and_destination(fake_dns):
    bad = await _secops(SecOps(), customer_id="nope").deliver_batch(_events(1))
    assert not bad.ok and not bad.retryable and "customer_id" in bad.detail
    unsafe = await _secops(SecOps(), ingestion_url="https://169.254.169.254").deliver_batch(_events(1))
    assert not unsafe.ok and not unsafe.retryable and "refused" in unsafe.detail
    no_key = GoogleSecOpsConnector({"customer_id": CID}, {}, client(SecOps()))
    res = await no_key.deliver_batch(_events(1))
    assert not res.ok and not res.retryable and "service_account_json" in res.detail


async def test_secops_refreshes_a_revoked_token_once(fake_dns):
    s = SecOps(revoke_first=True)
    res = await _secops(s).deliver_batch(_events(1))
    assert res.ok and s.tokens == 2


async def test_secops_partial_delivery_reports_what_was_accepted(fake_dns):
    s = SecOps(fail_after=1)
    res = await _secops(s).deliver_batch(_events(450))
    assert not res.ok and res.retryable and "after 200 event(s) were accepted" in res.detail


async def test_secops_test_button_sends_a_real_event(fake_dns):
    s = SecOps()
    res = await _secops(s).test()
    assert res.ok and len(s.bodies()) == 1
    assert (await _secops(SecOps(ingest_status=403)).test()).ok is False


def test_udm_mapping_handles_ip_and_url_targets():
    from app.integrations import ocsf

    ev = _events(1)[0]
    rec = ocsf.event_to_ocsf(ev)
    rec["resources"] = [{"name": "203.0.113.7", "type": "ipv4", "uid": "x"}]
    assert ocsf_to_udm(rec, ev)["target"]["ip"] == ["203.0.113.7"]
    rec["resources"] = [{"name": "https://a.example/x", "type": "endpoint"}]
    assert ocsf_to_udm(rec, ev)["target"]["url"] == "https://a.example/x"
    rec.pop("resources")
    assert "target" not in ocsf_to_udm(rec, ev)
