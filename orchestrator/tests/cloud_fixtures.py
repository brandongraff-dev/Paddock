"""Recorded-shape fixtures + mock transports for the GCP / Azure / SecOps tests.

The payloads mirror the real REST shapes (Cloud Asset ``listAssets``, Azure
Resource Graph ``objectArray``, Google OAuth token) trimmed to the fields the
connectors read. Nothing here touches the network.
"""
from __future__ import annotations

import base64
import json
import types
from typing import Any, Callable
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.integrations import netsafety

SA_SECRET_MARK = "TOP-SECRET-KEY-MATERIAL"


@pytest.fixture
def fake_dns(monkeypatch):
    """Every name resolves to a public address, so the REAL netsafety policy runs."""
    def getaddrinfo(host, port, *a, **k):
        return [(2, 1, 6, "", ("93.184.216.34", port))]
    monkeypatch.setattr(netsafety, "socket", types.SimpleNamespace(getaddrinfo=getaddrinfo))


_KEY: dict[str, Any] = {}


def rsa_key():
    if "k" not in _KEY:
        _KEY["k"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _KEY["k"]


def sa_json(project: str = "acme-prod") -> str:
    pem = rsa_key().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    return json.dumps({
        "type": "service_account", "project_id": project, "private_key_id": "kid-1",
        "private_key": pem, "client_email": f"paddock@{project}.iam.gserviceaccount.com",
        # A hostile key file naming its own token endpoint must be ignored.
        "token_uri": "https://evil.example/token",
    })


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_assertion(assertion: str) -> dict[str, Any]:
    """Check the RS256 signature with the public key; return the claims."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    h, c, s = assertion.split(".")
    rsa_key().public_key().verify(b64d(s), f"{h}.{c}".encode(), padding.PKCS1v15(), hashes.SHA256())
    out = json.loads(b64d(c))
    out["_header"] = json.loads(b64d(h))
    return out


def form(req: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(req.content.decode()).items()}


def client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# --------------------------------------------------------------------------- #
# GCP: Cloud Asset listAssets fixtures
# --------------------------------------------------------------------------- #

P = "projects/acme-prod"
NET = "https://www.googleapis.com/compute/v1/projects/acme-prod/global/networks/default"


def a(atype: str, name: str, data: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"name": name, "assetType": atype}
    if data is not None:
        item["resource"] = {"data": data}
    item.update(extra)
    return item


VM_WEB = a("compute.googleapis.com/Instance",
           "//compute.googleapis.com/projects/acme-prod/zones/us-central1-a/instances/web-1",
           {"name": "web-1", "status": "RUNNING", "zone": ".../zones/us-central1-a",
            "tags": {"items": ["web"]}, "labels": {"env": "prod"},
            "networkInterfaces": [{"network": NET, "networkIP": "10.128.0.2",
                                   "accessConfigs": [{"natIP": "34.120.10.5"}]}]})
VM_PRIVATE = a("compute.googleapis.com/Instance",
               "//compute.googleapis.com/projects/acme-prod/zones/us-central1-a/instances/batch-1",
               {"name": "batch-1", "networkInterfaces": [{"network": NET, "networkIP": "10.128.0.9"}]})
VM_NOFW = a("compute.googleapis.com/Instance",
            "//compute.googleapis.com/projects/acme-prod/zones/us-central1-a/instances/db-edge",
            {"name": "db-edge", "tags": {"items": ["db"]},
             "networkInterfaces": [{"network": NET, "networkIP": "10.128.0.3",
                                    "accessConfigs": [{"natIP": "34.120.10.6"}]}]})
FW_SSH = a("compute.googleapis.com/Firewall",
           "//compute.googleapis.com/projects/acme-prod/global/firewalls/allow-ssh-world",
           {"name": "allow-ssh-world", "direction": "INGRESS", "network": NET,
            "sourceRanges": ["0.0.0.0/0"], "targetTags": ["web"],
            "allowed": [{"IPProtocol": "tcp", "ports": ["22", "8000-8100"]}]})
FW_DISABLED = a("compute.googleapis.com/Firewall",
                "//compute.googleapis.com/projects/acme-prod/global/firewalls/old",
                {"name": "old", "direction": "INGRESS", "network": NET, "disabled": True,
                 "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "all"}]})
FW_HTTP = a("compute.googleapis.com/Firewall",
            "//compute.googleapis.com/projects/acme-prod/global/firewalls/http",
            {"name": "http", "direction": "INGRESS", "network": NET, "sourceRanges": ["0.0.0.0/0"],
             "targetTags": ["db"], "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]})
LB = a("compute.googleapis.com/ForwardingRule",
       "//compute.googleapis.com/projects/acme-prod/global/forwardingRules/fe",
       {"name": "fe", "IPAddress": "35.190.1.1", "loadBalancingScheme": "EXTERNAL_MANAGED",
        "portRange": "443-443", "IPProtocol": "TCP"})
LB_INTERNAL = a("compute.googleapis.com/ForwardingRule",
                "//compute.googleapis.com/projects/acme-prod/regions/us/forwardingRules/ilb",
                {"name": "ilb", "IPAddress": "10.0.0.50", "loadBalancingScheme": "INTERNAL"})
SQL = a("sqladmin.googleapis.com/Instance", "//cloudsql.googleapis.com/projects/acme-prod/instances/orders",
        {"name": "orders", "databaseVersion": "POSTGRES_15",
         "ipAddresses": [{"type": "PRIMARY", "ipAddress": "34.70.0.9"},
                         {"type": "OUTGOING", "ipAddress": "34.70.0.10"}],
         "settings": {"ipConfiguration": {"ipv4Enabled": True,
                                          "authorizedNetworks": [{"value": "0.0.0.0/0"}]}}})
SQL_PRIVATE = a("sqladmin.googleapis.com/Instance", "//cloudsql.googleapis.com/projects/acme-prod/instances/priv",
                {"name": "priv", "ipAddresses": [{"type": "PRIVATE", "ipAddress": "10.9.0.3"}],
                 "settings": {"ipConfiguration": {"ipv4Enabled": False}}})
B_PUBLIC = a("storage.googleapis.com/Bucket", "//storage.googleapis.com/acme-assets",
             {"name": "acme-assets", "location": "US"})
B_ENFORCED = a("storage.googleapis.com/Bucket", "//storage.googleapis.com/acme-locked",
               {"name": "acme-locked", "iamConfiguration": {"publicAccessPrevention": "enforced"}})
B_PRIVATE = a("storage.googleapis.com/Bucket", "//storage.googleapis.com/acme-private",
              {"name": "acme-private"})
IAM_PUBLIC = a("storage.googleapis.com/Bucket", "//storage.googleapis.com/acme-assets",
               iamPolicy={"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]})
IAM_ENFORCED = a("storage.googleapis.com/Bucket", "//storage.googleapis.com/acme-locked",
                 iamPolicy={"bindings": [{"role": "roles/storage.objectViewer",
                                          "members": ["allAuthenticatedUsers"]}]})
IAM_PRIVATE = a("storage.googleapis.com/Bucket", "//storage.googleapis.com/acme-private",
                iamPolicy={"bindings": [{"role": "roles/storage.admin",
                                         "members": ["user:ops@acme.com"]}]})
RUN = a("run.googleapis.com/Service", "//run.googleapis.com/projects/acme-prod/locations/us/services/api",
        {"metadata": {"name": "api", "annotations": {"run.googleapis.com/ingress": "all"}},
         "status": {"url": "https://api-abc123-uc.a.run.app"}})
RUN_INTERNAL = a("run.googleapis.com/Service", "//run.googleapis.com/projects/acme-prod/locations/us/services/job",
                 {"metadata": {"name": "job", "annotations": {"run.googleapis.com/ingress": "internal"}},
                  "status": {"url": "https://job-abc123-uc.a.run.app"}})
FUNC = a("cloudfunctions.googleapis.com/CloudFunction",
         "//cloudfunctions.googleapis.com/projects/acme-prod/locations/us/functions/hook",
         {"name": "projects/acme-prod/locations/us/functions/hook", "ingressSettings": "ALLOW_ALL",
          "httpsTrigger": {"url": "https://us-central1-acme-prod.cloudfunctions.net/hook"}})
ZONE = a("dns.googleapis.com/ManagedZone", "//dns.googleapis.com/projects/acme-prod/managedZones/pub",
         {"name": "pub", "dnsName": "acme-test.com.", "visibility": "public",
          "nameServers": ["ns-cloud-a1.googledomains.com."]})
ZONE_PRIVATE = a("dns.googleapis.com/ManagedZone", "//dns.googleapis.com/projects/acme-prod/managedZones/priv",
                 {"name": "priv", "dnsName": "corp.internal.", "visibility": "private"})

RESOURCES: dict[str, list[dict[str, Any]]] = {
    "compute.googleapis.com/Instance": [VM_WEB, VM_PRIVATE, VM_NOFW],
    "compute.googleapis.com/Firewall": [FW_SSH, FW_DISABLED, FW_HTTP],
    "compute.googleapis.com/ForwardingRule": [LB, LB_INTERNAL],
    "sqladmin.googleapis.com/Instance": [SQL, SQL_PRIVATE],
    "storage.googleapis.com/Bucket": [B_PUBLIC, B_ENFORCED, B_PRIVATE],
    "run.googleapis.com/Service": [RUN, RUN_INTERNAL],
    "cloudfunctions.googleapis.com/CloudFunction": [FUNC],
    "dns.googleapis.com/ManagedZone": [ZONE, ZONE_PRIVATE],
}
IAM = [IAM_PUBLIC, IAM_ENFORCED, IAM_PRIVATE]


class Gcp:
    """A stateful fake of oauth2.googleapis.com + cloudasset.googleapis.com."""

    def __init__(self, *, page_size: int = 2, fail_types: dict[str, int] | None = None,
                 token_status: int = 200, throttle_once: bool = False,
                 revoke_first_token: bool = False) -> None:
        self.page_size = page_size
        self.fail_types = fail_types or {}
        self.token_status = token_status
        self.throttle_once = throttle_once
        self.revoke_first_token = revoke_first_token
        self.requests: list[httpx.Request] = []
        self.tokens = 0
        self._throttled = False

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if req.url.host == "oauth2.googleapis.com":
            assert req.method == "POST"
            f = form(req)
            assert f["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
            self.claims = verify_assertion(f["assertion"])
            if self.token_status != 200:
                return httpx.Response(self.token_status,
                                      json={"error": "invalid_grant", "detail": SA_SECRET_MARK})
            self.tokens += 1
            return httpx.Response(200, json={"access_token": f"tok-{self.tokens}", "expires_in": 3600})
        assert req.url.host == "cloudasset.googleapis.com", req.url
        if self.revoke_first_token and req.headers["authorization"] == "Bearer tok-1":
            return httpx.Response(401, json={"error": {"message": SA_SECRET_MARK}})
        if self.throttle_once and not self._throttled:
            self._throttled = True
            return httpx.Response(429, headers={"retry-after": "0"}, json={})
        q = req.url.params
        atype, content = q["assetTypes"], q["contentType"]
        if atype in self.fail_types:
            return httpx.Response(self.fail_types[atype], json={"error": SA_SECRET_MARK})
        items = IAM if content == "IAM_POLICY" else RESOURCES.get(atype, [])
        if content == "IAM_POLICY" and atype != "storage.googleapis.com/Bucket":
            items = []
        start = int(q.get("pageToken") or 0)
        size = int(q["pageSize"]) if int(q["pageSize"]) < self.page_size else self.page_size
        chunk = items[start:start + size]
        body: dict[str, Any] = {"assets": chunk}
        if start + size < len(items):
            body["nextPageToken"] = str(start + size)
        return httpx.Response(200, json=body)


# --------------------------------------------------------------------------- #
# Azure: Resource Graph fixtures
# --------------------------------------------------------------------------- #

SUB = "/subscriptions/0000-1111"
RG = f"{SUB}/resourceGroups/rg-prod/providers"
VM_ID = f"{RG}/Microsoft.Compute/virtualMachines/web-vm"
NIC_ID = f"{RG}/Microsoft.Network/networkInterfaces/web-nic"
NSG_ID = f"{RG}/Microsoft.Network/networkSecurityGroups/web-nsg"
NSG_SAFE_ID = f"{RG}/Microsoft.Network/networkSecurityGroups/safe-nsg"
PIP_VM = f"{RG}/Microsoft.Network/publicIPAddresses/web-pip"
PIP_LB = f"{RG}/Microsoft.Network/publicIPAddresses/lb-pip"
PIP_FREE = f"{RG}/Microsoft.Network/publicIPAddresses/spare-pip"
LB_ID = f"{RG}/Microsoft.Network/loadBalancers/edge-lb"
SUBNET = f"{RG}/Microsoft.Network/virtualNetworks/vnet/subnets/app"

ARG: dict[str, list[dict[str, Any]]] = {
    "publicips": [
        {"id": PIP_VM, "name": "web-pip", "subscriptionId": "0000-1111", "resourceGroup": "rg-prod",
         "location": "eastus", "ip": "20.10.0.4", "fqdn": "web.eastus.cloudapp.azure.com",
         "assoc": f"{NIC_ID}/ipConfigurations/ipconfig1", "sku": "Standard"},
        {"id": PIP_LB, "name": "lb-pip", "subscriptionId": "0000-1111", "resourceGroup": "rg-prod",
         "ip": "20.10.0.5", "fqdn": "",
         "assoc": f"{LB_ID}/frontendIPConfigurations/fe", "sku": "Standard"},
        {"id": PIP_FREE, "name": "spare-pip", "subscriptionId": "0000-1111", "resourceGroup": "rg-prod",
         "ip": "20.10.0.6", "fqdn": "", "assoc": "", "sku": "Basic"},
        {"id": f"{RG}/Microsoft.Network/publicIPAddresses/unallocated", "name": "unallocated",
         "ip": "", "assoc": ""},
    ],
    "nics": [{"id": NIC_ID, "vm": VM_ID, "nsg": NSG_ID,
              "ipconfigs": [{"name": "ipconfig1", "properties": {
                  "subnet": {"id": SUBNET}, "publicIPAddress": {"id": PIP_VM}}}]}],
    "vms": [{"id": VM_ID, "name": "web-vm", "subscriptionId": "0000-1111", "resourceGroup": "rg-prod",
             "location": "eastus", "size": "Standard_D2s_v5", "os": "Linux", "tags": {"env": "prod"}}],
    "vnets": [{"subnetId": SUBNET, "nsg": NSG_SAFE_ID}],
    "appservices": [
        {"id": f"{RG}/Microsoft.Web/sites/shop", "name": "shop", "subscriptionId": "0000-1111",
         "resourceGroup": "rg-prod", "kind": "app,linux", "host": "shop.azurewebsites.net",
         "hostnames": ["shop.azurewebsites.net", "www.acme-test.com"], "state": "Running",
         "httpsOnly": False, "publicNetworkAccess": "Enabled"},
        {"id": f"{RG}/Microsoft.Web/sites/internal", "name": "internal", "host": "internal.azurewebsites.net",
         "hostnames": ["internal.azurewebsites.net"], "httpsOnly": True, "publicNetworkAccess": "Disabled"},
    ],
    "storage": [
        {"id": f"{RG}/Microsoft.Storage/storageAccounts/acmepublic", "name": "acmepublic",
         "allowBlobPublicAccess": True, "publicNetworkAccess": "Enabled", "defaultAction": "Allow",
         "blobEndpoint": "https://acmepublic.blob.core.windows.net/"},
        {"id": f"{RG}/Microsoft.Storage/storageAccounts/acmefw", "name": "acmefw",
         "allowBlobPublicAccess": True, "publicNetworkAccess": "Enabled", "defaultAction": "Deny"},
        {"id": f"{RG}/Microsoft.Storage/storageAccounts/acmesafe", "name": "acmesafe",
         "allowBlobPublicAccess": False, "publicNetworkAccess": "Enabled", "defaultAction": "Allow"},
    ],
    "nsgs": [
        {"id": NSG_ID, "name": "web-nsg", "subscriptionId": "0000-1111", "resourceGroup": "rg-prod",
         "rules": [
             {"name": "ssh", "properties": {"direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                                            "sourceAddressPrefix": "Internet", "destinationPortRange": "22",
                                            "priority": 100}},
             {"name": "web", "properties": {"direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                                            "sourceAddressPrefix": "*",
                                            "destinationPortRanges": ["80", "443"], "priority": 110}},
             {"name": "corp", "properties": {"direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                                             "sourceAddressPrefix": "10.0.0.0/8",
                                             "destinationPortRange": "3389", "priority": 120}},
             {"name": "out", "properties": {"direction": "Outbound", "access": "Allow", "protocol": "*",
                                            "sourceAddressPrefix": "*", "destinationPortRange": "*"}}]},
        {"id": NSG_SAFE_ID, "name": "safe-nsg", "rules": [
            {"name": "corp", "properties": {"direction": "Inbound", "access": "Allow", "protocol": "*",
                                            "sourceAddressPrefix": "10.0.0.0/8", "destinationPortRange": "*"}}]},
    ],
    "dns": [{"id": f"{RG}/Microsoft.Network/dnszones/acme-test.com", "name": "acme-test.com",
             "zoneType": "Public", "nameServers": ["ns1-01.azure-dns.com."]}],
    "aks": [
        {"id": f"{RG}/Microsoft.ContainerService/managedClusters/open", "name": "open",
         "fqdn": "open-dns-1.hcp.eastus.azmk8s.io", "privateCluster": False, "authorizedRanges": None,
         "k8s": "1.29.4"},
        {"id": f"{RG}/Microsoft.ContainerService/managedClusters/locked", "name": "locked",
         "fqdn": "locked-dns-1.hcp.eastus.azmk8s.io", "privateCluster": False,
         "authorizedRanges": ["203.0.113.0/24"]},
        {"id": f"{RG}/Microsoft.ContainerService/managedClusters/priv", "name": "priv",
         "fqdn": "priv.privatelink.eastus.azmk8s.io", "privateCluster": True},
    ],
}


class Azure:
    """Fake of login.microsoftonline.com + management.azure.com (Resource Graph)."""

    def __init__(self, *, page_size: int = 2, fail: dict[str, int] | None = None,
                 token_status: int = 200, throttle: int = 0) -> None:
        self.page_size = page_size
        self.fail = fail or {}
        self.token_status = token_status
        self.throttle = throttle
        self.requests: list[httpx.Request] = []
        self.bodies: list[dict[str, Any]] = []
        self.tokens = 0

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if req.url.host == "login.microsoftonline.com":
            f = form(req)
            assert f["grant_type"] == "client_credentials" and f["scope"] == "https://management.azure.com/.default"
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "invalid_client",
                                                               "error_description": SA_SECRET_MARK})
            self.tokens += 1
            return httpx.Response(200, json={"access_token": f"arm-{self.tokens}", "expires_in": 3599})
        assert req.url.host == "management.azure.com" and req.url.path.endswith("/resources")
        assert req.headers["authorization"].startswith("Bearer arm-")
        body = json.loads(req.content)
        self.bodies.append(body)
        if self.throttle > 0:
            self.throttle -= 1
            return httpx.Response(429, headers={"retry-after": "0"}, json={"error": {"code": "RateLimiting"}})
        name = next((k for k, q in __import__("app.integrations.connectors.azure", fromlist=["QUERIES"]).QUERIES.items()
                     if q == body["query"]), None)
        if name is None:           # connector.test() probe
            return httpx.Response(200, json={"data": [], "count": 0, "totalRecords": 0})
        if name in self.fail:
            return httpx.Response(self.fail[name], json={"error": {"message": SA_SECRET_MARK}})
        rows = ARG[name]
        start = int(body["options"].get("$skipToken") or 0)
        chunk = rows[start:start + self.page_size]
        out: dict[str, Any] = {"data": chunk, "count": len(chunk), "totalRecords": len(rows)}
        if start + self.page_size < len(rows):
            out["$skipToken"] = str(start + self.page_size)
        return httpx.Response(200, json=out)
