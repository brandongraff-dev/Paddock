"""Microsoft Azure (SOURCE, read-only): internet-facing inventory via Resource Graph.

Auth is an Entra app registration (client credentials, scope
``https://management.azure.com/.default``). The app needs only the built-in
**Reader** role on the subscriptions (or a management group) it should see.
Everything is a read-only KQL query posted to Azure Resource Graph
(``POST /providers/Microsoft.ResourceGraph/resources``, paged with
``$skipToken``); each query is isolated, so one failing query is a *warning*
and the rest of the sync still lands:

* ``publicips``   -- public IP addresses + what they are attached to
* ``nics``/``vms``/``vnets`` -- which VM owns which IP, which NSG guards it
* ``appservices`` -- web/function apps and their default hostnames
* ``storage``     -- accounts that allow public blob access
* ``nsgs``        -- inbound Allow rules open to the internet
* ``dns``         -- public DNS zones
* ``aks``         -- managed clusters with a public API server

Graph: ``ipv4 --attached_to--> VM | load balancer | app gateway``,
``subdomain --routes_to--> app service``. A VM is ``public`` only when it has a
public IP AND an NSG (on its NIC or subnet) has an inbound Allow rule open to
the internet. Storage accounts are ``sensitive``.

**Scope suggestions, never scope.** Public IPs and public DNS zones become
PENDING ``scope_suggestions`` (schema 031); accepting one goes through the
normal scope add and its proof-of-control. Provider-owned names
(``*.azurewebsites.net``, ``*.blob.core.windows.net``, ``*.azmk8s.io``,
``*.cloudapp.azure.com``) become assets but are never suggested.

Findings (rule_source ``policy``): ``azure.nsg.admin_port_open_to_internet``,
``azure.compute.admin_port_open_to_internet``, ``azure.storage.public_blob_access``,
``azure.aks.api_server_public``, ``azure.appservice.http_allowed``.

NSG evaluation is a conservative over-approximation: a higher-priority Deny
rule that shadows an Allow is not evaluated.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any, Optional
from urllib.parse import quote

from ..base import Capability, Connector, HealthResult, SourceBatch, register
from ._common import (
    SourceError,
    asset,
    bool_cfg,
    checked_url,
    clean_hostname,
    edge,
    finding,
    hostname_suggestion,
    public_ip_suggestion,
    request_json,
)

SOURCE = "integration:azure"
ARM_SCOPE = "https://management.azure.com/.default"
ARG_API = "2022-10-01"
PAGE_SIZE = 1000
_MAX_PAGES = 100
_REFRESH_MARGIN_S = 300

DEFAULT_ADMIN_PORTS: tuple[int, ...] = (
    22, 23, 135, 139, 445, 1433, 1521, 2049, 2375, 2376, 2379, 3306, 3389,
    5432, 5601, 5900, 5984, 6379, 7001, 8086, 9042, 9200, 9300, 11211, 27017,
)
_WORLD_SRC = {"*", "0.0.0.0/0", "::/0", "internet", "any"}
PROVIDER_SUFFIXES = (".azurewebsites.net", ".blob.core.windows.net", ".azmk8s.io",
                     ".cloudapp.azure.com", ".cloudapp.net", ".azure-api.net",
                     ".trafficmanager.net", ".azurefd.net")

QUERIES: dict[str, str] = {
    "publicips": (
        "resources | where type =~ 'microsoft.network/publicipaddresses' "
        "| project id, name, subscriptionId, resourceGroup, location, "
        "ip = tostring(properties.ipAddress), fqdn = tostring(properties.dnsSettings.fqdn), "
        "assoc = tostring(properties.ipConfiguration.id), sku = tostring(sku.name)"),
    "nics": (
        "resources | where type =~ 'microsoft.network/networkinterfaces' "
        "| project id, vm = tostring(properties.virtualMachine.id), "
        "nsg = tostring(properties.networkSecurityGroup.id), "
        "ipconfigs = properties.ipConfigurations"),
    "vms": (
        "resources | where type =~ 'microsoft.compute/virtualmachines' "
        "| project id, name, subscriptionId, resourceGroup, location, tags, "
        "size = tostring(properties.hardwareProfile.vmSize), "
        "os = tostring(properties.storageProfile.osDisk.osType)"),
    "vnets": (
        "resources | where type =~ 'microsoft.network/virtualnetworks' "
        "| mv-expand subnet = properties.subnets "
        "| project subnetId = tostring(subnet.id), "
        "nsg = tostring(subnet.properties.networkSecurityGroup.id)"),
    "appservices": (
        "resources | where type =~ 'microsoft.web/sites' "
        "| project id, name, subscriptionId, resourceGroup, location, kind, "
        "host = tostring(properties.defaultHostName), hostnames = properties.hostNames, "
        "state = tostring(properties.state), httpsOnly = tobool(properties.httpsOnly), "
        "publicNetworkAccess = tostring(properties.publicNetworkAccess)"),
    "storage": (
        "resources | where type =~ 'microsoft.storage/storageaccounts' "
        "| project id, name, subscriptionId, resourceGroup, location, "
        "allowBlobPublicAccess = tobool(properties.allowBlobPublicAccess), "
        "publicNetworkAccess = tostring(properties.publicNetworkAccess), "
        "defaultAction = tostring(properties.networkAcls.defaultAction), "
        "blobEndpoint = tostring(properties.primaryEndpoints.blob)"),
    "nsgs": (
        "resources | where type =~ 'microsoft.network/networksecuritygroups' "
        "| project id, name, subscriptionId, resourceGroup, location, "
        "rules = properties.securityRules"),
    "dns": (
        "resources | where type =~ 'microsoft.network/dnszones' "
        "| project id, name, subscriptionId, resourceGroup, "
        "zoneType = tostring(properties.zoneType), nameServers = properties.nameServers"),
    "aks": (
        "resources | where type =~ 'microsoft.containerservice/managedclusters' "
        "| project id, name, subscriptionId, resourceGroup, location, "
        "fqdn = tostring(properties.fqdn), "
        "privateCluster = tobool(properties.apiServerAccessProfile.enablePrivateCluster), "
        "authorizedRanges = properties.apiServerAccessProfile.authorizedIPRanges, "
        "k8s = tostring(properties.kubernetesVersion)"),
}

# (authority, tenant, client_id, sha256(secret), scope) -> (token, expires_at_monotonic)
_TOKEN_CACHE: dict[tuple[str, str, str, str], tuple[str, float]] = {}


def clear_token_cache() -> None:
    _TOKEN_CACHE.clear()


def _lc(v: Any) -> str:
    return str(v or "").lower()


def _is_provider_host(host: str) -> bool:
    return any(host.endswith(s) for s in PROVIDER_SUFFIXES)


def _owner_of(ipconfig_id: str) -> str:
    """Parent resource id of an ``.../x/name/ipConfigurations/ipconfig1``-style id."""
    parts = ipconfig_id.split("/")
    return "/".join(parts[:9]) if len(parts) >= 9 else ipconfig_id


def _rtype(res_id: str) -> str:
    parts = res_id.split("/")
    return f"{parts[6]}/{parts[7]}".lower() if len(parts) >= 8 else "unknown"


# --------------------------------------------------------------------------- #
# Pure analysis helpers (unit-tested directly)
# --------------------------------------------------------------------------- #

def _port_ranges(rule: dict[str, Any]) -> list[tuple[int, int]]:
    raw: list[Any] = []
    if rule.get("destinationPortRange") is not None:
        raw.append(rule["destinationPortRange"])
    raw.extend(rule.get("destinationPortRanges") or [])
    out: list[tuple[int, int]] = []
    for r in raw:
        s = str(r).strip()
        if s == "*":
            out.append((0, 65535))
            continue
        lo, _, hi = s.partition("-")
        try:
            out.append((int(lo), int(hi or lo)))
        except ValueError:
            continue
    return out


def nsg_world_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Inbound Allow rules whose source includes the internet. Rule dicts are ARM
    ``securityRules`` items (``properties`` nested, or already flattened)."""
    out = []
    for r in rules or []:
        p = r.get("properties") if isinstance(r.get("properties"), dict) else r
        if _lc(p.get("direction")) != "inbound" or _lc(p.get("access")) != "allow":
            continue
        srcs = [p.get("sourceAddressPrefix"), *(p.get("sourceAddressPrefixes") or [])]
        if not any(_lc(s) in _WORLD_SRC for s in srcs if s is not None):
            continue
        proto = _lc(p.get("protocol")) or "*"
        out.append({"name": r.get("name") or p.get("name"), "protocol": proto,
                    "ranges": _port_ranges(p), "priority": p.get("priority")})
    return out


def admin_ports_hit(world: list[dict[str, Any]], admin: tuple[int, ...]) -> list[int]:
    hit: set[int] = set()
    for w in world:
        if w["protocol"] not in ("*", "tcp", "udp"):
            continue
        for lo, hi in w["ranges"]:
            hit.update(p for p in admin if lo <= p <= hi)
    return sorted(hit)


def describe_world(world: list[dict[str, Any]]) -> list[str]:
    out = []
    for w in world:
        for lo, hi in w["ranges"] or [(0, 65535)]:
            span = "all ports" if (lo, hi) == (0, 65535) else (str(lo) if lo == hi else f"{lo}-{hi}")
            out.append(f"{w['protocol']}/{span}")
    return out


# --------------------------------------------------------------------------- #
# Batch construction
# --------------------------------------------------------------------------- #

def build_batch(rows: dict[str, list[dict[str, Any]]], *,
                admin_ports: tuple[int, ...] = DEFAULT_ADMIN_PORTS,
                suggest: bool = True) -> SourceBatch:
    batch = SourceBatch()
    seen_sugg: set[tuple[str, str]] = set()

    def suggest_item(item: Optional[dict[str, Any]]) -> None:
        if suggest and item and (item["kind"], item["value"]) not in seen_sugg:
            seen_sugg.add((item["kind"], item["value"]))
            batch.scope_suggestions.append(item)

    nsgs = {_lc(n["id"]): n for n in rows.get("nsgs", []) if n.get("id")}
    world_by_nsg = {nid: nsg_world_rules(n.get("rules") or []) for nid, n in nsgs.items()}
    subnet_nsg = {_lc(v["subnetId"]): _lc(v["nsg"]) for v in rows.get("vnets", [])
                  if v.get("subnetId") and v.get("nsg")}
    vms = {_lc(v["id"]): v for v in rows.get("vms", []) if v.get("id")}

    # NIC -> (vm id, nsg ids guarding it, public ip ids on it)
    nic_vm: dict[str, str] = {}
    vm_nsgs: dict[str, set[str]] = {}
    pip_vm: dict[str, str] = {}
    for nic in rows.get("nics", []):
        nid, vm = _lc(nic.get("id")), _lc(nic.get("vm"))
        if vm:
            nic_vm[nid] = vm
        guards = {_lc(nic.get("nsg"))} if nic.get("nsg") else set()
        for ic in nic.get("ipconfigs") or []:
            p = ic.get("properties") or {}
            sn = _lc(((p.get("subnet") or {}).get("id")))
            if sn in subnet_nsg:
                guards.add(subnet_nsg[sn])
            pid = _lc((p.get("publicIPAddress") or {}).get("id"))
            if pid and vm:
                pip_vm[pid] = vm
        if vm:
            vm_nsgs.setdefault(vm, set()).update(g for g in guards if g)

    # NSGs ---------------------------------------------------------------- #
    for nid, n in nsgs.items():
        world = world_by_nsg[nid]
        if not world:
            continue
        hit = admin_ports_hit(world, admin_ports)
        batch.assets.append(asset("cloud_resource", nid, SOURCE, {
            "cloud": "azure", "resource_type": "network.nsg", "name": n.get("name"),
            "subscription": n.get("subscriptionId"), "resource_group": n.get("resourceGroup"),
            "world_open": describe_world(world)}))
        if hit:
            batch.findings.append(finding(
                "cloud_resource", nid, "azure.nsg.admin_port_open_to_internet", "high",
                f"NSG {n.get('name')} allows admin ports {hit} from the internet",
                "An inbound Allow rule with source Internet / * / 0.0.0.0/0 covers "
                "administration or database ports.",
                source=SOURCE, evidence={"nsg": n.get("name"), "ports": hit,
                                         "rules": [w["name"] for w in world]},
                remediation="Restrict the rule's source to your office/VPN ranges, or use "
                            "Azure Bastion / just-in-time access instead."))

    # public IPs -------------------------------------------------------------- #
    pip_owner: dict[str, str] = {}
    for p in rows.get("publicips", []):
        pid, ip = _lc(p.get("id")), p.get("ip")
        owner = pip_vm.get(pid) or (_owner_of(_lc(p["assoc"])) if p.get("assoc") else "")
        pip_owner[pid] = owner
        if not ip:
            continue
        kind = "ipv6" if ":" in str(ip) else "ipv4"
        vm_public = bool(owner in vms and any(world_by_nsg.get(g) for g in vm_nsgs.get(owner, ())))
        public = vm_public if owner in vms else bool(owner)   # LB / gateway frontends are public
        batch.assets.append(asset(kind, str(ip), SOURCE, {
            "cloud": "azure", "subscription": p.get("subscriptionId"), "resource_group": p.get("resourceGroup"),
            "location": p.get("location"), "public_ip_name": p.get("name"), "sku": p.get("sku"),
            "fqdn": p.get("fqdn") or None, "public": True if public else None,
            "attached_to": owner or None}))
        if owner:
            if owner not in vms:
                batch.assets.append(asset("cloud_resource", owner, SOURCE, {
                    "cloud": "azure", "resource_type": _rtype(owner), "public": True,
                    "subscription": p.get("subscriptionId")}))
            batch.edges.append(edge(kind, str(ip), "cloud_resource", owner, "attached_to"))
        suggest_item(public_ip_suggestion(ip, {"cloud": "azure", "resource": _lc(p.get("id")),
                                               "subscription": p.get("subscriptionId"),
                                               "attached_to": owner or None}))
        fq = clean_hostname(p.get("fqdn"))
        if fq and not _is_provider_host(fq):
            suggest_item(hostname_suggestion(fq, {"cloud": "azure", "resource": _lc(p.get("id"))}))

    # VMs ----------------------------------------------------------------------- #
    pips_of_vm: dict[str, list[str]] = {}
    for p in rows.get("publicips", []):
        o = pip_owner.get(_lc(p.get("id")), "")
        if o in vms and p.get("ip"):
            pips_of_vm.setdefault(o, []).append(str(p["ip"]))
    for vid, v in vms.items():
        pub = pips_of_vm.get(vid, [])
        guards = vm_nsgs.get(vid, set())
        world = [w for g in guards for w in world_by_nsg.get(g, [])]
        public = bool(pub and world)
        batch.assets.append(asset("cloud_resource", vid, SOURCE, {
            "cloud": "azure", "resource_type": "compute.vm", "name": v.get("name"),
            "subscription": v.get("subscriptionId"), "resource_group": v.get("resourceGroup"),
            "location": v.get("location"), "size": v.get("size"), "os": v.get("os"),
            "tags": v.get("tags") or None, "public_ips": pub,
            "nsgs": sorted(guards), "public": True if public else None}))
        hit = admin_ports_hit(world, admin_ports) if pub else []
        if hit:
            batch.findings.append(finding(
                "cloud_resource", vid, "azure.compute.admin_port_open_to_internet", "high",
                f"VM {v.get('name')} exposes admin ports {hit} to the internet",
                "The VM has a public IP and the NSG guarding it allows administration or "
                "database ports from the internet.",
                source=SOURCE, evidence={"vm": v.get("name"), "public_ips": pub, "ports": hit,
                                         "nsgs": sorted(guards)},
                remediation="Remove the public IP (use Bastion / a load balancer) or restrict "
                            "the NSG rule's source."))

    # App Services ---------------------------------------------------------------- #
    for a in rows.get("appservices", []):
        aid = _lc(a.get("id"))
        host = clean_hostname(a.get("host"))
        public = _lc(a.get("publicNetworkAccess")) != "disabled"
        batch.assets.append(asset("cloud_resource", aid, SOURCE, {
            "cloud": "azure", "resource_type": "web.site", "name": a.get("name"), "kind": a.get("kind"),
            "subscription": a.get("subscriptionId"), "resource_group": a.get("resourceGroup"),
            "location": a.get("location"), "state": a.get("state"), "https_only": a.get("httpsOnly"),
            "public": True if public else None}))
        names = [h for h in (clean_hostname(x) for x in [a.get("host"), *(a.get("hostnames") or [])]) if h]
        for h in dict.fromkeys(names):
            if not public:
                break
            batch.assets.append(asset("subdomain", h, SOURCE, {
                "cloud": "azure", "public": True, "serves": aid}))
            batch.edges.append(edge("subdomain", h, "cloud_resource", aid, "routes_to"))
            if not _is_provider_host(h):
                suggest_item(hostname_suggestion(h, {"cloud": "azure", "resource": aid}))
        if host and public and a.get("httpsOnly") is False:
            batch.findings.append(finding(
                "cloud_resource", aid, "azure.appservice.http_allowed", "low",
                f"App Service {a.get('name')} accepts plain HTTP",
                "httpsOnly is off, so the app serves unencrypted requests.",
                source=SOURCE, evidence={"app": a.get("name"), "host": host},
                remediation="Enable 'HTTPS Only' on the app."))

    # Storage ------------------------------------------------------------------------ #
    for s in rows.get("storage", []):
        sid = _lc(s.get("id"))
        reachable = _lc(s.get("publicNetworkAccess")) != "disabled" and _lc(s.get("defaultAction")) != "deny"
        pub_blob = s.get("allowBlobPublicAccess") is True
        batch.assets.append(asset("cloud_resource", sid, SOURCE, {
            "cloud": "azure", "resource_type": "storage.account", "name": s.get("name"),
            "subscription": s.get("subscriptionId"), "resource_group": s.get("resourceGroup"),
            "location": s.get("location"), "allow_blob_public_access": s.get("allowBlobPublicAccess"),
            "network_default_action": s.get("defaultAction") or None, "sensitive": True,
            "public": True if (pub_blob and reachable) else None}))
        if pub_blob and reachable:
            batch.findings.append(finding(
                "cloud_resource", sid, "azure.storage.public_blob_access", "high",
                f"Storage account {s.get('name')} allows public blob access",
                "allowBlobPublicAccess is on and the network firewall does not restrict the "
                "account, so any container set to public can be read anonymously.",
                source=SOURCE, evidence={"account": s.get("name"), "endpoint": s.get("blobEndpoint"),
                                         "network_default_action": s.get("defaultAction")},
                remediation="Set allowBlobPublicAccess to false on the account and review "
                            "container access levels."))

    # DNS ------------------------------------------------------------------------------ #
    for z in rows.get("dns", []):
        if _lc(z.get("zoneType") or "public") != "public":
            continue
        dom = clean_hostname(z.get("name"))
        if not dom or "." not in dom:
            continue
        batch.assets.append(asset("domain", dom, SOURCE, {
            "cloud": "azure", "subscription": z.get("subscriptionId"),
            "resource_group": z.get("resourceGroup"), "name_servers": z.get("nameServers") or []}))
        suggest_item(hostname_suggestion(dom, {"cloud": "azure", "resource": _lc(z.get("id"))}))

    # AKS ------------------------------------------------------------------------------- #
    for c in rows.get("aks", []):
        cid = _lc(c.get("id"))
        private = c.get("privateCluster") is True
        ranges = c.get("authorizedRanges") or []
        batch.assets.append(asset("cloud_resource", cid, SOURCE, {
            "cloud": "azure", "resource_type": "aks.cluster", "name": c.get("name"),
            "subscription": c.get("subscriptionId"), "resource_group": c.get("resourceGroup"),
            "location": c.get("location"), "kubernetes_version": c.get("k8s"),
            "api_server_private": private, "authorized_ranges": ranges,
            "public": True if not private else None}))
        fq = clean_hostname(c.get("fqdn"))
        if fq and not private:
            batch.assets.append(asset("subdomain", fq, SOURCE, {
                "cloud": "azure", "public": True, "serves": cid}))
            batch.edges.append(edge("subdomain", fq, "cloud_resource", cid, "routes_to"))
        if not private and not ranges:
            batch.findings.append(finding(
                "cloud_resource", cid, "azure.aks.api_server_public", "high",
                f"AKS cluster {c.get('name')} has a public API server open to all addresses",
                "The Kubernetes API server is internet-reachable and no authorized IP ranges "
                "limit who can connect.",
                source=SOURCE, evidence={"cluster": c.get("name"), "fqdn": c.get("fqdn")},
                remediation="Enable a private cluster, or set authorized IP ranges for the "
                            "API server."))
    return batch


# --------------------------------------------------------------------------- #
# Connector
# --------------------------------------------------------------------------- #

@register
class AzureConnector(Connector):
    kind = "azure"
    display_name = "Microsoft Azure (Resource Graph)"
    category = "cloud"
    capabilities = frozenset({Capability.SOURCE})
    config_schema = {
        "type": "object",
        "required": ["tenant_id", "client_id"],
        "properties": {
            "tenant_id": {"type": "string", "description": "Entra (Azure AD) tenant id"},
            "client_id": {"type": "string", "description": "App registration (client) id"},
            "subscriptions": {"type": "array", "items": {"type": "string"},
                              "description": "Subscription ids to query (default: every one "
                                             "the app can read)"},
            "admin_ports": {"type": "array", "items": {"type": "integer"}},
            "suggest_scope": {"type": "boolean", "default": True,
                              "description": "Propose public IPs / DNS zones as pending scope "
                                             "suggestions (never added automatically)"},
            "authority_host": {"type": "string", "default": "login.microsoftonline.com"},
            "management_host": {"type": "string", "default": "management.azure.com",
                                "description": "Override for sovereign clouds"},
            "sync_interval_minutes": {"type": "integer", "default": 360, "minimum": 15},
        },
    }
    secret_fields = ("client_secret",)
    docs_url = "docs/INTEGRATIONS-CONTEXT.md#8-microsoft-azure"

    def __init__(self, config, secrets, http) -> None:
        super().__init__(config, secrets, http)
        self.last_warnings: list[str] = []

    def _allow_private(self) -> bool:
        return bool_cfg(self.config, "allow_private", False)

    def _cache_key(self) -> tuple[str, str, str, str]:
        return (str(self.config.get("authority_host") or "login.microsoftonline.com").lower(),
                str(self.config.get("tenant_id") or ""), str(self.config.get("client_id") or ""),
                hashlib.sha256((self.secrets.get("client_secret") or "").encode()).hexdigest())

    async def _token(self, *, force: bool = False) -> str:
        key = self._cache_key()
        now = time.monotonic()
        hit = _TOKEN_CACHE.get(key)
        if hit and not force and hit[1] - _REFRESH_MARGIN_S > now:
            return hit[0]
        authority, tenant, client_id, _ = key
        secret = self.secrets.get("client_secret")
        if not (tenant and client_id and secret):
            raise SourceError("tenant_id, client_id and secret 'client_secret' are required",
                              retryable=False)
        url = await checked_url(f"https://{authority}/{quote(tenant, safe='')}/oauth2/v2.0/token",
                                allow_private=self._allow_private())
        body = await request_json(self.http, "POST", url, what="Entra token request", data={
            "grant_type": "client_credentials", "client_id": client_id,
            "client_secret": secret, "scope": ARM_SCOPE})
        tok = body.get("access_token") if isinstance(body, dict) else None
        if not tok:
            raise SourceError("Entra token response had no access_token", retryable=False)
        try:
            ttl = float(body.get("expires_in") or 3600)
        except (TypeError, ValueError):
            ttl = 3600.0
        _TOKEN_CACHE[key] = (str(tok), now + ttl)
        return str(tok)

    async def _arm(self) -> str:
        host = str(self.config.get("management_host") or "management.azure.com")
        return await checked_url(f"https://{host}", allow_private=self._allow_private())

    async def _post(self, url: str, body: dict[str, Any], what: str) -> Any:
        tok = await self._token()
        try:
            return await request_json(self.http, "POST", url, what=what, json=body,
                                      headers={"Authorization": f"Bearer {tok}"}, retries=3)
        except SourceError as exc:
            if exc.status_code != 401:
                raise
        tok = await self._token(force=True)   # token revoked early: refresh once
        return await request_json(self.http, "POST", url, what=what, json=body,
                                  headers={"Authorization": f"Bearer {tok}"}, retries=3)

    async def _query(self, base: str, name: str, *, top: int = PAGE_SIZE) -> list[dict[str, Any]]:
        url = f"{base}/providers/Microsoft.ResourceGraph/resources?api-version={ARG_API}"
        subs = [str(s) for s in self.config.get("subscriptions") or [] if s]
        out: list[dict[str, Any]] = []
        skip: Optional[str] = None
        for _ in range(_MAX_PAGES):
            options: dict[str, Any] = {"$top": top, "resultFormat": "objectArray"}
            if skip:
                options["$skipToken"] = skip
            body: dict[str, Any] = {"query": QUERIES[name], "options": options}
            if subs:
                body["subscriptions"] = subs
            res = await self._post(url, body, f"Resource Graph '{name}'")
            out.extend(r for r in (res or {}).get("data") or [] if isinstance(r, dict))
            skip = (res or {}).get("$skipToken") or None
            if not skip:
                break
        return out

    async def test(self) -> HealthResult:
        try:
            base = await self._arm()
            url = f"{base}/providers/Microsoft.ResourceGraph/resources?api-version={ARG_API}"
            subs = [str(s) for s in self.config.get("subscriptions") or [] if s]
            body: dict[str, Any] = {"query": "resources | take 1", "options": {"$top": 1}}
            if subs:
                body["subscriptions"] = subs
            await self._post(url, body, "Resource Graph test")
        except SourceError as exc:
            return HealthResult(ok=False, detail=str(exc))
        return HealthResult(ok=True, detail="Resource Graph reachable with the Reader role")

    async def pull(self) -> SourceBatch:
        self.last_warnings = []
        base = await self._arm()
        await self._token()   # auth failure is a hard error, not a warning
        rows: dict[str, list[dict[str, Any]]] = {}
        failures = 0
        first_error: Optional[SourceError] = None
        for name in QUERIES:
            try:
                rows[name] = await self._query(base, name)
            except SourceError as exc:
                failures += 1
                first_error = first_error or exc
                rows[name] = []
                self.last_warnings.append(f"{name}: {exc}")
        if failures == len(QUERIES) and first_error is not None:
            raise first_error
        admin = tuple(int(p) for p in self.config.get("admin_ports") or DEFAULT_ADMIN_PORTS)
        return build_batch(rows, admin_ports=admin,
                           suggest=bool_cfg(self.config, "suggest_scope", True))
