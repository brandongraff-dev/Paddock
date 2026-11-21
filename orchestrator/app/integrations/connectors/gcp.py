"""Google Cloud (SOURCE, read-only): internet-facing inventory from Cloud Asset Inventory.

Auth is a service-account key (``service_account_json`` secret): a signed JWT
is exchanged for an OAuth2 token (``_gcp_auth``; ``cryptography`` only, no
Google SDK). Every call is a ``GET`` of the Cloud Asset ``listAssets`` API
(``roles/cloudasset.viewer`` is the only role needed), once per asset type and
parent, so a failure of one type is a *warning*, not a failed sync:

* ``compute.googleapis.com/Instance``      -- external IPs, network tags
* ``compute.googleapis.com/ForwardingRule`` -- EXTERNAL load balancers
* ``compute.googleapis.com/Firewall``      -- ingress rules open to 0.0.0.0/0
* ``sqladmin.googleapis.com/Instance``     -- Cloud SQL public IPs + authorized networks
* ``storage.googleapis.com/Bucket`` (RESOURCE + IAM_POLICY) -- public buckets
* ``run.googleapis.com/Service`` / ``cloudfunctions.googleapis.com/CloudFunction`` -- URLs
* ``dns.googleapis.com/ManagedZone``       -- public zones

Graph: ``ipv4 --attached_to--> instance|forwarding rule|SQL instance``. An
instance is ``public`` only when it has an external IP AND an enabled ingress
firewall rule open to the world applies to it (same network, matching target
tags): GCP denies ingress by default, so an external IP alone proves nothing.
Buckets and Cloud SQL are ``sensitive`` (crown-jewel candidates).

**Scope suggestions, never scope.** External IPs and public DNS zones come back
as PENDING ``scope_suggestions`` (schema 031). A human accepts them through the
normal scope add, which still needs proof-of-control. Provider-owned hostnames
(``*.run.app``, ``*.cloudfunctions.net``) are assets but are never suggested:
nobody can prove control of them.

Findings (rule_source ``policy``): ``gcp.storage.bucket_public``,
``gcp.firewall.admin_port_open_to_world``, ``gcp.compute.admin_port_open_to_internet``,
``gcp.sql.public_ip_open_to_world`` / ``gcp.sql.public_ip``.
"""
from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlsplit

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
from ._gcp_auth import access_token, parse_key

SOURCE = "integration:gcp"
SCOPE_URL = "https://www.googleapis.com/auth/cloud-platform"
DEFAULT_BASE = "https://cloudasset.googleapis.com"
PAGE_SIZE = 1000
_MAX_PAGES = 200

DEFAULT_ADMIN_PORTS: tuple[int, ...] = (
    22, 23, 135, 139, 445, 1433, 1521, 2049, 2375, 2376, 2379, 3306, 3389,
    5432, 5601, 5900, 5984, 6379, 7001, 8086, 9042, 9200, 9300, 11211, 27017,
)
_WORLD = ("0.0.0.0/0", "::/0")
_PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")
# Hostnames Google owns: assets yes, scope suggestions never.
PROVIDER_SUFFIXES = (".run.app", ".cloudfunctions.net", ".appspot.com", ".googleapis.com")

T_INSTANCE = "compute.googleapis.com/Instance"
T_FORWARDING = "compute.googleapis.com/ForwardingRule"
T_FIREWALL = "compute.googleapis.com/Firewall"
T_SQL = "sqladmin.googleapis.com/Instance"
T_BUCKET = "storage.googleapis.com/Bucket"
T_RUN = "run.googleapis.com/Service"
T_FUNCTION = "cloudfunctions.googleapis.com/CloudFunction"
T_DNS = "dns.googleapis.com/ManagedZone"
RESOURCE_TYPES = (T_INSTANCE, T_FORWARDING, T_FIREWALL, T_SQL, T_BUCKET, T_RUN, T_FUNCTION, T_DNS)


def _tail(v: Any) -> str:
    return str(v or "").rstrip("/").rsplit("/", 1)[-1]


def _project(name: str) -> Optional[str]:
    m = re.search(r"/projects/([^/]+)/", name)
    return m.group(1) if m else None


def _net_key(url: Any) -> str:
    """``.../projects/p/global/networks/n`` -> ``projects/p/global/networks/n``."""
    s = str(url or "")
    i = s.find("projects/")
    return s[i:] if i >= 0 else s


def _is_provider_host(host: str) -> bool:
    return any(host.endswith(s) for s in PROVIDER_SUFFIXES)


# --------------------------------------------------------------------------- #
# Pure analysis helpers (unit-tested directly)
# --------------------------------------------------------------------------- #

def firewall_world_ports(fw: dict[str, Any]) -> Optional[list[tuple[str, int, int]]]:
    """(protocol, lo, hi) allowed from the world by an ENABLED INGRESS rule, else None."""
    if fw.get("disabled") or str(fw.get("direction") or "INGRESS").upper() != "INGRESS":
        return None
    if not any(r in _WORLD for r in fw.get("sourceRanges") or []):
        return None
    out: list[tuple[str, int, int]] = []
    for a in fw.get("allowed") or []:
        proto = str(a.get("IPProtocol") or a.get("ipProtocol") or "all").lower()
        ports = a.get("ports") or []
        if proto in ("all", "-1") or (not ports and proto in ("tcp", "udp")):
            out.append((proto if proto not in ("-1",) else "all", 0, 65535))
            continue
        for p in ports:
            try:
                lo, _, hi = str(p).partition("-")
                out.append((proto, int(lo), int(hi or lo)))
            except ValueError:
                continue
    return out or None


def admin_ports_hit(ranges: list[tuple[str, int, int]], admin: tuple[int, ...]) -> list[int]:
    hit: set[int] = set()
    for proto, lo, hi in ranges:
        if proto not in ("tcp", "all", "udp"):
            continue
        hit.update(p for p in admin if lo <= p <= hi)
    return sorted(hit)


def describe_ranges(ranges: list[tuple[str, int, int]]) -> list[str]:
    return ["all traffic" if p == "all" else (f"{p}/{lo}" if lo == hi else f"{p}/{lo}-{hi}")
            for p, lo, hi in ranges]


def instance_ips(data: dict[str, Any]) -> tuple[list[str], list[str]]:
    """(private ips, external ips) of a compute instance."""
    priv: list[str] = []
    pub: list[str] = []
    for nic in data.get("networkInterfaces") or []:
        if nic.get("networkIP"):
            priv.append(str(nic["networkIP"]))
        for ac in nic.get("accessConfigs") or []:
            if ac.get("natIP"):
                pub.append(str(ac["natIP"]))
        for ac in nic.get("ipv6AccessConfigs") or []:
            if ac.get("externalIpv6"):
                pub.append(str(ac["externalIpv6"]))
    return priv, pub


def firewall_applies(fw: dict[str, Any], data: dict[str, Any]) -> bool:
    nets = {_net_key(n.get("network")) for n in data.get("networkInterfaces") or []}
    if _net_key(fw.get("network")) not in nets:
        return False
    targets = set(fw.get("targetTags") or [])
    if fw.get("targetServiceAccounts"):
        return False  # cannot be evaluated from inventory data: stay conservative
    if not targets:
        return True
    return bool(targets & set((data.get("tags") or {}).get("items") or []))


def bucket_is_public(policy: Optional[dict[str, Any]], data: dict[str, Any]) -> bool:
    pap = str(((data.get("iamConfiguration") or {}).get("publicAccessPrevention")) or "").lower()
    if pap == "enforced":
        return False
    for b in ((policy or {}).get("bindings") or []):
        if any(m in _PUBLIC_MEMBERS for m in b.get("members") or []):
            return True
    return False


# --------------------------------------------------------------------------- #
# Batch construction
# --------------------------------------------------------------------------- #

def build_batch(resources: dict[str, list[dict[str, Any]]], iam: dict[str, dict[str, Any]], *,
                admin_ports: tuple[int, ...] = DEFAULT_ADMIN_PORTS,
                suggest: bool = True) -> SourceBatch:
    """``resources``: asset type -> listAssets items; ``iam``: asset name -> iamPolicy."""
    batch = SourceBatch()
    seen_sugg: set[tuple[str, str]] = set()

    def suggest_item(item: Optional[dict[str, Any]]) -> None:
        if suggest and item and (item["kind"], item["value"]) not in seen_sugg:
            seen_sugg.add((item["kind"], item["value"]))
            batch.scope_suggestions.append(item)

    def ip_asset(ip: str, parent_name: str, public: bool, project: Optional[str], label: str) -> None:
        kind = "ipv6" if ":" in ip else "ipv4"
        batch.assets.append(asset(kind, ip, SOURCE, {
            "cloud": "gcp", "project": project, "public": True if public else None,
            "attached_to": parent_name}, confidence=90))
        batch.edges.append(edge(kind, ip, "cloud_resource", parent_name, "attached_to"))
        suggest_item(public_ip_suggestion(ip, {"cloud": "gcp", "project": project,
                                               "resource": parent_name, "type": label}))

    firewalls = [a for a in resources.get(T_FIREWALL, []) if (a.get("resource") or {}).get("data")]
    fw_data = [(a["name"], a["resource"]["data"]) for a in firewalls]

    for fname, fw in fw_data:
        ranges = firewall_world_ports(fw)
        if not ranges:
            continue
        hit = admin_ports_hit(ranges, admin_ports)
        batch.assets.append(asset("cloud_resource", fname, SOURCE, {
            "cloud": "gcp", "resource_type": "compute.firewall", "name": fw.get("name"),
            "project": _project(fname), "network": _tail(fw.get("network")),
            "world_open": describe_ranges(ranges)}))
        if hit:
            batch.findings.append(finding(
                "cloud_resource", fname, "gcp.firewall.admin_port_open_to_world", "high",
                f"Firewall rule {fw.get('name')} opens admin ports {hit} to the internet",
                f"The enabled ingress rule allows {', '.join(describe_ranges(ranges))} from "
                "0.0.0.0/0 or ::/0, which includes administration or database ports.",
                source=SOURCE, evidence={"firewall": fw.get("name"), "ports": hit,
                                         "network": _tail(fw.get("network")),
                                         "target_tags": fw.get("targetTags") or []},
                remediation="Restrict sourceRanges to your office/VPN CIDRs or use IAP "
                            "TCP forwarding; delete the rule if it is unused."))

    for a in resources.get(T_INSTANCE, []):
        data = (a.get("resource") or {}).get("data") or {}
        name = a["name"]
        priv, pub = instance_ips(data)
        applying = [(n, fw) for n, fw in fw_data if firewall_applies(fw, data)
                    and firewall_world_ports(fw)]
        public = bool(pub) and bool(applying)
        batch.assets.append(asset("cloud_resource", name, SOURCE, {
            "cloud": "gcp", "resource_type": "compute.instance", "name": data.get("name"),
            "project": _project(name), "zone": _tail(data.get("zone")),
            "status": data.get("status"), "labels": data.get("labels") or {},
            "network_tags": (data.get("tags") or {}).get("items") or [],
            "private_ips": priv, "public_ips": pub, "hostname": data.get("hostname"),
            "public": True if public else None}))
        for ip in pub:
            ip_asset(ip, name, public, _project(name), "compute.instance")
        if pub:
            ports: list[tuple[str, int, int]] = []
            for _, fw in applying:
                ports.extend(firewall_world_ports(fw) or [])
            hit = admin_ports_hit(ports, admin_ports)
            if hit:
                batch.findings.append(finding(
                    "cloud_resource", name, "gcp.compute.admin_port_open_to_internet", "high",
                    f"VM {data.get('name')} exposes admin ports {hit} to the internet",
                    "The instance has an external IP and an ingress firewall rule open to "
                    "0.0.0.0/0 covers administration or database ports.",
                    source=SOURCE, evidence={"instance": data.get("name"), "external_ips": pub,
                                             "ports": hit, "rules": [fw.get("name") for _, fw in applying]},
                    remediation="Remove the external IP (use IAP / Cloud NAT) or restrict the "
                                "firewall rule's sourceRanges."))

    for a in resources.get(T_FORWARDING, []):
        data = (a.get("resource") or {}).get("data") or {}
        scheme = str(data.get("loadBalancingScheme") or "").upper()
        if not scheme.startswith("EXTERNAL"):
            continue
        name = a["name"]
        ip = data.get("IPAddress") or data.get("ipAddress")
        batch.assets.append(asset("cloud_resource", name, SOURCE, {
            "cloud": "gcp", "resource_type": "compute.forwarding_rule", "name": data.get("name"),
            "project": _project(name), "scheme": scheme, "ip": ip,
            "port_range": data.get("portRange"), "ports": data.get("ports"),
            "protocol": data.get("IPProtocol"), "public": True}))
        if ip:
            ip_asset(str(ip), name, True, _project(name), "forwarding_rule")

    for a in resources.get(T_SQL, []):
        data = (a.get("resource") or {}).get("data") or {}
        name = a["name"]
        ipc = (data.get("settings") or {}).get("ipConfiguration") or {}
        public_ips = [str(i["ipAddress"]) for i in data.get("ipAddresses") or []
                      if str(i.get("type") or "").upper() in ("PRIMARY", "") and i.get("ipAddress")]
        nets = [str(n.get("value")) for n in ipc.get("authorizedNetworks") or [] if n.get("value")]
        has_public = bool(public_ips) and ipc.get("ipv4Enabled", True) is not False
        world = has_public and any(n in _WORLD for n in nets)
        batch.assets.append(asset("cloud_resource", name, SOURCE, {
            "cloud": "gcp", "resource_type": "sql.instance", "name": data.get("name"),
            "project": _project(name), "engine": data.get("databaseVersion"),
            "public_ips": public_ips if has_public else [], "authorized_networks": nets,
            "private_network": ipc.get("privateNetwork"), "sensitive": True,
            "public": True if has_public else None}))
        if has_public:
            for ip in public_ips:
                ip_asset(ip, name, True, _project(name), "sql.instance")
            sev, rule = ("high", "gcp.sql.public_ip_open_to_world") if world else \
                ("medium", "gcp.sql.public_ip")
            batch.findings.append(finding(
                "cloud_resource", name, rule, sev,
                f"Cloud SQL instance {data.get('name')} has a public IP"
                + (" open to the world" if world else ""),
                "The instance accepts connections on a public IPv4 address"
                + (" from 0.0.0.0/0 (authorized network)." if world else
                   ", restricted to its authorized networks."),
                source=SOURCE, evidence={"instance": data.get("name"), "public_ips": public_ips,
                                         "authorized_networks": nets},
                remediation="Disable the public IP and use the private IP / Cloud SQL "
                            "connector, or narrow authorizedNetworks to known CIDRs."))

    for a in resources.get(T_BUCKET, []):
        data = (a.get("resource") or {}).get("data") or {}
        name = a["name"]
        public = bucket_is_public(iam.get(name), data)
        bucket = data.get("name") or _tail(name)
        batch.assets.append(asset("cloud_resource", name, SOURCE, {
            "cloud": "gcp", "resource_type": "storage.bucket", "name": bucket,
            "project": _project(name), "location": data.get("location"),
            "public_access_prevention": (data.get("iamConfiguration") or {}).get("publicAccessPrevention"),
            "sensitive": True, "public": True if public else None}))
        if public:
            batch.findings.append(finding(
                "cloud_resource", name, "gcp.storage.bucket_public", "high",
                f"GCS bucket {bucket} is readable by the public",
                "An IAM binding grants a role to allUsers or allAuthenticatedUsers and "
                "public access prevention is not enforced.",
                source=SOURCE, evidence={"bucket": bucket, "location": data.get("location")},
                remediation="Remove the allUsers/allAuthenticatedUsers bindings and enforce "
                            "public access prevention on the bucket or the project."))

    for typ, label in ((T_RUN, "run.service"), (T_FUNCTION, "functions.function")):
        for a in resources.get(typ, []):
            data = (a.get("resource") or {}).get("data") or {}
            name = a["name"]
            if typ == T_RUN:
                url = (data.get("status") or {}).get("url") or data.get("uri")
                ann = (data.get("metadata") or {}).get("annotations") or {}
                ingress = str(ann.get("run.googleapis.com/ingress") or data.get("ingress") or "all").lower()
                public = ingress in ("all", "ingress_traffic_all")
                short = (data.get("metadata") or {}).get("name") or data.get("name") or _tail(name)
            else:
                url = (data.get("httpsTrigger") or {}).get("url") or \
                    (data.get("serviceConfig") or {}).get("uri")
                ingress = str(data.get("ingressSettings") or
                              (data.get("serviceConfig") or {}).get("ingressSettings") or "ALLOW_ALL").upper()
                public = bool(url) and ingress == "ALLOW_ALL"
                short = _tail(data.get("name") or name)
            batch.assets.append(asset("cloud_resource", name, SOURCE, {
                "cloud": "gcp", "resource_type": label, "name": short, "project": _project(name),
                "url": url, "ingress": ingress, "public": True if public else None}))
            host = clean_hostname(urlsplit(str(url)).hostname) if url else None
            if host and public:
                batch.assets.append(asset("subdomain", host, SOURCE, {
                    "cloud": "gcp", "project": _project(name), "public": True,
                    "serves": name}))
                batch.edges.append(edge("subdomain", host, "cloud_resource", name, "routes_to"))
                if not _is_provider_host(host):
                    suggest_item(hostname_suggestion(host, {"cloud": "gcp", "resource": name}))

    for a in resources.get(T_DNS, []):
        data = (a.get("resource") or {}).get("data") or {}
        if str(data.get("visibility") or "public").lower() != "public":
            continue
        dom = clean_hostname(data.get("dnsName"))
        if not dom or "." not in dom:
            continue
        batch.assets.append(asset("domain", dom, SOURCE, {
            "cloud": "gcp", "project": _project(a["name"]), "dns_zone": data.get("name"),
            "name_servers": data.get("nameServers") or []}))
        suggest_item(hostname_suggestion(dom, {"cloud": "gcp", "resource": a["name"],
                                               "dns_zone": data.get("name")}))
    return batch


# --------------------------------------------------------------------------- #
# Connector
# --------------------------------------------------------------------------- #

@register
class GcpConnector(Connector):
    kind = "gcp"
    display_name = "Google Cloud (Asset Inventory)"
    category = "cloud"
    capabilities = frozenset({Capability.SOURCE})
    config_schema = {
        "type": "object",
        "required": ["parents"],
        "properties": {
            "parents": {"type": "array", "items": {"type": "string"},
                        "description": "Where to list assets: projects/<id>, folders/<n> or "
                                       "organizations/<n> (a bare project id is accepted)"},
            "admin_ports": {"type": "array", "items": {"type": "integer"},
                            "description": "Ports treated as administrative (default: SSH/RDP/SMB/DBs)"},
            "suggest_scope": {"type": "boolean", "default": True,
                              "description": "Propose external IPs / public DNS zones as pending "
                                             "scope suggestions (never added automatically)"},
            "base_url": {"type": "string", "description": "Override https://cloudasset.googleapis.com"},
            "token_uri": {"type": "string", "description": "Override the OAuth token endpoint"},
            "sync_interval_minutes": {"type": "integer", "default": 360, "minimum": 15},
        },
    }
    secret_fields = ("service_account_json",)
    docs_url = "docs/INTEGRATIONS-CONTEXT.md#7-google-cloud"

    def __init__(self, config, secrets, http) -> None:
        super().__init__(config, secrets, http)
        self.last_warnings: list[str] = []

    # -- helpers ------------------------------------------------------------ #
    def _parents(self, key: Optional[dict[str, Any]] = None) -> list[str]:
        raw = self.config.get("parents") or []
        if isinstance(raw, str):
            raw = [p for p in re.split(r"[,\s]+", raw) if p]
        out: list[str] = []
        for p in raw:
            p = str(p).strip()
            if not re.match(r"^(projects|folders|organizations)/[A-Za-z0-9_.:-]+$", p):
                if re.match(r"^[a-z][a-z0-9-]{4,61}[a-z0-9]$", p):
                    p = f"projects/{p}"
                else:
                    raise SourceError(f"invalid parent {p[:60]!r}: use projects/<id>, "
                                      "folders/<n> or organizations/<n>", retryable=False)
            if p not in out:
                out.append(p)
        if not out and key and key.get("project_id"):
            out.append(f"projects/{key['project_id']}")
        if not out:
            raise SourceError("config 'parents' is required", retryable=False)
        return out

    async def _base(self) -> str:
        return await checked_url(str(self.config.get("base_url") or DEFAULT_BASE),
                                 allow_private=bool_cfg(self.config, "allow_private", False))

    async def _token(self, key: dict[str, Any], *, force: bool = False) -> str:
        return await access_token(self.http, key, self.config, SCOPE_URL,
                                  allow_private=bool_cfg(self.config, "allow_private", False),
                                  force=force)

    async def _get(self, key: dict[str, Any], url: str, params: list[tuple[str, str]], what: str) -> Any:
        tok = await self._token(key)
        try:
            return await request_json(self.http, "GET", url, what=what, params=params,
                                      headers={"Authorization": f"Bearer {tok}"})
        except SourceError as exc:
            if exc.status_code != 401:
                raise
        tok = await self._token(key, force=True)   # cached token revoked early: refresh once
        return await request_json(self.http, "GET", url, what=what, params=params,
                                  headers={"Authorization": f"Bearer {tok}"})

    async def _list(self, key: dict[str, Any], base: str, parent: str, atype: str,
                    content: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        token: Optional[str] = None
        for _ in range(_MAX_PAGES):
            params = [("contentType", content), ("assetTypes", atype), ("pageSize", str(PAGE_SIZE))]
            if token:
                params.append(("pageToken", token))
            body = await self._get(key, f"{base}/v1/{parent}/assets", params,
                                   f"Cloud Asset {atype}")
            out.extend(x for x in (body or {}).get("assets") or [] if isinstance(x, dict) and x.get("name"))
            token = (body or {}).get("nextPageToken") or None
            if not token:
                break
        return out

    # -- contract ----------------------------------------------------------- #
    async def test(self) -> HealthResult:
        try:
            key = parse_key(self.secrets.get("service_account_json"))
            base = await self._base()
            parent = self._parents(key)[0]
            await self._get(key, f"{base}/v1/{parent}/assets",
                            [("contentType", "RESOURCE"), ("assetTypes", T_DNS), ("pageSize", "1")],
                            "Cloud Asset test")
        except SourceError as exc:
            return HealthResult(ok=False, detail=str(exc))
        return HealthResult(ok=True, detail="Cloud Asset API reachable with roles/cloudasset.viewer")

    async def pull(self) -> SourceBatch:
        self.last_warnings = []
        key = parse_key(self.secrets.get("service_account_json"))
        base = await self._base()
        parents = self._parents(key)
        await self._token(key)   # an auth failure is a hard error, not a warning
        resources: dict[str, dict[str, dict[str, Any]]] = {t: {} for t in RESOURCE_TYPES}
        iam: dict[str, dict[str, Any]] = {}
        attempts = failures = 0
        first_error: Optional[SourceError] = None
        jobs = [(p, t, "RESOURCE") for p in parents for t in RESOURCE_TYPES] + \
               [(p, T_BUCKET, "IAM_POLICY") for p in parents]
        for parent, atype, content in jobs:
            attempts += 1
            try:
                items = await self._list(key, base, parent, atype, content)
            except SourceError as exc:
                failures += 1
                first_error = first_error or exc
                self.last_warnings.append(f"{parent} {atype} ({content.lower()}): {exc}")
                continue
            for it in items:
                if content == "IAM_POLICY":
                    iam[it["name"]] = it.get("iamPolicy") or {}
                else:
                    resources[atype][it["name"]] = it
        if failures == attempts and first_error is not None:
            raise first_error      # nothing worked: a failed sync, not a partial one
        admin = tuple(int(p) for p in self.config.get("admin_ports") or DEFAULT_ADMIN_PORTS)
        return build_batch({t: list(v.values()) for t, v in resources.items()}, iam,
                           admin_ports=admin, suggest=bool_cfg(self.config, "suggest_scope", True))
