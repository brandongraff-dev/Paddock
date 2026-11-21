"""CrowdStrike Falcon (SOURCE, read-only): hosts + prevention status.

OAuth2 client credentials against the Falcon API of the configured cloud,
then:

* ``GET  /devices/queries/devices-scroll/v1``  -- every host id (scroll)
* ``POST /devices/entities/devices/v2``         -- host details (batched)
* ``GET  /policy/entities/prevention/v1``       -- the applied prevention policies

Hosts MERGE onto existing assets by local IP / hostname / MAC (never by the
external NAT IP, which is shared by a whole office). Findings: prevention
policy not applied, prevention policy disabled, sensor in reduced-functionality
mode.

API client scopes: ``Hosts: Read`` and ``Prevention policies: Read``. Nothing
else (in particular NOT ``Hosts: Write``, which allows network containment).
"""
from __future__ import annotations

from typing import Any

from ..base import Capability, Connector, HealthResult, SourceBatch, register
from ._common import (
    SourceError,
    bool_cfg,
    checked_url,
    device_asset,
    device_finding,
    int_cfg,
    merge_hint,
    request_json,
)

SOURCE = "integration:crowdstrike"

CLOUDS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}
_DETAIL_BATCH = 500
_MAX_SCROLL_PAGES = 400


@register
class CrowdStrikeConnector(Connector):
    kind = "crowdstrike"
    display_name = "CrowdStrike Falcon"
    category = "edr"
    capabilities = frozenset({Capability.SOURCE})
    config_schema = {
        "type": "object",
        "required": ["client_id"],
        "properties": {
            "client_id": {"type": "string"},
            "cloud": {"type": "string", "enum": sorted(CLOUDS), "default": "us-1"},
            "base_url": {"type": "string", "description": "Overrides `cloud` (e.g. a proxy)"},
            "member_cid": {"type": "string", "description": "Flight Control child CID"},
            "filter": {"type": "string", "description": "FQL host filter, e.g. platform_name:'Windows'"},
            "page_size": {"type": "integer", "default": 5000, "maximum": 5000},
            "create_unmatched": {"type": "boolean", "default": True},
            "sync_interval_minutes": {"type": "integer", "default": 360, "minimum": 15},
        },
    }
    secret_fields = ("client_secret",)
    docs_url = "docs/INTEGRATIONS-CONTEXT.md#crowdstrike-falcon"

    async def _base(self) -> str:
        url = self.config.get("base_url") or CLOUDS.get(str(self.config.get("cloud") or "us-1"))
        if not url:
            raise SourceError("unknown CrowdStrike cloud", retryable=False)
        return await checked_url(str(url), allow_private=bool_cfg(self.config, "allow_private", False))

    async def _token(self, base: str) -> str:
        cid = str(self.config.get("client_id") or "")
        secret = self.secrets.get("client_secret")
        if not cid or not secret:
            raise SourceError("client_id and client_secret are required", retryable=False)
        form = {"client_id": cid, "client_secret": secret}
        if self.config.get("member_cid"):
            form["member_cid"] = str(self.config["member_cid"])
        body = await request_json(self.http, "POST", f"{base}/oauth2/token",
                                  what="Falcon token request", data=form)
        tok = (body or {}).get("access_token")
        if not tok:
            raise SourceError("Falcon token response had no access_token", retryable=False)
        return str(tok)

    async def test(self) -> HealthResult:
        try:
            base = await self._base()
            tok = await self._token(base)
            await request_json(self.http, "GET", f"{base}/devices/queries/devices-scroll/v1",
                               what="Falcon hosts query", params={"limit": 1},
                               headers={"Authorization": f"Bearer {tok}"})
        except SourceError as exc:
            return HealthResult(ok=False, detail=str(exc))
        return HealthResult(ok=True, detail="Falcon API reachable with Hosts: Read")

    async def pull(self) -> SourceBatch:
        base = await self._base()
        tok = await self._token(base)
        hdr = {"Authorization": f"Bearer {tok}"}
        limit = int_cfg(self.config, "page_size", 5000, lo=1, hi=5000)
        ids: list[str] = []
        offset: str | None = None
        for _ in range(_MAX_SCROLL_PAGES):
            params: dict[str, Any] = {"limit": limit}
            if offset:
                params["offset"] = offset
            if self.config.get("filter"):
                params["filter"] = str(self.config["filter"])
            body = await request_json(self.http, "GET", f"{base}/devices/queries/devices-scroll/v1",
                                      what="Falcon hosts query", params=params, headers=hdr)
            page = [str(i) for i in (body or {}).get("resources") or []]
            ids.extend(page)
            pag = ((body or {}).get("meta") or {}).get("pagination") or {}
            nxt = pag.get("offset")
            total = pag.get("total")
            if not page or not nxt or nxt == offset or (total is not None and len(ids) >= int(total)):
                break
            offset = str(nxt)

        hosts: list[dict[str, Any]] = []
        for i in range(0, len(ids), _DETAIL_BATCH):
            body = await request_json(self.http, "POST", f"{base}/devices/entities/devices/v2",
                                      what="Falcon host details", json={"ids": ids[i:i + _DETAIL_BATCH]},
                                      headers=hdr)
            hosts.extend(h for h in (body or {}).get("resources") or [] if isinstance(h, dict))

        policy_ids = sorted({str(((h.get("device_policies") or {}).get("prevention") or {})
                                 .get("policy_id")) for h in hosts
                             if ((h.get("device_policies") or {}).get("prevention") or {}).get("policy_id")})
        policies: dict[str, dict[str, Any]] = {}
        for i in range(0, len(policy_ids), 100):
            body = await request_json(self.http, "GET", f"{base}/policy/entities/prevention/v1",
                                      what="Falcon prevention policies",
                                      params=[("ids", p) for p in policy_ids[i:i + 100]], headers=hdr)
            for p in (body or {}).get("resources") or []:
                if isinstance(p, dict) and p.get("id"):
                    policies[str(p["id"])] = p
        return build_batch(hosts, policies,
                           create_unmatched=bool_cfg(self.config, "create_unmatched", True))


def build_batch(hosts: list[dict[str, Any]], policies: dict[str, dict[str, Any]], *,
                create_unmatched: bool = True) -> SourceBatch:
    batch = SourceBatch()
    for h in hosts:
        hostname = h.get("hostname")
        domain = h.get("machine_domain")
        fqdn = f"{hostname}.{domain}" if hostname and domain and "." not in hostname else None
        hint = merge_hint(ips=[h.get("local_ip")], hostnames=[fqdn, hostname],
                          macs=[h.get("mac_address")])
        prev = (h.get("device_policies") or {}).get("prevention") or {}
        policy = policies.get(str(prev.get("policy_id") or ""), {})
        applied = bool(prev.get("applied"))
        enabled = policy.get("enabled") if policy else None
        rfm = str(h.get("reduced_functionality_mode") or "").lower() == "yes"
        md: dict[str, Any] = {
            "hostname": fqdn or hostname,
            "os": h.get("platform_name"),
            "os_version": h.get("os_version"),
            "edr": "crowdstrike",
            "crowdstrike": {
                "device_id": h.get("device_id"), "agent_version": h.get("agent_version"),
                "status": h.get("status"), "last_seen": h.get("last_seen"),
                "product_type": h.get("product_type_desc"), "serial": h.get("serial_number"),
                "prevention_policy": policy.get("name") or prev.get("policy_id"),
                "prevention_applied": applied, "prevention_enabled": enabled,
                "reduced_functionality_mode": rfm, "tags": h.get("tags") or [],
                "external_ip": h.get("external_ip"),
            },
            "contained": h.get("status") in ("contained", "containment_pending") or None,
        }
        if hint["macs"]:
            md["mac"] = hint["macs"][0]
        item = device_asset(hint, SOURCE, md, create_unmatched=create_unmatched)
        if item is None:
            continue
        batch.assets.append(item)
        label = md["hostname"] or item["value"]
        ev = {"device_id": h.get("device_id"), "policy_id": prev.get("policy_id")}
        if not prev.get("policy_id") or not applied:
            batch.findings.append(device_finding(
                item, "crowdstrike.prevention_policy_not_applied", "medium",
                f"Falcon prevention policy not applied on {label}",
                "The host has no prevention policy applied (or it is still pending), so the "
                "sensor detects but does not block.",
                source=SOURCE, evidence=ev,
                remediation="Assign the host to a host group covered by a prevention policy "
                            "and confirm the sensor picks it up."))
        elif enabled is False:
            batch.findings.append(device_finding(
                item, "crowdstrike.prevention_policy_disabled", "high",
                f"Falcon prevention policy '{policy.get('name')}' on {label} is disabled",
                "The prevention policy assigned to this host is disabled.",
                source=SOURCE, evidence=ev,
                remediation="Enable the prevention policy or move the host to an enabled one."))
        if rfm:
            batch.findings.append(device_finding(
                item, "crowdstrike.reduced_functionality_mode", "medium",
                f"Falcon sensor on {label} runs in reduced functionality mode",
                "The sensor is in RFM (usually an unsupported kernel), so most protection "
                "is off.", source=SOURCE, evidence=ev,
                remediation="Update the sensor or move the host to a supported kernel."))
    return batch
