"""Microsoft Defender for Endpoint + Intune (SOURCE, read-only).

Client-credentials (app-only) OAuth against Entra ID, then:

* MDE  ``GET /api/machines``                       -- devices, OS/build, exposure
                                                     level, risk score, sensor health,
                                                     IPs + MACs
* Graph ``GET /v1.0/deviceManagement/managedDevices`` -- Intune managed/compliant
                                                     flags, primary user (UPN)

Records are joined on the Entra device id (``aadDeviceId`` /
``azureADDeviceId``), falling back to the host name, and MERGED onto assets
Paddock already knows by IP / hostname / MAC (see ``_common`` merge hints).
The primary user becomes ``metadata.owner``.

Findings (rule_source ``policy``): Intune non-compliant, MDE exposure level
High, MDE risk score High, onboarded sensor not reporting.

Permissions (application, admin-consented): MDE ``Machine.Read.All``;
Graph ``DeviceManagementManagedDevices.Read.All``. Nothing writable.
"""
from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlsplit

from ..base import Capability, Connector, HealthResult, SourceBatch, register
from ._common import (
    SourceError,
    bool_cfg,
    checked_url,
    device_asset,
    device_finding,
    merge_hint,
    owner_rule,
    owner_tag,
    request_json,
)

SOURCE = "integration:microsoft_defender"

_INTUNE_FIELDS = (
    "id,deviceName,operatingSystem,osVersion,complianceState,managementState,"
    "managedDeviceOwnerType,userPrincipalName,emailAddress,azureADDeviceId,"
    "wiFiMacAddress,ethernetMacAddress,serialNumber,lastSyncDateTime,isEncrypted,"
    "model,manufacturer,jailBroken"
)
_INACTIVE = {"Inactive", "ImpairedCommunication", "NoSensorData", "NoSensorDataImpairedCommunication"}
_MAX_PAGES = 200


@register
class MicrosoftDefenderConnector(Connector):
    kind = "microsoft_defender"
    display_name = "Microsoft Defender for Endpoint + Intune"
    category = "edr"
    capabilities = frozenset({Capability.SOURCE})
    config_schema = {
        "type": "object",
        "required": ["tenant_id", "client_id"],
        "properties": {
            "tenant_id": {"type": "string", "title": "Entra tenant id"},
            "client_id": {"type": "string", "title": "App registration (client) id"},
            "include_defender": {"type": "boolean", "default": True},
            "include_intune": {"type": "boolean", "default": True},
            "login_url": {"type": "string", "default": "https://login.microsoftonline.com"},
            "graph_url": {"type": "string", "default": "https://graph.microsoft.com"},
            "defender_url": {"type": "string", "default": "https://api.securitycenter.microsoft.com"},
            "create_unmatched": {"type": "boolean", "default": True},
            "emit_owner_rules": {"type": "boolean", "default": False},
            "sync_interval_minutes": {"type": "integer", "default": 360, "minimum": 15},
        },
    }
    secret_fields = ("client_secret",)
    docs_url = "docs/INTEGRATIONS-CONTEXT.md#microsoft-defender-for-endpoint--intune"

    # ------------------------------------------------------------------ #
    def _cfg_url(self, key: str, default: str) -> str:
        return str(self.config.get(key) or default)

    async def _token(self, resource: str) -> str:
        tenant = str(self.config.get("tenant_id") or "").strip()
        client_id = str(self.config.get("client_id") or "").strip()
        secret = self.secrets.get("client_secret")
        if not tenant or not client_id or not secret:
            raise SourceError("tenant_id, client_id and client_secret are required", retryable=False)
        if "/" in tenant or "?" in tenant:
            raise SourceError("tenant_id is malformed", retryable=False)
        login = await checked_url(self._cfg_url("login_url", "https://login.microsoftonline.com"),
                                  allow_private=False)
        body = await request_json(
            self.http, "POST", f"{login}/{tenant}/oauth2/v2.0/token", what="Entra token request",
            data={"client_id": client_id, "client_secret": secret,
                  "grant_type": "client_credentials", "scope": f"{resource}/.default"},
        )
        token = (body or {}).get("access_token")
        if not token:
            raise SourceError("Entra token response had no access_token", retryable=False)
        return str(token)

    async def _odata(self, url: str, token: str, what: str) -> list[dict[str, Any]]:
        host = urlsplit(url).hostname
        out: list[dict[str, Any]] = []
        pages = 0
        while url and pages < _MAX_PAGES:
            body = await request_json(self.http, "GET", url, what=what,
                                      headers={"Authorization": f"Bearer {token}"})
            out.extend(v for v in (body or {}).get("value") or [] if isinstance(v, dict))
            nxt = (body or {}).get("@odata.nextLink")
            # Never follow a nextLink off the host we were configured for.
            url = nxt if nxt and urlsplit(nxt).hostname == host else None
            pages += 1
        return out

    # ------------------------------------------------------------------ #
    async def test(self) -> HealthResult:
        try:
            if bool_cfg(self.config, "include_defender", True):
                base = await checked_url(self._cfg_url("defender_url",
                                                       "https://api.securitycenter.microsoft.com"),
                                         allow_private=False)
                tok = await self._token(base)
                await request_json(self.http, "GET", f"{base}/api/machines?$top=1",
                                   what="MDE machines", headers={"Authorization": f"Bearer {tok}"})
            if bool_cfg(self.config, "include_intune", True):
                graph = await checked_url(self._cfg_url("graph_url", "https://graph.microsoft.com"),
                                          allow_private=False)
                tok = await self._token(graph)
                await request_json(self.http, "GET",
                                   f"{graph}/v1.0/deviceManagement/managedDevices?$top=1&$select=id",
                                   what="Intune managedDevices",
                                   headers={"Authorization": f"Bearer {tok}"})
        except SourceError as exc:
            return HealthResult(ok=False, detail=str(exc))
        return HealthResult(ok=True, detail="Defender/Intune reachable with read permissions")

    async def pull(self) -> SourceBatch:
        machines: list[dict[str, Any]] = []
        devices: list[dict[str, Any]] = []
        if bool_cfg(self.config, "include_defender", True):
            base = await checked_url(self._cfg_url("defender_url",
                                                   "https://api.securitycenter.microsoft.com"),
                                     allow_private=False)
            tok = await self._token(base)
            machines = await self._odata(f"{base}/api/machines", tok, "MDE machines")
        if bool_cfg(self.config, "include_intune", True):
            graph = await checked_url(self._cfg_url("graph_url", "https://graph.microsoft.com"),
                                      allow_private=False)
            tok = await self._token(graph)
            devices = await self._odata(
                f"{graph}/v1.0/deviceManagement/managedDevices?$select={_INTUNE_FIELDS}",
                tok, "Intune managedDevices")
        return build_batch(machines, devices,
                           create_unmatched=bool_cfg(self.config, "create_unmatched", True),
                           emit_owner_rules=bool_cfg(self.config, "emit_owner_rules", False))


# --------------------------------------------------------------------------- #
# Pure mapping (unit-tested without HTTP)
# --------------------------------------------------------------------------- #

def _short(name: Optional[str]) -> str:
    return (name or "").split(".")[0].lower()


def build_batch(machines: list[dict[str, Any]], devices: list[dict[str, Any]], *,
                create_unmatched: bool = True, emit_owner_rules: bool = False) -> SourceBatch:
    batch = SourceBatch()
    by_aad = {d.get("azureADDeviceId"): d for d in devices
              if d.get("azureADDeviceId") and d["azureADDeviceId"] != "00000000-0000-0000-0000-000000000000"}
    by_name = {_short(d.get("deviceName")): d for d in devices if d.get("deviceName")}
    used: set[str] = set()
    owners: set[str] = set()

    pairs: list[tuple[Optional[dict[str, Any]], Optional[dict[str, Any]]]] = []
    for m in machines:
        d = by_aad.get(m.get("aadDeviceId")) or by_name.get(_short(m.get("computerDnsName")))
        if d is not None:
            used.add(str(d.get("id")))
        pairs.append((m, d))
    for d in devices:
        if str(d.get("id")) not in used:
            pairs.append((None, d))

    for m, d in pairs:
        m = m or {}
        d = d or {}
        # Only the primary interface (the one carrying lastIpAddress): secondary
        # NICs (docker/hyper-v bridges, VPN adapters) share addresses across
        # thousands of machines and would merge unrelated devices together.
        primary = m.get("lastIpAddress")
        nic_macs = [r.get("macAddress") for r in m.get("ipAddresses") or []
                    if isinstance(r, dict) and primary and r.get("ipAddress") == primary]
        hint = merge_hint(
            ips=[primary],
            hostnames=[m.get("computerDnsName"), d.get("deviceName")],
            macs=[*nic_macs, d.get("wiFiMacAddress"), d.get("ethernetMacAddress")],
        )
        owner = d.get("userPrincipalName") or d.get("emailAddress") or None
        compliance = d.get("complianceState") if d else None
        md: dict[str, Any] = {
            "hostname": (m.get("computerDnsName") or d.get("deviceName") or None),
            "os": m.get("osPlatform") or d.get("operatingSystem"),
            "os_version": m.get("osVersion") or d.get("osVersion"),
            "managed": bool(d) and d.get("managementState", "managed") == "managed",
            "compliant": (compliance == "compliant") if compliance else None,
            "owner": owner,
            "exposure_level": m.get("exposureLevel"),
            "edr": "microsoft_defender" if m else None,
        }
        if m:
            md["mde"] = {
                "id": m.get("id"), "os_build": m.get("osBuild"), "version": m.get("version"),
                "health_status": m.get("healthStatus"), "risk_score": m.get("riskScore"),
                "exposure_level": m.get("exposureLevel"), "onboarding": m.get("onboardingStatus"),
                "last_seen": m.get("lastSeen"), "rbac_group": m.get("rbacGroupName"),
                "tags": m.get("machineTags") or [], "aad_device_id": m.get("aadDeviceId"),
            }
        if d:
            md["intune"] = {
                "id": d.get("id"), "compliance_state": compliance,
                "management_state": d.get("managementState"),
                "ownership": d.get("managedDeviceOwnerType"), "encrypted": d.get("isEncrypted"),
                "jailbroken": d.get("jailBroken"), "last_sync": d.get("lastSyncDateTime"),
                "model": d.get("model"), "manufacturer": d.get("manufacturer"),
                "serial": d.get("serialNumber"),
            }
        if hint["macs"]:
            md["mac"] = hint["macs"][0]
        if owner and emit_owner_rules:
            md["tags"] = [owner_tag(owner)]
            owners.add(owner)
        item = device_asset(hint, SOURCE, md, create_unmatched=create_unmatched)
        if item is None:
            continue
        batch.assets.append(item)

        label = md["hostname"] or item["value"]
        for rule_id, sev, title, desc, cond in (
            ("msdefender.device_noncompliant", "medium",
             f"{label} is non-compliant in Intune",
             "Intune reports this device does not meet the tenant's compliance policies "
             "(patch level, encryption, AV, OS version...).",
             compliance == "noncompliant"),
            ("msdefender.high_exposure", "medium",
             f"{label} has a High exposure level in Defender",
             "Defender Vulnerability Management rates this device's exposure as High "
             "(missing security updates / misconfigurations).",
             m.get("exposureLevel") == "High"),
            ("msdefender.high_risk", "high",
             f"{label} has a High risk score in Defender",
             "Defender for Endpoint has active alerts raising this device's risk score to High.",
             m.get("riskScore") == "High"),
            ("msdefender.sensor_not_reporting", "low",
             f"Defender sensor on {label} is not reporting",
             f"Sensor health is '{m.get('healthStatus')}'; the device is effectively unmonitored.",
             bool(m) and m.get("healthStatus") in _INACTIVE),
        ):
            if not cond:
                continue
            batch.findings.append(device_finding(
                item, rule_id, sev, title, desc, source=SOURCE,
                evidence={"mde_id": m.get("id"), "intune_id": d.get("id")}))

    for o in sorted(owners):
        batch.owners.append(owner_rule(o, source="microsoft_defender", contact=o, priority=80))
    return batch
