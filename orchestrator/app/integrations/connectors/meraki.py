"""Cisco Meraki (ACTION): quarantine / release a client via the Dashboard API.

Quarantine applies a client policy on ONE network:

* ``quarantine_policy = group_policy`` (default) -- ``devicePolicy: "Group policy"``
  with ``group_policy_id`` (create a "Quarantine" group policy in Dashboard that
  denies everything except, say, DHCP/DNS and your remediation portal);
* ``quarantine_policy = blocked`` -- ``devicePolicy: "Blocked"``.

Before changing anything the client's CURRENT policy is read
(``GET /networks/{id}/clients/{mac}/policy``) and returned as the revert plan,
so release restores exactly what was there (falling back to ``Normal``).

Auth: a Dashboard API key (``Authorization: Bearer``) of an admin scoped to
the target network(s) only -- *network* admin with full access on those
networks, NOT organization admin. ``test()`` reads the network only.
Redirects are followed only to ``*.meraki.com`` / ``*.meraki.cn`` shard hosts
and every hop passes netsafety.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

from ..base import HealthResult, register
from ._common import ActionResult, SourceError, checked_url, request_json
from ._network import NetworkActionConnector

_FOLLOW = ("meraki.com", "meraki.cn", "meraki.ca", "gov-meraki.com")
_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@register
class MerakiConnector(NetworkActionConnector):
    kind = "meraki"
    display_name = "Cisco Meraki"
    config_schema = {
        "type": "object",
        "required": ["network_id"],
        "properties": {
            "base_url": {"type": "string", "default": "https://api.meraki.com/api/v1"},
            "network_id": {"type": "string", "title": "Network id (L_... / N_...)"},
            "quarantine_policy": {"type": "string", "enum": ["group_policy", "blocked"],
                                  "default": "group_policy"},
            "group_policy_id": {"type": "string",
                                "description": "Id of the quarantine group policy"},
            "protected_macs": {"type": "array", "items": {"type": "string"}},
        },
    }
    secret_fields = ("api_key",)
    docs_url = "docs/INTEGRATIONS-CONTEXT.md#cisco-meraki"

    async def _ctx(self) -> tuple[str, str, dict[str, str]]:
        base = await checked_url(str(self.config.get("base_url") or "https://api.meraki.com/api/v1"),
                                 allow_private=self._allow_private())
        nid = str(self.config.get("network_id") or "")
        if not _ID.match(nid):
            raise SourceError("network_id is missing or malformed", retryable=False)
        key = self.secrets.get("api_key")
        if not key:
            raise SourceError("api_key is required", retryable=False)
        return base, nid, {"Authorization": f"Bearer {key}", "Accept": "application/json"}

    async def _req(self, method: str, url: str, hdr: dict[str, str], what: str,
                   json: Any = None) -> Any:
        return await request_json(self.http, method, url, what=what, headers=hdr, json=json,
                                  follow_suffixes=_FOLLOW, allow_private=self._allow_private())

    async def test(self) -> HealthResult:
        try:
            base, nid, hdr = await self._ctx()
            net = await self._req("GET", f"{base}/networks/{nid}", hdr, "Meraki network")
        except SourceError as exc:
            return HealthResult(ok=False, detail=str(exc))
        return HealthResult(ok=True, detail=f"Meraki network {(net or {}).get('name') or nid!r} reachable")

    def _is_quarantine(self, policy: Mapping[str, Any]) -> bool:
        mode = str(self.config.get("quarantine_policy") or "group_policy")
        if mode == "blocked":
            return policy.get("devicePolicy") == "Blocked"
        return (policy.get("devicePolicy") == "Group policy"
                and policy.get("groupPolicyId") == self.config.get("group_policy_id"))

    async def _act(self, typ: str, mac: str, dry_run: bool,
                   action: Mapping[str, Any]) -> ActionResult:
        base, nid, hdr = await self._ctx()
        url = f"{base}/networks/{nid}/clients/{mac}/policy"
        current = await self._req("GET", url, hdr, "Meraki client policy") or {}
        prior = {k: current[k] for k in ("devicePolicy", "groupPolicyId") if current.get(k)}
        if typ == "quarantine_device":
            mode = str(self.config.get("quarantine_policy") or "group_policy")
            if mode == "blocked":
                body: dict[str, Any] = {"devicePolicy": "Blocked"}
            else:
                gid = str(self.config.get("group_policy_id") or "")
                if not _ID.match(gid):
                    raise SourceError("group_policy_id is required for quarantine_policy="
                                      "group_policy", retryable=False)
                body = {"devicePolicy": "Group policy", "groupPolicyId": gid}
        else:
            # Restore exactly what was there before the quarantine; if there is
            # no plan (a direct release) or the "prior" IS the quarantine
            # policy, fall back to Normal.
            plan_prior = dict((action.get("revert") or {}).get("prior") or {})
            if not plan_prior.get("devicePolicy") or self._is_quarantine(plan_prior):
                plan_prior = {"devicePolicy": "Normal"}
            body = plan_prior
        planned = [f"PUT /networks/{nid}/clients/{mac}/policy {body.get('devicePolicy')}"]
        if dry_run:
            return ActionResult(ok=True, dry_run=True, planned=planned,
                                detail=f"dry run: {mac} policy {prior.get('devicePolicy', '?')} "
                                       f"-> {body.get('devicePolicy')}")
        await self._req("PUT", url, hdr, "Meraki set client policy", json=body)
        revert = {"prior": prior or {"devicePolicy": "Normal"}} if typ == "quarantine_device" else {}
        return ActionResult(ok=True, planned=planned, external_id=mac, revert=revert,
                            detail=f"{mac} policy set to {body.get('devicePolicy')}")
