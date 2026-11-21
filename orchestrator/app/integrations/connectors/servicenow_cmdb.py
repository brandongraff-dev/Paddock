"""ServiceNow CMDB (SOURCE, read-only): CIs -> ownership + crown-jewel criticality.

Reads, through the Table API:

* the configured CI tables (default ``cmdb_ci_computer``, which includes
  servers) -- name, IP, MAC, FQDN, owner, support group
* ``cmdb_ci_service`` -- business services and their ``busines_criticality``
  (sic: that is the real ServiceNow column name)
* ``cmdb_rel_ci`` -- which CIs each business service depends on

and maps them onto Paddock:

* each CI MERGES onto existing assets by IP / FQDN / host name / MAC and adds
  ``owner``, ``owner_team`` (support group), ``business_service(s)`` and the
  ``servicenow`` block; CIs serving a business service whose criticality is in
  ``crown_jewel_criticalities`` get ``metadata.crown_jewel = true``, which
  makes them attack-path targets;
* one ``asset_owners`` rule per support group (match on the tag
  ``owner:<group>``), so findings on those assets route to that team.

Credentials: a dedicated integration user with the ``itil`` read role or,
better, a custom role granting read ACLs on exactly the tables above (see
docs). Basic auth (username/password) or an OAuth bearer token.
"""
from __future__ import annotations

import base64
from typing import Any

from ..base import Capability, Connector, HealthResult, SourceBatch, register
from ._common import (
    SourceError,
    bool_cfg,
    checked_url,
    device_asset,
    int_cfg,
    merge_hint,
    owner_rule,
    owner_tag,
    request_json,
)

SOURCE = "integration:servicenow_cmdb"

_CI_FIELDS = (
    "sys_id,name,sys_class_name,ip_address,mac_address,fqdn,host_name,dns_domain,"
    "owned_by,owned_by.email,managed_by,assigned_to,support_group,support_group.email,"
    "operational_status,environment,os,os_version,serial_number"
)
_SVC_FIELDS = "sys_id,name,busines_criticality,owned_by,support_group,support_group.email,used_for"
_MAX_PAGES = 500


def _v(row: dict[str, Any], key: str) -> str | None:
    """Raw value of a field under sysparm_display_value=all (or plain)."""
    f = row.get(key)
    if isinstance(f, dict):
        f = f.get("value")
    return str(f) if f not in (None, "") else None


def _d(row: dict[str, Any], key: str) -> str | None:
    """Display value of a field under sysparm_display_value=all (or plain)."""
    f = row.get(key)
    if isinstance(f, dict):
        f = f.get("display_value") or f.get("value")
    return str(f) if f not in (None, "") else None


@register
class ServiceNowCmdbConnector(Connector):
    kind = "servicenow_cmdb"
    display_name = "ServiceNow CMDB"
    category = "cmdb"
    capabilities = frozenset({Capability.SOURCE})
    config_schema = {
        "type": "object",
        "required": ["instance_url"],
        "properties": {
            "instance_url": {"type": "string", "title": "https://<instance>.service-now.com"},
            "tables": {"type": "array", "items": {"type": "string"},
                       "default": ["cmdb_ci_computer"]},
            "query": {"type": "string", "description": "Encoded query, e.g. operational_status=1"},
            "include_services": {"type": "boolean", "default": True},
            "crown_jewel_criticalities": {"type": "array", "items": {"type": "string"},
                                          "default": ["1 - most critical"]},
            "page_size": {"type": "integer", "default": 1000, "maximum": 10000},
            "create_unmatched": {"type": "boolean", "default": True},
            "emit_owner_rules": {"type": "boolean", "default": True},
            "sync_interval_minutes": {"type": "integer", "default": 720, "minimum": 15},
        },
    }
    secret_fields = ("username", "password", "oauth_token")
    docs_url = "docs/INTEGRATIONS-CONTEXT.md#servicenow-cmdb"

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if self.secrets.get("oauth_token"):
            h["Authorization"] = f"Bearer {self.secrets['oauth_token']}"
        elif self.secrets.get("username") and self.secrets.get("password"):
            raw = f"{self.secrets['username']}:{self.secrets['password']}".encode()
            h["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        else:
            raise SourceError("username/password or oauth_token is required", retryable=False)
        return h

    async def _base(self) -> str:
        return await checked_url(str(self.config.get("instance_url") or ""),
                                 allow_private=bool_cfg(self.config, "allow_private", False))

    async def _table(self, base: str, table: str, fields: str, query: str | None,
                     hdr: dict[str, str]) -> list[dict[str, Any]]:
        if not table.replace("_", "").isalnum():
            raise SourceError(f"invalid table name {table!r}", retryable=False)
        size = int_cfg(self.config, "page_size", 1000, lo=1, hi=10000)
        out: list[dict[str, Any]] = []
        for page in range(_MAX_PAGES):
            params = {"sysparm_fields": fields, "sysparm_display_value": "all",
                      "sysparm_exclude_reference_link": "true", "sysparm_limit": str(size),
                      "sysparm_offset": str(page * size)}
            if query:
                params["sysparm_query"] = query
            body = await request_json(self.http, "GET", f"{base}/api/now/table/{table}",
                                      what=f"ServiceNow {table}", params=params, headers=hdr)
            rows = [r for r in (body or {}).get("result") or [] if isinstance(r, dict)]
            out.extend(rows)
            if len(rows) < size:
                break
        return out

    async def test(self) -> HealthResult:
        try:
            base = await self._base()
            hdr = self._headers()
            await request_json(self.http, "GET", f"{base}/api/now/table/cmdb_ci_computer",
                               what="ServiceNow cmdb_ci_computer",
                               params={"sysparm_limit": "1", "sysparm_fields": "sys_id"}, headers=hdr)
        except SourceError as exc:
            return HealthResult(ok=False, detail=str(exc))
        return HealthResult(ok=True, detail="ServiceNow CMDB readable")

    async def pull(self) -> SourceBatch:
        base = await self._base()
        hdr = self._headers()
        cis: list[dict[str, Any]] = []
        for table in self.config.get("tables") or ["cmdb_ci_computer"]:
            cis.extend(await self._table(base, str(table), _CI_FIELDS,
                                         self.config.get("query"), hdr))
        services: list[dict[str, Any]] = []
        rels: list[dict[str, Any]] = []
        if bool_cfg(self.config, "include_services", True):
            services = await self._table(base, "cmdb_ci_service", _SVC_FIELDS, None, hdr)
            rels = await self._table(base, "cmdb_rel_ci", "parent,child,type",
                                     "parent.sys_class_nameINSTANCEOFcmdb_ci_service", hdr)
        crit = [str(c).lower() for c in (self.config.get("crown_jewel_criticalities")
                                         or ["1 - most critical"])]
        return build_batch(cis, services, rels, crown_criticalities=crit,
                           create_unmatched=bool_cfg(self.config, "create_unmatched", True),
                           emit_owner_rules=bool_cfg(self.config, "emit_owner_rules", True))


def build_batch(cis: list[dict[str, Any]], services: list[dict[str, Any]],
                rels: list[dict[str, Any]], *, crown_criticalities: list[str],
                create_unmatched: bool = True, emit_owner_rules: bool = True) -> SourceBatch:
    batch = SourceBatch()
    svc_by_id = {_v(s, "sys_id"): s for s in services if _v(s, "sys_id")}
    svcs_of_ci: dict[str, list[dict[str, Any]]] = {}
    for r in rels:
        parent, child = _v(r, "parent"), _v(r, "child")
        if parent in svc_by_id and child:
            svcs_of_ci.setdefault(child, []).append(svc_by_id[parent])

    teams: dict[str, str | None] = {}
    for ci in cis:
        sys_id = _v(ci, "sys_id")
        fqdn = _d(ci, "fqdn")
        host = _d(ci, "host_name") or _d(ci, "name")
        if host and "." not in host and _d(ci, "dns_domain"):
            fqdn = fqdn or f"{host}.{_d(ci, 'dns_domain')}"
        hint = merge_hint(ips=[_d(ci, "ip_address")], hostnames=[fqdn, host, _d(ci, "name")],
                          macs=[_d(ci, "mac_address")])
        svcs = svcs_of_ci.get(sys_id or "", [])
        crits = [(_d(s, "busines_criticality") or "") for s in svcs]
        crown = any(c.lower() in crown_criticalities for c in crits)
        team = _d(ci, "support_group")
        if not team:
            for s in svcs:
                team = _d(s, "support_group")
                if team:
                    break
        owner = _d(ci, "owned_by.email") or _d(ci, "owned_by") or _d(ci, "managed_by")
        md: dict[str, Any] = {
            "hostname": fqdn or host,
            "owner": owner,
            "owner_team": team,
            "business_service": _d(svcs[0], "name") if svcs else None,
            "business_services": [_d(s, "name") for s in svcs] or None,
            "servicenow": {
                "sys_id": sys_id, "class": _v(ci, "sys_class_name"), "name": _d(ci, "name"),
                "operational_status": _d(ci, "operational_status"),
                "environment": _d(ci, "environment"), "os": _d(ci, "os"),
                "os_version": _d(ci, "os_version"), "serial": _d(ci, "serial_number"),
                "support_group": team, "owned_by": _d(ci, "owned_by"),
                "assigned_to": _d(ci, "assigned_to"), "criticalities": crits or None,
            },
        }
        if crown:
            md["crown_jewel"] = True
            md["criticality"] = next(c for c in crits if c.lower() in crown_criticalities)
        if hint["macs"]:
            md["mac"] = hint["macs"][0]
        if team and emit_owner_rules:
            md["tags"] = [owner_tag(team)]
            teams.setdefault(team, None)
            email = _d(ci, "support_group.email")
            if email:
                teams[team] = email
        item = device_asset(hint, SOURCE, md, create_unmatched=create_unmatched, confidence=85)
        if item is not None:
            batch.assets.append(item)

    for team, contact in sorted(teams.items()):
        batch.owners.append(owner_rule(team, source="servicenow_cmdb", contact=contact, priority=40))
    return batch
