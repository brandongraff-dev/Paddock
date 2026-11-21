"""PagerDuty Events API v2.

* ``dedup_key`` is the finding id (chain id / attack-path fingerprint / scan id
  for those events), so re-deliveries and later updates fold into ONE incident.
* ``finding.resolved`` and ``finding.accepted`` send ``event_action=resolve``
  for that key; everything else triggers.
* The Test button triggers an ``info`` alert with a throwaway key and resolves
  it immediately, so it never leaves an open incident behind.

Setup: PagerDuty -> Service -> Integrations -> Add integration ->
"Events API V2" -> copy the Integration Key (routing key).
"""
from __future__ import annotations

from typing import Any

from .. import outbound
from ..base import Capability, Connector, DeliveryResult, Event, HealthResult, register
from ._render import asset_label, truncate, why

ENDPOINTS = {
    "us": "https://events.pagerduty.com/v2/enqueue",
    "eu": "https://events.eu.pagerduty.com/v2/enqueue",
}
_PD_SEVERITY = {"critical": "critical", "high": "error", "medium": "warning", "low": "info", "info": "info"}
RESOLVE_TYPES = frozenset({"finding.resolved", "finding.accepted"})


def dedup_key(event: Event) -> str:
    d = event.data
    for k in ("finding_id", "chain_id", "fingerprint", "attack_path_id", "scan_id", "asset_id"):
        if d.get(k):
            prefix = "" if k == "finding_id" else f"{k.removesuffix('_id')}:"
            return f"{prefix}{d[k]}"
    return event.id


def build_payload(event: Event, routing_key: str, *, source: str = "paddock",
                  action: str | None = None, key: str | None = None) -> dict[str, Any]:
    action = action or ("resolve" if event.type in RESOLVE_TYPES else "trigger")
    body: dict[str, Any] = {
        "routing_key": routing_key,
        "event_action": action,
        "dedup_key": key or dedup_key(event),
    }
    if action == "trigger":
        d = event.data
        body["payload"] = {
            "summary": truncate(event.title, 1024),
            "source": truncate(d.get("asset") or source, 255),
            "severity": _PD_SEVERITY.get(event.severity or "", "warning"),
            "timestamp": event.occurred_at.isoformat(),
            "component": truncate(asset_label(event), 255),
            "group": d.get("asset_kind") or "paddock",
            "class": event.type,
            "custom_details": {
                "why": why(event),
                "event_id": event.id,
                **{k: v for k, v in d.items() if v not in (None, "", [])},
            },
        }
        body["client"] = "Paddock"
        if event.url:
            body["client_url"] = event.url
            body["links"] = [{"href": event.url, "text": "Open in Paddock"}]
    return body


@register
class PagerDutyConnector(Connector):
    kind = "pagerduty"
    display_name = "PagerDuty"
    category = "paging"
    capabilities = frozenset({Capability.NOTIFY})
    config_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "region": {"type": "string", "enum": ["us", "eu"], "default": "us", "title": "Service region"},
            "source": {"type": "string", "maxLength": 255, "default": "paddock",
                       "title": "Default source", "description": "Used when an event has no asset."},
        },
    }
    secret_fields = ("routing_key",)
    required_secrets = ("routing_key",)
    docs_url = "docs/INTEGRATIONS.md#pagerduty"

    @property
    def endpoint(self) -> str:
        return ENDPOINTS.get(self.config.get("region") or "us", ENDPOINTS["us"])

    async def _send(self, body: dict[str, Any]) -> DeliveryResult:
        result, resp = await outbound.post(self.http, self.endpoint, json_body=body, secrets=self.secrets.values())
        if result.ok:
            result.external_id = body["dedup_key"]
        return result

    async def deliver(self, event: Event) -> DeliveryResult:
        key = self.secrets.get("routing_key")
        if not key:
            return DeliveryResult(ok=False, retryable=False, detail="routing key is not set")
        source = self.config.get("source") or "paddock"
        if event.type == "integration.test":
            tkey = f"paddock-test-{event.id}"
            res = await self._send(build_payload(event, key, source=source, action="trigger", key=tkey))
            if res.ok:
                res2 = await self._send(build_payload(event, key, source=source, action="resolve", key=tkey))
                if not res2.ok:
                    res2.detail = f"test alert triggered but resolve failed: {res2.detail}"
                    return res2
                res.detail = f"{res.detail} (test alert triggered and resolved)"
            return res
        return await self._send(build_payload(event, key, source=source))

    async def test(self) -> HealthResult:
        res = await self.deliver(Event(type="integration.test", title="Paddock PagerDuty test",
                                       summary="Triggered and immediately resolved by the Test button.",
                                       severity="info"))
        return HealthResult(ok=res.ok, detail=res.detail)
