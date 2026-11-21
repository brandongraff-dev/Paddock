"""Microsoft Teams via a Workflows (Power Automate) webhook, as an Adaptive Card.

Office 365 "Incoming Webhook" connectors are retired; Teams now uses the
Workflows app: in the channel -> ... -> Workflows -> "Post to a channel when a
webhook request is received" -> copy the URL. The URL embeds a signature
(``sig=``), so it is a secret field.
"""
from __future__ import annotations

from typing import Any

from .. import outbound
from ..base import Capability, Connector, DeliveryResult, Event, HealthResult, register
from ._render import facts, truncate, when, why

_SEV_COLOR = {"critical": "Attention", "high": "Attention", "medium": "Warning", "low": "Default", "info": "Default"}


def build_card(event: Event) -> dict[str, Any]:
    body: list[dict[str, Any]] = [
        {"type": "TextBlock", "text": "PADDOCK", "size": "Small", "weight": "Bolder", "isSubtle": True,
         "spacing": "None"},
        {"type": "TextBlock", "text": truncate(event.title, 300), "size": "Medium", "weight": "Bolder",
         "wrap": True, "color": _SEV_COLOR.get(event.severity or "", "Default")},
        {"type": "FactSet", "facts": [{"title": k, "value": truncate(v, 300)} for k, v in facts(event)]
                                    + [{"title": "When", "value": when(event)}]},
        {"type": "TextBlock", "text": truncate(why(event), 2000), "wrap": True},
    ]
    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "msteams": {"width": "Full"},
        "body": body,
    }
    if event.url:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Open in Paddock", "url": event.url}]
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": None,
            "content": card,
        }],
    }


@register
class TeamsConnector(Connector):
    kind = "teams"
    display_name = "Microsoft Teams"
    category = "chat"
    capabilities = frozenset({Capability.NOTIFY})
    config_schema = {"type": "object", "additionalProperties": False, "properties": {}}
    secret_fields = ("webhook_url",)
    required_secrets = ("webhook_url",)
    url_fields = ("webhook_url",)
    docs_url = "docs/INTEGRATIONS.md#microsoft-teams"

    async def deliver(self, event: Event) -> DeliveryResult:
        url = self.secrets.get("webhook_url")
        if not url:
            return DeliveryResult(ok=False, retryable=False, detail="workflow URL is not set")
        result, _ = await outbound.post(self.http, url, json_body=build_card(event), secrets=self.secrets.values())
        return result

    async def test(self) -> HealthResult:
        res = await self.deliver(Event(type="integration.test", title="Paddock is connected to this channel",
                                       summary="Findings you subscribe to will be posted here.",
                                       severity="info"))
        return HealthResult(ok=res.ok, detail=res.detail)
