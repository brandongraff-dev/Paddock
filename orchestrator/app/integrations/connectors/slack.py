"""Slack via an Incoming Webhook (Block Kit message).

The webhook URL *is* the credential, so it is a secret field, encrypted at
rest and never echoed. Setup: api.slack.com/apps -> Create app -> Incoming
Webhooks -> Add New Webhook to Workspace -> pick a channel -> copy the URL.
"""
from __future__ import annotations

from typing import Any

from .. import outbound
from ..base import Capability, Connector, DeliveryResult, Event, HealthResult, register
from ._render import SEV_EMOJI, asset_label, event_label, severity_label, truncate, when, why


def build_message(event: Event, *, mention: str | None = None) -> dict[str, Any]:
    sev = event.severity or ""
    emoji = SEV_EMOJI.get(sev, ":large_blue_circle:")
    prefix = f"{mention} " if mention and sev in ("high", "critical") else ""
    fallback = truncate(f"{prefix}[{severity_label(event)}] {event.title}", 300)
    fields = [
        {"type": "mrkdwn", "text": f"*Severity*\n{emoji} {severity_label(event)}"},
        {"type": "mrkdwn", "text": f"*Asset*\n{truncate(asset_label(event), 200)}"},
        {"type": "mrkdwn", "text": f"*Event*\n{truncate(event_label(event), 200)}"},
    ]
    if event.data.get("owner"):
        fields.append({"type": "mrkdwn", "text": f"*Owner*\n{truncate(event.data['owner'], 200)}"})
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": truncate(event.title, 150), "emoji": True}},
        {"type": "section", "fields": fields},
        {"type": "section", "text": {"type": "mrkdwn", "text": truncate(f"{prefix}*Why it matters:* {why(event)}", 2900)}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Paddock · `{event.type}` · {when(event)}"}]},
    ]
    if event.url:
        blocks.append({"type": "actions", "elements": [{
            "type": "button", "text": {"type": "plain_text", "text": "Open in Paddock"},
            "url": event.url, "action_id": "paddock_open",
        }]})
    return {"text": fallback, "blocks": blocks, "unfurl_links": False, "unfurl_media": False}


@register
class SlackConnector(Connector):
    kind = "slack"
    display_name = "Slack"
    category = "chat"
    capabilities = frozenset({Capability.NOTIFY})
    config_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "mention": {"type": "string", "maxLength": 64, "title": "Mention on high/critical",
                        "description": "Optional, e.g. <!here>, <!channel> or <@U012AB3CD>."},
        },
    }
    secret_fields = ("webhook_url",)
    required_secrets = ("webhook_url",)
    url_fields = ("webhook_url",)
    docs_url = "docs/INTEGRATIONS.md#slack"

    async def deliver(self, event: Event) -> DeliveryResult:
        url = self.secrets.get("webhook_url")
        if not url:
            return DeliveryResult(ok=False, retryable=False, detail="webhook URL is not set")
        msg = build_message(event, mention=self.config.get("mention"))
        result, resp = await outbound.post(self.http, url, json_body=msg, secrets=self.secrets.values())
        # Slack answers 404 no_service / 410 channel_is_archived for dead hooks.
        if resp is not None and resp.status_code in (404, 410):
            result.retryable = False
        return result

    async def test(self) -> HealthResult:
        res = await self.deliver(Event(type="integration.test", title="Paddock is connected to this channel",
                                       summary="Findings you subscribe to will be posted here.",
                                       severity="info"))
        return HealthResult(ok=res.ok, detail=res.detail)
