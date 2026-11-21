"""Shared, connector-agnostic rendering of an ``Event`` for humans."""
from __future__ import annotations

from datetime import timezone
from typing import Any

from ..base import EVENT_TYPES, Event

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
SEV_EMOJI = {"critical": ":red_circle:", "high": ":large_orange_circle:", "medium": ":large_yellow_circle:",
             "low": ":white_circle:", "info": ":information_source:"}
SEV_HEX = {"critical": "#D5493C", "high": "#E67350", "medium": "#EE9D72", "low": "#F3C6A5", "info": "#8A8175"}


def severity_label(event: Event) -> str:
    return SEV_LABEL.get(event.severity or "", "—")


def asset_label(event: Event) -> str:
    d = event.data
    a = d.get("asset") or d.get("target") or d.get("asset_id")
    if not a:
        return "—"
    kind = d.get("asset_kind")
    return f"{a} ({kind})" if kind else str(a)


def event_label(event: Event) -> str:
    return EVENT_TYPES.get(event.type, event.type)


def why(event: Event) -> str:
    """The one-paragraph 'why this matters' line."""
    if event.summary:
        return event.summary
    return event_label(event)


def facts(event: Event) -> list[tuple[str, str]]:
    out = [("Severity", severity_label(event)), ("Asset", asset_label(event)), ("Event", event.type)]
    d = event.data
    if d.get("owner"):
        out.append(("Owner", str(d["owner"])))
    if d.get("rule_id"):
        out.append(("Rule", str(d["rule_id"])))
    return out


def when(event: Event) -> str:
    ts = event.occurred_at
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc)
    return ts.strftime("%Y-%m-%d %H:%M UTC")


def truncate(text: Any, n: int) -> str:
    s = str(text or "")
    return s if len(s) <= n else s[: n - 1] + "…"
