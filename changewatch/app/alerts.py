"""Alert rule matching + delivery.

After a detection pass, enabled ``alert_rules`` are matched against each new
``surface_change``. A match is the AND of three optional predicates — any
absent key is a wildcard:

  * ``change_types`` — change_type ∈ list
  * ``min_severity`` — change severity ≥ threshold
  * ``kinds``        — the change's asset_kind ∈ list

Matching rules deliver on their channel:

  * ``log``             — a structured log line; delivery recorded ``sent``.
  * ``webhook``/``slack`` — a single JSON POST to ``rule.target`` (slack uses the
    ``{"text": ...}`` shape, webhook uses ``{change, rule, ts}``), 5 s timeout;
    delivery recorded ``sent``/``failed`` with a truncated response snippet.

SAFETY: the ONLY URL this module ever contacts is ``rule.target`` — the opaque,
user-configured alert endpoint. It never derives a URL from change/asset data
and makes no other outbound request. Rules with no target are ``suppressed``.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from .config import Config
from .db import Database
from .detect import SEVERITY_ORDER

log = logging.getLogger("changewatch.alerts")

_RESPONSE_SNIPPET_MAX = 500

# A poster takes (url, payload, headers, timeout_s) and returns
# (ok, status, response_snippet). Injectable so tests never hit the network.
Poster = Callable[
    [str, dict[str, Any], dict[str, str], float],
    Awaitable[tuple[bool, Optional[int], str]],
]


def rule_matches(match: dict[str, Any], change: dict[str, Any]) -> bool:
    """True if ``change`` satisfies every present predicate in ``match``."""
    change_types = match.get("change_types")
    if change_types and change.get("change_type") not in change_types:
        return False

    min_sev = match.get("min_severity")
    if min_sev:
        want = SEVERITY_ORDER.get(min_sev, 0)
        have = SEVERITY_ORDER.get(change.get("severity", "info"), 0)
        if have < want:
            return False

    kinds = match.get("kinds")
    if kinds and change.get("asset_kind") not in kinds:
        return False

    return True


def _valid_target(target: Optional[str]) -> bool:
    return bool(target) and target.startswith(("http://", "https://"))


def _slack_text(change: dict[str, Any]) -> str:
    sev = change.get("severity", "info").upper()
    return f"[{sev}] {change.get('change_type')}: {change.get('summary', '')}"


class AlertDispatcher:
    def __init__(
        self,
        db: Database,
        cfg: Config,
        post_fn: Optional[Poster] = None,
    ) -> None:
        self.db = db
        self.cfg = cfg
        self._post_fn = post_fn

    def _headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.cfg.user_agent,
            "Content-Type": "application/json",
        }

    async def dispatch(self, changes: list[dict[str, Any]]) -> dict[str, int]:
        """Match every change against every enabled rule and deliver.

        Returns counters: matched rules fired, deliveries attempted/sent/failed/suppressed.
        """
        if not changes:
            return {"attempted": 0, "sent": 0, "failed": 0, "suppressed": 0, "fired_rules": 0}

        rules = await self.db.enabled_rules()
        counts = {"attempted": 0, "sent": 0, "failed": 0, "suppressed": 0}
        fired_rule_ids: set[str] = set()

        for change in changes:
            for rule in rules:
                if not rule_matches(rule.get("match") or {}, change):
                    continue
                status = await self._deliver(rule, change)
                counts["attempted"] += 1
                counts[status] = counts.get(status, 0) + 1
                fired_rule_ids.add(rule["id"])

        # One last_fired bump per rule that matched at least one change.
        for rid in fired_rule_ids:
            try:
                await self.db.bump_last_fired(rid)
            except Exception:  # pragma: no cover - defensive
                log.exception("bump_last_fired failed for %s", rid)

        counts["fired_rules"] = len(fired_rule_ids)
        return counts

    async def _deliver(self, rule: dict[str, Any], change: dict[str, Any]) -> str:
        """Deliver one change on one rule; record + return the status string."""
        channel = rule["channel"]
        change_id = change.get("id")

        if channel == "log":
            log.info(
                "alert",
                extra={"rule": rule["name"], "change": {
                    "id": change_id,
                    "change_type": change.get("change_type"),
                    "severity": change.get("severity"),
                    "summary": change.get("summary"),
                }},
            )
            # Also emit a plain structured line for log scrapers.
            log.info(json.dumps({
                "event": "alert_delivery",
                "channel": "log",
                "rule": rule["name"],
                "change_id": change_id,
                "change_type": change.get("change_type"),
                "severity": change.get("severity"),
                "summary": change.get("summary"),
            }, default=str))
            await self._record(rule, change_id, "sent", channel, "logged")
            return "sent"

        # webhook / slack — the only outbound traffic we ever make.
        target = rule.get("target")
        if not _valid_target(target):
            await self._record(
                rule, change_id, "suppressed", channel,
                "no valid target configured",
            )
            return "suppressed"

        ts = datetime.now(timezone.utc).isoformat()
        if channel == "slack":
            payload: dict[str, Any] = {"text": _slack_text(change)}
        else:  # webhook
            payload = {
                "change": change,
                "rule": {"id": rule["id"], "name": rule["name"], "channel": channel},
                "ts": ts,
            }

        poster = self._post_fn or _default_poster
        try:
            ok, http_status, snippet = await poster(
                target, payload, self._headers(), float(self.cfg.webhook_timeout_s)
            )
        except Exception as exc:  # network error, timeout, DNS, etc.
            await self._record(rule, change_id, "failed", channel, f"error: {exc}"[:_RESPONSE_SNIPPET_MAX])
            return "failed"

        status = "sent" if ok else "failed"
        resp = f"HTTP {http_status}: {snippet}" if http_status is not None else snippet
        await self._record(rule, change_id, status, channel, (resp or "")[:_RESPONSE_SNIPPET_MAX])
        return status

    async def _record(
        self,
        rule: dict[str, Any],
        change_id: Optional[str],
        status: str,
        channel: str,
        response: Optional[str],
    ) -> None:
        try:
            await self.db.record_delivery(rule["id"], change_id, status, channel, response)
        except Exception:  # pragma: no cover - defensive
            log.exception("record_delivery failed for rule %s", rule.get("id"))


async def _default_poster(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout_s: float,
) -> tuple[bool, Optional[int], str]:
    """Default poster: a single JSON POST to ``url`` via aiohttp.

    ``url`` is always ``rule.target``. This function is the sole outbound-call
    site in the service.
    """
    import aiohttp

    timeout = aiohttp.ClientTimeout(total=timeout_s)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, json=payload, headers=headers) as resp:
            body = await resp.text()
            ok = 200 <= resp.status < 300
            return ok, resp.status, body[:_RESPONSE_SNIPPET_MAX]
