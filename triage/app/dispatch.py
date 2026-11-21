"""External ticket dispatch.

An ``internal`` ticket is DB-only and never dispatched. For ``webhook`` /
``github`` / ``jira`` tickets the ticket JSON is POSTed to a single configured
target URL and the response is parsed for an external id / url.

Target selection (the ONLY URL this module ever contacts):

  * the owner rule's ``contact`` when it is an http(s) URL, else
  * the service-level ``TRIAGE_WEBHOOK_URL``.

If neither is a usable URL the dispatch is a no-op failure and the caller keeps
the ticket ``internal`` with a note. 5 s timeout. The target is opaque and
user-configured; this module never derives a URL from asset/finding data and
makes no other outbound request. The poster is injectable so tests never touch
the network.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Awaitable, Callable, Optional

from .config import Config

log = logging.getLogger("triage.dispatch")

_RESPONSE_SNIPPET_MAX = 500

# A poster takes (url, payload, headers, timeout_s) and returns
# (ok, status, response_snippet). Injectable so tests never hit the network.
Poster = Callable[
    [str, dict[str, Any], dict[str, str], float],
    Awaitable[tuple[bool, Optional[int], str]],
]

# Response keys we try, in order, to pull an external id / url out of a ticket
# system's JSON reply (GitHub issues, Jira issues, generic webhooks).
_EXT_ID_KEYS = ("external_id", "id", "number", "key", "iid", "ticket_id")
_EXT_URL_KEYS = ("external_url", "html_url", "url", "self", "web_url", "ticket_url")


def _valid_url(target: Optional[str]) -> bool:
    return bool(target) and target.startswith(("http://", "https://"))


def choose_target(system: str, contact: Optional[str], webhook_url: Optional[str]) -> Optional[str]:
    """The target URL for a non-internal ticket, or ``None`` if none configured."""
    if system == "internal":
        return None
    if _valid_url(contact):
        return contact
    if _valid_url(webhook_url):
        return webhook_url
    return None


def parse_external(body: str) -> tuple[Optional[str], Optional[str]]:
    """Pull ``(external_id, external_url)`` out of a JSON response body."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    ext_id: Optional[str] = None
    for k in _EXT_ID_KEYS:
        if data.get(k) is not None:
            ext_id = str(data[k])
            break
    ext_url: Optional[str] = None
    for k in _EXT_URL_KEYS:
        v = data.get(k)
        if isinstance(v, str) and v:
            ext_url = v
            break
    return ext_id, ext_url


class TicketDispatcher:
    def __init__(self, cfg: Config, post_fn: Optional[Poster] = None) -> None:
        self.cfg = cfg
        self._post_fn = post_fn

    def _headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.cfg.user_agent,
            "Content-Type": "application/json",
        }

    async def dispatch(
        self,
        ticket: dict[str, Any],
        system: str,
        contact: Optional[str],
    ) -> dict[str, Any]:
        """POST ``ticket`` to its configured target.

        Returns ``{"ok", "target", "note", "external_id"?, "external_url"?,
        "status"?}``. ``ok`` is False (with a note, and nothing sent) when no
        target is configured; the caller then keeps the ticket ``internal``.
        """
        target = choose_target(system, contact, self.cfg.webhook_url)
        if target is None:
            return {"ok": False, "target": None,
                    "note": f"{system}: no target URL configured"}

        payload = _ticket_payload(ticket)
        poster = self._post_fn or _default_poster
        try:
            ok, status, snippet = await poster(
                target, payload, self._headers(), float(self.cfg.webhook_timeout_s)
            )
        except Exception as exc:  # network error, timeout, DNS, etc.
            return {"ok": False, "target": target,
                    "note": f"error: {exc}"[:_RESPONSE_SNIPPET_MAX]}

        if not ok:
            resp = f"HTTP {status}: {snippet}" if status is not None else (snippet or "")
            return {"ok": False, "target": target,
                    "status": status, "note": resp[:_RESPONSE_SNIPPET_MAX]}

        ext_id, ext_url = parse_external(snippet or "")
        return {
            "ok": True,
            "target": target,
            "status": status,
            "external_id": ext_id,
            "external_url": ext_url,
        }


def _ticket_payload(ticket: dict[str, Any]) -> dict[str, Any]:
    """A JSON-serialisable view of the ticket for the outbound POST body."""
    fields = (
        "id", "finding_id", "title", "severity", "owner_team", "contact",
        "system", "status", "sla_hours", "sla_due", "opened_at",
    )
    out: dict[str, Any] = {}
    for f in fields:
        if f not in ticket:
            continue
        v = ticket[f]
        if hasattr(v, "isoformat"):
            v = v.isoformat()
        out[f] = v
    return out


async def _default_poster(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout_s: float,
) -> tuple[bool, Optional[int], str]:
    """Default poster: a single JSON POST to ``url`` via aiohttp.

    ``url`` is always the user-configured ticket target. This is the sole
    outbound-call site in the service.
    """
    import aiohttp

    timeout = aiohttp.ClientTimeout(total=timeout_s)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, json=payload, headers=headers) as resp:
            body = await resp.text()
            ok = 200 <= resp.status < 300
            return ok, resp.status, body[:_RESPONSE_SNIPPET_MAX]
