"""Shared plumbing for the TICKET connectors (Jira, ServiceNow, Linear).

A ``TicketConnector`` turns finding lifecycle events into ticket operations::

    finding.opened    -> create (or refresh the existing ticket; reopen if done)
    finding.updated   -> update fields (create if the finding has no ticket yet)
    finding.resolved  -> transition to done      (no-op if already done)
    finding.reopened  -> transition back to open (create if missing)
    finding.accepted  -> comment on the ticket

Idempotency, in order of preference:

1. **Link table** -- when the connector is ``bind()``-ed to its integration row
   and a DB pool, ``integration_links`` is consulted before creating and
   written after (see ``app.integrations.links``).
2. **Remote marker** -- every ticket carries ``paddock-<finding_id>`` (a Jira
   label, a ServiceNow ``correlation_id``, a line in the Linear description),
   so an unbound connector (or one whose link row was lost) finds the ticket
   it created instead of opening a duplicate.
3. **State convergence** -- transitions are skipped when the remote already
   is in the target state, so a retried or echoed event changes nothing.

Loop prevention: an event whose ``data["origin"]`` names this integration
(``integration_id``) or this connector kind + the target ticket
(``kind`` + ``external_id``) was caused BY this ticket system and is not sent
back to it. ``app.integrations.ticketing.apply_inbound`` sets that marker.

Event ``data`` keys read (all optional except a finding id):
``finding_id`` (or ``finding.id`` / ``id``), ``asset`` (string or object with
``value``/``name``/``identifier``), ``asset_id``, ``description``, ``impact``
(why it matters), ``remediation``, ``rule_id``, ``status``, ``cvss``,
``epss``, ``kev``, ``url``, ``origin``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from .. import netsafety
from ..base import (
    Capability,
    Connector,
    DeliveryResult,
    Event,
    HealthResult,
    InboundUpdate,
)

log = logging.getLogger(__name__)

MARKER_PREFIX = "paddock-"
COMMENT_PREFIX = "[Paddock]"
FINDING_EVENTS = frozenset({
    "finding.opened", "finding.updated", "finding.resolved",
    "finding.reopened", "finding.accepted",
})
# The statuses an InboundUpdate may carry (``app.integrations.ticketing``
# degrades accepted/false_positive when the DB constraint lacks them).
PADDOCK_STATUSES = frozenset({"open", "triaged", "fixed", "accepted", "false_positive"})

# Normalised remote state categories used for convergence checks.
CAT_NEW, CAT_ACTIVE, CAT_DONE = "new", "active", "done"

_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_MAX_ERR = 300


# --------------------------------------------------------------------------- #
# Small value types
# --------------------------------------------------------------------------- #

@dataclass
class TicketInboundUpdate(InboundUpdate):
    """``InboundUpdate`` plus the raw remote status (stored on the link)."""

    external_status: Optional[str] = None
    external_url: Optional[str] = None


@dataclass
class ExternalRef:
    external_id: str
    external_url: Optional[str] = None
    status: Optional[str] = None          # raw remote status name/value
    category: Optional[str] = None        # CAT_NEW | CAT_ACTIVE | CAT_DONE
    display: Optional[str] = None         # human key, e.g. SEC-12 / INC0010001


class RemoteError(Exception):
    """An expected remote failure. ``detail`` never contains secrets."""

    def __init__(self, detail: str, status_code: Optional[int] = None, retryable: bool = True) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code
        self.retryable = retryable


class NotFound(RemoteError):
    def __init__(self, detail: str = "not found") -> None:
        super().__init__(detail, 404, retryable=False)


@dataclass
class FindingView:
    """The finding fields a ticket needs, pulled defensively from an Event."""

    finding_id: Optional[str]
    title: str
    severity: str = "medium"
    status: Optional[str] = None
    asset: Optional[str] = None
    asset_id: Optional[str] = None
    description: str = ""
    impact: str = ""
    remediation: str = ""
    rule_id: Optional[str] = None
    url: Optional[str] = None
    cvss: Any = None
    epss: Any = None
    kev: Any = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def marker(self) -> str:
        return f"{MARKER_PREFIX}{self.finding_id}"

    @property
    def why(self) -> str:
        return self.impact or self.description or "No impact statement recorded."

    @classmethod
    def from_event(cls, event: Event) -> "FindingView":
        data = dict(event.data or {})
        finding = data.get("finding") if isinstance(data.get("finding"), Mapping) else {}
        merged: dict[str, Any] = {**finding, **{k: v for k, v in data.items() if k != "finding"}}
        fid = merged.get("finding_id") or finding.get("id") or data.get("id")
        fid = str(fid) if fid and _UUID_RE.fullmatch(str(fid)) else None
        asset = merged.get("asset")
        if isinstance(asset, Mapping):
            asset = asset.get("value") or asset.get("name") or asset.get("identifier") or asset.get("hostname")
        url = event.url or merged.get("url")
        if not url and fid:
            base = (os.environ.get("PADDOCK_PUBLIC_URL") or "").rstrip("/")
            if base:
                url = f"{base}/findings/{fid}"
        sev = event.severity or merged.get("severity") or "medium"
        return cls(
            finding_id=fid,
            title=_one_line(merged.get("title") or event.title or "Paddock finding"),
            severity=str(sev).lower(),
            status=merged.get("status"),
            asset=str(asset) if asset else None,
            asset_id=str(merged["asset_id"]) if merged.get("asset_id") else None,
            description=str(merged.get("description") or event.summary or ""),
            impact=str(merged.get("impact") or ""),
            remediation=str(merged.get("remediation") or ""),
            rule_id=merged.get("rule_id"),
            url=url,
            cvss=merged.get("cvss"),
            epss=merged.get("epss"),
            kev=merged.get("kev"),
        )

    def facts(self) -> list[tuple[str, str]]:
        """Label/value pairs shown at the top of every ticket body."""
        out = [("Severity", self.severity.upper())]
        if self.asset:
            out.append(("Asset", self.asset))
        if self.rule_id:
            out.append(("Rule", str(self.rule_id)))
        if self.cvss not in (None, ""):
            out.append(("CVSS", str(self.cvss)))
        if self.epss not in (None, ""):
            out.append(("EPSS", str(self.epss)))
        if self.kev:
            out.append(("Known exploited (CISA KEV)", "yes"))
        return out

    def plain_text(self) -> str:
        lines = [f"{k}: {v}" for k, v in self.facts()]
        lines += ["", "Why it matters:", self.why]
        if self.remediation:
            lines += ["", "Remediation:", self.remediation]
        if self.url:
            lines += ["", f"Open in Paddock: {self.url}"]
        lines += ["", f"{self.marker} (do not remove: used for two-way sync)"]
        return "\n".join(lines)

    def markdown(self) -> str:
        lines = [f"**{k}:** {v}" for k, v in self.facts()]
        lines += ["", "### Why it matters", self.why]
        if self.remediation:
            lines += ["", "### Remediation", self.remediation]
        if self.url:
            lines += ["", f"[Open in Paddock]({self.url})"]
        lines += ["", f"`{self.marker}`"]
        return "\n".join(lines)


def _one_line(s: Any, limit: int = 240) -> str:
    text = " ".join(str(s).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def finding_id_from_marker(text: Any) -> Optional[str]:
    """Pull ``<uuid>`` out of a ``paddock-<uuid>`` marker anywhere in ``text``."""
    if not text:
        return None
    m = re.search(re.escape(MARKER_PREFIX) + r"(" + _UUID_RE.pattern + r")", str(text))
    return m.group(1).lower() if m else None


def summary_for(fv: FindingView, limit: int = 240) -> str:
    return _one_line(f"[Paddock][{fv.severity.upper()}] {fv.title}", limit)


# --------------------------------------------------------------------------- #
# Signature helpers (constant time everywhere)
# --------------------------------------------------------------------------- #

def lower_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def constant_eq(a: Optional[str], b: Optional[str]) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def hmac_sha256_hex(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify_hmac_sha256(secret: str, body: bytes, presented: Optional[str]) -> bool:
    """``presented`` may be bare hex or ``sha256=<hex>`` (GitHub/Atlassian style)."""
    if not presented:
        return False
    sig = presented.strip()
    if "=" in sig:
        algo, _, sig = sig.partition("=")
        if algo.strip().lower() != "sha256":
            return False
    return constant_eq(hmac_sha256_hex(secret, body), sig.strip().lower())


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8") or "null")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("request body is not valid JSON") from exc


# --------------------------------------------------------------------------- #
# The base class
# --------------------------------------------------------------------------- #

class TicketConnector(Connector):
    """Base for two-way ticketing connectors. Subclasses implement the hooks."""

    category = "ticketing"
    capabilities = frozenset({Capability.TICKET})

    # Set by bind(); all optional so the shared ``Connector(config, secrets,
    # http)`` construction keeps working unchanged.
    integration_id: Optional[str] = None
    pool: Any = None
    allow_private: bool = False
    # Set by the inbound router once the integration's ``inbound_token``
    # (query string / header) has been verified in constant time.
    inbound_token_verified: bool = False

    def __init__(self, config: Mapping[str, Any], secrets: Mapping[str, str], http: Any) -> None:
        super().__init__(config, secrets, http)
        self.allow_private = bool(self.config.get("allow_private", False))
        self._validated: set[tuple[str, str, Optional[int]]] = set()

    def bind(
        self,
        *,
        integration_id: Any = None,
        pool: Any = None,
        allow_private: Optional[bool] = None,
    ) -> "TicketConnector":
        """Attach the integration row's id, a DB pool (link table) and its
        ``allow_private`` flag. Returns ``self`` for chaining."""
        if integration_id is not None:
            self.integration_id = str(integration_id)
        if pool is not None:
            self.pool = pool
        if allow_private is not None:
            self.allow_private = bool(allow_private)
        return self

    # -- hooks ------------------------------------------------------------- #
    async def _find(self, fv: FindingView) -> Optional[ExternalRef]:
        """Find the ticket for ``fv`` by its remote marker."""
        return None

    async def _get(self, external_id: str) -> Optional[ExternalRef]:
        raise NotImplementedError

    async def _create(self, fv: FindingView, event: Event) -> ExternalRef:
        raise NotImplementedError

    async def _update(self, ref: ExternalRef, fv: FindingView, event: Event) -> ExternalRef:
        raise NotImplementedError

    async def _close(self, ref: ExternalRef, fv: FindingView, event: Event) -> ExternalRef:
        raise NotImplementedError

    async def _reopen(self, ref: ExternalRef, fv: FindingView, event: Event) -> ExternalRef:
        raise NotImplementedError

    async def _comment(self, ref: ExternalRef, text: str) -> None:
        raise NotImplementedError

    # -- outbound ---------------------------------------------------------- #
    def origin_is_self(self, event: Event, ref: Optional[ExternalRef] = None) -> bool:
        origin = (event.data or {}).get("origin")
        if not isinstance(origin, Mapping):
            return False
        oid = origin.get("integration_id")
        if oid and self.integration_id:
            return str(oid) == self.integration_id
        if origin.get("kind") == self.kind and ref is not None and origin.get("external_id"):
            return str(origin["external_id"]) in {ref.external_id, ref.display}
        return False

    async def _existing(self, fv: FindingView) -> Optional[ExternalRef]:
        if self.pool is not None and self.integration_id:
            from .. import links

            link = await links.get_by_finding(self.pool, self.integration_id, fv.finding_id)
            if link is not None:
                try:
                    ref = await self._get(link.external_id)
                except NotFound:
                    ref = None          # deleted remotely -> recreate
                if ref is not None:
                    return ref
        return await self._find(fv)

    async def _record_link(self, fv: FindingView, ref: ExternalRef) -> None:
        if self.pool is None or not self.integration_id or not fv.finding_id:
            return
        from .. import links

        try:
            await links.upsert(
                self.pool, self.integration_id, fv.finding_id,
                ref.external_id, ref.external_url, ref.status,
            )
        except Exception:  # noqa: BLE001 -- the ticket exists; the remote marker still dedupes
            log.exception("ticket_link_persist_failed", extra={"kind": self.kind})

    def _skip(self, why: str, ref: Optional[ExternalRef] = None) -> DeliveryResult:
        return DeliveryResult(
            ok=True, detail=f"skipped: {why}", retryable=False,
            external_id=ref.external_id if ref else None,
            external_url=ref.external_url if ref else None,
        )

    async def deliver(self, event: Event) -> DeliveryResult:
        if event.type == "integration.test":
            h = await self.test()
            return DeliveryResult(ok=h.ok, detail=h.detail, retryable=False)
        if event.type not in FINDING_EVENTS:
            return self._skip(f"{event.type} is not a ticket event")
        fv = FindingView.from_event(event)
        if not fv.finding_id:
            return DeliveryResult(ok=False, retryable=False, detail="event carries no finding_id")
        if self.origin_is_self(event):
            return self._skip("change originated from this integration")
        try:
            ref = await self._existing(fv)
            if ref is not None and self.origin_is_self(event, ref):
                return self._skip("change originated from this ticket", ref)
            action = ""
            t = event.type
            if t in ("finding.opened", "finding.updated"):
                if ref is None:
                    ref, action = await self._create(fv, event), "created"
                else:
                    ref, action = await self._update(ref, fv, event), "updated"
                    if t == "finding.opened" and ref.category == CAT_DONE:
                        ref, action = await self._reopen(ref, fv, event), "reopened"
            elif t == "finding.resolved":
                if ref is None:
                    return self._skip("no ticket for this finding")
                if ref.category == CAT_DONE:
                    await self._record_link(fv, ref)
                    return self._skip("ticket already done", ref)
                ref, action = await self._close(ref, fv, event), "closed"
            elif t == "finding.reopened":
                if ref is None:
                    ref, action = await self._create(fv, event), "created"
                elif ref.category == CAT_DONE:
                    ref, action = await self._reopen(ref, fv, event), "reopened"
                else:
                    await self._record_link(fv, ref)
                    return self._skip("ticket already open", ref)
            elif t == "finding.accepted":
                if ref is None:
                    return self._skip("no ticket for this finding")
                status = (event.data or {}).get("status") or "accepted"
                note = (event.data or {}).get("note") or (event.data or {}).get("justification") or ""
                text = f"{COMMENT_PREFIX} Finding marked {status} in Paddock."
                if note:
                    text += f" Reason: {_one_line(note, 1000)}"
                await self._comment(ref, text)
                action = "commented"
            await self._record_link(fv, ref)
            label = ref.display or ref.external_id
            return DeliveryResult(
                ok=True, status_code=200, external_id=ref.external_id,
                external_url=ref.external_url, detail=f"{action} {label}", retryable=False,
            )
        except netsafety.UnsafeURL as exc:
            return DeliveryResult(ok=False, retryable=False, detail=f"unsafe URL: {exc}")
        except RemoteError as exc:
            return DeliveryResult(
                ok=False, status_code=exc.status_code,
                retryable=exc.retryable, detail=self.scrub(exc.detail),
            )
        except httpx.TimeoutException:
            return DeliveryResult(ok=False, retryable=True, detail="timed out talking to the ticket system")
        except httpx.HTTPError as exc:
            return DeliveryResult(ok=False, retryable=True, detail=f"transport error ({type(exc).__name__})")

    # -- inbound helpers ---------------------------------------------------- #
    def check_inbound_auth(self, verified: Optional[bool]) -> None:
        """Enforce the inbound auth policy.

        ``verified`` -- True: a configured signature/secret matched; False:
        it was configured and did NOT match (or was missing); None: no
        signature secret is configured, so the inbound token is required.
        """
        if verified is True:
            return
        if verified is False:
            raise PermissionError("signature verification failed")
        if not self.inbound_token_verified:
            raise PermissionError("no signing secret configured and no valid inbound token")

    def delivery_id(self, headers: Mapping[str, str], body: bytes) -> Optional[str]:
        """A per-delivery id from the sender, for replay de-duplication."""
        return None

    def status_override(self, *keys: Any) -> Optional[str]:
        """Look ``keys`` up (case-insensitively) in config ``status_map``."""
        smap = self.config.get("status_map") or {}
        if not isinstance(smap, Mapping):
            return None
        norm = {str(k).strip().lower(): v for k, v in smap.items()}
        for k in keys:
            if k is None:
                continue
            v = norm.get(str(k).strip().lower())
            if v in PADDOCK_STATUSES:
                return v
        return None

    # -- HTTP --------------------------------------------------------------- #
    def scrub(self, text: str) -> str:
        """Remove any configured secret value from ``text`` and cap its length."""
        out = str(text)
        for v in self.secrets.values():
            if v and len(v) >= 4:
                out = out.replace(v, "****")
        return out[:_MAX_ERR]

    async def _validate(self, url: str) -> None:
        p = urlsplit(url)
        key = (p.scheme, (p.hostname or "").lower(), p.port)
        if key in self._validated:
            return
        await netsafety.validate_outbound_url(url, allow_private=self.allow_private)
        self._validated.add(key)

    @staticmethod
    def _error_text(resp: httpx.Response) -> str:
        try:
            body = resp.json()
        except ValueError:
            return ""
        if isinstance(body, Mapping):
            parts: list[str] = []
            for key in ("errorMessages", "messages"):
                if isinstance(body.get(key), list):
                    parts += [str(m) for m in body[key]]
            if isinstance(body.get("errors"), Mapping):
                parts += [f"{k}: {v}" for k, v in body["errors"].items()]
            err = body.get("error")
            if isinstance(err, Mapping):
                parts += [str(err.get("message") or ""), str(err.get("detail") or "")]
            elif isinstance(err, str):
                parts.append(err)
            return "; ".join(p for p in parts if p)
        return ""

    async def _request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        await self._validate(url)
        kw.setdefault("timeout", 20.0)
        resp = await self.http.request(method, url, **kw)
        code = resp.status_code
        if code < 300:
            return resp
        if code == 404:
            raise NotFound(f"HTTP 404 from {self.display_name}")
        if code in (401, 403):
            raise RemoteError(f"{self.display_name} rejected the credentials (HTTP {code})", code, retryable=False)
        if code == 429 or code >= 500:
            raise RemoteError(f"{self.display_name} returned HTTP {code}", code, retryable=True)
        if 300 <= code < 400:
            raise RemoteError(f"{self.display_name} answered with a redirect (HTTP {code}); "
                              "check the base URL", code, retryable=False)
        msg = self._error_text(resp)
        raise RemoteError(f"{self.display_name} returned HTTP {code}" + (f": {msg}" if msg else ""),
                          code, retryable=False)

    async def _health(self, coro: Any) -> HealthResult:
        """Run a test coroutine, mapping expected failures to a HealthResult."""
        try:
            return await coro
        except netsafety.UnsafeURL as exc:
            return HealthResult(ok=False, detail=f"unsafe URL: {exc}")
        except RemoteError as exc:
            return HealthResult(ok=False, detail=self.scrub(exc.detail))
        except httpx.TimeoutException:
            return HealthResult(ok=False, detail="timed out")
        except httpx.HTTPError as exc:
            return HealthResult(ok=False, detail=f"transport error ({type(exc).__name__})")


def is_uuid(value: Any) -> bool:
    try:
        UUID(str(value))
        return True
    except (TypeError, ValueError):
        return False
