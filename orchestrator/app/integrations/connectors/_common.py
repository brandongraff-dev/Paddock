"""Shared helpers for the context SOURCE and network ACTION connectors.

Nothing here is a connector; it is the small toolkit they share:

* ``SourceError`` -- the one exception a ``pull()`` raises for an expected
  remote failure. Its message is built by us (status code + endpoint path),
  never from a response body that might echo a credential.
* ``ActionResult`` -- a ``DeliveryResult`` subclass (so the contract holds)
  that also carries the revert plan and, for a dry run, the planned calls.
* ``checked_url`` -- every customer-configurable base URL goes through
  ``netsafety.validate_outbound_url`` before the first request.
* MAC / IP / hostname normalisation used for merge hints.
* ``asset`` / ``edge`` / ``finding`` builders that emit the orchestrator's
  bulk-endpoint shapes.

Merge hints (an additive key on SourceBatch asset/finding items)
----------------------------------------------------------------
EDR/MDM/CMDB records describe machines Paddock may already know under another
name. Such items carry ``merge_on = {"ips": [...], "hostnames": [...],
"macs": [...]}``. ``app.integrations.ingest`` attaches the item's metadata to
every EXISTING asset that matches (ipv4/ipv6 by address, iot/ot devices by IP
or MAC, (sub)domains by hostname, anything by ``metadata.hostname`` /
``metadata.mac``) and only falls back to creating the item's own
``kind``/``value`` when nothing matches. The bulk endpoints ignore the key, so
the shape stays backward compatible.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import urlsplit

from .. import netsafety
from ..base import DeliveryResult


class SourceError(RuntimeError):
    """An expected remote failure during ``pull()``/``act()``. Message is safe."""

    def __init__(self, message: str, *, status_code: Optional[int] = None,
                 retryable: bool = True) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable


@dataclass
class ActionResult(DeliveryResult):
    """``DeliveryResult`` + what an approved network action needs to persist."""

    dry_run: bool = False
    # How to undo this action (stored on the agent_actions row, fed back to
    # ``act({"type": "release_device", "revert": ...})``).
    revert: dict[str, Any] = field(default_factory=dict)
    # The API calls that were (or, in a dry run, would have been) made.
    # Method + path only: never headers, never bodies with credentials.
    planned: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Outbound URL safety
# --------------------------------------------------------------------------- #

async def checked_url(url: str, *, allow_private: bool) -> str:
    """Validate a customer-configured base URL; return it without a trailing /."""
    if not url or not isinstance(url, str):
        raise SourceError("base URL is not configured", retryable=False)
    try:
        await netsafety.validate_outbound_url(url, allow_private=allow_private)
    except netsafety.UnsafeURL as exc:
        raise SourceError(f"refused outbound URL: {exc}", retryable=False) from exc
    return url.rstrip("/")


def url_path(url: str) -> str:
    """The path part of a URL, for safe error messages (no query, no host creds)."""
    try:
        return urlsplit(url).path or "/"
    except ValueError:
        return "?"


def status_error(resp: Any, what: str) -> SourceError:
    """Build a SourceError from an httpx response WITHOUT reading its body."""
    code = getattr(resp, "status_code", None)
    retryable = code is None or code >= 500 or code == 429
    hint = ""
    if code in (401, 403):
        hint = " (check the credential and its permissions)"
    return SourceError(f"{what}: HTTP {code}{hint}", status_code=code, retryable=retryable)


async def request_json(http: Any, method: str, url: str, *, what: str,
                       headers: Mapping[str, str] | None = None,
                       params: Any = None, json: Any = None, data: Any = None,
                       retries: int = 2, follow_suffixes: tuple[str, ...] = (),
                       allow_private: bool = False, empty_ok: bool = False) -> Any:
    """One HTTP call through the injected client, mapped to safe errors.

    * 429/503 are retried (``Retry-After`` honoured, capped at 10 s).
    * Redirects are NOT followed unless the target host ends with one of
      ``follow_suffixes`` (e.g. Meraki shard hosts) AND passes netsafety.
    * Error messages carry the status code and a description we wrote, never
      a response body (which might reflect a credential back).
    """
    import httpx  # local: keep module import cheap for the catalogue

    hops = 0
    attempt = 0
    while True:
        try:
            resp = await http.request(method, url, headers=dict(headers or {}), params=params,
                                      json=json, data=data)
        except httpx.TimeoutException as exc:
            raise SourceError(f"{what}: timed out") from exc
        except httpx.HTTPError as exc:
            raise SourceError(f"{what}: {type(exc).__name__}") from exc
        code = resp.status_code
        if code in (301, 302, 303, 307, 308) and follow_suffixes and hops < 3:
            loc = resp.headers.get("location", "")
            host = (urlsplit(loc).hostname or "").lower()
            if loc.startswith("https://") and any(host == s or host.endswith("." + s)
                                                   for s in follow_suffixes):
                url = await checked_url(loc, allow_private=allow_private)
                hops += 1
                if code == 303:
                    method, json, data = "GET", None, None
                continue
            raise SourceError(f"{what}: refused redirect to an unexpected host", status_code=code,
                              retryable=False)
        if code in (429, 503) and attempt < retries:
            attempt += 1
            try:
                wait = float(resp.headers.get("retry-after", "1"))
            except ValueError:
                wait = 1.0
            await asyncio.sleep(max(0.0, min(wait, 10.0)))
            continue
        if code >= 400:
            raise status_error(resp, what)
        if code == 204 or not resp.content:
            if empty_ok:
                return None
            raise SourceError(f"{what}: empty response", status_code=code)
        try:
            return resp.json()
        except ValueError as exc:
            raise SourceError(f"{what}: response was not JSON", status_code=code) from exc


def fallback_anchor(hint: Mapping[str, list[str]]) -> Optional[tuple[str, str]]:
    """The asset to create when a merge hint matches nothing: an IP, else an FQDN."""
    for ip in hint.get("ips") or []:
        return ip_kind(ip), ip
    for h in hint.get("hostnames") or []:
        if "." in h and not h.endswith(".local"):
            return "subdomain", h
    return None


def bool_cfg(config: Mapping[str, Any], key: str, default: bool) -> bool:
    v = config.get(key, default)
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes", "on"}
    return bool(v)


def int_cfg(config: Mapping[str, Any], key: str, default: int, *, lo: int, hi: int) -> int:
    try:
        v = int(config.get(key, default))
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #

_MAC_HEX = re.compile(r"^[0-9a-f]{12}$")


def normalize_mac(raw: Any) -> Optional[str]:
    """``00-1A-2b.3c:4D5E`` -> ``00:1a:2b:3c:4d:5e``; None when not a MAC."""
    if not raw or not isinstance(raw, str):
        return None
    hexes = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if not _MAC_HEX.match(hexes) or hexes in ("000000000000", "ffffffffffff"):
        return None
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2))


def is_unicast_mac(mac: str) -> bool:
    """False for multicast/broadcast MACs (I/G bit set): never quarantinable."""
    try:
        return (int(mac[:2], 16) & 1) == 0
    except (ValueError, TypeError):
        return False


def clean_ip(raw: Any) -> Optional[str]:
    if not raw or not isinstance(raw, str):
        return None
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return None
    return str(ip)


def ip_kind(ip: str) -> str:
    return "ipv6" if ":" in ip else "ipv4"


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def clean_hostname(raw: Any) -> Optional[str]:
    if not raw or not isinstance(raw, str):
        return None
    h = raw.strip().rstrip(".").lower()
    if not h or len(h) > 253 or not re.match(r"^[a-z0-9_][a-z0-9_.-]*$", h):
        return None
    return h


def dedupe(values: Iterable[Optional[str]]) -> list[str]:
    seen: list[str] = []
    for v in values:
        if v and v not in seen:
            seen.append(v)
    return seen


def merge_hint(ips: Iterable[Any] = (), hostnames: Iterable[Any] = (),
               macs: Iterable[Any] = ()) -> dict[str, list[str]]:
    return {
        "ips": dedupe(clean_ip(i) for i in ips),
        "hostnames": dedupe(clean_hostname(h) for h in hostnames),
        "macs": dedupe(normalize_mac(m) for m in macs),
    }


# --------------------------------------------------------------------------- #
# Bulk-shape builders
# --------------------------------------------------------------------------- #

def asset(kind: str, value: str, source: str, metadata: Mapping[str, Any] | None = None,
          *, confidence: int = 90, merge_on: Mapping[str, list[str]] | None = None
          ) -> dict[str, Any]:
    item: dict[str, Any] = {
        "kind": kind,
        "value": value,
        "source": source,
        "confidence": confidence,
        "metadata": {k: v for k, v in (metadata or {}).items() if v is not None},
    }
    if merge_on and any(merge_on.values()):
        item["merge_on"] = dict(merge_on)
    return item


def edge(src_kind: str, src: str, dst_kind: str, dst: str, kind: str,
         metadata: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "src_kind": src_kind, "src_canonical": src,
        "dst_kind": dst_kind, "dst_canonical": dst,
        "kind": kind, "metadata": dict(metadata or {}),
    }


def finding(asset_kind: str, asset_value: str, rule_id: str, severity: str, title: str,
            description: str, *, source: str, remediation: str | None = None,
            impact: str | None = None, evidence: Mapping[str, Any] | None = None,
            merge_on: Mapping[str, list[str]] | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {
        "asset_kind": asset_kind,
        "asset_value": asset_value,
        "rule_id": rule_id,
        # Posture/config findings from a connected system. `policy` is the
        # existing rule_source for configuration-derived findings.
        "rule_source": "policy",
        "severity": severity,
        "title": title[:512],
        "description": description,
        "impact": impact,
        "remediation": remediation,
        "evidence": dict(evidence or {}),
        "metadata": {"source": source, "integration": source.split(":", 1)[-1]},
    }
    if merge_on and any(merge_on.values()):
        item["merge_on"] = dict(merge_on)
    return item


def scope_suggestion(kind: str, value: str, evidence: Mapping[str, Any] | None = None
                     ) -> dict[str, Any]:
    """A PENDING scope suggestion (schema 031). Never adds scope by itself."""
    return {"kind": kind, "value": value, "evidence": dict(evidence or {})}


def public_ip_suggestion(ip: Any, evidence: Mapping[str, Any] | None = None
                         ) -> Optional[dict[str, Any]]:
    """/32 (/128) suggestion for a PUBLIC address; None for anything else."""
    cleaned = clean_ip(ip)
    if not cleaned or not is_public_ip(cleaned):
        return None
    return scope_suggestion("ipv6_cidr" if ":" in cleaned else "ipv4_cidr",
                            f"{cleaned}/{128 if ':' in cleaned else 32}", evidence)


def hostname_suggestion(host: Any, evidence: Mapping[str, Any] | None = None
                        ) -> Optional[dict[str, Any]]:
    """Domain suggestion for a public FQDN (no IPs, no *.local/.internal)."""
    h = clean_hostname(host)
    if not h or "." not in h or h.endswith((".local", ".internal", ".localdomain")):
        return None
    try:
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    return scope_suggestion("domain", h, evidence)


def device_asset(hint: Mapping[str, list[str]], source: str, metadata: Mapping[str, Any], *,
                 create_unmatched: bool = True, confidence: int = 80) -> Optional[dict[str, Any]]:
    """Asset item for an EDR/MDM/CMDB machine record.

    Carries the merge hint; its own kind/value (an IP, else an FQDN) is only
    created when no existing asset matches. ``merge_only`` items (no anchor,
    or ``create_unmatched`` off) are dropped by ingest when nothing matches.
    """
    anchor = fallback_anchor(hint)
    if anchor is None and not any(hint.values()):
        return None
    kind, value = anchor or ("subdomain", "-")
    item = asset(kind, value, source, metadata, confidence=confidence, merge_on=hint)
    if anchor is None or not create_unmatched:
        item["merge_only"] = True
    return item


def device_finding(item: Mapping[str, Any], rule_id: str, severity: str, title: str,
                   description: str, *, source: str, **kw: Any) -> dict[str, Any]:
    """A finding that lands on whatever asset ``item`` merges onto."""
    f = finding(item["kind"], item["value"], rule_id, severity, title, description,
                source=source, merge_on=item.get("merge_on"), **kw)
    if item.get("merge_only"):
        f["merge_only"] = True
    return f


def owner_rule(team: str, *, source: str, contact: str | None = None,
               priority: int = 50) -> dict[str, Any]:
    """An ``asset_owners`` rule routing assets tagged ``owner:<team>`` to ``team``."""
    return {
        "name": f"{source}:{team}"[:200],
        "match": {"tag": owner_tag(team), "system": source},
        "team": team,
        "contact": contact,
        "priority": priority,
    }


def owner_tag(team: str) -> str:
    return f"owner:{team}"
