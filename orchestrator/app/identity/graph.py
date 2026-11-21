"""Microsoft Entra ID group overage: resolve a user's groups through Graph.

Entra stops putting groups in the token once a user is in too many (150 in a
SAML assertion, 200 in a JWT, 6 for implicit-flow tokens). It emits instead:

* OIDC: ``hasgroups: true`` (v1 / implicit) or ``_claim_names: {"groups": "src"}``
  + ``_claim_sources`` (v2). The source ``endpoint`` is the legacy
  ``graph.windows.net`` URL; we NEVER follow it (it is token-supplied data and
  would send a bearer token wherever a forged claim points). We call the
  configured Graph base URL instead.
* SAML: the attribute ``http://schemas.microsoft.com/claims/groups.link``.

Two ways to get the list (``transitiveMemberOf``, so nested groups count):

* ``delegated``  -- the user's own OIDC access token, ``GET /me/transitiveMemberOf``
  (OIDC only; the app needs ``User.Read`` + ``GroupMember.Read.All``-class consent).
* ``app``        -- client-credentials token for the configured app registration,
  ``GET /users/{oid}/transitiveMemberOf`` (works for SAML too; needs the
  ``GroupMember.Read.All`` APPLICATION permission).

Only group OBJECT IDS are returned (``$select=id``). Display names are not
unique in Entra and, by default, any user may create a group and name it
"Paddock Admins": mapping on a display name would be a privilege-escalation
path. Map roles on object IDs.

Failure mode: any problem (no credentials, 401/403, throttling, bad payload,
paging loop, ...) raises ``GraphError``. Callers then treat the user's groups
as UNRESOLVED: no role mapping is applied, ``require_mapping`` providers deny
the login, existing users keep their current role (never upgraded). Nothing
here can add a group that Graph did not return.

Every request goes through the DNS-pinned transport (``app.integrations.pinned``).
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import quote, urlsplit

import httpx

from ..integrations.pinned import PinnedTransport

logger = logging.getLogger(__name__)

GROUPS_LINK_ATTR = "http://schemas.microsoft.com/claims/groups.link"
OID_ATTR = "http://schemas.microsoft.com/identity/claims/objectidentifier"

DEFAULT_GRAPH = "https://graph.microsoft.com"
DEFAULT_LOGIN = "https://login.microsoftonline.com"

MAX_PAGES = 50
MAX_GROUPS = 20_000
_MAX_PAGE_BYTES = 4 * 1024 * 1024
_TIMEOUT = httpx.Timeout(10.0)
_GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$")


def cache_ttl_sec() -> int:
    try:
        return max(0, int(os.environ.get("PADDOCK_GRAPH_GROUP_CACHE_SEC", "300")))
    except ValueError:
        return 300


class GraphError(Exception):
    """``code`` is safe to show/audit; ``detail`` is for logs (no secrets)."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class GraphConfig:
    mode: str = "delegated"               # delegated | app
    base_url: str = DEFAULT_GRAPH
    login_url: str = DEFAULT_LOGIN
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    allow_private: bool = False


# Tests inject an httpx.MockTransport (a fake Graph); production is pinned.
_transport: httpx.AsyncBaseTransport | None = None
_group_cache: dict[tuple[str, str], tuple[float, tuple[str, ...]]] = {}
_token_cache: dict[tuple[str, str, str], tuple[float, str]] = {}
_CACHE_MAX = 2048


def set_transport(t: httpx.AsyncBaseTransport | None) -> None:
    global _transport
    _transport = t


def clear_caches() -> None:
    _group_cache.clear()
    _token_cache.clear()


def _client(cfg: GraphConfig) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=_transport or PinnedTransport(allow_private=cfg.allow_private),
        timeout=_TIMEOUT, follow_redirects=False,
    )


# --------------------------------------------------------------------------- #
# Overage detection
# --------------------------------------------------------------------------- #

def oidc_overage(claims: Mapping[str, Any]) -> bool:
    if str(claims.get("hasgroups", "")).lower() == "true":
        return True
    names = claims.get("_claim_names")
    return isinstance(names, Mapping) and "groups" in names


def saml_overage(attributes: Mapping[str, list[str]]) -> bool:
    return bool(attributes.get(GROUPS_LINK_ATTR))


def saml_object_id(attributes: Mapping[str, list[str]]) -> str | None:
    vals = attributes.get(OID_ATTR) or []
    return vals[0] if vals and _GUID.match(vals[0]) else None


def tenant_from_issuer(issuer: str) -> str | None:
    """``https://login.microsoftonline.com/<tenant>/v2.0`` -> ``<tenant>``."""
    parts = [p for p in urlsplit(issuer).path.split("/") if p]
    return parts[0] if parts and _TENANT.match(parts[0]) else None


# --------------------------------------------------------------------------- #
# Fetching
# --------------------------------------------------------------------------- #

def _check_base(url: str) -> str:
    p = urlsplit(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password:
        raise GraphError("graph_misconfigured", "Graph URL must be https://host")
    return f"{p.scheme}://{p.netloc}"


async def _app_token(cfg: GraphConfig) -> str:
    if not (cfg.tenant_id and cfg.client_id and cfg.client_secret):
        raise GraphError("graph_not_configured", "app credentials (tenant, client id, secret) are missing")
    if not _TENANT.match(cfg.tenant_id):
        raise GraphError("graph_misconfigured", "tenant id is not valid")
    key = (cfg.tenant_id, cfg.client_id, cfg.base_url)
    hit = _token_cache.get(key)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    login = _check_base(cfg.login_url)
    try:
        async with _client(cfg) as c:
            r = await c.post(
                f"{login}/{quote(cfg.tenant_id, safe='')}/oauth2/v2.0/token",
                data={"grant_type": "client_credentials", "client_id": cfg.client_id,
                      "client_secret": cfg.client_secret,
                      "scope": _check_base(cfg.base_url) + "/.default"},
                headers={"Accept": "application/json"},
            )
    except (httpx.HTTPError, ValueError) as exc:
        raise GraphError("graph_unreachable", f"token request failed: {type(exc).__name__}") from exc
    except Exception as exc:  # noqa: BLE001 -- UnsafeURL from the pinned transport
        raise GraphError("graph_unreachable", f"token request refused: {type(exc).__name__}") from exc
    body = _json(r)
    tok = body.get("access_token") if r.status_code == 200 else None
    if not isinstance(tok, str) or not tok:
        raise GraphError("graph_auth_failed", f"app token request HTTP {r.status_code}")
    try:
        ttl = max(60, int(body.get("expires_in") or 3600) - 60)
    except (TypeError, ValueError):
        ttl = 600
    if len(_token_cache) >= 64:
        _token_cache.clear()
    _token_cache[key] = (time.monotonic() + ttl, tok)
    return tok


def _json(r: httpx.Response) -> dict[str, Any]:
    if len(r.content) > _MAX_PAGE_BYTES:
        raise GraphError("graph_bad_response", "response too large")
    try:
        v = r.json()
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


async def _get_page(c: httpx.AsyncClient, url: str, token: str) -> httpx.Response:
    for attempt in (0, 1):
        try:
            r = await c.get(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json",
                                           "ConsistencyLevel": "eventual"})
        except httpx.HTTPError as exc:
            raise GraphError("graph_unreachable", f"GET failed: {type(exc).__name__}") from exc
        except Exception as exc:  # noqa: BLE001 -- UnsafeURL from the pinned transport
            raise GraphError("graph_unreachable", f"request refused: {type(exc).__name__}") from exc
        if r.status_code in (429, 503) and attempt == 0:
            try:
                wait = min(5.0, float(r.headers.get("retry-after", "1")))
            except ValueError:
                wait = 1.0
            await asyncio.sleep(max(0.0, wait))
            continue
        return r
    return r  # pragma: no cover


async def _list_group_ids(cfg: GraphConfig, path: str, token: str) -> list[str]:
    base = _check_base(cfg.base_url)
    url = f"{base}{path}?$select=id&$top=999"
    ids: list[str] = []
    seen_urls: set[str] = set()
    async with _client(cfg) as c:
        for _ in range(MAX_PAGES):
            if url in seen_urls:
                raise GraphError("graph_bad_response", "paging loop")
            seen_urls.add(url)
            r = await _get_page(c, url, token)
            if r.status_code in (401, 403):
                raise GraphError("graph_forbidden", f"Graph HTTP {r.status_code} (consent / permission?)")
            if r.status_code == 429 or r.status_code >= 500:
                raise GraphError("graph_throttled", f"Graph HTTP {r.status_code}")
            if r.status_code != 200:
                raise GraphError("graph_error", f"Graph HTTP {r.status_code}")
            body = _json(r)
            value = body.get("value")
            if not isinstance(value, list):
                raise GraphError("graph_bad_response", "no value array")
            for g in value:
                gid = g.get("id") if isinstance(g, Mapping) else None
                if isinstance(gid, str) and 0 < len(gid) <= 64:
                    ids.append(gid)
            if len(ids) > MAX_GROUPS:
                raise GraphError("graph_bad_response", "too many groups")
            nxt = body.get("@odata.nextLink")
            if not nxt:
                return list(dict.fromkeys(ids))
            if not isinstance(nxt, str):
                raise GraphError("graph_bad_response", "bad nextLink")
            p = urlsplit(nxt)
            # A nextLink is server-supplied: it must stay on the Graph host,
            # or the bearer token would follow it anywhere.
            if f"{p.scheme}://{p.netloc}" != base or p.username or p.password:
                raise GraphError("graph_bad_response", "nextLink leaves the Graph host")
            url = nxt
    raise GraphError("graph_bad_response", f"more than {MAX_PAGES} pages")


def _cached(key: tuple[str, str]) -> list[str] | None:
    hit = _group_cache.get(key)
    if hit and hit[0] > time.monotonic():
        return list(hit[1])
    _group_cache.pop(key, None)
    return None


def _store(key: tuple[str, str], groups: list[str]) -> None:
    ttl = cache_ttl_sec()
    if not ttl:
        return
    if len(_group_cache) >= _CACHE_MAX:
        now = time.monotonic()
        for k in [k for k, v in _group_cache.items() if v[0] <= now] or list(_group_cache)[: _CACHE_MAX // 2]:
            _group_cache.pop(k, None)
    _group_cache[key] = (time.monotonic() + ttl, tuple(groups))


async def resolve_groups(
    cfg: GraphConfig, *, cache_scope: str, subject: str, oid: str | None = None,
    access_token: str | None = None,
) -> list[str]:
    """Group object ids of the user (transitive). Raises ``GraphError``.

    ``cache_scope`` (provider id) + ``subject`` key the cache. A successful
    answer is reused for ``PADDOCK_GRAPH_GROUP_CACHE_SEC`` (default 300 s,
    0 = off); failures are never cached and never served stale.
    """
    key = (cache_scope, subject)
    hit = _cached(key)
    if hit is not None:
        return hit
    if cfg.mode == "delegated":
        if not access_token:
            raise GraphError("graph_not_configured", "no access token for a delegated Graph call")
        ids = await _list_group_ids(cfg, "/v1.0/me/transitiveMemberOf/microsoft.graph.group", access_token)
    elif cfg.mode == "app":
        if not oid or not _GUID.match(oid):
            raise GraphError("graph_no_user", "the user's object id is missing or not a GUID")
        token = await _app_token(cfg)
        ids = await _list_group_ids(
            cfg, f"/v1.0/users/{quote(oid, safe='')}/transitiveMemberOf/microsoft.graph.group", token,
        )
    else:
        raise GraphError("graph_misconfigured", f"unknown mode {cfg.mode!r}")
    _store(key, ids)
    return ids
