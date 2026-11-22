"""Single sign-on: OIDC + SAML 2.0 login flows and admin configuration (schema 020).

Public (the middleware treats these as unauthenticated routes):

- ``GET  /v1/auth/sso/providers``          -- enabled IdPs for the login page.
- ``GET  /v1/auth/sso/{slug}/start``       -- 302 to the IdP (state + nonce + PKCE).
- ``GET  /v1/auth/sso/{slug}/callback``    -- OIDC redirect URI.
- ``POST /v1/auth/sso/{slug}/acs``         -- SAML assertion consumer service.
- ``GET  /v1/auth/sso/{slug}/metadata``    -- SAML SP metadata (also the entity id).
- ``POST /v1/auth/sso/exchange``           -- one-time code (+ SPA verifier) -> JWT.
- ``GET  /v1/auth/sso/{slug}/sls``         -- SAML single-logout endpoint (signed IdP messages only).
- ``POST /v1/auth/sso/logout``             -- (authenticated) end the caller's sessions; for a
  SAML login with an IdP SLO URL, also returns the IdP LogoutRequest redirect.

Token delivery: the callback never puts a token in a URL. It redirects the
browser to ``<SSO_DASHBOARD_URL>/sso/callback?code=...`` with a 256-bit,
single-use code that lives ``SSO_CODE_TTL_SEC`` seconds and is bound to a
verifier the SPA generated before leaving (PKCE-style), so a code leaked
through history / Referer / logs is useless on its own.

Admin (capability ``admin``), all audited:

- ``GET|POST /v1/auth/sso/admin/providers``, ``GET|PATCH|DELETE .../{id}``,
  ``POST .../{id}/test``
- ``GET|PUT /v1/auth/sso/admin/settings`` (SSO-required, break-glass, SCIM mappings)
- ``GET|POST /v1/auth/sso/admin/scim-tokens``, ``DELETE .../{id}``
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, ValidationError
from starlette.concurrency import run_in_threadpool

from .. import audit
from .. import auth as auth_svc
from .. import tenancy
from ..auth import current_principal, require
from ..billing import gate as billing_gate
from ..config import settings
from ..db import get_pool
from ..identity import graph, mapping, oidc, saml, scim_logic
from ..identity import store
from ..identity.models import (
    ExchangeIn,
    IdentitySettingsIn,
    IdentitySettingsOut,
    OIDCConfig,
    ProviderIn,
    ProviderOut,
    ProviderPatch,
    PublicProvider,
    PublicProvidersOut,
    SAMLConfig,
    ScimTokenCreateOut,
    ScimTokenIn,
    ScimTokenOut,
)
from ..integrations import secrets as secret_box

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/auth/sso", tags=["sso"])

STATE_COOKIE = "paddock_sso_state"
_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_MAX_SAML_RESPONSE = 1_000_000

# Unauthenticated /start writes a state row; cap it per client IP so a flood
# can't bloat sso_login_states (rows also expire after the state TTL).
_START_MAX_PER_MIN = 30
_starts: dict[str, deque[float]] = defaultdict(deque)


def _start_throttled(ip: str) -> bool:
    now = time.monotonic()
    q = _starts[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= _START_MAX_PER_MIN:
        return True
    q.append(now)
    if len(_starts) > 10_000:  # bound memory: forget idle buckets
        for k in [k for k, v in _starts.items() if not v or now - v[-1] > 60]:
            _starts.pop(k, None)
    return False


class ExchangeOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    clearance: str
    expires_in: int
    username: str


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _base() -> str:
    return settings.sso_base_url.rstrip("/")


def _redirect_uri(slug: str) -> str:
    return f"{_base()}/v1/auth/sso/{slug}/callback"


def _safe_return_to(value: str | None) -> str:
    """Only same-origin absolute paths; anything else becomes "/"."""
    if not value or len(value) > 512:
        return "/"
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    if any(ord(ch) < 0x20 for ch in value):
        return "/"
    return value


def _to_dashboard(**params: str) -> RedirectResponse:
    url = settings.sso_dashboard_url.rstrip("/") + "/sso/callback?" + urlencode(params)
    resp = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


def _cookie_secure() -> bool:
    return urlsplit(settings.sso_base_url).scheme == "https"


async def _audit(
    request: Request,
    *,
    action: str,
    actor: str,
    actor_role: str | None,
    resource_type: str,
    resource_id: str | None,
    status_code: int,
    details: dict[str, Any],
) -> None:
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        return
    try:
        await audit.record(
            pool,
            action=action,
            actor=actor,
            actor_role=actor_role,
            resource_type=resource_type,
            resource_id=resource_id,
            method=request.method,
            path=request.url.path,
            status=status_code,
            ip=auth_svc.client_ip(request),
            request_id=getattr(request.state, "request_id", None),
            details=details,
        )
    except Exception:  # noqa: BLE001 -- never fail the flow on audit
        logger.exception("sso_audit_failed")


async def _login_failed(request: Request, provider, code: str, detail: str, actor: str = "anonymous"):
    slug = provider["slug"] if provider is not None else request.path_params.get("slug")
    logger.warning("sso_login_failed", extra={"provider": slug, "code": code, "detail": detail[:300]})
    await _audit(
        request,
        action="login",
        actor=actor,
        actor_role=None,
        resource_type="sso",
        resource_id=slug,
        status_code=401,
        details={
            "outcome": "failure",
            "protocol": provider["kind"] if provider is not None else None,
            "reason": code,
            "detail": detail[:300],
        },
    )
    resp = _to_dashboard(error=code)
    resp.delete_cookie(STATE_COOKIE, path="/v1/auth/sso")
    return resp


async def _login_succeeded(request: Request, provider, result: store.ProvisionResult, spa_challenge, return_to,
                           groups_error: str | None = None):
    pool = request.app.state.pool
    user = result.user
    code = await store.issue_exchange_code(
        pool, user_id=user["id"], provider_id=provider["id"], spa_challenge=spa_challenge,
    )
    await _audit(
        request,
        action="login",
        actor=user["username"],
        actor_role=user["role"],
        resource_type="sso",
        resource_id=provider["slug"],
        status_code=200,
        details={
            "outcome": "success",
            "protocol": provider["kind"],
            "linked": result.linked,
            "jit_created": result.created,
            "role": user["role"],
            "clearance": user["clearance"],
            "matched_group": result.role_decision.matched,
            "role_changed": result.role_changed,
            "groups_unresolved": result.groups_unresolved,
            **({"groups_error": groups_error} if groups_error else {}),
        },
    )
    params = {"code": code}
    if return_to and return_to != "/":
        params["next"] = return_to
    resp = _to_dashboard(**params)
    resp.delete_cookie(STATE_COOKIE, path="/v1/auth/sso")
    return resp


def _bool_claim(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.lower() in ("true", "false"):
        return v.lower() == "true"
    return None


def identity_from_oidc_claims(provider, claims: dict[str, Any]) -> store.ExternalIdentity:
    preset = provider["preset"]
    email = claims.get("email") if isinstance(claims.get("email"), str) else None
    verified = _bool_claim(claims.get("email_verified"))
    external_ids: list[str] = []
    if preset == "entra":
        # Entra's `email` is optional and unverified (nOAuth); never trust it
        # for linking. The immutable object id `oid` is what SCIM stores as
        # externalId, so link on that. UPN / preferred_username are tenant-
        # verified domains, fine for the allow-list + JIT username.
        email = email or claims.get("upn") or claims.get("preferred_username")
        verified = None
        if claims.get("oid"):
            external_ids.append(str(claims["oid"]))
    hd = claims.get("hd") if isinstance(claims.get("hd"), str) else None
    return store.ExternalIdentity(
        subject=str(claims["sub"]),
        email=email if isinstance(email, str) else None,
        email_verified=verified,
        name=claims.get("name") if isinstance(claims.get("name"), str) else None,
        preferred_username=claims.get("preferred_username")
        if isinstance(claims.get("preferred_username"), str) else None,
        groups=mapping.extract_groups(claims, provider["groups_claim"]),
        hosted_domain=hd,
        external_ids=external_ids,
    )


def identity_from_saml(provider, res: saml.SAMLResult) -> store.ExternalIdentity:
    cfg = store.provider_config(provider)

    def first(attr: str | None) -> str | None:
        if not attr:
            return None
        vals = res.attributes.get(attr) or []
        return vals[0] if vals else None

    email = first(cfg.get("email_attribute"))
    if not email and "@" in res.name_id:
        email = res.name_id
    groups_attr = cfg.get("groups_attribute") or provider["groups_claim"]
    return store.ExternalIdentity(
        subject=res.name_id,
        email=email,
        # The assertion is signed by the enterprise IdP the admin pinned by
        # certificate; its email attribute is authoritative for linking.
        email_verified=bool(email),
        name=first(cfg.get("name_attribute")),
        groups=list(res.attributes.get(groups_attr) or []),
        idp_session={
            "name_id": res.name_id, "format": res.name_id_format, "nq": res.name_id_nq,
            "spnq": res.name_id_spnq, "session_index": res.session_index,
        },
    )


def _provider_out(row) -> ProviderOut:
    d = dict(row)
    d["config"] = store.provider_config(row)
    d["role_mappings"] = store.provider_mappings(row)
    secrets_ = store.provider_secrets(row) if row["secrets"] else {}
    d["has_client_secret"] = bool(secrets_.get("client_secret"))
    d["has_sp_private_key"] = bool(secrets_.get("sp_private_key"))
    d["has_graph_client_secret"] = bool(secrets_.get("graph_client_secret"))
    d["allowed_domains"] = list(row["allowed_domains"] or [])
    if row["kind"] == "oidc":
        d["redirect_uri"] = _redirect_uri(row["slug"])
    else:
        urls = saml.sp_urls(row["slug"])
        d["saml_acs_url"] = urls["acs_url"]
        d["saml_entity_id"] = urls["entity_id"]
        d["saml_metadata_url"] = urls["metadata_url"]
        d["saml_sls_url"] = urls["sls_url"]
    return ProviderOut.model_validate(d)


# --------------------------------------------------------------------------- #
# Public: providers list
# --------------------------------------------------------------------------- #

@router.get("/providers", response_model=PublicProvidersOut)
async def public_providers(
    tenant: str | None = Query(None, max_length=64, description="tenant slug or id (default: the default tenant)"),
    pool=Depends(get_pool),
):
    tid = tenancy.DEFAULT_TENANT_ID
    if tenant:
        tid = await tenancy.resolve_tenant_ref(pool, tenant)
        if tid is None:  # unknown tenant: same empty answer as a tenant without SSO
            return PublicProvidersOut(providers=[], sso_required=False)
    with tenancy.tenant_context(tid):
        async with pool.acquire() as con:
            rows = await con.fetch(
                "SELECT slug, kind, preset, display_name FROM identity_providers "
                "WHERE enabled ORDER BY display_name"
            )
            s = await store.get_settings(con)
    return PublicProvidersOut(
        providers=[
            PublicProvider(
                slug=r["slug"], kind=r["kind"], preset=r["preset"], display_name=r["display_name"],
                start_url=f"/v1/auth/sso/{r['slug']}/start",
            )
            for r in rows
        ],
        sso_required=bool(s["sso_required"]),
    )


# --------------------------------------------------------------------------- #
# Public: start
# --------------------------------------------------------------------------- #

@router.get("/{slug}/start")
async def sso_start(
    slug: str,
    request: Request,
    return_to: str | None = Query(None, max_length=512),
    spa_challenge: str | None = Query(None, max_length=64),
    pool=Depends(get_pool),
):
    # Resolve the provider's tenant first; the whole flow runs inside it.
    async with store.provider_scope(pool, slug) as provider:
        return await _sso_start(slug, request, provider, return_to, spa_challenge, pool)


async def _sso_start(slug, request, provider, return_to, spa_challenge, pool):
    if provider is None:
        raise HTTPException(status_code=404, detail="unknown identity provider")
    # Mandatory: binds the eventual one-time code to the tab that started the
    # login. This is also what stops SAML login-CSRF: an attacker who replays
    # their own SAMLResponse into a victim's browser can't redeem the code.
    if spa_challenge is None or not _CHALLENGE_RE.match(spa_challenge):
        raise HTTPException(status_code=400, detail="spa_challenge must be base64url(sha256(verifier))")
    if _start_throttled(auth_svc.client_ip(request) or "?"):
        raise HTTPException(status_code=429, detail="too many sign-in attempts; try again shortly")
    return_to = _safe_return_to(return_to)
    cfg = store.provider_config(provider)

    if provider["kind"] == "oidc":
        try:
            ocfg = OIDCConfig.model_validate(cfg)
            disc = await oidc.discover(ocfg.issuer, allow_private=ocfg.allow_private)
        except (oidc.OIDCError, ValidationError) as exc:
            code = exc.code if isinstance(exc, oidc.OIDCError) else "provider_misconfigured"
            return await _login_failed(request, provider, code, str(exc))
        verifier, challenge = oidc.pkce_pair()
        nonce = secrets.token_urlsafe(32)
        state = await store.create_state(
            pool, provider_id=provider["id"], nonce=nonce, code_verifier=verifier,
            spa_challenge=spa_challenge, return_to=return_to,
        )
        url = oidc.authorization_url(
            disc, client_id=ocfg.client_id, redirect_uri=_redirect_uri(slug), scopes=ocfg.scopes,
            state=state, nonce=nonce, code_challenge=challenge, extra=ocfg.extra_auth_params,
        )
        resp = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
        # Binds the state to THIS browser (login-CSRF defence). Lax is enough:
        # the IdP returns with a top-level GET navigation.
        resp.set_cookie(
            STATE_COOKIE, state, max_age=settings.sso_state_ttl_sec, httponly=True,
            samesite="lax", secure=_cookie_secure(), path="/v1/auth/sso",
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # SAML (SP-initiated, HTTP-Redirect binding). The RelayState carries the
    # state; the AuthnRequest ID is stored as the "nonce" and must come back
    # as InResponseTo.
    if not saml.SAML_AVAILABLE:
        raise HTTPException(status_code=501, detail="SAML support is not installed (see docs/SSO.md)")
    state = secrets.token_urlsafe(32)
    try:
        SAMLConfig.model_validate(cfg)
        url, request_id = await run_in_threadpool(
            saml.start_login, slug, cfg, state, store.provider_secrets(provider).get("sp_private_key"),
        )
    except (saml.SAMLError, ValidationError) as exc:
        return await _login_failed(request, provider, "provider_misconfigured", str(exc))
    await store.create_state(
        pool, provider_id=provider["id"], nonce=request_id, code_verifier=None,
        spa_challenge=spa_challenge, return_to=return_to, state=state,
    )
    resp = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
    resp.headers["Cache-Control"] = "no-store"
    return resp


# --------------------------------------------------------------------------- #
# Public: OIDC callback
# --------------------------------------------------------------------------- #

@router.get("/{slug}/callback")
async def oidc_callback(
    slug: str,
    request: Request,
    code: str | None = Query(None, max_length=4096),
    state: str | None = Query(None, max_length=512),
    error: str | None = Query(None, max_length=256),
    pool=Depends(get_pool),
):
    async with store.provider_scope(pool, slug) as provider:
        return await _oidc_callback(slug, request, provider, code, state, error, pool)


async def _oidc_callback(slug, request, provider, code, state, error, pool):
    if provider is None or provider["kind"] != "oidc":
        return await _login_failed(request, None, "unknown_provider", f"no enabled OIDC provider {slug!r}")
    if not state:
        return await _login_failed(request, provider, "state_mismatch", "callback without state")
    # Burn the state first so it can never be retried, whatever happens next.
    row = await store.consume_state(pool, provider_id=provider["id"], state=state)
    cookie = request.cookies.get(STATE_COOKIE) or ""
    if row is None:
        return await _login_failed(request, provider, "state_mismatch", "unknown, expired or reused state")
    if not hmac.compare_digest(cookie.encode("utf-8"), state.encode("utf-8")):
        return await _login_failed(request, provider, "state_mismatch", "state not bound to this browser")
    if error:
        return await _login_failed(request, provider, "idp_error", f"IdP returned error={error[:64]}")
    if not code:
        return await _login_failed(request, provider, "idp_error", "callback without code")

    try:
        ocfg = OIDCConfig.model_validate(store.provider_config(provider))
        disc = await oidc.discover(ocfg.issuer, allow_private=ocfg.allow_private)
        tokens = await oidc.exchange_code(
            disc,
            client_id=ocfg.client_id,
            client_secret=store.provider_secrets(provider).get("client_secret"),
            auth_method=ocfg.token_auth_method,
            code=code,
            redirect_uri=_redirect_uri(slug),
            code_verifier=row["code_verifier"],
            allow_private=ocfg.allow_private,
        )
        claims = await oidc.validate_id_token(
            str(tokens["id_token"]),
            discovery=disc,
            client_id=ocfg.client_id,
            nonce=row["nonce"],
            leeway=settings.sso_clock_skew_sec,
            allow_private=ocfg.allow_private,
        )
        if ocfg.use_userinfo and tokens.get("access_token"):
            ui = await oidc.fetch_userinfo(disc, str(tokens["access_token"]), allow_private=ocfg.allow_private)
            if ui and str(ui.get("sub")) != str(claims["sub"]):
                raise oidc.OIDCError("invalid_token", "userinfo sub differs from ID token sub")
            claims = {**ui, **claims}  # ID-token claims win
    except oidc.OIDCError as exc:
        return await _login_failed(request, provider, exc.code, exc.detail)
    except ValidationError as exc:
        return await _login_failed(request, provider, "provider_misconfigured", str(exc))

    # Defence in depth: a nonce is accepted once per provider, ever (until
    # the token would have expired anyway).
    exp = datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc) + timedelta(
        seconds=settings.sso_clock_skew_sec
    )
    nonce_key = f"oidc:{provider['id']}:{hashlib.sha256(row['nonce'].encode()).hexdigest()}"
    if not await store.remember_once(pool, nonce_key, exp):
        return await _login_failed(request, provider, "replay", "ID token nonce already used")

    ident = identity_from_oidc_claims(provider, claims)
    if ocfg.graph_overage == "auto" and graph.oidc_overage(claims):
        await _resolve_overage_oidc(provider, ocfg, claims, tokens, ident)
    try:
        result = await store.provision(pool, provider, ident)
    except store.ProvisionError as exc:
        return await _login_failed(request, provider, exc.code, exc.detail, actor=ident.email or "anonymous")
    return await _login_succeeded(request, provider, result, row["spa_challenge"], row["return_to"],
                                  groups_error=ident.groups_error)


async def _resolve_overage_oidc(provider, ocfg: OIDCConfig, claims: dict[str, Any], tokens: dict[str, Any],
                                ident: store.ExternalIdentity) -> None:
    """Entra omitted the groups from the token (hasgroups / _claim_names):
    ask Microsoft Graph. On any failure the groups stay UNRESOLVED (no role
    mapping is applied) -- see identity/graph.py."""
    ident.groups = []  # never trust a partial list next to an overage marker
    try:
        gcfg = graph.GraphConfig(
            mode=ocfg.graph_mode, base_url=ocfg.graph_base_url, login_url=ocfg.graph_login_url,
            tenant_id=ocfg.graph_tenant_id or (str(claims["tid"]) if claims.get("tid") else None)
            or graph.tenant_from_issuer(ocfg.issuer),
            client_id=ocfg.client_id, client_secret=store.provider_secrets(provider).get("client_secret"),
            allow_private=ocfg.allow_private,
        )
        oid = str(claims["oid"]) if claims.get("oid") else None
        ident.groups = await graph.resolve_groups(
            gcfg, cache_scope=str(provider["id"]), subject=str(claims["sub"]), oid=oid,
            access_token=str(tokens["access_token"]) if tokens.get("access_token") else None,
        )
        ident.groups_source = "graph"
    except graph.GraphError as exc:
        ident.groups_unresolved, ident.groups_error = True, exc.code
        logger.warning("sso_graph_overage_failed",
                       extra={"provider": provider["slug"], "code": exc.code, "detail": exc.detail[:200]})


# --------------------------------------------------------------------------- #
# Public: SAML ACS + SP metadata
# --------------------------------------------------------------------------- #

@router.post("/{slug}/acs")
async def saml_acs(slug: str, request: Request, pool=Depends(get_pool)):
    async with store.provider_scope(pool, slug) as provider:
        return await _saml_acs(slug, request, provider, pool)


async def _saml_acs(slug, request, provider, pool):
    if provider is None or provider["kind"] != "saml":
        return await _login_failed(request, None, "unknown_provider", f"no enabled SAML provider {slug!r}")
    if not saml.SAML_AVAILABLE:
        raise HTTPException(status_code=501, detail="SAML support is not installed (see docs/SSO.md)")
    # Public and unauthenticated: stop reading at the cap instead of buffering an
    # arbitrarily large body first and measuring it afterwards.
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > _MAX_SAML_RESPONSE * 2:
            return await _login_failed(request, provider, "invalid_assertion", "SAMLResponse too large")
    raw = bytes(buf)
    form = parse_qs(raw.decode("latin-1"), max_num_fields=8)
    saml_response = (form.get("SAMLResponse") or [""])[0]
    relay_state = (form.get("RelayState") or [""])[0]
    if not saml_response:
        return await _login_failed(request, provider, "invalid_assertion", "no SAMLResponse")
    if not relay_state:
        # No RelayState = IdP-initiated (unsolicited). Refused by design.
        return await _login_failed(request, provider, "state_mismatch", "unsolicited SAML response")
    row = await store.consume_state(pool, provider_id=provider["id"], state=relay_state)
    if row is None:
        return await _login_failed(request, provider, "state_mismatch", "unknown, expired or reused RelayState")
    cfg = store.provider_config(provider)
    psecrets = store.provider_secrets(provider)
    try:
        res = await run_in_threadpool(
            saml.process_response, slug, cfg,
            saml_response=saml_response, relay_state=relay_state, request_id=row["nonce"],
            sp_private_key=psecrets.get("sp_private_key"),
        )
    except saml.SAMLError as exc:
        return await _login_failed(request, provider, exc.code, exc.detail)

    exp = (
        datetime.fromtimestamp(res.not_on_or_after, tz=timezone.utc)
        if res.not_on_or_after else datetime.now(timezone.utc) + timedelta(hours=1)
    ) + timedelta(seconds=settings.sso_clock_skew_sec)
    if not res.assertion_id or not await store.remember_once(
        pool, f"saml:{provider['id']}:{res.assertion_id}", exp,
    ):
        return await _login_failed(request, provider, "replay", "SAML assertion already consumed")

    ident = identity_from_saml(provider, res)
    if cfg.get("graph_overage", "auto") == "auto" and graph.saml_overage(res.attributes):
        await _resolve_overage_saml(provider, cfg, psecrets, res, ident)
    try:
        result = await store.provision(pool, provider, ident)
    except store.ProvisionError as exc:
        return await _login_failed(request, provider, exc.code, exc.detail, actor=ident.email or "anonymous")
    return await _login_succeeded(request, provider, result, row["spa_challenge"], row["return_to"],
                                  groups_error=ident.groups_error)


async def _resolve_overage_saml(provider, cfg: dict[str, Any], psecrets: dict[str, str], res: saml.SAMLResult,
                                ident: store.ExternalIdentity) -> None:
    """SAML groups.link claim: the assertion carries a link instead of groups.
    The link is legacy and untrusted; we call Graph with the app credentials."""
    ident.groups = []
    try:
        gcfg = graph.GraphConfig(
            mode="app", base_url=cfg.get("graph_base_url") or graph.DEFAULT_GRAPH,
            login_url=cfg.get("graph_login_url") or graph.DEFAULT_LOGIN,
            tenant_id=cfg.get("graph_tenant_id"), client_id=cfg.get("graph_client_id"),
            client_secret=psecrets.get("graph_client_secret"),
        )
        ident.groups = await graph.resolve_groups(
            gcfg, cache_scope=str(provider["id"]), subject=res.name_id, oid=graph.saml_object_id(res.attributes),
        )
        ident.groups_source = "graph"
    except graph.GraphError as exc:
        ident.groups_unresolved, ident.groups_error = True, exc.code
        logger.warning("sso_graph_overage_failed",
                       extra={"provider": provider["slug"], "code": exc.code, "detail": exc.detail[:200]})


@router.get("/{slug}/metadata")
async def saml_metadata(slug: str, pool=Depends(get_pool)):
    async with store.provider_scope(pool, slug) as provider:
        return await _saml_metadata(provider)


async def _saml_metadata(provider):
    slug = provider["slug"] if provider is not None else ""
    if provider is None or provider["kind"] != "saml":
        raise HTTPException(status_code=404, detail="unknown SAML provider")
    if not saml.SAML_AVAILABLE:
        raise HTTPException(status_code=501, detail="SAML support is not installed (see docs/SSO.md)")
    try:
        xml = await run_in_threadpool(
            saml.sp_metadata, slug, store.provider_config(provider),
            store.provider_secrets(provider).get("sp_private_key"))
    except saml.SAMLError as exc:
        raise HTTPException(status_code=500, detail=exc.code) from exc
    return Response(xml, media_type="application/samlmetadata+xml")


# --------------------------------------------------------------------------- #
# Single logout
# --------------------------------------------------------------------------- #

@router.get("/{slug}/sls")
async def saml_sls(slug: str, request: Request, pool=Depends(get_pool)):
    """SAML SingleLogoutService (HTTP-Redirect). Handles (a) the IdP's
    LogoutResponse to a logout WE started and (b) an IdP-initiated
    LogoutRequest. Both must be signed by the pinned IdP certificate."""
    async with store.provider_scope(pool, slug) as provider:
        return await _saml_sls(slug, request, provider, pool)


async def _saml_sls(slug, request, provider, pool):
    if provider is None or provider["kind"] != "saml":
        raise HTTPException(status_code=404, detail="unknown SAML provider")
    if not saml.SAML_AVAILABLE:
        raise HTTPException(status_code=501, detail="SAML support is not installed (see docs/SSO.md)")
    cfg = store.provider_config(provider)
    query = request.url.query
    if len(query) > 64_000:
        raise HTTPException(status_code=414, detail="logout message too large")
    request_id = None
    relay = (parse_qs(query).get("RelayState") or [""])[0]
    if "SAMLResponse=" in query:
        # a response to OUR LogoutRequest: its RelayState is single-use state
        # carrying the request id the response must answer (InResponseTo).
        st = await store.consume_state(pool, provider_id=provider["id"], state=relay) if relay else None
        if st is None:
            await _audit(request, action="logout", actor="anonymous", actor_role=None, resource_type="sso",
                         resource_id=slug, status_code=400,
                         details={"outcome": "failure", "reason": "state_mismatch"})
            raise HTTPException(status_code=400, detail="unknown, expired or reused logout state")
        request_id = st["nonce"]
    try:
        res = await run_in_threadpool(
            saml.process_sls, slug, cfg, query_string=query, request_id=request_id,
            sp_private_key=store.provider_secrets(provider).get("sp_private_key"),
        )
    except saml.SAMLError as exc:
        await _audit(request, action="logout", actor="anonymous", actor_role=None, resource_type="sso",
                     resource_id=slug, status_code=400,
                     details={"outcome": "failure", "reason": exc.code, "detail": exc.detail[:200]})
        raise HTTPException(status_code=400, detail="invalid logout message") from exc

    if res.kind == "response":
        resp = RedirectResponse(settings.sso_dashboard_url.rstrip("/") + "/", status_code=status.HTTP_303_SEE_OTHER)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # IdP-initiated LogoutRequest: end the matching user's sessions.
    revoked = 0
    async with pool.acquire() as con:
        async with con.transaction():
            row = await con.fetchrow(
                "SELECT i.user_id, i.idp_session FROM user_identities i "
                "WHERE i.provider_id = $1 AND i.subject = $2",
                provider["id"], res.name_id,
            )
            if row is not None:
                sess = row["idp_session"]
                if isinstance(sess, str):
                    sess = json.loads(sess)
                stored = (sess or {}).get("session_index")
                if not res.session_indexes or not stored or stored in res.session_indexes:
                    await store.revoke_user_sessions(con, row["user_id"], revoke_api_keys=False)
                    revoked = 1
    await _audit(request, action="logout", actor=res.name_id or "unknown", actor_role=None, resource_type="sso",
                 resource_id=slug, status_code=302,
                 details={"outcome": "success", "initiator": "idp", "sessions_revoked": bool(revoked)})
    resp = RedirectResponse(res.redirect_url or "/", status_code=status.HTTP_302_FOUND)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@router.post("/logout")
async def sso_logout(request: Request, pool=Depends(get_pool)):
    """End the caller's session(s) everywhere Paddock controls: every JWT
    issued so far stops working (session watermark) and pending SSO exchange
    codes are deleted. If the user signed in through SAML and the IdP has a
    single-logout URL, ``idp_logout_url`` is the (signed) LogoutRequest
    redirect the SPA should navigate to so the IdP session ends too; for OIDC
    it is the IdP's ``end_session_endpoint`` when it has one."""
    p = current_principal(request)
    if p.kind != "user" or not p.user_id:
        raise HTTPException(status_code=400, detail="no interactive session to end (API keys are revoked in Settings)")
    uid = UUID(p.user_id)
    async with pool.acquire() as con:
        async with con.transaction():
            await store.revoke_user_sessions(con, uid, revoke_api_keys=False)
            ident = await con.fetchrow(
                "SELECT i.subject, i.idp_session, p.* FROM user_identities i "
                "JOIN identity_providers p ON p.id = i.provider_id "
                "WHERE i.user_id = $1 AND p.enabled ORDER BY i.last_login DESC NULLS LAST LIMIT 1",
                uid,
            )
    idp_url: str | None = None
    note: str | None = None
    if ident is not None:
        cfg = store.provider_config(ident)
        try:
            if ident["kind"] == "saml" and saml.SAML_AVAILABLE and saml.slo_supported(cfg):
                sess = ident["idp_session"]
                sess = json.loads(sess) if isinstance(sess, str) else (sess or {})
                if sess.get("name_id"):
                    relay = secrets.token_urlsafe(32)
                    idp_url, req_id = await run_in_threadpool(
                        saml.build_logout_request, ident["slug"], cfg, name_id=sess["name_id"],
                        session_index=sess.get("session_index"), name_id_format=sess.get("format"),
                        name_id_nq=sess.get("nq"), name_id_spnq=sess.get("spnq"), relay_state=relay,
                        sp_private_key=store.provider_secrets(ident).get("sp_private_key"),
                    )
                    await store.create_state(
                        pool, provider_id=ident["id"], nonce=req_id, code_verifier=None,
                        spa_challenge=None, return_to="/", state=relay,
                    )
            elif ident["kind"] == "oidc":
                ocfg = OIDCConfig.model_validate(cfg)
                disc = await oidc.discover(ocfg.issuer, allow_private=ocfg.allow_private)
                end = disc.get("end_session_endpoint")
                if isinstance(end, str) and end:
                    await oidc.check_url(end, allow_private=ocfg.allow_private)
                    idp_url = end + ("&" if "?" in end else "?") + urlencode({
                        "client_id": ocfg.client_id,
                        "post_logout_redirect_uri": settings.sso_dashboard_url.rstrip("/") + "/",
                    })
        except (saml.SAMLError, oidc.OIDCError, ValidationError) as exc:
            note = "idp_logout_unavailable"
            logger.warning("sso_idp_logout_failed", extra={"provider": ident["slug"], "detail": str(exc)[:200]})
    await _audit(request, action="logout", actor=p.actor, actor_role=p.role, resource_type="sso",
                 resource_id=ident["slug"] if ident is not None else None, status_code=200,
                 details={"outcome": "success", "initiator": "user", "idp_logout": bool(idp_url),
                          **({"note": note} if note else {})})
    resp = Response(json.dumps({"revoked": True, "idp_logout_url": idp_url}), media_type="application/json")
    resp.headers["Cache-Control"] = "no-store"
    return resp


# --------------------------------------------------------------------------- #
# Public: one-time code exchange
# --------------------------------------------------------------------------- #

@router.post("/exchange", response_model=ExchangeOut)
async def exchange(body: ExchangeIn, request: Request, pool=Depends(get_pool)):
    user = await store.redeem_exchange_code(pool, code=body.code, verifier=body.verifier)
    if user is None or not user["active"]:
        await _audit(
            request, action="login", actor="anonymous", actor_role=None, resource_type="sso",
            resource_id="exchange", status_code=400,
            details={"outcome": "failure", "reason": "invalid_code"},
        )
        raise HTTPException(status_code=400, detail="invalid, expired or already-used code")
    token, ttl = auth_svc.issue_jwt(
        user_id=str(user["id"]), username=user["username"], role=user["role"], clearance=user["clearance"],
        tenant_id=str(user["tenant_id"]),
    )
    return ExchangeOut(
        access_token=token, role=user["role"], clearance=user["clearance"], expires_in=ttl,
        username=user["username"],
    )


# =========================================================================== #
# Admin
# =========================================================================== #

_admin = [Depends(require("admin"))]


def _require_secret_key() -> None:
    if settings.auth_mode == "enforce" and not secret_box.has_persistent_key():
        raise HTTPException(
            status_code=409,
            detail="PADDOCK_SECRET_KEY must be set before storing IdP client secrets",
        )


async def _validated_config(
    kind: str, slug: str, oidc_cfg, saml_cfg, metadata_xml, metadata_url: str | None = None,
    sp_private_key: str | None = None, existing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if kind == "oidc":
        if oidc_cfg is None:
            raise HTTPException(status_code=422, detail="oidc settings are required for kind=oidc")
        scheme = urlsplit(oidc_cfg.issuer).scheme
        if scheme != "https" and not (scheme == "http" and oidc_cfg.allow_private):
            raise HTTPException(status_code=422, detail="issuer must be https:// (http only with allow_private)")
        return oidc_cfg.model_dump()
    if not saml.SAML_AVAILABLE:
        raise HTTPException(status_code=501, detail="SAML support is not installed (see docs/SSO.md)")
    base: dict[str, Any] = dict(existing or {})   # PATCH: unspecified fields keep their value
    try:
        if metadata_url and not metadata_xml:
            # fetched through the DNS-pinned transport (https, public only)
            metadata_xml = await saml.fetch_idp_metadata(metadata_url)
        if metadata_xml:
            base.update(await run_in_threadpool(saml.parse_idp_metadata, metadata_xml))
        if saml_cfg is not None:
            fields = saml_cfg.model_fields_set if existing else None
            base.update({k: v for k, v in saml_cfg.model_dump().items()
                         if v is not None and (fields is None or k in fields)})
        cfg = SAMLConfig.model_validate(base).model_dump()
        await run_in_threadpool(saml.validate_config, slug, cfg, sp_private_key)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=f"saml settings invalid: {exc.errors()[:3]}") from exc
    except saml.SAMLError as exc:
        raise HTTPException(status_code=422, detail=exc.detail) from exc
    return cfg


def _actor(request: Request):
    p = current_principal(request)
    return p.actor, p.role


@router.get("/admin/providers", response_model=list[ProviderOut], dependencies=_admin)
async def admin_list_providers(pool=Depends(get_pool)):
    async with pool.acquire() as con:
        rows = await con.fetch("SELECT * FROM identity_providers ORDER BY created_at")
    return [_provider_out(r) for r in rows]


@router.get("/admin/providers/{provider_id}", response_model=ProviderOut, dependencies=_admin)
async def admin_get_provider(provider_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        row = await con.fetchrow("SELECT * FROM identity_providers WHERE id = $1", provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="provider not found")
    return _provider_out(row)


@router.post(
    "/admin/providers", response_model=ProviderOut, status_code=status.HTTP_201_CREATED,
    dependencies=_admin,
)
async def admin_create_provider(body: ProviderIn, request: Request, pool=Depends(get_pool)):
    if body.slug in store.RESERVED_SLUGS:
        raise HTTPException(status_code=422, detail=f"slug {body.slug!r} is reserved")
    if body.kind == "saml":
        await billing_gate.ensure_feature(request, "sso_saml")  # 402 on a plan without SAML
    cfg = await _validated_config(
        body.kind, body.slug, body.oidc, body.saml, body.saml_metadata_xml, body.idp_metadata_url,
        body.sp_private_key,
    )
    blob = None
    new_secrets = {"client_secret": body.client_secret, "sp_private_key": body.sp_private_key,
                   "graph_client_secret": body.graph_client_secret}
    if any(new_secrets.values()):
        _require_secret_key()
        blob = store.pack_secrets({}, new_secrets)
    actor, role = _actor(request)
    async with pool.acquire() as con:
        exists = await con.fetchval("SELECT 1 FROM identity_providers WHERE slug = $1", body.slug)
        if exists:
            raise HTTPException(status_code=409, detail="a provider with this slug exists")
        try:
            row = await _insert_provider(con, body, cfg, blob, actor)
        except asyncpg.UniqueViolationError as exc:  # slug is global; another tenant may own it
            raise HTTPException(status_code=409, detail="a provider with this slug exists") from exc
    await _audit(
        request, action="create", actor=actor, actor_role=role, resource_type="identity_provider",
        resource_id=str(row["id"]), status_code=201,
        details={"slug": body.slug, "kind": body.kind, "preset": body.preset,
                 "client_secret_set": bool(blob), "role_mappings": len(body.role_mappings)},
    )
    return _provider_out(row)


async def _insert_provider(con, body, cfg, blob, actor):
    return await con.fetchrow(
        """
        INSERT INTO identity_providers
            (slug, kind, preset, display_name, enabled, config, secrets, allowed_domains,
             jit_provisioning, sync_roles, require_mapping, default_role, default_clearance,
             groups_claim, role_mappings, created_by)
        VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8::text[],$9,$10,$11,$12,$13,$14,$15::jsonb,$16)
        RETURNING *
        """,
        body.slug, body.kind, body.preset, body.display_name, body.enabled,
        _json(cfg), blob, body.allowed_domains, body.jit_provisioning, body.sync_roles,
        body.require_mapping, body.default_role, body.default_clearance, body.groups_claim,
        _json([m.model_dump() for m in body.role_mappings]), actor,
    )


@router.patch("/admin/providers/{provider_id}", response_model=ProviderOut, dependencies=_admin)
async def admin_update_provider(
    provider_id: UUID, body: ProviderPatch, request: Request, pool=Depends(get_pool),
):
    async with pool.acquire() as con:
        cur = await con.fetchrow("SELECT * FROM identity_providers WHERE id = $1", provider_id)
    if cur is None:
        raise HTTPException(status_code=404, detail="provider not found")
    sets: dict[str, Any] = {}
    secret_fields = ("client_secret", "sp_private_key", "graph_client_secret")
    changed = sorted(k for k in body.model_fields_set
                     if k not in (*secret_fields, "saml_metadata_xml", "idp_metadata_url"))
    cur_secrets = store.provider_secrets(cur) if cur["secrets"] else {}
    key_after = (body.sp_private_key or None) if "sp_private_key" in body.model_fields_set \
        else cur_secrets.get("sp_private_key")
    if cur["kind"] == "oidc" and body.oidc is not None:
        sets["config"] = _json(await _validated_config("oidc", cur["slug"], body.oidc, None, None))
    if cur["kind"] == "saml" and (body.saml is not None or body.saml_metadata_xml or body.idp_metadata_url):
        await billing_gate.ensure_feature(request, "sso_saml")  # reconfiguring SAML is a paid action
        # metadata (if given) is the base; explicit `saml` fields override it
        sets["config"] = _json(
            await _validated_config("saml", cur["slug"], None, body.saml, body.saml_metadata_xml,
                                    body.idp_metadata_url, key_after, store.provider_config(cur))
        )
        changed = sorted(set(changed) | {"saml"})
    elif cur["kind"] == "saml" and "sp_private_key" in body.model_fields_set:
        try:  # a rotated key must still match the configured SP certificate
            await run_in_threadpool(saml.validate_config, cur["slug"], store.provider_config(cur), key_after)
        except saml.SAMLError as exc:
            raise HTTPException(status_code=422, detail=exc.detail) from exc
    for f in ("display_name", "enabled", "preset", "jit_provisioning", "sync_roles", "require_mapping",
              "default_role", "default_clearance", "groups_claim", "allowed_domains"):
        if f in body.model_fields_set and getattr(body, f) is not None:
            sets[f] = getattr(body, f)
    if body.role_mappings is not None:
        sets["role_mappings"] = _json([m.model_dump() for m in body.role_mappings])
    secret_change: dict[str, str] = {}
    updates = {f: getattr(body, f) for f in secret_fields if f in body.model_fields_set}
    if updates:
        if any(updates.values()):
            _require_secret_key()
        sets["secrets"] = store.pack_secrets(cur_secrets, updates)
        secret_change = {f: ("rotated" if v else "cleared") for f, v in updates.items()}
    if not sets:
        return _provider_out(cur)
    casts = {"config": "::jsonb", "role_mappings": "::jsonb", "allowed_domains": "::text[]"}
    cols = list(sets)
    assign = ", ".join(f"{c} = ${i + 2}{casts.get(c, '')}" for i, c in enumerate(cols))
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"UPDATE identity_providers SET {assign}, updated_at = NOW() WHERE id = $1 RETURNING *",
            provider_id, *[sets[c] for c in cols],
        )
    actor, role = _actor(request)
    await _audit(
        request, action="update", actor=actor, actor_role=role, resource_type="identity_provider",
        resource_id=str(provider_id), status_code=200,
        details={"slug": cur["slug"], "changed": changed, "secrets": secret_change},
    )
    return _provider_out(row)


@router.delete(
    "/admin/providers/{provider_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=_admin,
)
async def admin_delete_provider(provider_id: UUID, request: Request, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "DELETE FROM identity_providers WHERE id = $1 RETURNING slug, kind", provider_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="provider not found")
    actor, role = _actor(request)
    await _audit(
        request, action="delete", actor=actor, actor_role=role, resource_type="identity_provider",
        resource_id=str(provider_id), status_code=204, details={"slug": row["slug"], "kind": row["kind"]},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/admin/providers/{provider_id}/saml-sp-keypair", dependencies=_admin)
async def admin_generate_sp_keypair(provider_id: UUID, request: Request, pool=Depends(get_pool)):
    """Generate (or rotate) the SAML SP signing/encryption key pair. The
    private key is stored encrypted and never returned; the certificate is
    saved in the provider config and returned for the IdP (it is also in the
    SP metadata)."""
    async with pool.acquire() as con:
        cur = await con.fetchrow("SELECT * FROM identity_providers WHERE id = $1", provider_id)
    if cur is None or cur["kind"] != "saml":
        raise HTTPException(status_code=404, detail="SAML provider not found")
    if not saml.SAML_AVAILABLE:
        raise HTTPException(status_code=501, detail="SAML support is not installed (see docs/SSO.md)")
    await billing_gate.ensure_feature(request, "sso_saml")  # SAML reconfiguration is a paid action
    _require_secret_key()
    cert_pem, key_pem = await run_in_threadpool(saml.generate_sp_keypair, cur["slug"])
    cfg = {**store.provider_config(cur), "sp_x509_cert": cert_pem}
    blob = store.pack_secrets(store.provider_secrets(cur) if cur["secrets"] else {}, {"sp_private_key": key_pem})
    async with pool.acquire() as con:
        await con.execute(
            "UPDATE identity_providers SET config = $2::jsonb, secrets = $3, updated_at = NOW() WHERE id = $1",
            provider_id, _json(cfg), blob,
        )
    actor, role = _actor(request)
    await _audit(request, action="update", actor=actor, actor_role=role, resource_type="identity_provider",
                 resource_id=str(provider_id), status_code=200,
                 details={"slug": cur["slug"], "changed": ["saml_sp_keypair"]})
    return {"sp_x509_cert": cert_pem, "metadata_url": saml.sp_urls(cur["slug"])["metadata_url"]}


@router.post("/admin/providers/{provider_id}/test", dependencies=_admin)
async def admin_test_provider(provider_id: UUID, pool=Depends(get_pool)):
    """Connectivity / configuration check. OIDC: run discovery + fetch JWKS."""
    async with pool.acquire() as con:
        row = await con.fetchrow("SELECT * FROM identity_providers WHERE id = $1", provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="provider not found")
    cfg = store.provider_config(row)
    try:
        if row["kind"] == "oidc":
            ocfg = OIDCConfig.model_validate(cfg)
            disc = await oidc.discover(ocfg.issuer, allow_private=ocfg.allow_private)
            keys = await oidc.jwks_cache._fetch(str(disc["jwks_uri"]), ocfg.allow_private)
            return {
                "ok": True,
                "issuer": disc["issuer"],
                "authorization_endpoint": disc["authorization_endpoint"],
                "token_endpoint": disc["token_endpoint"],
                "jwks_keys": len(keys),
                "has_client_secret": bool(store.provider_secrets(row).get("client_secret")),
            }
        await run_in_threadpool(
            saml.validate_config, row["slug"], cfg, store.provider_secrets(row).get("sp_private_key"))
        return {"ok": True, "idp_entity_id": cfg.get("idp_entity_id"), "idp_sso_url": cfg.get("idp_sso_url"),
                "idp_slo_url": cfg.get("idp_slo_url"), "signs_requests": bool(cfg.get("sign_authn_requests")),
                "has_sp_private_key": bool(store.provider_secrets(row).get("sp_private_key"))}
    except (oidc.OIDCError, saml.SAMLError) as exc:
        return {"ok": False, "error": exc.code, "detail": exc.detail}
    except ValidationError as exc:
        return {"ok": False, "error": "provider_misconfigured", "detail": str(exc.errors()[:3])}


# --- settings ------------------------------------------------------------- #

def _settings_out(s: dict[str, Any]) -> IdentitySettingsOut:
    return IdentitySettingsOut(
        sso_required=s["sso_required"],
        break_glass_users=list(s["break_glass_users"] or []),
        scim_role_mappings=s["scim_role_mappings"],
        scim_default_role=s["scim_default_role"],
        scim_default_clearance=s["scim_default_clearance"],
        updated_by=s.get("updated_by"),
        updated_at=s["updated_at"],
        scim_base_url=f"{_base()}/scim/v2",
    )


@router.get("/admin/settings", response_model=IdentitySettingsOut, dependencies=_admin)
async def admin_get_settings(pool=Depends(get_pool)):
    async with pool.acquire() as con:
        return _settings_out(await store.get_settings(con))


@router.put("/admin/settings", response_model=IdentitySettingsOut, dependencies=_admin)
async def admin_put_settings(body: IdentitySettingsIn, request: Request, pool=Depends(get_pool)):
    actor, role = _actor(request)
    async with pool.acquire() as con:
        async with con.transaction():
            cur = await store.get_settings(con)
            sso_required = cur["sso_required"] if body.sso_required is None else body.sso_required
            break_glass = cur["break_glass_users"] if body.break_glass_users is None else sorted(
                {u.strip() for u in body.break_glass_users if u.strip()}
            )
            if sso_required:
                n = await con.fetchval("SELECT count(*) FROM identity_providers WHERE enabled")
                if not n:
                    raise HTTPException(status_code=409, detail="enable an identity provider before requiring SSO")
                if not break_glass:
                    raise HTTPException(
                        status_code=409,
                        detail="keep at least one break-glass user when SSO is required (lock-out guard)",
                    )
            mappings = cur["scim_role_mappings"] if body.scim_role_mappings is None else [
                m.model_dump() for m in body.scim_role_mappings
            ]
            row = await con.fetchrow(
                """
                UPDATE identity_settings
                   SET sso_required = $1, break_glass_users = $2::text[], scim_role_mappings = $3::jsonb,
                       scim_default_role = $4, scim_default_clearance = $5,
                       updated_by = $6, updated_at = NOW()
                 WHERE id RETURNING *
                """,
                sso_required, break_glass, _json(mappings),
                body.scim_default_role or cur["scim_default_role"],
                body.scim_default_clearance or cur["scim_default_clearance"],
                actor,
            )
            s = dict(row)
            s["scim_role_mappings"] = mappings
            recomputed = 0
            if (
                body.scim_role_mappings is not None
                or body.scim_default_role is not None
                or body.scim_default_clearance is not None
            ):
                recomputed = await scim_logic.recompute_roles(con, None)
    await _audit(
        request, action="update", actor=actor, actor_role=role, resource_type="identity_settings",
        resource_id="global", status_code=200,
        details={
            "changed": sorted(body.model_fields_set),
            "sso_required": sso_required,
            "break_glass_users": break_glass,
            "scim_role_mappings": len(mappings),
            "scim_users_recomputed": recomputed,
        },
    )
    return _settings_out(s)


# --- SCIM tokens ------------------------------------------------------------ #

@router.get("/admin/scim-tokens", response_model=list[ScimTokenOut], dependencies=_admin)
async def admin_list_scim_tokens(pool=Depends(get_pool)):
    async with pool.acquire() as con:
        rows = await con.fetch(
            "SELECT id, name, prefix, created_by, created_at, last_used, expires_at, revoked "
            "FROM scim_tokens ORDER BY created_at DESC"
        )
    return [ScimTokenOut.model_validate(dict(r)) for r in rows]


@router.post(
    "/admin/scim-tokens", response_model=ScimTokenCreateOut, status_code=status.HTTP_201_CREATED,
    dependencies=_admin,
)
async def admin_create_scim_token(body: ScimTokenIn, request: Request, pool=Depends(get_pool)):
    await billing_gate.ensure_feature(request, "scim")
    actor, role = _actor(request)
    full, prefix, token_hash = auth_svc.generate_scim_token()
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO scim_tokens (name, prefix, token_hash, created_by, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, name, prefix, created_by, created_at, last_used, expires_at, revoked
            """,
            body.name, prefix, token_hash, actor, body.expires_at,
        )
    await _audit(
        request, action="create", actor=actor, actor_role=role, resource_type="scim_token",
        resource_id=str(row["id"]), status_code=201, details={"name": body.name, "prefix": prefix},
    )
    return ScimTokenCreateOut.model_validate({**dict(row), "token": full})


@router.delete("/admin/scim-tokens/{token_id}", response_model=ScimTokenOut, dependencies=_admin)
async def admin_revoke_scim_token(token_id: UUID, request: Request, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "UPDATE scim_tokens SET revoked = TRUE WHERE id = $1 "
            "RETURNING id, name, prefix, created_by, created_at, last_used, expires_at, revoked",
            token_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="SCIM token not found")
    actor, role = _actor(request)
    await _audit(
        request, action="delete", actor=actor, actor_role=role, resource_type="scim_token",
        resource_id=str(token_id), status_code=200, details={"name": row["name"], "prefix": row["prefix"]},
    )
    return ScimTokenOut.model_validate(dict(row))


def _json(value: Any) -> str:
    return json.dumps(value)
