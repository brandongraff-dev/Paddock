"""Identity persistence: providers, login state, exchange codes, JIT users.

All one-time values (SSO ``state``, SPA exchange codes, SCIM tokens) are
stored as sha256 hashes and consumed with ``DELETE ... RETURNING`` so a
value can be redeemed at most once even under concurrent requests.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import settings
from ..integrations import secrets as secret_box
from . import mapping

logger = logging.getLogger(__name__)

RESERVED_SLUGS = frozenset({"admin", "providers", "exchange"})


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _jsonb(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #

async def get_settings(con) -> dict[str, Any]:
    row = await con.fetchrow("SELECT * FROM identity_settings WHERE id")
    if row is None:  # the migration seeds it; recreate defensively
        row = await con.fetchrow(
            "INSERT INTO identity_settings (id) VALUES (TRUE) "
            "ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id RETURNING *"
        )
    d = dict(row)
    d["scim_role_mappings"] = _jsonb(d["scim_role_mappings"]) or []
    return d


async def password_login_allowed(pool, username: str) -> bool:
    """False when SSO is required and ``username`` is not a break-glass user.

    Decided from the policy alone (not from whether the user exists), so the
    answer leaks nothing about which accounts exist.
    """
    async with pool.acquire() as con:
        s = await get_settings(con)
    if not s["sso_required"]:
        return True
    wanted = username.strip().lower().encode("utf-8")
    allowed = False
    for bg in s["break_glass_users"] or []:
        # constant-time per entry; no early exit
        allowed |= hmac.compare_digest(bg.strip().lower().encode("utf-8"), wanted)
    return allowed


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #

def provider_secrets(row) -> dict[str, str]:
    try:
        return secret_box.decrypt_secrets(row["secrets"])
    except Exception:  # noqa: BLE001 -- rotated-away key etc.; never log the blob
        logger.error("sso_provider_secret_undecryptable", extra={"slug": row["slug"]})
        return {}


def provider_config(row) -> dict[str, Any]:
    return _jsonb(row["config"]) or {}


def provider_mappings(row) -> list[dict[str, Any]]:
    return _jsonb(row["role_mappings"]) or []


async def provider_by_slug(con, slug: str, *, enabled_only: bool = True):
    sql = "SELECT * FROM identity_providers WHERE slug = $1"
    if enabled_only:
        sql += " AND enabled"
    return await con.fetchrow(sql, slug)


# --------------------------------------------------------------------------- #
# Login state (state / nonce / PKCE) -- single use
# --------------------------------------------------------------------------- #

async def create_state(
    pool,
    *,
    provider_id,
    nonce: str,
    code_verifier: str | None,
    spa_challenge: str | None,
    return_to: str | None,
    state: str | None = None,
) -> str:
    state = state or secrets.token_urlsafe(32)
    exp = _now() + timedelta(seconds=settings.sso_state_ttl_sec)
    async with pool.acquire() as con:
        await con.execute("DELETE FROM sso_login_states WHERE expires_at < NOW()")
        await con.execute(
            """
            INSERT INTO sso_login_states
                (state_hash, provider_id, nonce, code_verifier, spa_challenge, return_to, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            sha256_hex(state), provider_id, nonce, code_verifier, spa_challenge, return_to, exp,
        )
    return state


async def consume_state(pool, *, provider_id, state: str):
    async with pool.acquire() as con:
        return await con.fetchrow(
            """
            DELETE FROM sso_login_states
             WHERE state_hash = $1 AND provider_id = $2 AND expires_at > NOW()
         RETURNING nonce, code_verifier, spa_challenge, return_to
            """,
            sha256_hex(state), provider_id,
        )


async def remember_once(pool, key: str, expires_at: datetime) -> bool:
    """Record a one-time value; False if it was already seen (replay)."""
    async with pool.acquire() as con:
        await con.execute("DELETE FROM sso_replay_cache WHERE expires_at < NOW()")
        got = await con.fetchval(
            "INSERT INTO sso_replay_cache (key, expires_at) VALUES ($1, $2) "
            "ON CONFLICT (key) DO NOTHING RETURNING key",
            key, expires_at,
        )
    return got is not None


# --------------------------------------------------------------------------- #
# One-time SPA exchange codes
# --------------------------------------------------------------------------- #

async def issue_exchange_code(pool, *, user_id, provider_id, spa_challenge: str | None) -> str:
    code = secrets.token_urlsafe(32)
    exp = _now() + timedelta(seconds=settings.sso_code_ttl_sec)
    async with pool.acquire() as con:
        await con.execute("DELETE FROM sso_exchange_codes WHERE expires_at < NOW()")
        await con.execute(
            "INSERT INTO sso_exchange_codes (code_hash, user_id, provider_id, spa_challenge, expires_at) "
            "VALUES ($1, $2, $3, $4, $5)",
            sha256_hex(code), user_id, provider_id, spa_challenge, exp,
        )
    return code


async def redeem_exchange_code(pool, *, code: str, verifier: str | None):
    """Consume a code (always, even on a verifier mismatch) and return the
    user row, or None."""
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "DELETE FROM sso_exchange_codes WHERE code_hash = $1 "
            "RETURNING user_id, provider_id, spa_challenge, expires_at",
            sha256_hex(code),
        )
        if row is None or row["expires_at"] <= _now():
            return None
        # Fail closed: every code is bound to the starting tab's verifier.
        if not row["spa_challenge"] or not verifier or not hmac.compare_digest(
            s256(verifier).encode(), row["spa_challenge"].encode()
        ):
            return None
        return await con.fetchrow(
            "SELECT id, username, role, clearance, active FROM app_users WHERE id = $1",
            row["user_id"],
        )


# --------------------------------------------------------------------------- #
# Session revocation
# --------------------------------------------------------------------------- #

async def revoke_user_sessions(con, user_id, *, revoke_api_keys: bool) -> None:
    """Invalidate every JWT issued so far (auth checks iat vs. this watermark)
    and, on deactivation, every API key, plus pending SSO exchange codes."""
    await con.execute(
        "UPDATE app_users SET sessions_revoked_at = NOW(), updated_at = NOW() WHERE id = $1",
        user_id,
    )
    await con.execute("DELETE FROM sso_exchange_codes WHERE user_id = $1", user_id)
    if revoke_api_keys:
        await con.execute(
            "UPDATE api_keys SET revoked = TRUE WHERE user_id = $1 AND NOT revoked", user_id,
        )


# --------------------------------------------------------------------------- #
# JIT provisioning + linking
# --------------------------------------------------------------------------- #

class ProvisionError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass
class ExternalIdentity:
    subject: str
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    preferred_username: str | None = None
    groups: list[str] = field(default_factory=list)
    hosted_domain: str | None = None
    # Stable IdP-side ids that SCIM may have stored as externalId
    # (Okta: sub; Entra: oid).
    external_ids: list[str] = field(default_factory=list)


@dataclass
class ProvisionResult:
    user: dict[str, Any]
    created: bool
    linked: str  # identity | external_id | email | jit
    role_decision: mapping.RoleDecision
    role_changed: bool


async def provision(pool, provider, ident: ExternalIdentity) -> ProvisionResult:
    cfg = provider_config(provider)
    slug = provider["slug"]
    email = (ident.email or "").strip().lower() or None

    if not mapping.domain_allowed(email, provider["allowed_domains"] or [], hosted_domain=ident.hosted_domain):
        raise ProvisionError("domain_not_allowed", f"domain of {mapping.email_domain(email)!r} not allowed")

    decision = mapping.resolve_role(
        ident.groups,
        provider_mappings(provider),
        default_role=provider["default_role"],
        default_clearance=provider["default_clearance"],
    )
    if provider["require_mapping"] and decision.matched is None:
        raise ProvisionError("no_mapping", "no role mapping matched the user's groups")

    trust_email = bool(email) and (
        ident.email_verified is True or bool(cfg.get("trust_unverified_email"))
    )
    cols = "id, username, email, role, clearance, active, provisioned_by"
    ucols = ", ".join("u." + c for c in cols.split(", "))

    async with pool.acquire() as con:
        async with con.transaction():
            idp_settings = await get_settings(con)
            user = None
            linked = "identity"
            row = await con.fetchrow(
                f"SELECT {ucols} "
                "FROM user_identities i JOIN app_users u ON u.id = i.user_id "
                "WHERE i.provider_id = $1 AND i.subject = $2",
                provider["id"], ident.subject,
            )
            if row is not None:
                user = dict(row)
            if user is None and ident.external_ids:
                row = await con.fetchrow(
                    f"SELECT {cols} FROM app_users WHERE provisioned_by = 'scim' "
                    "AND external_id = ANY($1::text[]) LIMIT 1",
                    [ident.subject, *ident.external_ids],
                )
                if row is not None:
                    user, linked = dict(row), "external_id"
            if user is None and email:
                row = await con.fetchrow(
                    f"SELECT {cols} FROM app_users WHERE lower(email) = $1 OR lower(username) = $1 "
                    "ORDER BY (lower(username) = $1) DESC LIMIT 1",
                    email,
                )
                if row is not None:
                    if not trust_email:
                        raise ProvisionError(
                            "account_conflict",
                            "an account with this email exists but the IdP did not assert a verified email",
                        )
                    user, linked = dict(row), "email"
            # Break-glass accounts exist for when the IdP is down or
            # compromised: an IdP identity may never claim one.
            break_glass = {u.lower() for u in idp_settings["break_glass_users"] or []}
            if user is not None and user["username"].lower() in break_glass:
                raise ProvisionError("account_conflict", "account is a break-glass account (local sign-in only)")
            created = False
            if user is None:
                if not provider["jit_provisioning"]:
                    raise ProvisionError("provisioning_disabled", "no linked account and JIT is off")
                username = email or (ident.preferred_username or "").strip().lower() or f"{slug}:{ident.subject}"
                taken = await con.fetchval("SELECT 1 FROM app_users WHERE lower(username) = lower($1)", username)
                if taken or username.lower() in break_glass:
                    raise ProvisionError("account_conflict", "username already taken by an unlinked account")
                row = await con.fetchrow(
                    f"""
                    INSERT INTO app_users (username, email, display_name, role, clearance, provisioned_by)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    RETURNING {cols}
                    """,
                    username, email, ident.name, decision.role, decision.clearance, f"sso:{slug}",
                )
                user, linked, created = dict(row), "jit", True

            if not user["active"]:
                raise ProvisionError("user_disabled", "account is deactivated")

            role_changed = False
            scim_managed = user.get("provisioned_by") == "scim" and bool(idp_settings["scim_role_mappings"])
            if (
                not created
                and provider["sync_roles"]
                and provider_mappings(provider)
                and user["username"].lower() not in break_glass
                and not scim_managed
                and (user["role"], user["clearance"]) != (decision.role, decision.clearance)
            ):
                await con.execute(
                    "UPDATE app_users SET role = $2, clearance = $3, updated_at = NOW() WHERE id = $1",
                    user["id"], decision.role, decision.clearance,
                )
                user["role"], user["clearance"] = decision.role, decision.clearance
                role_changed = True

            await con.execute(
                """
                INSERT INTO user_identities (user_id, provider_id, subject, email, groups, last_login)
                VALUES ($1, $2, $3, $4, $5::text[], NOW())
                ON CONFLICT (provider_id, subject) DO UPDATE
                   SET email = EXCLUDED.email, groups = EXCLUDED.groups, last_login = NOW()
                """,
                user["id"], provider["id"], ident.subject, email, ident.groups[:200],
            )
            await con.execute(
                "UPDATE app_users SET last_login = NOW(), email = COALESCE(email, $2) WHERE id = $1",
                user["id"], email,
            )
    return ProvisionResult(
        user=user, created=created, linked=linked, role_decision=decision, role_changed=role_changed,
    )
