"""Editions, offline-verifiable license keys, and feature entitlements.

Design rules (see docs/EDITIONS.md):

* **No license = Community.** Everything that exists in the open-source tree
  today stays free and is NEVER gated. Only *new* commercial features opt in
  through :func:`require_feature`.
* **Offline verification.** A license key is an Ed25519-signed JSON payload::

      PDK1.<base64url(payload-json)>.<base64url(signature)>

  The signature covers the exact decoded payload bytes. Verification needs
  only the vendor *public* key(s); the private key lives with the vendor
  (``scripts/issue_license.py``) and never in this repository.
* **Fail soft, never break the product.** An expired / invalid / missing
  license degrades to Community. Limits (seats, sites, assets) are *reported*
  (``/v1/license``, ``/v1/usage``), never enforced by blocking ingestion or
  scans.
* **Honesty note.** This is AGPL software: anyone may patch these checks out
  of their own copy. The license is a commercial-trust mechanism for paying
  customers (and the basis for support/true-up), not DRM.

Other engineers adopting a gate::

    from ..licensing import require_feature

    @router.post("/v1/scim/v2/Users", dependencies=[Depends(require_feature("scim"))])
    async def scim_create_user(...): ...

Configuration (environment, all optional):

* ``PADDOCK_LICENSE_KEY``          -- the signed key inline.
* ``PADDOCK_LICENSE_FILE``         -- path to a file holding the key.
* ``PADDOCK_LICENSE_PUBLIC_KEYS``  -- extra trusted vendor public keys,
  comma-separated, each raw 32-byte Ed25519 key in base64/base64url (or hex).
* ``PADDOCK_LICENSE_GRACE_DAYS``   -- days features keep working after expiry
  (default 14).

Precedence: an admin-uploaded key (``POST /v1/license``, stored in
``license_keys``) > ``PADDOCK_LICENSE_KEY`` > ``PADDOCK_LICENSE_FILE`` >
Community.
"""
from __future__ import annotations

import base64
import binascii
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from fastapi import HTTPException, Request
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

KEY_PREFIX = "PDK1"

EDITIONS: tuple[str, ...] = ("community", "team", "enterprise", "edge")


@dataclass(frozen=True)
class FeatureInfo:
    name: str
    min_edition: str
    description: str


# The catalogue of GATEABLE features. Every entry is a feature that does not
# exist in the Community tree today (or is a commercial service, e.g. support).
# Adding a name here is the only way to make it gateable -- require_feature()
# rejects unknown names at import time so typos can't silently lock things.
FEATURES: dict[str, FeatureInfo] = {
    f.name: f
    for f in (
        FeatureInfo("sso_saml", "team", "SAML 2.0 single sign-on"),
        FeatureInfo("digest_branding", "team", "Custom-branded digests and executive reports"),
        FeatureInfo("hosted_sites", "team", "Hosted Sentry site management beyond self-hosting"),
        FeatureInfo("assurance", "team", "Provable containment: invariants, reach graph and continuous evaluation"),
        FeatureInfo("scim", "enterprise", "SCIM 2.0 user/group provisioning"),
        FeatureInfo("multi_tenant", "enterprise", "Multi-tenant / MSP workspaces"),
        FeatureInfo("audit_anchoring", "enterprise", "Keyed + externally anchored audit chain"),
        FeatureInfo("audit_export", "enterprise", "Continuous audit-log export to a SIEM"),
        FeatureInfo("compliance_packs", "enterprise", "Compliance evidence packs (PCI, IEC 62443, NIST CSF, CRA)"),
        FeatureInfo("support_sla", "enterprise", "Contractual support SLA"),
        FeatureInfo("air_gapped", "edge", "Air-gapped deployment with offline feed bundles"),
        FeatureInfo("federation", "edge", "Federation of multiple Paddock instances"),
        FeatureInfo("ot_deep_protocols", "edge", "Deep OT protocol analytics"),
    )
}

_EDITION_RANK = {"community": 0, "team": 1, "enterprise": 2, "edge": 3}


def edition_features(edition: str) -> frozenset[str]:
    """Features an edition includes by default (higher editions are supersets)."""
    rank = _EDITION_RANK.get(edition, 0)
    return frozenset(n for n, f in FEATURES.items() if _EDITION_RANK[f.min_edition] <= rank)


class LicenseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PADDOCK_", env_file=".env", extra="ignore")

    license_key: str | None = None
    license_file: str | None = None
    license_public_keys: str = ""
    license_grace_days: int = 14
    # How long a resolved license is cached per process (seconds).
    license_cache_ttl_sec: float = 30.0


license_settings = LicenseSettings()

# Vendor public keys compiled into the build. The official release pipeline
# injects the vendor key here (or via PADDOCK_LICENSE_PUBLIC_KEYS). Empty in the
# open-source tree: without a trusted key every license is "invalid" and the
# instance runs as Community -- which is the full open-source product.
VENDOR_PUBLIC_KEYS: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# The License value
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class License:
    """The effective license of this instance."""

    edition: str = "community"            # EFFECTIVE edition (after expiry etc.)
    status: str = "community"             # community | active | grace | expired | invalid
    source: str = "default"               # default | db | env | file
    licensed_edition: str | None = None   # what the key says (even if expired)
    license_id: str | None = None
    licensee: str | None = None
    seats: int | None = None              # None = unlimited
    sites: int | None = None
    assets: int | None = None
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    features: frozenset[str] = field(default_factory=frozenset)
    error: str | None = None

    def has(self, feature: str) -> bool:
        return feature in self.features

    @property
    def days_remaining(self) -> int | None:
        if self.expires_at is None:
            return None
        delta = self.expires_at - datetime.now(timezone.utc)
        return int(delta.total_seconds() // 86400)

    def limits(self) -> dict[str, int | None]:
        return {"seats": self.seats, "sites": self.sites, "assets": self.assets}

    def as_dict(self) -> dict[str, Any]:
        return {
            "edition": self.edition,
            "status": self.status,
            "source": self.source,
            "licensed_edition": self.licensed_edition,
            "license_id": self.license_id,
            "licensee": self.licensee,
            "limits": self.limits(),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "days_remaining": self.days_remaining,
            "features": sorted(self.features),
            "error": self.error,
        }


COMMUNITY = License()


class LicenseError(ValueError):
    """A license key is malformed, untrusted or otherwise unusable."""


# --------------------------------------------------------------------------- #
# Encoding helpers
# --------------------------------------------------------------------------- #

def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64_decode_any(text: str) -> bytes:
    """Decode base64 / base64url, padded or not."""
    t = text.strip().replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    return base64.b64decode(t, validate=True)


def canonical_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _load_public_key(spec: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    spec = spec.strip()
    raw: bytes | None = None
    if len(spec) == 64:
        try:
            raw = bytes.fromhex(spec)
        except ValueError:
            raw = None
    if raw is None:
        try:
            raw = _b64_decode_any(spec)
        except (binascii.Error, ValueError) as exc:
            raise LicenseError(f"bad public key encoding: {exc}") from exc
    if len(raw) != 32:
        raise LicenseError("an Ed25519 public key is 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def parse_public_keys(specs: Iterable[str]) -> list:
    keys = []
    for s in specs:
        if s and s.strip():
            try:
                keys.append(_load_public_key(s))
            except LicenseError:
                logger.warning("ignoring malformed license public key")
    return keys


def trusted_public_keys() -> list:
    extra = [s for s in license_settings.license_public_keys.split(",") if s.strip()]
    return parse_public_keys([*VENDOR_PUBLIC_KEYS, *extra])


# --------------------------------------------------------------------------- #
# Sign (vendor side; used by scripts/issue_license.py and tests) + verify
# --------------------------------------------------------------------------- #

def sign_license(payload: dict[str, Any], private_key) -> str:
    """Return a ``PDK1.`` key for ``payload`` signed with an Ed25519 private key."""
    validate_payload(payload)
    body = canonical_payload(payload)
    sig = private_key.sign(body)
    return f"{KEY_PREFIX}.{_b64url_encode(body)}.{_b64url_encode(sig)}"


def _parse_ts(value: Any, field_name: str) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise LicenseError(f"{field_name}: not an ISO-8601 timestamp") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    raise LicenseError(f"{field_name}: bad type")


def _opt_limit(payload: dict[str, Any], name: str) -> int | None:
    v = payload.get(name)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise LicenseError(f"{name}: must be a non-negative integer or null")
    return v


def validate_payload(payload: dict[str, Any]) -> None:
    """Structural validation shared by issuer and verifier."""
    if not isinstance(payload, dict):
        raise LicenseError("payload must be a JSON object")
    if payload.get("v", 1) != 1:
        raise LicenseError("unsupported license version")
    if not payload.get("license_id") or not isinstance(payload["license_id"], str):
        raise LicenseError("license_id is required")
    if payload.get("edition") not in EDITIONS:
        raise LicenseError(f"edition must be one of {EDITIONS}")
    for name in ("seats", "sites", "assets"):
        _opt_limit(payload, name)
    feats = payload.get("features", [])
    if not isinstance(feats, list) or not all(isinstance(f, str) for f in feats):
        raise LicenseError("features must be a list of strings")
    _parse_ts(payload.get("issued_at"), "issued_at")
    _parse_ts(payload.get("expires_at"), "expires_at")


def decode_key(key_text: str) -> tuple[bytes, bytes]:
    parts = (key_text or "").strip().split(".")
    if len(parts) != 3 or parts[0] != KEY_PREFIX:
        raise LicenseError("not a Paddock license key (expected PDK1.<payload>.<signature>)")
    try:
        return _b64_decode_any(parts[1]), _b64_decode_any(parts[2])
    except (binascii.Error, ValueError) as exc:
        raise LicenseError("license key is not valid base64url") from exc


def verify_license_key(
    key_text: str,
    *,
    public_keys: list | None = None,
    now: datetime | None = None,
    grace_days: int | None = None,
    source: str = "db",
) -> License:
    """Verify ``key_text`` offline and return the effective :class:`License`.

    Raises :class:`LicenseError` when the key is malformed or its signature
    does not verify against any trusted public key. An *expired* but genuine
    key does NOT raise: it returns ``status="grace"`` (features still on) or
    ``status="expired"`` (Community), so the UI can say so.
    """
    from cryptography.exceptions import InvalidSignature

    body, sig = decode_key(key_text)
    keys = trusted_public_keys() if public_keys is None else public_keys
    if not keys:
        raise LicenseError("no trusted license public key is configured")
    for k in keys:
        try:
            k.verify(sig, body)
            break
        except InvalidSignature:
            continue
    else:
        raise LicenseError("license signature does not verify")

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LicenseError("license payload is not JSON") from exc
    validate_payload(payload)

    now = now or datetime.now(timezone.utc)
    grace = license_settings.license_grace_days if grace_days is None else grace_days
    edition = payload["edition"]
    expires_at = _parse_ts(payload.get("expires_at"), "expires_at")
    issued_at = _parse_ts(payload.get("issued_at"), "issued_at")
    features = (edition_features(edition) | frozenset(payload.get("features", []))) & frozenset(FEATURES)

    status = "active"
    if expires_at is not None and now >= expires_at:
        status = "grace" if now < expires_at + timedelta(days=grace) else "expired"

    common = dict(
        source=source,
        licensed_edition=edition,
        license_id=payload["license_id"],
        licensee=payload.get("licensee"),
        issued_at=issued_at,
        expires_at=expires_at,
    )
    if status == "expired":
        return License(
            edition="community", status="expired", features=frozenset(),
            error="license expired; running as Community", **common,
        )
    return License(
        edition=edition,
        status=status,
        seats=_opt_limit(payload, "seats"),
        sites=_opt_limit(payload, "sites"),
        assets=_opt_limit(payload, "assets"),
        features=features,
        **common,
    )


def _invalid(source: str, exc: Exception) -> License:
    return License(status="invalid", source=source, error=str(exc))


def _from_env_or_file() -> License | None:
    if license_settings.license_key:
        try:
            return verify_license_key(license_settings.license_key, source="env")
        except LicenseError as exc:
            logger.warning("PADDOCK_LICENSE_KEY rejected: %s", exc)
            return _invalid("env", exc)
    if license_settings.license_file:
        p = Path(license_settings.license_file)
        try:
            text = p.read_text(encoding="utf-8").strip()
        except OSError as exc:
            logger.warning("PADDOCK_LICENSE_FILE unreadable: %s", exc)
            return _invalid("file", LicenseError(f"license file unreadable: {exc.strerror}"))
        try:
            return verify_license_key(text, source="file")
        except LicenseError as exc:
            logger.warning("PADDOCK_LICENSE_FILE rejected: %s", exc)
            return _invalid("file", exc)
    return None


async def load_active_license(pool) -> License:
    """Resolve the effective license. Never raises; worst case is Community."""
    if pool is not None:
        try:
            async with pool.acquire() as con:
                exists = await con.fetchval("SELECT to_regclass('public.license_keys') IS NOT NULL")
                row = None
                if exists:
                    row = await con.fetchrow(
                        "SELECT key_text FROM license_keys WHERE removed_at IS NULL "
                        "ORDER BY uploaded_at DESC, id DESC LIMIT 1"
                    )
            if row is not None:
                try:
                    return verify_license_key(row["key_text"], source="db")
                except LicenseError as exc:
                    # e.g. the trusted key set changed after upload.
                    return _invalid("db", exc)
        except Exception:  # noqa: BLE001 -- metering must never take the API down
            logger.exception("license_load_failed")
    return _from_env_or_file() or COMMUNITY


# --------------------------------------------------------------------------- #
# Per-app cache + FastAPI integration
# --------------------------------------------------------------------------- #

_CACHE_ATTR = "_paddock_license_cache"


def invalidate_cache(app) -> None:
    try:
        setattr(app.state, _CACHE_ATTR, {})
    except Exception:  # noqa: BLE001
        pass


async def current_license(request: Request) -> License:
    """The effective license of the CURRENT TENANT for this request's app
    (cached briefly). The license row is per tenant (RLS), so the cache is
    keyed per tenant: a single app-wide slot served one tenant's licensee,
    edition and features to every other tenant for the TTL."""
    from . import tenancy

    app = request.app
    cache = getattr(app.state, _CACHE_ATTR, None)
    if not isinstance(cache, dict):
        cache = {}
        setattr(app.state, _CACHE_ATTR, cache)
    key = tenancy.current_tenant_key()
    cached = cache.get(key)
    now = time.monotonic()
    if cached is not None and now - cached[0] < license_settings.license_cache_ttl_sec:
        return cached[1]
    lic = await load_active_license(getattr(app.state, "pool", None))
    if len(cache) > 1024:
        cache.clear()
    cache[key] = (now, lic)
    return lic


def require_feature(feature: str):
    """FastAPI dependency factory gating a NEW commercial feature.

    Responds ``402 Payment Required`` with a machine-readable body when the
    effective license lacks ``feature``. Unknown feature names raise at import
    time (catch typos before they ship).
    """
    if feature not in FEATURES:
        raise ValueError(f"unknown licensable feature {feature!r}; add it to licensing.FEATURES")
    info = FEATURES[feature]

    async def _dep(request: Request) -> License:
        lic = await current_license(request)
        if not lic.has(feature):
            raise HTTPException(
                status_code=402,
                detail={
                    "error": "feature_not_licensed",
                    "feature": feature,
                    "description": info.description,
                    "required_edition": info.min_edition,
                    "current_edition": lic.edition,
                    "license_status": lic.status,
                    "docs": "docs/EDITIONS.md",
                },
            )
        return lic

    _dep.__name__ = f"require_feature_{feature}"
    return _dep


async def feature_enabled(request: Request, feature: str) -> bool:
    """Non-raising check for code paths that degrade instead of refusing."""
    if feature not in FEATURES:
        raise ValueError(f"unknown licensable feature {feature!r}")
    return (await current_license(request)).has(feature)
