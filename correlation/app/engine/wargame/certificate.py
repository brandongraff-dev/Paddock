"""Signed, expiring "this boundary is closed" certificates.

A certificate (``docs/WARGAME.md`` §2.3/§3) is a claim that no route exists
across a boundary, pinned to the exact config it was proved against (by hash),
shipped with its **stated assumptions**, a corroboration window, and an
**expiry**. The honesty rules the whole product rests on:

* **No proof without stated assumptions.** :func:`build_certificate` refuses an
  empty assumption list — a closed proof that hides its own limits is
  forbidden.
* **No false "closed".** If no sensor sits on the protected side, the
  certificate must say in so many words that this is *absence of evidence*,
  not proof the boundary is shut. :func:`build_certificate` injects an
  ``observation_side`` assumption rather than silently asserting closure.
* **Lapsed or contradicted certificates are never current.** :func:`is_current`
  checks both status and expiry; :func:`mark_contradicted` flips the status
  when impossible traffic is seen crossing the boundary.

Signing is an HMAC-SHA256 fingerprint over a canonical serialisation of the
certificate's semantic fields, so tampering with any of them breaks
verification. Determinism: no wall-clock time is ever embedded — every
timestamp comes from the ``datetime`` values passed in.

Keys (:mod:`.signing`): :func:`sign_with` signs with a per-tenant key derived
from ``WARGAME_SIGNING_KEY`` and records its ``key_id``; with no key
configured it uses the public development key, sets ``key_id="unsigned-dev"``
and adds an ``unsigned_dev_signature`` assumption, so an unkeyed fingerprint
can never pass as a signature. :func:`verify_with` picks the key by
``key_id``; :func:`signature_status` says ``signed`` / ``unsigned-dev`` /
``invalid``. :func:`sign` / :func:`verify` with a raw key are kept for callers
that manage their own key.

stdlib only (``hashlib`` / ``hmac`` / ``datetime`` / ``json``).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

from typing import Optional

from . import safety, signing
from .model import Assumption, Certificate, Corroboration, PortRange, Proto

#: Assumption key used to make the "absence of evidence only" limit explicit
#: when there is no sensor on the protected side of the boundary.
OBSERVATION_SIDE_KEY = "observation_side"

_OBSERVATION_SIDE_TEXT = (
    "No sensor sits on the protected side of this boundary, so this certifies "
    "absence of evidence of a route, not a protected-side observation that the "
    "boundary is closed."
)


#: Assumption key stating that the fingerprint was made with the public
#: development key and so is not a signature.
UNSIGNED_DEV_KEY = "unsigned_dev_signature"

_UNSIGNED_DEV_TEXT = (
    "UNSIGNED (development): no signing key was configured "
    "(WARGAME_SIGNING_KEY), so this certificate's fingerprint was made with a "
    "public development key. Anyone can produce it; it is not a signature and "
    "must not be presented as signed evidence."
)


def hash_snapshot(config_text: str) -> str:
    """SHA-256 hex digest of a config snapshot."""
    return hashlib.sha256(config_text.encode("utf-8")).hexdigest()


def _to_utc_iso(dt: datetime) -> str:
    """Normalise a datetime to UTC and render as ISO-8601. A naive datetime is
    assumed to already be UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp to a tz-aware UTC datetime."""
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def describe_port(port: "PortRange | None") -> str:
    """Plain wording for a port range, for the default claim text."""
    if port is None:
        return "any port"
    if port.proto is Proto.ANY and port.low == 0 and port.high == 65535:
        return "any port"
    proto = port.proto.value
    if port.low == port.high:
        return f"{proto}/{port.low}"
    return f"{proto}/{port.low}-{port.high}"


def _default_claim(src: str, dst: str, port: "PortRange | None") -> str:
    return f"no route from {src} to {dst} on {describe_port(port)}"


def build_certificate(
    *,
    boundary_src: str,
    boundary_dst: str,
    port: "PortRange | None",
    config_hashes: "tuple[str, ...] | list[str]",
    assumptions: "list[Assumption]",
    corroboration: Corroboration,
    issued_at: datetime,
    ttl_hours: int,
    claim: "str | None" = None,
) -> Certificate:
    """Build an unsigned, valid certificate.

    Raises :class:`ValueError` if ``assumptions`` is empty — a proof with no
    stated assumptions is forbidden. If ``corroboration.sensor_on_protected_side``
    is ``False`` and no ``observation_side`` assumption is present, one is added
    making the "absence of evidence only" limit explicit. The claim text (the
    default, or a caller-supplied one) is run through
    :func:`safety.assert_safe_text`.
    """
    if not assumptions:
        raise ValueError(
            "a certificate must ship with at least one stated assumption; "
            "a closed proof with no stated limits is forbidden"
        )

    # Copy so we never mutate the caller's list.
    assumptions = list(assumptions)

    if not corroboration.sensor_on_protected_side:
        if not any(a.key == OBSERVATION_SIDE_KEY for a in assumptions):
            assumptions.append(
                Assumption(key=OBSERVATION_SIDE_KEY, text=_OBSERVATION_SIDE_TEXT)
            )

    if claim is None:
        claim = _default_claim(boundary_src, boundary_dst, port)
    safety.assert_safe_text(claim)

    issued_iso = _to_utc_iso(issued_at)
    expires_iso = _to_utc_iso(issued_at + timedelta(hours=ttl_hours))

    return Certificate(
        claim=claim,
        boundary_src=boundary_src,
        boundary_dst=boundary_dst,
        port=port,
        config_hashes=tuple(config_hashes),
        assumptions=assumptions,
        corroboration=corroboration,
        issued_at=issued_iso,
        expires_at=expires_iso,
        status="valid",
    )


def _canonical_ts(value: "str | datetime | None") -> "str | None":
    """A timestamp as UTC ISO-8601, whatever offset/format it arrived in, so a
    certificate re-read from Postgres (``timestamptz``) or written with
    ``Z`` / a non-UTC offset canonicalises to the same bytes it was signed
    over. ``build_certificate`` already stores this form, so legacy
    fingerprints are unchanged."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return _to_utc_iso(value)
    try:
        return _to_utc_iso(datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except ValueError:
        return str(value)  # not a timestamp: sign it verbatim


def _canonical_port(port: "PortRange | None") -> "dict | None":
    """``None`` and the protocol-agnostic full range mean the same thing ("any
    port") and are stored identically (``store.format_port`` -> ``"any"``), so
    they canonicalise identically too."""
    if port is None:
        return None
    if port.proto is Proto.ANY and port.low == 0 and port.high == 65535:
        return None
    return {"proto": port.proto.value, "low": port.low, "high": port.high}


def _canonical(cert: Certificate) -> bytes:
    """Stable, deterministic serialisation of the semantic fields.

    Covers claim, boundaries, port, sorted config hashes, sorted assumptions,
    corroboration, issued/expires timestamps (normalised to UTC) and the
    ``key_id`` (bound so a fingerprint can't be relabelled as made by another
    key; omitted when empty so legacy fingerprints still verify) — but NOT the
    fingerprint or the mutable ``status`` (so :func:`mark_contradicted` works
    without the key; ``status`` is therefore not tamper-evident: read it
    together with the impossible-traffic log). ``json.dumps`` with
    ``sort_keys`` and sorted lists makes this independent of dict/list order.
    """
    payload = {
        "claim": cert.claim,
        "boundary_src": cert.boundary_src,
        "boundary_dst": cert.boundary_dst,
        "port": _canonical_port(cert.port),
        "config_hashes": sorted(cert.config_hashes),
        "assumptions": sorted(
            ([a.key, a.text] for a in cert.assumptions),
            key=lambda kv: (kv[0], kv[1]),
        ),
        "corroboration": {
            "observed_flows": int(cert.corroboration.observed_flows),
            "window_days": int(cert.corroboration.window_days),
            "sensor_on_protected_side": bool(cert.corroboration.sensor_on_protected_side),
            "probe_tested": bool(cert.corroboration.probe_tested),
        },
        "issued_at": _canonical_ts(cert.issued_at),
        "expires_at": _canonical_ts(cert.expires_at),
    }
    kid = getattr(cert, "key_id", "") or ""
    if kid:
        payload["key_id"] = kid
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(cert: Certificate, key: bytes, *, key_id: Optional[str] = None) -> Certificate:
    """Compute and set the HMAC-SHA256 fingerprint over the canonical form.

    ``key_id`` (when given) is recorded on the certificate first, so it is
    bound into the fingerprint. Prefer :func:`sign_with`, which also labels a
    development-key fingerprint as unsigned."""
    if key_id is not None:
        cert.key_id = key_id
    cert.fingerprint = hmac.new(key, _canonical(cert), hashlib.sha256).hexdigest()
    return cert


def sign_with(cert: Certificate, signing_key: "signing.SigningKey") -> Certificate:
    """Sign ``cert`` with a :class:`signing.SigningKey` and record its id.

    With the public development key (``signing_key.unsigned``) the
    ``unsigned_dev_signature`` assumption is added *before* fingerprinting, so
    the certificate itself says, in a signed field, that it is not signed."""
    if signing_key.unsigned and not any(
        a.key == UNSIGNED_DEV_KEY for a in cert.assumptions
    ):
        cert.assumptions = list(cert.assumptions) + [
            Assumption(key=UNSIGNED_DEV_KEY, text=_UNSIGNED_DEV_TEXT)
        ]
    return sign(cert, signing_key.key, key_id=signing_key.kid)


def verify(cert: Certificate, key: bytes) -> bool:
    """True iff ``cert``'s fingerprint matches a fresh HMAC over its fields.

    Any change to a semantic field after signing (e.g. the claim) changes the
    canonical form and so fails this check. Uses a constant-time compare.
    This checks integrity under ``key`` only; whether that key is a real one
    is :func:`signature_status`'s job.
    """
    fp = cert.fingerprint
    if not fp or not isinstance(fp, str) or not fp.isascii():
        return False
    expected = hmac.new(key, _canonical(cert), hashlib.sha256).hexdigest()
    return hmac.compare_digest(fp, expected)


def verify_with(
    cert: Certificate, keyring: "signing.Keyring", tenant_id: Optional[str]
) -> bool:
    """Verify with the key ``cert.key_id`` names, derived for ``tenant_id``.

    False when the key id matches no configured master (forged or foreign),
    or the fingerprint does not match. A development-key certificate verifies
    here (its integrity is intact) but :func:`signature_status` reports it as
    ``unsigned-dev``."""
    try:
        key = keyring.verification_key(getattr(cert, "key_id", "") or "", tenant_id)
    except ValueError:
        return False  # no tenant to derive for
    if key is None:
        return False
    return verify(cert, key)


def signature_status(
    cert: Certificate, keyring: "signing.Keyring", tenant_id: Optional[str]
) -> str:
    """``"signed"`` (a real per-tenant key verifies it), ``"unsigned-dev"``
    (intact, but fingerprinted with the public development key or a legacy
    certificate) or ``"invalid"`` (does not verify)."""
    if not verify_with(cert, keyring, tenant_id):
        return "invalid"
    if is_unsigned(cert):
        return "unsigned-dev"
    return "signed"


def is_unsigned(cert: Certificate) -> bool:
    """True when the certificate's fingerprint is not a real signature: it was
    made with the public development key (or predates key ids)."""
    return signing.is_unsigned_kid(getattr(cert, "key_id", "") or "") or any(
        a.key == UNSIGNED_DEV_KEY for a in (cert.assumptions or [])
    )


def is_current(cert: Certificate, now: datetime) -> bool:
    """True iff the certificate is still ``valid`` and not yet expired at
    ``now``. A lapsed or contradicted certificate is never current."""
    if cert.status != "valid":
        return False
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc) < _parse_iso(cert.expires_at)


def mark_contradicted(cert: Certificate) -> Certificate:
    """Flip status to ``contradicted`` (impossible traffic seen crossing the
    boundary the certificate proved closed)."""
    cert.status = "contradicted"
    return cert
