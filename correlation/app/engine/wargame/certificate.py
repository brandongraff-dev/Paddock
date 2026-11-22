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

stdlib only (``hashlib`` / ``hmac`` / ``datetime`` / ``json``).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

from . import safety
from .model import Assumption, Certificate, Corroboration, PortRange, Proto

#: Assumption key used to make the "absence of evidence only" limit explicit
#: when there is no sensor on the protected side of the boundary.
OBSERVATION_SIDE_KEY = "observation_side"

_OBSERVATION_SIDE_TEXT = (
    "No sensor sits on the protected side of this boundary, so this certifies "
    "absence of evidence of a route, not a protected-side observation that the "
    "boundary is closed."
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


def _canonical(cert: Certificate) -> bytes:
    """Stable, deterministic serialisation of the semantic fields.

    Covers claim, boundaries, port, sorted config hashes, sorted assumptions,
    corroboration and issued/expires timestamps — but NOT the fingerprint or
    mutable status. ``json.dumps`` with ``sort_keys`` and a fixed key order
    makes this independent of dict/list ordering.
    """
    port = cert.port
    port_obj = (
        None
        if port is None
        else {"proto": port.proto.value, "low": port.low, "high": port.high}
    )
    payload = {
        "claim": cert.claim,
        "boundary_src": cert.boundary_src,
        "boundary_dst": cert.boundary_dst,
        "port": port_obj,
        "config_hashes": sorted(cert.config_hashes),
        "assumptions": sorted(
            ([a.key, a.text] for a in cert.assumptions),
            key=lambda kv: (kv[0], kv[1]),
        ),
        "corroboration": {
            "observed_flows": cert.corroboration.observed_flows,
            "window_days": cert.corroboration.window_days,
            "sensor_on_protected_side": cert.corroboration.sensor_on_protected_side,
            "probe_tested": cert.corroboration.probe_tested,
        },
        "issued_at": cert.issued_at,
        "expires_at": cert.expires_at,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(cert: Certificate, key: bytes) -> Certificate:
    """Compute and set the HMAC-SHA256 fingerprint over the canonical form."""
    cert.fingerprint = hmac.new(key, _canonical(cert), hashlib.sha256).hexdigest()
    return cert


def verify(cert: Certificate, key: bytes) -> bool:
    """True iff ``cert``'s fingerprint matches a fresh HMAC over its fields.

    Any change to a semantic field after signing (e.g. the claim) changes the
    canonical form and so fails this check. Uses a constant-time compare.
    """
    if not cert.fingerprint:
        return False
    expected = hmac.new(key, _canonical(cert), hashlib.sha256).hexdigest()
    return hmac.compare_digest(cert.fingerprint, expected)


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
