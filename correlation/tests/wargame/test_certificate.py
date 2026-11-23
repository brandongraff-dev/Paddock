"""Tests for the signed, expiring boundary certificate."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.engine.wargame import certificate as cert_mod
from app.engine.wargame.model import (
    Assumption,
    Corroboration,
    PortRange,
    Proto,
)
from app.engine.wargame.safety import UnsafeWargameAction

_KEY = b"paddock-test-signing-key"
_ISSUED = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _corro(sensor_on_protected_side: bool = True) -> Corroboration:
    return Corroboration(
        observed_flows=0,
        window_days=30,
        sensor_on_protected_side=sensor_on_protected_side,
        probe_tested=True,
    )


def _assumptions() -> list[Assumption]:
    return [Assumption(key="scope", text="boundary modelled from firewall export only")]


def _build(**overrides):
    kw = dict(
        boundary_src="guest_wifi",
        boundary_dst="cardholder_db",
        port=PortRange.single(Proto.TCP, 1433),
        config_hashes=(cert_mod.hash_snapshot("ruleset-A"),),
        assumptions=_assumptions(),
        corroboration=_corro(),
        issued_at=_ISSUED,
        ttl_hours=24,
    )
    kw.update(overrides)
    return cert_mod.build_certificate(**kw)


# ---------------------------------------------------------------------------
# hash_snapshot
# ---------------------------------------------------------------------------

def test_hash_snapshot_is_sha256_hex_and_stable():
    h = cert_mod.hash_snapshot("some config text")
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)
    assert h == cert_mod.hash_snapshot("some config text")
    assert h != cert_mod.hash_snapshot("some config text!")


# ---------------------------------------------------------------------------
# build_certificate — honesty rules
# ---------------------------------------------------------------------------

def test_missing_assumptions_raises():
    with pytest.raises(ValueError):
        _build(assumptions=[])


def test_default_claim_text_is_plain_impact():
    cert = _build()
    assert cert.claim == "no route from guest_wifi to cardholder_db on tcp/1433"
    assert cert.status == "valid"


def test_default_claim_any_port():
    cert = _build(port=None)
    assert cert.claim == "no route from guest_wifi to cardholder_db on any port"
    cert2 = _build(port=PortRange.any())
    assert cert2.claim.endswith("on any port")


def test_port_range_claim():
    cert = _build(port=PortRange(Proto.TCP, 1000, 2000))
    assert cert.claim.endswith("on tcp/1000-2000")


def test_sensor_off_protected_side_injects_observation_assumption():
    cert = _build(corroboration=_corro(sensor_on_protected_side=False))
    keys = {a.key for a in cert.assumptions}
    assert cert_mod.OBSERVATION_SIDE_KEY in keys
    obs = next(a for a in cert.assumptions if a.key == cert_mod.OBSERVATION_SIDE_KEY)
    assert "absence of evidence" in obs.text.lower()


def test_sensor_on_protected_side_does_not_inject():
    cert = _build(corroboration=_corro(sensor_on_protected_side=True))
    keys = {a.key for a in cert.assumptions}
    assert cert_mod.OBSERVATION_SIDE_KEY not in keys


def test_existing_observation_side_assumption_not_duplicated():
    custom = [Assumption(key=cert_mod.OBSERVATION_SIDE_KEY, text="my own absence-of-evidence note")]
    cert = _build(assumptions=custom, corroboration=_corro(sensor_on_protected_side=False))
    obs = [a for a in cert.assumptions if a.key == cert_mod.OBSERVATION_SIDE_KEY]
    assert len(obs) == 1
    assert obs[0].text == "my own absence-of-evidence note"


def test_build_does_not_mutate_caller_assumptions():
    caller = _assumptions()
    _build(assumptions=caller, corroboration=_corro(sensor_on_protected_side=False))
    # the injected observation_side assumption must not leak into the caller list
    assert all(a.key != cert_mod.OBSERVATION_SIDE_KEY for a in caller)


def test_unsafe_claim_text_raises():
    with pytest.raises(UnsafeWargameAction):
        _build(claim="reverse shell from guest to db")


# ---------------------------------------------------------------------------
# timestamps / expiry
# ---------------------------------------------------------------------------

def test_issued_and_expires_set_from_passed_datetime():
    cert = _build(ttl_hours=24)
    issued = cert_mod._parse_iso(cert.issued_at)
    expires = cert_mod._parse_iso(cert.expires_at)
    assert issued == _ISSUED
    assert expires - issued == timedelta(hours=24)


def test_naive_datetime_assumed_utc():
    naive = datetime(2026, 1, 1, 12, 0, 0)
    cert = _build(issued_at=naive, ttl_hours=1)
    assert cert_mod._parse_iso(cert.issued_at) == _ISSUED


# ---------------------------------------------------------------------------
# sign / verify
# ---------------------------------------------------------------------------

def test_sign_verify_round_trip():
    cert = cert_mod.sign(_build(), _KEY)
    assert cert.fingerprint
    assert cert_mod.verify(cert, _KEY) is True


def test_verify_fails_with_wrong_key():
    cert = cert_mod.sign(_build(), _KEY)
    assert cert_mod.verify(cert, b"a-different-key") is False


def test_unsigned_certificate_does_not_verify():
    assert cert_mod.verify(_build(), _KEY) is False


def test_tampering_with_claim_breaks_verification():
    cert = cert_mod.sign(_build(), _KEY)
    assert cert_mod.verify(cert, _KEY) is True
    cert.claim = "no route from guest_wifi to cardholder_db on tcp/22"
    assert cert_mod.verify(cert, _KEY) is False


def test_tampering_with_config_hashes_breaks_verification():
    cert = cert_mod.sign(_build(), _KEY)
    cert.config_hashes = cert.config_hashes + (cert_mod.hash_snapshot("extra"),)
    assert cert_mod.verify(cert, _KEY) is False


def test_tampering_with_assumption_breaks_verification():
    cert = cert_mod.sign(_build(), _KEY)
    cert.assumptions.append(Assumption(key="sneaky", text="added after signing"))
    assert cert_mod.verify(cert, _KEY) is False


def test_signature_is_deterministic():
    a = cert_mod.sign(_build(), _KEY)
    b = cert_mod.sign(_build(), _KEY)
    assert a.fingerprint == b.fingerprint


def test_signature_insensitive_to_assumption_order():
    asm = [
        Assumption(key="b", text="second"),
        Assumption(key="a", text="first"),
    ]
    asm_rev = list(reversed(asm))
    a = cert_mod.sign(_build(assumptions=asm), _KEY)
    b = cert_mod.sign(_build(assumptions=asm_rev), _KEY)
    assert a.fingerprint == b.fingerprint


# ---------------------------------------------------------------------------
# is_current
# ---------------------------------------------------------------------------

def test_is_current_before_expiry():
    cert = _build(ttl_hours=24)
    assert cert_mod.is_current(cert, _ISSUED + timedelta(hours=1)) is True


def test_is_current_after_expiry():
    cert = _build(ttl_hours=24)
    assert cert_mod.is_current(cert, _ISSUED + timedelta(hours=25)) is False


def test_is_current_exactly_at_expiry_is_not_current():
    cert = _build(ttl_hours=24)
    assert cert_mod.is_current(cert, _ISSUED + timedelta(hours=24)) is False


def test_is_current_handles_naive_now():
    cert = _build(ttl_hours=24)
    naive_now = datetime(2026, 1, 1, 13, 0, 0)
    assert cert_mod.is_current(cert, naive_now) is True


# ---------------------------------------------------------------------------
# status transitions
# ---------------------------------------------------------------------------

def test_mark_contradicted_sets_status():
    cert = _build()
    cert_mod.mark_contradicted(cert)
    assert cert.status == "contradicted"


def test_contradicted_is_never_current():
    cert = _build(ttl_hours=24)
    cert_mod.mark_contradicted(cert)
    # even well before expiry
    assert cert_mod.is_current(cert, _ISSUED + timedelta(hours=1)) is False


def test_contradiction_does_not_change_fingerprint_validity():
    # status is not part of the signed canonical form, so marking it
    # contradicted does not break the signature (it just stops being current).
    cert = cert_mod.sign(_build(), _KEY)
    cert_mod.mark_contradicted(cert)
    assert cert_mod.verify(cert, _KEY) is True
