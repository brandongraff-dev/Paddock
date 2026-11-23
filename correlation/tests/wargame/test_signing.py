"""Certificate signing keys: per-tenant derivation, key ids, rotation, the
labelled development fallback, and canonical-form robustness."""
from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from app.engine.wargame import certificate as cert_mod
from app.engine.wargame import signing
from app.engine.wargame.model import Assumption, Corroboration, PortRange, Proto

T1 = "00000000-0000-0000-0000-0000000000a1"
T2 = "00000000-0000-0000-0000-0000000000a2"
MASTER = "m" * 48
OLD = "o" * 48
_ISSUED = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _cert(**kw):
    base = dict(
        boundary_src="guest",
        boundary_dst="db",
        port=None,
        config_hashes=("h2", "h1"),
        assumptions=[Assumption("b", "two"), Assumption("a", "one")],
        corroboration=Corroboration(0, 0, sensor_on_protected_side=False),
        issued_at=_ISSUED,
        ttl_hours=24,
    )
    base.update(kw)
    return cert_mod.build_certificate(**base)


# -- key handling -----------------------------------------------------------

def test_per_tenant_keys_differ_and_need_a_tenant():
    m = MASTER.encode()
    assert signing.derive_tenant_key(m, T1) != signing.derive_tenant_key(m, T2)
    assert signing.derive_tenant_key(m, T1) != m
    # Case/whitespace of the tenant id does not change the key.
    assert signing.derive_tenant_key(m, T1.upper() + " ") == signing.derive_tenant_key(m, T1)
    for bad in (None, "", "  "):
        with pytest.raises(ValueError):
            signing.derive_tenant_key(m, bad)


def test_key_id_is_public_and_stable():
    kid = signing.key_id(MASTER.encode())
    assert kid.startswith("wg1-") and len(kid) == 4 + 16
    assert MASTER not in kid
    assert kid == signing.Keyring.from_strings(MASTER).signing_key(T1).kid
    assert kid != signing.key_id(OLD.encode())


def test_keyring_repr_does_not_leak_keys():
    ring = signing.Keyring.from_strings(MASTER, OLD)
    assert MASTER not in repr(ring) and OLD not in repr(ring)
    assert MASTER not in repr(ring.signing_key(T1))


def test_no_key_falls_back_to_labelled_dev_key():
    sk = signing.Keyring.from_strings(None).signing_key(T1)
    assert sk.unsigned and sk.kid == signing.DEV_KEY_ID
    assert sk.key == signing.DEMO_SIGNING_KEY
    assert signing.Keyring.from_strings("   ").configured is False


# -- signing / verifying ----------------------------------------------------

def test_signed_certificate_verifies_only_for_its_tenant():
    ring = signing.Keyring.from_strings(MASTER)
    c = cert_mod.sign_with(_cert(), ring.signing_key(T1))
    assert not cert_mod.is_unsigned(c)
    assert cert_mod.signature_status(c, ring, T1) == "signed"
    assert cert_mod.signature_status(c, ring, T2) == "invalid"
    assert cert_mod.signature_status(c, signing.Keyring(), T1) == "invalid"
    assert not cert_mod.verify(c, signing.DEMO_SIGNING_KEY)
    assert not cert_mod.verify(c, MASTER.encode())  # never the master itself


def test_rotation_keeps_old_certificates_verifiable():
    old = cert_mod.sign_with(_cert(), signing.Keyring.from_strings(OLD).signing_key(T1))
    rotated = signing.Keyring.from_strings(MASTER, f"{OLD}, other-retired-key")
    assert cert_mod.signature_status(old, rotated, T1) == "signed"
    new = cert_mod.sign_with(_cert(), rotated.signing_key(T1))
    assert new.key_id == signing.key_id(MASTER.encode()) != old.key_id
    # Retiring the old key entirely makes its certificates unverifiable.
    assert cert_mod.signature_status(old, signing.Keyring.from_strings(MASTER), T1) == "invalid"


def test_key_id_is_bound_into_the_fingerprint():
    ring = signing.Keyring.from_strings(MASTER, OLD)
    c = cert_mod.sign_with(_cert(), ring.signing_key(T1))
    relabelled = dataclasses.replace(c, key_id=signing.key_id(OLD.encode()))
    assert cert_mod.signature_status(relabelled, ring, T1) == "invalid"
    forged = dataclasses.replace(c, key_id="wg1-ffffffffffffffff")
    assert cert_mod.signature_status(forged, ring, T1) == "invalid"
    assert cert_mod.signature_status(dataclasses.replace(c, key_id="wg1-é"), ring, T1) == "invalid"


def test_dev_signed_certificate_says_so_in_a_signed_field():
    c = cert_mod.sign_with(_cert(), signing.Keyring().signing_key(T1))
    assert c.key_id == "unsigned-dev"
    assert any(a.key == cert_mod.UNSIGNED_DEV_KEY for a in c.assumptions)
    assert cert_mod.is_unsigned(c)
    assert cert_mod.signature_status(c, signing.Keyring.from_strings(MASTER), T1) == "unsigned-dev"
    # Stripping the warning breaks the fingerprint.
    stripped = dataclasses.replace(
        c, assumptions=[a for a in c.assumptions if a.key != cert_mod.UNSIGNED_DEV_KEY]
    )
    assert not cert_mod.verify(stripped, signing.DEMO_SIGNING_KEY)
    # Relabelling a dev certificate as signed by a real key does not verify.
    ring = signing.Keyring.from_strings(MASTER)
    assert cert_mod.signature_status(
        dataclasses.replace(c, key_id=signing.key_id(MASTER.encode())), ring, T1
    ) == "invalid"


def test_legacy_certificate_without_key_id_is_unsigned_dev():
    legacy = cert_mod.sign(_cert(), signing.DEMO_SIGNING_KEY)  # old assess.py path
    assert legacy.key_id == ""
    assert cert_mod.verify(legacy, b"twin")                      # still verifies
    assert cert_mod.signature_status(legacy, signing.Keyring.from_strings(MASTER), T1) == "unsigned-dev"


def test_non_ascii_fingerprint_is_rejected_not_raised():
    c = cert_mod.sign(_cert(), b"k")
    c.fingerprint = "é" * 64
    assert cert_mod.verify(c, b"k") is False


# -- canonical form ---------------------------------------------------------

def test_reordered_assumptions_and_hashes_still_verify():
    c = cert_mod.sign(_cert(), b"k")
    c.assumptions = list(reversed(c.assumptions))
    c.config_hashes = tuple(reversed(c.config_hashes))
    assert cert_mod.verify(c, b"k")


def test_timestamps_are_normalised_to_utc():
    c = cert_mod.sign(_cert(), b"k")
    # Same instant written with Z, with another offset, or as a datetime.
    for issued in (
        "2026-01-01T12:00:00Z",
        "2026-01-01T13:00:00+01:00",
        datetime(2026, 1, 1, 7, 0, tzinfo=timezone(timedelta(hours=-5))),
    ):
        assert cert_mod.verify(dataclasses.replace(c, issued_at=issued), b"k"), issued
    # A different instant does not verify.
    assert not cert_mod.verify(dataclasses.replace(c, issued_at="2026-01-01T12:00:01Z"), b"k")


def test_none_port_and_any_port_are_the_same_claim_scope():
    c = cert_mod.sign(_cert(port=None, claim="no route from guest to db on any port"), b"k")
    full_any = dataclasses.replace(c, port=PortRange(Proto.ANY, 0, 65535))
    assert cert_mod.verify(full_any, b"k")
    # A narrower port is a different claim scope.
    assert not cert_mod.verify(dataclasses.replace(c, port=PortRange.single(Proto.TCP, 22)), b"k")


@pytest.mark.parametrize("field,value", [
    ("claim", "no route at all"),
    ("boundary_src", "other"),
    ("boundary_dst", "other"),
    ("config_hashes", ("h1",)),
    ("corroboration", Corroboration(0, 0, sensor_on_protected_side=False, probe_tested=True)),
    ("corroboration", Corroboration(0, 30, sensor_on_protected_side=False)),
    ("expires_at", "2030-01-01T00:00:00+00:00"),
])
def test_every_semantic_field_is_covered(field, value):
    c = cert_mod.sign(_cert(), b"k")
    assert not cert_mod.verify(dataclasses.replace(c, **{field: value}), b"k")


# -- config plumbing --------------------------------------------------------

def test_settings_read_key_from_env_and_file(monkeypatch, tmp_path):
    from app.config import Settings

    for v in ("WARGAME_SIGNING_KEY", "WARGAME_SIGNING_KEY_FILE", "WARGAME_SIGNING_PREVIOUS_KEYS"):
        monkeypatch.delenv(v, raising=False)
    assert Settings.load().wargame_keyring().configured is False

    monkeypatch.setenv("WARGAME_SIGNING_KEY", MASTER)
    monkeypatch.setenv("WARGAME_SIGNING_PREVIOUS_KEYS", OLD)
    ring = Settings.load().wargame_keyring()
    assert ring.signing_key(T1).kid == signing.key_id(MASTER.encode())
    assert ring.verification_key(signing.key_id(OLD.encode()), T1) is not None

    f = tmp_path / "key"
    f.write_text(OLD + "\n")
    monkeypatch.setenv("WARGAME_SIGNING_KEY_FILE", str(f))     # file wins
    assert Settings.load().wargame_keyring().signing_key(T1).kid == signing.key_id(OLD.encode())
