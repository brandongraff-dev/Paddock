"""Ed25519: RFC 8032 vectors for both backends, byte-identical output, and fail-closed verification."""
from __future__ import annotations

import hashlib
import random

import pytest

from paddock_agent import ed25519_pure, signing

# RFC 8032 section 7.1. TEST 1 (empty message), TEST 2 (one byte), TEST 3 (two bytes).
RFC = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
     "d25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c"
     "387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc659"
     "4a7c15e9716ed28dc027beceea1ec40a"),
]


def _backends():
    out = [("pure", signing.get_backend("pure"))]
    try:
        out.append(("cryptography", signing.get_backend("cryptography")))
    except signing.SigningError:
        pass
    return out


@pytest.mark.parametrize("name,backend", _backends(), ids=lambda v: v if isinstance(v, str) else "")
@pytest.mark.parametrize("sk,pk,msg,sig", RFC)
def test_rfc8032_vectors(name, backend, sk, pk, msg, sig):
    seed, message = bytes.fromhex(sk), bytes.fromhex(msg)
    assert backend.public_key(seed).hex() == pk
    assert backend.sign(seed, message).hex() == sig
    assert backend.verify(bytes.fromhex(pk), message, bytes.fromhex(sig)) is True


def test_both_backends_are_available_here_or_the_identity_test_is_vacuous():
    names = [n for n, _ in _backends()]
    if names != ["pure", "cryptography"]:
        pytest.skip("cryptography is not importable in this interpreter; identity cannot be shown")


def test_backends_are_byte_identical_on_random_inputs():
    names = dict(_backends())
    if "cryptography" not in names:
        pytest.skip("cryptography is not importable")
    pure, crypto = names["pure"], names["cryptography"]
    rng = random.Random(8032)
    for i in range(40):
        seed = bytes(rng.getrandbits(8) for _ in range(32))
        msg = bytes(rng.getrandbits(8) for _ in range(rng.choice([0, 1, 31, 32, 33, 64, 300, 2000])))
        assert pure.public_key(seed) == crypto.public_key(seed)
        sp, sc = pure.sign(seed, msg), crypto.sign(seed, msg)
        assert sp == sc, "signature differs for seed %s" % seed.hex()
        pub = pure.public_key(seed)
        # Cross-verification in both directions.
        assert crypto.verify(pub, msg, sp) and pure.verify(pub, msg, sc)


def test_pure_verify_fails_closed():
    seed = hashlib.sha256(b"k").digest()
    pub = ed25519_pure.public_key(seed)
    msg = b"hello"
    sig = ed25519_pure.sign(seed, msg)
    assert ed25519_pure.verify(pub, msg, sig)
    assert not ed25519_pure.verify(pub, msg + b"!", sig)
    bad = bytearray(sig)
    bad[0] ^= 1
    assert not ed25519_pure.verify(pub, msg, bytes(bad))
    bad = bytearray(sig)
    bad[40] ^= 1
    assert not ed25519_pure.verify(pub, msg, bytes(bad))
    # wrong key
    assert not ed25519_pure.verify(ed25519_pure.public_key(hashlib.sha256(b"k2").digest()), msg, sig)
    # malleability: S + L is rejected (S must be < L)
    s = int.from_bytes(sig[32:], "little") + ed25519_pure._Q
    assert not ed25519_pure.verify(pub, msg, sig[:32] + s.to_bytes(33, "little")[:32])
    # garbage never raises
    for junk in (b"", b"x" * 31, b"\xff" * 64, None):
        assert ed25519_pure.verify(pub, msg, junk) is False
    assert ed25519_pure.verify(b"\xff" * 32, msg, sig) is False   # y >= p: not a point
    assert ed25519_pure.verify(pub[:31], msg, sig) is False


def test_seed_length_is_enforced():
    for bad in (b"", b"x" * 31, b"x" * 33, "x" * 32, None):
        with pytest.raises(Exception):
            ed25519_pure.public_key(bad)
        with pytest.raises(signing.SigningError):
            signing.sign(bad, b"m")


def test_key_id_is_the_first_32_hex_of_sha256_of_the_public_key():
    pub = bytes.fromhex(RFC[0][1])
    assert signing.key_id(pub) == hashlib.sha256(pub).hexdigest()[:32]
    assert len(signing.key_id(pub)) == 32
    with pytest.raises(signing.SigningError):
        signing.key_id(pub[:31])


def test_auto_backend_falls_back_to_pure_when_cryptography_is_unusable(monkeypatch):
    def boom(self):
        raise ImportError("no cryptography here")
    monkeypatch.setattr(signing._CryptographyBackend, "__init__", boom)
    monkeypatch.setattr(signing, "_cache", {})
    monkeypatch.delenv(signing.ENV_BACKEND, raising=False)
    assert signing.backend_name() == "pure"
    assert signing.public_key(bytes.fromhex(RFC[0][0])).hex() == RFC[0][1]
    # ...but a FORCED unavailable backend is an error, never a silent switch
    monkeypatch.setenv(signing.ENV_BACKEND, "cryptography")
    with pytest.raises(signing.SigningError):
        signing.get_backend()


def test_forced_backend_env(monkeypatch):
    monkeypatch.setattr(signing, "_cache", {})
    monkeypatch.setenv(signing.ENV_BACKEND, "pure")
    assert signing.backend_name() == "pure"
    monkeypatch.setenv(signing.ENV_BACKEND, "nonsense")
    with pytest.raises(signing.SigningError):
        signing.get_backend()


def test_generate_seed_is_random_32_bytes():
    a, b = signing.generate_seed(), signing.generate_seed()
    assert len(a) == 32 and a != b
