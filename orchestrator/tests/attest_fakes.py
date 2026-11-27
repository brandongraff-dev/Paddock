"""Test support for the P3.3 suites (not a test module): a throwaway attestation platform.

It builds a root, an issuer and a revoker (Ed25519), their certificates, the encrypted PKCS8 key files, the cert files
and a trust-roots file, using ONLY ``cryptography`` and the verifier's byte primitives (``paddock_verify.canon``,
``dsse``, ``b64``, ``timefmt``). It deliberately imports nothing from ``app.attest.certs`` / ``platform_keys`` so that
those production modules are cross-checked against an independent construction, not against themselves.

Every key here is a throwaway; no real key exists in the repository.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from paddock_verify import b64, canon, dsse, ed25519, timefmt
from pydantic import SecretStr

KEK = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="      # 32 x 0x07 (the P3.2 test KEK)
PASSPHRASE = "correct horse battery staple 42"

T0 = timefmt.parse("2026-12-01T00:00:00Z")
DAY = 86400
ESTATE_A = "e_" + "a" * 26
ESTATE_B = "e_" + "b" * 26


def ts(epoch: int) -> str:
    return timefmt.format(epoch)


def raw_pub(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def kid_of(pub: bytes) -> str:
    return hashlib.sha256(pub).hexdigest()[:32]


def cert_payload(*, usage: str, pub: bytes, issuer_kid: str, not_before: int, not_after: int, serial: int = 1,
                 estate: str | None = None, custody: str = "hosted", alg: str = "ed25519", kid: str | None = None,
                 **extra: Any) -> bytes:
    doc: dict[str, Any] = {
        "_type": "https://paddock.dev/key-cert/v1", "alg": alg, "custody": custody, "issuer_kid": issuer_kid,
        "kid": kid if kid is not None else kid_of(pub), "not_after": ts(not_after), "not_before": ts(not_before),
        "public_key": b64.encode(pub), "serial": serial, "usage": usage,
    }
    if estate is not None:
        doc["estate"] = estate
    doc.update(extra)
    return canon.dumps(doc)


def envelope(priv: Ed25519PrivateKey, signer_kid: str, payload_type: str, payload: bytes) -> bytes:
    sig = priv.sign(dsse.pae(payload_type, payload))
    return dsse.build_envelope(payload_type, payload, signer_kid, sig)


def make_cert(signer: Ed25519PrivateKey, signer_kid: str, *, usage: str, pub: bytes, not_before: int, not_after: int,
              serial: int = 1, estate: str | None = None, custody: str = "hosted", **extra: Any) -> bytes:
    payload = cert_payload(usage=usage, pub=pub, issuer_kid=signer_kid, not_before=not_before, not_after=not_after,
                           serial=serial, estate=estate, custody=custody, **extra)
    return envelope(signer, signer_kid, dsse.PAYLOAD_TYPE_KEY_CERT, payload)


def cert_doc(env: bytes | str | dict) -> dict:
    """The parsed payload of a cert envelope WITHOUT trusting it (test inspection only)."""
    if isinstance(env, (bytes, str)):
        env = json.loads(env)
    return json.loads(b64.strict_decode(env["payload"]))


def independent_cert_check(env: bytes | str | dict, parent_pub: bytes) -> dict:
    """Verify a cert envelope with nothing but the verifier primitives: strict envelope, canonical payload, the PAE
    signature under ``parent_pub``. Returns the payload dict."""
    raw = env if isinstance(env, bytes) else (json.dumps(env).encode() if isinstance(env, dict) else env.encode())
    e = dsse.parse_envelope(raw, expected_type=dsse.PAYLOAD_TYPE_KEY_CERT)
    value = canon.roundtrip(e.payload)
    assert ed25519.verify(parent_pub, dsse.pae(e.payload_type, e.payload), e.sig), "signature does not verify"
    assert e.keyid == value["issuer_kid"]
    return value


@dataclass
class Platform:
    dir: Path
    root_priv: Ed25519PrivateKey
    issuer_priv: Ed25519PrivateKey
    revoker_priv: Ed25519PrivateKey
    issuer_cert: bytes
    revoker_cert: bytes
    roots: list[dict[str, Any]]
    root_kid: str = ""
    issuer_kid: str = ""
    revoker_kid: str = ""
    passphrase: str = PASSPHRASE
    files: dict[str, str] = field(default_factory=dict)

    @property
    def root_pub(self) -> bytes:
        return raw_pub(self.root_priv)

    @property
    def issuer_pub(self) -> bytes:
        return raw_pub(self.issuer_priv)

    @property
    def revoker_pub(self) -> bytes:
        return raw_pub(self.revoker_priv)


def _pem(priv: Ed25519PrivateKey, passphrase: str) -> bytes:
    return priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.BestAvailableEncryption(passphrase.encode()))


def make_platform(
    directory: Path, *,
    root_window: tuple[int, int] = (T0 - 400 * DAY, T0 + 3000 * DAY),
    issuer_window: tuple[int, int] = (T0 - 150 * DAY, T0 + 365 * DAY),
    revoker_window: tuple[int, int] = (T0 - 150 * DAY, T0 + 365 * DAY),
    root_usage: str = "root",
    passphrase: str = PASSPHRASE,
    revoker_certified_by: str = "root",
) -> Platform:
    directory.mkdir(parents=True, exist_ok=True)
    root, issuer, revoker = (Ed25519PrivateKey.generate() for _ in range(3))
    root_kid = kid_of(raw_pub(root))
    issuer_cert = make_cert(root, root_kid, usage="issue-cert", pub=raw_pub(issuer), not_before=issuer_window[0],
                            not_after=issuer_window[1], serial=1)
    if revoker_certified_by == "issuer":          # the open verifier's own vectors certify the revoker through the issuer
        revoker_cert = make_cert(issuer, kid_of(raw_pub(issuer)), usage="revoke", pub=raw_pub(revoker),
                                 not_before=revoker_window[0], not_after=revoker_window[1], serial=2)
    else:
        revoker_cert = make_cert(root, root_kid, usage="revoke", pub=raw_pub(revoker), not_before=revoker_window[0],
                                 not_after=revoker_window[1], serial=2)
    roots = [{"kid": root_kid, "public_key": b64.encode(raw_pub(root)), "usage": root_usage,
              "not_before": ts(root_window[0]), "not_after": ts(root_window[1])}]
    plat = Platform(directory, root, issuer, revoker, issuer_cert, revoker_cert, roots, root_kid=root_kid,
                    issuer_kid=kid_of(raw_pub(issuer)), revoker_kid=kid_of(raw_pub(revoker)), passphrase=passphrase)
    files = {
        "issuer_key_file": ("issuer.pem", _pem(issuer, passphrase)),
        "issuer_cert_file": ("issuer.cert.json", issuer_cert),
        "revoker_key_file": ("revoker.pem", _pem(revoker, passphrase)),
        "revoker_cert_file": ("revoker.cert.json", revoker_cert),
        "trust_roots_file": ("trust_roots.json", json.dumps(roots).encode()),
    }
    for attr, (name, data) in files.items():
        path = directory / name
        path.write_bytes(data)
        plat.files[attr] = str(path)
    return plat


def install(monkeypatch, plat: Platform, *, kek: str | None = KEK, with_roots: bool = True) -> None:
    """Point the attestation settings at ``plat`` (and a KEK) for one test."""
    from app.attest import config as attest_config

    s = attest_config.settings
    monkeypatch.setattr(s, "kek", SecretStr(kek) if kek else None)
    monkeypatch.setattr(s, "kek_file", None)
    monkeypatch.setattr(s, "kek_previous", None)
    monkeypatch.setattr(s, "platform_key_passphrase", SecretStr(plat.passphrase))
    for attr, path in plat.files.items():
        if attr == "trust_roots_file" and not with_roots:
            monkeypatch.setattr(s, attr, None)
            continue
        monkeypatch.setattr(s, attr, path)
    try:                                                    # a stale platform cache from another test must not leak
        from app.attest import platform_keys
        platform_keys.reset_cache()
    except ImportError:                                     # pragma: no cover - before the module exists
        pass
