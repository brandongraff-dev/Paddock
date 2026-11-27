#!/usr/bin/env python3
"""Attestation ROOT ceremony (docs/ASSURANCE_P3.md 3.1, D16). Run OFFLINE.

The attestation root is a NEW Ed25519 key. It is **never the license key** (``vendor_key_ceremony.py``): that key signs
un-domain-separated license JSON on every license issue, so reusing it for certificates would invite cross-protocol
confusion. The root certifies the two online platform keys once a year; everything below them is certified online.

    # 1. air-gapped machine, after reading the runbook (docs/ATTESTATION_OPS.md)
    PADDOCK_ATTEST_ROOT_PASSPHRASE=... \\
      python scripts/attest_root_ceremony.py generate-root --out-dir /mnt/usb/attest-root-2026

    # 2. certify the online issuer and revoker (a new key pair is generated unless --public-key-file is given)
    PADDOCK_ATTEST_ROOT_PASSPHRASE=... PADDOCK_ATTEST_PLATFORM_KEY_PASSPHRASE=... \\
      python scripts/attest_root_ceremony.py certify-issuer  --root-key-file /mnt/usb/attest-root-2026/paddock-attest-root.pem \\
          --out-dir /mnt/usb/issuer-2026 --serial 1
      python scripts/attest_root_ceremony.py certify-revoker --root-key-file ... --out-dir /mnt/usb/revoker-2026 --serial 2

    # 3. release machine: embed ONLY the public root entry (trust_roots.json) in the verifier, build the wheel, then
    #    read the root back out of the artifact before shipping
    python scripts/attest_root_ceremony.py check --wheel dist/paddock_verify-X.whl --public-key-file paddock-attest-root.pub

    python scripts/attest_root_ceremony.py fingerprint --public-key-file paddock-attest-root.pub

Safety rules (same as the license ceremony): key material is never written inside this repository; the private key is
PKCS8 encrypted with a passphrase of at least 16 characters (an unencrypted key is refused; the passphrase comes from the
environment or a tty prompt, never from an argument); existing files are never overwritten; every certificate is
verified with the open verifier's byte-level primitives before anything is reported as done. This script depends on
``cryptography`` and ``paddock_verify`` only (it must run on an offline machine).
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from paddock_verify import b64, canon, dsse, ed25519, timefmt  # noqa: E402
from paddock_verify.jsonstrict import JsonError  # noqa: E402

ROOT_PASSPHRASE_ENV = "PADDOCK_ATTEST_ROOT_PASSPHRASE"
PLATFORM_PASSPHRASE_ENV = "PADDOCK_ATTEST_PLATFORM_KEY_PASSPHRASE"
MIN_PASSPHRASE = 16
CERT_TYPE = "https://paddock.dev/key-cert/v1"
ROOT_FILES = ("paddock-attest-root.pem", "paddock-attest-root.pub", "trust_roots.json", "ceremony-record.txt")


class CeremonyError(SystemExit):
    def __init__(self, message: str) -> None:
        super().__init__(f"error: {message}")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def kid_of(pub: bytes) -> str:
    return hashlib.sha256(pub).hexdigest()[:32]


def fingerprint(pub: bytes) -> str:
    return "sha256:" + hashlib.sha256(pub).hexdigest()


def _inside_repo(path: Path) -> bool:
    try:
        return path.expanduser().resolve().is_relative_to(ROOT.resolve())
    except OSError:
        return False


def _passphrase(env: str, what: str, confirm: bool) -> str:
    pw = os.environ.get(env)
    if pw is None:
        if not sys.stdin.isatty():
            raise CeremonyError(f"set {env} (or run interactively) - an unencrypted {what} key is refused")
        pw = getpass.getpass(f"Passphrase for the {what} private key: ")
        if confirm and getpass.getpass("Repeat passphrase: ") != pw:
            raise CeremonyError("passphrases differ")
    if len(pw) < MIN_PASSPHRASE:
        raise CeremonyError(f"the passphrase must be at least {MIN_PASSPHRASE} characters")
    return pw


def _now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _t(text: str, what: str) -> int:
    try:
        return timefmt.parse(text)
    except JsonError:
        raise CeremonyError(f"{what} must look like 2026-12-01T00:00:00Z") from None


def _add_years(epoch: int, years: int) -> int:
    d = datetime.fromtimestamp(epoch, timezone.utc)
    try:
        d = d.replace(year=d.year + years)
    except ValueError:                                        # 29 February
        d = d.replace(year=d.year + years, day=28)
    return int(d.timestamp())


def _write_new(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _pem(key: Ed25519PrivateKey, passphrase: str) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.BestAvailableEncryption(passphrase.encode("utf-8")))


def read_public_key(path: str) -> bytes:
    """Load a public-key file (one base64 line, 32 raw bytes). A private key file is refused."""
    text = Path(path).expanduser().read_text(encoding="utf-8").strip()
    if "PRIVATE" in text.upper() or "BEGIN" in text.upper():
        raise CeremonyError("that file looks like a PRIVATE key; pass the public key file only")
    try:
        raw = b64.strict_decode(text)
    except JsonError:
        raise CeremonyError(f"{path}: not canonical base64") from None
    if len(raw) != 32:
        raise CeremonyError(f"{path}: an Ed25519 public key is 32 bytes (got {len(raw)})")
    return raw


def _load_root_key(path: str, passphrase: str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).expanduser().read_bytes(), password=passphrase.encode("utf-8"))
    except (OSError, ValueError, TypeError):
        raise CeremonyError("the root key cannot be opened (wrong passphrase, unencrypted or damaged)") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise CeremonyError("the root key is not an Ed25519 key")
    return key


def _cert_payload(*, usage: str, pub: bytes, issuer_kid: str, not_before: int, not_after: int, serial: int) -> bytes:
    """The certificate payload, built here independently of the orchestrator (a second implementation: the tests check
    it against ``app.attest.certs`` in both directions)."""
    doc = {
        "_type": CERT_TYPE, "alg": "ed25519", "custody": "hosted", "issuer_kid": issuer_kid, "kid": kid_of(pub),
        "not_after": timefmt.format(not_after), "not_before": timefmt.format(not_before),
        "public_key": b64.encode(pub), "serial": serial, "usage": usage,
    }
    return canon.dumps(doc)


def _self_test_cert(envelope: bytes, root_pub: bytes, usage: str, root_entry: dict) -> None:
    """Verify with the open verifier's primitives: strict envelope, canonical payload, PAE signature, usage, window.
    If the orchestrator's chain verifier is importable it must agree."""
    try:
        env = dsse.parse_envelope(envelope, expected_type=dsse.PAYLOAD_TYPE_KEY_CERT)
        body = canon.roundtrip(env.payload)
    except JsonError as exc:
        raise CeremonyError(f"self-test failed: the certificate is not well formed ({exc.code})") from None
    if not ed25519.verify(root_pub, dsse.pae(env.payload_type, env.payload), env.sig):
        raise CeremonyError("self-test failed: the certificate signature does not verify under the root")
    if body["usage"] != usage or body["issuer_kid"] != kid_of(root_pub) or env.keyid != body["issuer_kid"]:
        raise CeremonyError("self-test failed: wrong usage or issuer")
    try:                                                      # optional second opinion
        sys.path.insert(0, str(ROOT / "orchestrator"))
        from app.attest import certs
    except Exception:  # noqa: BLE001 -- the offline machine may not have the orchestrator
        return
    finally:
        if sys.path and sys.path[0] == str(ROOT / "orchestrator"):
            sys.path.pop(0)
    try:
        certs.verify_chain(envelope, issuers=[], roots=certs.parse_roots([root_entry]), at=certs.parse_cert(envelope).not_before,
                           expect_usage=usage)
    except certs.CertError as exc:
        raise CeremonyError(f"self-test failed under the orchestrator's chain verifier: {exc}") from None


# --------------------------------------------------------------------------- #
# generate-root
# --------------------------------------------------------------------------- #

def cmd_generate_root(a: argparse.Namespace) -> int:
    out = Path(a.out_dir).expanduser()
    if _inside_repo(out):
        raise CeremonyError("refusing to write key material inside the repository")
    paths = {name: out / name for name in ROOT_FILES}
    for p in paths.values():
        if p.exists():
            raise CeremonyError(f"{p} exists; never overwrite a root key (pick a new --out-dir)")
    pw = _passphrase(ROOT_PASSPHRASE_ENV, "attestation root", confirm=True)
    nb = _t(a.not_before, "--not-before") if a.not_before else _now()
    na = _add_years(nb, a.years)

    key = Ed25519PrivateKey.generate()
    pub = _raw(key)
    entry = {"kid": kid_of(pub), "public_key": b64.encode(pub), "usage": "root",
             "not_before": timefmt.format(nb), "not_after": timefmt.format(na)}

    # prove the pair works through the verifier's primitives before anything is written down
    probe_pub = _raw(Ed25519PrivateKey.generate())
    payload = _cert_payload(usage="issue-cert", pub=probe_pub, issuer_kid=entry["kid"], not_before=nb, not_after=nb + 86400,
                            serial=1)
    probe = dsse.build_envelope(dsse.PAYLOAD_TYPE_KEY_CERT, payload, entry["kid"], key.sign(dsse.pae(dsse.PAYLOAD_TYPE_KEY_CERT, payload)))
    _self_test_cert(probe, pub, "issue-cert", entry)

    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    _write_new(paths["paddock-attest-root.pem"], _pem(key, pw), 0o600)
    _write_new(paths["paddock-attest-root.pub"], (entry["public_key"] + "\n").encode("ascii"), 0o644)
    _write_new(paths["trust_roots.json"], (json.dumps([entry], indent=2) + "\n").encode("ascii"), 0o644)
    record = (
        "Paddock attestation ROOT - ceremony record (contains NO secret; safe to file)\n"
        f"created_utc : {timefmt.format(_now())}\n"
        "algorithm   : Ed25519\n"
        f"kid         : {entry['kid']}\n"
        f"public key  : {entry['public_key']}\n"
        f"fingerprint : {fingerprint(pub)}\n"
        f"valid       : {entry['not_before']} .. {entry['not_after']}\n"
        "self-test   : signed + verified a probe issuer certificate with the verifier primitives\n"
        "private key : paddock-attest-root.pem (PKCS#8, passphrase-encrypted); store offline, 2 copies, 2 custodians\n"
        "This root is never the license key: the license key (vendor_key_ceremony.py) is a different key and must never be reused here.\n"
        "Embed only trust_roots.json in the verifier release; read it back with `check` before shipping.\n"
    )
    _write_new(paths["ceremony-record.txt"], record.encode("ascii"), 0o644)
    print(f"private key : {paths['paddock-attest-root.pem']}  (mode 0600, encrypted)")
    print(f"public key  : {paths['paddock-attest-root.pub']}")
    print(f"trust root  : {paths['trust_roots.json']}")
    print(f"kid         : {entry['kid']}")
    print(f"fingerprint : {fingerprint(pub)}")
    print("\nNext: move the private key to offline storage, import ONLY trust_roots.json to the release pipeline.")
    return 0


# --------------------------------------------------------------------------- #
# certify-issuer / certify-revoker
# --------------------------------------------------------------------------- #

def _root_window(root_key_path: str, root_pub: bytes, explicit: str | None) -> tuple | None:
    candidate = Path(explicit) if explicit else Path(root_key_path).expanduser().with_name("trust_roots.json")
    try:
        entries = json.loads(candidate.read_text(encoding="ascii"))
    except (OSError, ValueError):
        if explicit:
            raise CeremonyError(f"cannot read {candidate}") from None
        return None
    for e in entries if isinstance(entries, list) else []:
        if isinstance(e, dict) and e.get("public_key") == b64.encode(root_pub):
            return _t(e["not_before"], "root not_before"), _t(e["not_after"], "root not_after"), e
    raise CeremonyError(f"{candidate} does not list this root key")


def _issuer_window(a: argparse.Namespace, issuer_pub: bytes) -> tuple:
    if not a.issuer_cert_file:
        raise CeremonyError("--issuer-key-file needs --issuer-cert-file (its window bounds the revoker's)")
    try:
        env = dsse.parse_envelope(Path(a.issuer_cert_file).expanduser().read_bytes(), expected_type=dsse.PAYLOAD_TYPE_KEY_CERT)
        body = canon.roundtrip(env.payload)
        if body["usage"] != "issue-cert" or b64.strict_decode(body["public_key"]) != issuer_pub:
            raise ValueError("not this issuer's certificate")
        return timefmt.parse(body["not_before"]), timefmt.parse(body["not_after"])
    except (OSError, ValueError, KeyError, JsonError):
        raise CeremonyError("--issuer-cert-file is not the certificate of --issuer-key-file") from None


def _certify(a: argparse.Namespace, *, usage: str, label: str) -> int:
    out = Path(a.out_dir).expanduser()
    if _inside_repo(out):
        raise CeremonyError("refusing to write key material inside the repository")
    names = {"cert": out / f"{label}.cert.json", "pem": out / f"{label}.pem", "pub": out / f"{label}.pub"}
    for p in names.values():
        if p.exists():
            raise CeremonyError(f"{p} exists; never overwrite (pick a new --out-dir)")
    if a.serial < 1:
        raise CeremonyError("--serial is a positive integer")
    if getattr(a, "issuer_key_file", None) and usage != "revoke":
        raise CeremonyError("--issuer-key-file applies to certify-revoker only (an issuer is certified by the root)")
    if getattr(a, "issuer_key_file", None):
        # the revoker certified through the ISSUER (the open verifier accepts both): the issuer key signs, online
        root = _load_root_key(a.issuer_key_file, _passphrase(PLATFORM_PASSPHRASE_ENV, "issuer", confirm=False))
    else:
        root = _load_root_key(a.root_key_file, _passphrase(ROOT_PASSPHRASE_ENV, "attestation root", confirm=False))
    root_pub = _raw(root)
    nb = _t(a.not_before, "--not-before") if a.not_before else _now()
    na = _t(a.not_after, "--not-after") if a.not_after else _add_years(nb, 1)
    if not nb < na:
        raise CeremonyError("the window is empty")
    if getattr(a, "issuer_key_file", None):
        window = _issuer_window(a, root_pub)
        if not (window[0] <= nb and na <= window[1]):
            raise CeremonyError("the requested window is outside the issuer's validity window")
    else:
        window = _root_window(a.root_key_file, root_pub, a.roots_file)
        if window is not None and not (window[0] <= nb and na <= window[1]):
            raise CeremonyError("the requested window is outside the root's validity window")

    generated: Ed25519PrivateKey | None = None
    if a.public_key_file:
        pub = read_public_key(a.public_key_file)
    else:
        generated = Ed25519PrivateKey.generate()
        pub = _raw(generated)
    pem = _pem(generated, _passphrase(PLATFORM_PASSPHRASE_ENV, label, confirm=False)) if generated is not None else None
    payload = _cert_payload(usage=usage, pub=pub, issuer_kid=kid_of(root_pub), not_before=nb, not_after=na,
                            serial=a.serial)
    envelope = dsse.build_envelope(dsse.PAYLOAD_TYPE_KEY_CERT, payload, kid_of(root_pub),
                                   root.sign(dsse.pae(dsse.PAYLOAD_TYPE_KEY_CERT, payload)))
    if getattr(a, "issuer_key_file", None):
        root_entry = {"kid": kid_of(root_pub), "public_key": b64.encode(root_pub), "usage": "issue-cert",
                      "not_before": timefmt.format(window[0]), "not_after": timefmt.format(window[1])}
    else:
        root_entry = window[2] if window is not None else {
            "kid": kid_of(root_pub), "public_key": b64.encode(root_pub), "usage": "root",
            "not_before": timefmt.format(nb), "not_after": timefmt.format(na)}
    _self_test_cert(envelope, root_pub, usage, root_entry)

    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    if pem is not None:
        _write_new(names["pem"], pem, 0o600)
        _write_new(names["pub"], (b64.encode(pub) + "\n").encode("ascii"), 0o644)
    _write_new(names["cert"], envelope, 0o644)
    print(f"certificate : {names['cert']}  (usage {usage}, serial {a.serial}, kid {kid_of(pub)})")
    if pem is not None:
        print(f"private key : {names['pem']}  (mode 0600, encrypted with {PLATFORM_PASSPHRASE_ENV})")
    print(f"valid       : {timefmt.format(nb)} .. {timefmt.format(na)}")
    return 0


def cmd_certify_issuer(a: argparse.Namespace) -> int:
    return _certify(a, usage="issue-cert", label="issuer")


def cmd_certify_revoker(a: argparse.Namespace) -> int:
    return _certify(a, usage="revoke", label="revoker")


# --------------------------------------------------------------------------- #
# fingerprint / check
# --------------------------------------------------------------------------- #

def cmd_fingerprint(a: argparse.Namespace) -> int:
    pub = read_public_key(a.public_key_file)
    print(f"{kid_of(pub)}  {fingerprint(pub)}")
    return 0


def cmd_check(a: argparse.Namespace) -> int:
    try:
        with zipfile.ZipFile(a.wheel) as z:
            names = [n for n in z.namelist() if n.endswith("paddock_verify/data/trust_roots.json")]
            if not names:
                print("error: the wheel has no paddock_verify/data/trust_roots.json", file=sys.stderr)
                return 1
            data = z.read(names[0])
    except (OSError, zipfile.BadZipFile) as exc:
        print(f"error: cannot read the wheel: {exc}", file=sys.stderr)
        return 2
    try:
        embedded = json.loads(data)
        if not isinstance(embedded, list):
            raise ValueError("not a list")
        keys = [e["public_key"] for e in embedded if isinstance(e, dict) and e.get("usage") == "root"]
    except (ValueError, KeyError):
        print("error: the embedded trust_roots.json is malformed", file=sys.stderr)
        return 1
    for k in keys:
        try:
            print(f"embedded: {kid_of(b64.strict_decode(k))}  {fingerprint(b64.strict_decode(k))}")
        except JsonError:
            print("embedded: (malformed entry)", file=sys.stderr)
            return 1
    if not keys:
        print("error: the wheel embeds no trust root (a source build exits 2 config.no_trust_roots)", file=sys.stderr)
        return 1
    want = [b64.encode(read_public_key(p)) for p in a.public_key_file]
    if not want:
        return 0
    missing = [k for k in want if k not in keys]
    extra = [k for k in keys if k not in want] if a.exact else []
    for k in missing:
        print(f"MISSING   : {kid_of(b64.strict_decode(k))}", file=sys.stderr)
    for k in extra:
        print(f"UNEXPECTED: {kid_of(b64.strict_decode(k))}", file=sys.stderr)
    if missing or extra:
        return 1
    print("ok: the build trusts the expected attestation root(s)")
    return 0


def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate-root", help="create the attestation root key pair (run OFFLINE)")
    g.add_argument("--out-dir", required=True, help="empty directory OUTSIDE the repository (e.g. an encrypted USB)")
    g.add_argument("--not-before", help="start of the root's validity (default now), e.g. 2026-01-01T00:00:00Z")
    g.add_argument("--years", type=int, default=10, help="validity in years (default 10)")
    g.set_defaults(fn=cmd_generate_root)

    for name, fn in (("certify-issuer", cmd_certify_issuer), ("certify-revoker", cmd_certify_revoker)):
        c = sub.add_parser(name, help=f"certify the online {name.split('-')[1]} key with the root")
        c.add_argument("--root-key-file", required=True)
        c.add_argument("--out-dir", required=True)
        c.add_argument("--serial", type=int, required=True)
        c.add_argument("--not-before", help="default now")
        c.add_argument("--not-after", help="default one year after --not-before")
        c.add_argument("--public-key-file", help="certify this public key instead of generating a key pair")
        c.add_argument("--roots-file", help="trust_roots.json to read the root window from (default: next to the root key)")
        if name == "certify-revoker":
            c.add_argument("--issuer-key-file", help="certify the revoker through the (online) issuer key instead of the root")
            c.add_argument("--issuer-cert-file", help="the issuer's certificate (bounds the revoker's window)")
        c.set_defaults(fn=fn)

    f = sub.add_parser("fingerprint", help="print a public key's kid and fingerprint")
    f.add_argument("--public-key-file", required=True)
    f.set_defaults(fn=cmd_fingerprint)

    k = sub.add_parser("check", help="read the trust root back from a built verifier wheel")
    k.add_argument("--wheel", required=True)
    k.add_argument("--public-key-file", action="append", default=[])
    k.add_argument("--exact", action="store_true", help="fail if any OTHER root is embedded too")
    k.set_defaults(fn=cmd_check)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
