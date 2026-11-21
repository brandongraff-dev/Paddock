#!/usr/bin/env python3
"""Vendor-side license issuance for Paddock editions (see docs/EDITIONS.md).

The PRIVATE signing key never lives in this repository. Keep it in a KMS/HSM
or an offline vault; this script only ever reads it from a path you pass.

    # one-time: create a vendor keypair (private key written 0600)
    python scripts/issue_license.py keygen --private-key ~/vault/paddock-vendor.pem

    # print the public key to embed (licensing.VENDOR_PUBLIC_KEYS) or to set as
    # PADDOCK_LICENSE_PUBLIC_KEYS on a customer instance
    python scripts/issue_license.py pubkey --private-key ~/vault/paddock-vendor.pem

    # issue a key
    python scripts/issue_license.py issue --private-key ~/vault/paddock-vendor.pem \\
        --license-id ACME-2027-001 --licensee "Acme Corp" --edition enterprise \\
        --seats 50 --sites 5 --assets 20000 --days 365 --feature audit_export

    # inspect / verify a key offline
    python scripts/issue_license.py verify --public-key <b64> --key PDK1....

Uses the same encoder/verifier as the orchestrator (orchestrator/app/licensing.py),
so an issued key is guaranteed to parse.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "orchestrator"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app import licensing  # noqa: E402


def _load_private(path: str) -> Ed25519PrivateKey:
    data = Path(path).expanduser().read_bytes()
    pw = os.environ.get("PADDOCK_VENDOR_KEY_PASSPHRASE")
    key = serialization.load_pem_private_key(data, password=pw.encode() if pw else None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit("error: not an Ed25519 private key")
    return key


def _pub_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("ascii")


def cmd_keygen(a: argparse.Namespace) -> int:
    out = Path(a.private_key).expanduser()
    if out.exists() and not a.force:
        sys.exit(f"error: {out} exists (use --force to overwrite)")
    try:
        if out.resolve().is_relative_to(ROOT.resolve()):
            sys.exit("error: refusing to write the vendor private key inside the repository")
    except OSError:
        pass
    key = Ed25519PrivateKey.generate()
    pw = os.environ.get("PADDOCK_VENDOR_KEY_PASSPHRASE")
    enc = serialization.BestAvailableEncryption(pw.encode()) if pw else serialization.NoEncryption()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    print(f"private key written to {out} (mode 0600){' (encrypted)' if pw else ''}")
    print(f"public key (base64): {_pub_b64(key)}")
    return 0


def cmd_pubkey(a: argparse.Namespace) -> int:
    print(_pub_b64(_load_private(a.private_key)))
    return 0


def cmd_issue(a: argparse.Namespace) -> int:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        "v": 1,
        "license_id": a.license_id,
        "licensee": a.licensee,
        "edition": a.edition,
        "seats": a.seats,
        "sites": a.sites,
        "assets": a.assets,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(days=a.days)).isoformat() if a.days else None,
        "features": sorted(set(a.feature or [])),
    }
    unknown = [f for f in payload["features"] if f not in licensing.FEATURES]
    if unknown:
        sys.exit(f"error: unknown feature(s) {unknown}; known: {sorted(licensing.FEATURES)}")
    try:
        key = licensing.sign_license(payload, _load_private(a.private_key))
    except licensing.LicenseError as exc:
        sys.exit(f"error: {exc}")
    if a.out:
        Path(a.out).write_text(key + "\n", encoding="utf-8")
        print(f"license written to {a.out}", file=sys.stderr)
    else:
        print(key)
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    keys = licensing.parse_public_keys([a.public_key])
    text = Path(a.key[1:]).read_text().strip() if a.key.startswith("@") else a.key
    try:
        lic = licensing.verify_license_key(text, public_keys=keys, source="offline")
    except licensing.LicenseError as exc:
        print(f"INVALID: {exc}")
        return 1
    print(json.dumps(lic.as_dict(), indent=2, default=str))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="create a vendor Ed25519 keypair")
    k.add_argument("--private-key", required=True)
    k.add_argument("--force", action="store_true")
    k.set_defaults(fn=cmd_keygen)

    pk = sub.add_parser("pubkey", help="print the public key for a private key")
    pk.add_argument("--private-key", required=True)
    pk.set_defaults(fn=cmd_pubkey)

    i = sub.add_parser("issue", help="sign a license key")
    i.add_argument("--private-key", required=True)
    i.add_argument("--license-id", required=True)
    i.add_argument("--licensee", required=True)
    i.add_argument("--edition", required=True, choices=licensing.EDITIONS)
    i.add_argument("--seats", type=int)
    i.add_argument("--sites", type=int)
    i.add_argument("--assets", type=int, help="monitored-asset allowance")
    i.add_argument("--days", type=int, default=365, help="validity in days (0 = perpetual)")
    i.add_argument("--feature", action="append", help="extra feature beyond the edition default")
    i.add_argument("--out", help="write the key to this file instead of stdout")
    i.set_defaults(fn=cmd_issue)

    v = sub.add_parser("verify", help="verify a key offline")
    v.add_argument("--public-key", required=True)
    v.add_argument("--key", required=True, help="the key, or @path/to/file")
    v.set_defaults(fn=cmd_verify)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
