#!/usr/bin/env python3
"""Vendor signing-key ceremony helpers (see docs/BILLING.md, "Vendor key ceremony").

The vendor Ed25519 PRIVATE key signs every license (``scripts/issue_license.py``).
It must be created OFFLINE, stored encrypted, and never touch this repository.
Only the PUBLIC key is embedded in official builds
(``licensing.VENDOR_PUBLIC_KEYS``). This script does the mechanical parts and
refuses the unsafe shortcuts. It never generates or commits a key by itself:
nothing here runs at import time or in CI except ``check``.

    # 1. On an air-gapped machine (no network), after reading the runbook:
    PADDOCK_VENDOR_KEY_PASSPHRASE=... \\
      python scripts/vendor_key_ceremony.py generate --out-dir /mnt/usb/paddock-ceremony-2027

    # 2. On the release machine/CI, with ONLY the public file imported:
    python scripts/vendor_key_ceremony.py embed --public-key-file paddock-vendor.pub \\
        --source orchestrator/app/licensing.py          # edits the CI checkout, never commit it

    # 3. After building: prove the artifact trusts exactly that key
    python scripts/vendor_key_ceremony.py check --public-key-file paddock-vendor.pub \\
        --source orchestrator/app/licensing.py

    python scripts/vendor_key_ceremony.py fingerprint --public-key-file paddock-vendor.pub
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "orchestrator"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

PASSPHRASE_ENV = "PADDOCK_VENDOR_KEY_PASSPHRASE"
MIN_PASSPHRASE = 16
_ASSIGN = re.compile(r"^VENDOR_PUBLIC_KEYS: tuple\[str, \.\.\.\] = \((?P<body>[^)]*)\)\s*$", re.MULTILINE)


class CeremonyError(SystemExit):
    def __init__(self, message: str) -> None:
        super().__init__(f"error: {message}")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def pub_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def fingerprint(pub: str) -> str:
    """SHA-256 of the raw public key, as colon-grouped hex (for reading aloud
    / printing on the ceremony record)."""
    raw = base64.b64decode(pub)
    h = hashlib.sha256(raw).hexdigest()
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))


def read_public_key(path: str) -> str:
    """Load and validate a public-key file (one base64 line, 32 raw bytes)."""
    text = Path(path).expanduser().read_text(encoding="utf-8").strip()
    if "PRIVATE" in text.upper():
        raise CeremonyError("that file looks like a PRIVATE key; pass the public key file only")
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise CeremonyError(f"{path}: not base64") from exc
    if len(raw) != 32:
        raise CeremonyError(f"{path}: an Ed25519 public key is 32 bytes (got {len(raw)})")
    return text


def _inside_repo(path: Path) -> bool:
    try:
        return path.resolve().is_relative_to(ROOT.resolve())
    except OSError:
        return False


def _passphrase(confirm: bool) -> str:
    pw = os.environ.get(PASSPHRASE_ENV)
    if pw is None:
        if not sys.stdin.isatty():
            raise CeremonyError(f"set {PASSPHRASE_ENV} (or run interactively) - an unencrypted vendor key is refused")
        pw = getpass.getpass("Passphrase for the vendor private key: ")
        if confirm and getpass.getpass("Repeat passphrase: ") != pw:
            raise CeremonyError("passphrases differ")
    if len(pw) < MIN_PASSPHRASE:
        raise CeremonyError(f"passphrase must be at least {MIN_PASSPHRASE} characters")
    return pw


# --------------------------------------------------------------------------- #
# generate
# --------------------------------------------------------------------------- #

def cmd_generate(a: argparse.Namespace) -> int:
    out = Path(a.out_dir).expanduser()
    if _inside_repo(out):
        raise CeremonyError("refusing to write key material inside the repository")
    priv_path, pub_path, rec_path = out / "paddock-vendor.pem", out / "paddock-vendor.pub", out / "ceremony-record.txt"
    for p in (priv_path, pub_path, rec_path):
        if p.exists():
            raise CeremonyError(f"{p} exists; never overwrite a vendor key (pick a new --out-dir)")
    pw = _passphrase(confirm=True)

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(pw.encode()),
    )
    pub = pub_b64(key)

    # Prove the pair works before anything is written down: sign + verify through
    # the same code path the orchestrator uses.
    from app import licensing

    probe = licensing.sign_license({"v": 1, "license_id": "ceremony-selftest", "edition": "community"}, key)
    licensing.verify_license_key(probe, public_keys=licensing.parse_public_keys([pub]), source="ceremony")

    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    pub_path.write_text(pub + "\n", encoding="utf-8")
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    rec_path.write_text(
        "Paddock vendor signing key - ceremony record (contains NO secret; safe to file)\n"
        f"created_utc : {now}\n"
        f"algorithm   : Ed25519\n"
        f"public key  : {pub}\n"
        f"fingerprint : {fingerprint(pub)}\n"
        "self-test   : signed + verified a probe license\n"
        "private key : paddock-vendor.pem (PKCS#8, passphrase-encrypted); store offline, 2 copies, 2 custodians\n",
        encoding="utf-8",
    )
    print(f"private key : {priv_path}  (mode 0600, encrypted)")
    print(f"public key  : {pub_path}")
    print(f"record      : {rec_path}")
    print(f"fingerprint : {fingerprint(pub)}")
    print("\nNext: move the private key to offline storage, import ONLY the .pub to the release pipeline,"
          "\nand read the fingerprint back from the built artifact (`check`) before shipping.")
    return 0


# --------------------------------------------------------------------------- #
# embed / check
# --------------------------------------------------------------------------- #

def _embedded(source: str) -> tuple[str, list[str], re.Match[str]]:
    text = Path(source).read_text(encoding="utf-8")
    m = _ASSIGN.search(text)
    if not m:
        raise CeremonyError(f"{source}: could not find the VENDOR_PUBLIC_KEYS assignment")
    return text, re.findall(r'"([^"]+)"', m.group("body")), m


def _render(keys: list[str]) -> str:
    if not keys:
        return "VENDOR_PUBLIC_KEYS: tuple[str, ...] = ()"
    body = "".join(f'\n    "{k}",' for k in keys)
    return f"VENDOR_PUBLIC_KEYS: tuple[str, ...] = ({body}\n)"


def cmd_embed(a: argparse.Namespace) -> int:
    keys_in = [read_public_key(p) for p in a.public_key_file]
    text, current, m = _embedded(a.source)
    merged = list(dict.fromkeys([*keys_in, *([] if a.replace else current)]))  # new first, no dupes
    new_text = text[: m.start()] + _render(merged) + text[m.end():]
    if a.dry_run:
        print(_render(merged))
        return 0
    if _inside_repo(Path(a.source)) and not a.i_am_in_a_release_checkout:
        raise CeremonyError(
            "this edits a source file in the repository checkout. Run it in the release pipeline's "
            "throwaway checkout and pass --i-am-in-a-release-checkout; never commit the result"
        )
    Path(a.source).write_text(new_text, encoding="utf-8")
    for k in merged:
        print(f"embedded {fingerprint(k)}")
    return 0


def cmd_check(a: argparse.Namespace) -> int:
    _, current, _ = _embedded(a.source)
    want = [read_public_key(p) for p in a.public_key_file]
    missing = [k for k in want if k not in current]
    extra = [k for k in current if k not in want]
    for k in current:
        print(f"embedded: {fingerprint(k)}")
    if not want:
        return 0
    if missing or (extra and a.exact):
        for k in missing:
            print(f"MISSING : {fingerprint(k)}", file=sys.stderr)
        for k in extra if a.exact else []:
            print(f"UNEXPECTED: {fingerprint(k)}", file=sys.stderr)
        return 1
    print("ok: the build trusts the expected vendor key(s)")
    return 0


def cmd_fingerprint(a: argparse.Namespace) -> int:
    print(fingerprint(read_public_key(a.public_key_file)))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="create the vendor keypair (run OFFLINE)")
    g.add_argument("--out-dir", required=True, help="empty directory OUTSIDE the repository (e.g. an encrypted USB)")
    g.set_defaults(fn=cmd_generate)

    e = sub.add_parser("embed", help="write the PUBLIC key into licensing.VENDOR_PUBLIC_KEYS (release checkout only)")
    e.add_argument("--public-key-file", action="append", required=True, help="repeat to trust several keys (rotation)")
    e.add_argument("--source", default=str(ROOT / "orchestrator" / "app" / "licensing.py"))
    e.add_argument("--replace", action="store_true", help="drop keys already embedded instead of adding")
    e.add_argument("--dry-run", action="store_true")
    e.add_argument("--i-am-in-a-release-checkout", action="store_true")
    e.set_defaults(fn=cmd_embed)

    c = sub.add_parser("check", help="verify what a source file embeds")
    c.add_argument("--public-key-file", action="append", default=[])
    c.add_argument("--source", default=str(ROOT / "orchestrator" / "app" / "licensing.py"))
    c.add_argument("--exact", action="store_true", help="fail if any OTHER key is embedded too")
    c.set_defaults(fn=cmd_check)

    f = sub.add_parser("fingerprint", help="print a public key's fingerprint")
    f.add_argument("--public-key-file", required=True)
    f.set_defaults(fn=cmd_fingerprint)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
