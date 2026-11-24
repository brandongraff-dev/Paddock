#!/usr/bin/env python3
"""Build the release bundle for a Paddock version.

    python scripts/make_release_bundle.py --version 1.2.3 --out dist/

Writes into ``--out``:

  paddock-lite-1.2.3.zip    compose file, schema/, .env.example, install.bat,
                            install.ps1, install.sh and a short README.txt
  install.ps1, install.sh   the same installers stamped with the version, for
                            ``releases/latest/download/install.*`` one-liners
  BUNDLE_SHA256SUMS.txt     sha256 of the three files above

"Stamped" means the installer's ``STAMPED_VERSION`` line is filled in, which
switches it from "build from source" to "pull the prebuilt images for this
release". The zip is reproducible: fixed timestamps, sorted entries.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$")
ZIP_TIME = (2020, 1, 1, 0, 0, 0)   # fixed: the zip is reproducible

# (file, exact line to find, replacement template)
STAMPS = {
    "install.sh": ('STAMPED_VERSION=""', 'STAMPED_VERSION="{v}"'),
    "install.ps1": ("$StampedVersion = ''", "$StampedVersion = '{v}'"),
}


def stamp(name: str, text: str, version: str) -> str:
    old, new = STAMPS[name]
    if text.count(old) != 1:
        raise SystemExit(f"{name}: expected exactly one {old!r} line to stamp, found {text.count(old)}")
    return text.replace(old, new.format(v=version))


def crlf(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\n", "\r\n")


def build(version: str, out: Path) -> list[Path]:
    if not VERSION_RE.match(version):
        raise SystemExit(f"--version must look like 1.2.3 (no leading v), got {version!r}")
    out.mkdir(parents=True, exist_ok=True)

    sh = stamp("install.sh", (SCRIPTS / "install.sh").read_text(), version)
    ps1 = stamp("install.ps1", (SCRIPTS / "install.ps1").read_text(), version)
    bat = crlf((SCRIPTS / "install.bat").read_text())
    readme = crlf((SCRIPTS / "bundle" / "README.txt").read_text().replace("{{VERSION}}", version))
    if not ps1.isascii():
        raise SystemExit("install.ps1 must be ASCII-only (Windows PowerShell 5.1 reads BOM-less files as ANSI)")

    folder = f"paddock-lite-{version}"
    entries: dict[str, tuple[bytes, int]] = {
        "docker-compose.lite.yml": ((ROOT / "docker-compose.lite.yml").read_bytes(), 0o644),
        ".env.example": ((ROOT / ".env.example").read_bytes(), 0o644),
        "install.sh": (sh.encode(), 0o755),
        "install.ps1": (ps1.encode(), 0o644),
        "install.bat": (bat.encode(), 0o644),
        "README.txt": (readme.encode(), 0o644),
    }
    for f in sorted((ROOT / "schema").rglob("*")):
        if f.is_file():
            entries[f"schema/{f.relative_to(ROOT / 'schema').as_posix()}"] = (f.read_bytes(), 0o644)

    zpath = out / f"{folder}.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name in sorted(entries):
            data, mode = entries[name]
            zi = zipfile.ZipInfo(f"{folder}/{name}", ZIP_TIME)
            zi.external_attr = (0o100000 | mode) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, data)

    (out / "install.sh").write_text(sh)
    (out / "install.ps1").write_text(ps1)
    files = [zpath, out / "install.sh", out / "install.ps1"]
    sums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files)
    (out / "BUNDLE_SHA256SUMS.txt").write_text(sums)
    return files + [out / "BUNDLE_SHA256SUMS.txt"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", required=True, help="release version without the leading v, e.g. 1.2.3")
    ap.add_argument("--out", type=Path, default=ROOT / "dist")
    a = ap.parse_args(argv)
    for p in build(a.version, a.out):
        print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
