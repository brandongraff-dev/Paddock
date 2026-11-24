#!/usr/bin/env python3
"""Gather the files Paddock Setup embeds into its .exe (build.rs bundles ../resources).

    python3 installer/scripts/prepare_resources.py [--version 1.2.3]

Writes installer/resources/ with the same layout as the release zip:

    install.ps1                the installer script the wizard runs (stamped when --version is given)
    docker-compose.lite.yml
    .env.example
    schema/*
    VERSION                    "1.2.3" or "dev"; shown in the wizard header

Without --version the script is left unstamped and builds Paddock from source (a developer
build); a release passes the tag's version so Setup pulls the prebuilt images instead.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import make_release_bundle as bundle  # noqa: E402  (stamp(), VERSION_RE)

OUT = ROOT / "installer" / "resources"


def prepare(version: str | None, out: Path = OUT) -> list[str]:
    if version is not None and not bundle.VERSION_RE.match(version):
        raise SystemExit(f"--version must look like 1.2.3 (no leading v), got {version!r}")
    if out.exists():
        shutil.rmtree(out)
    (out / "schema").mkdir(parents=True)

    ps1 = (ROOT / "scripts" / "install.ps1").read_text()
    if not ps1.isascii():
        raise SystemExit("install.ps1 must be ASCII-only (Windows PowerShell 5.1 reads BOM-less files as ANSI)")
    if version:
        ps1 = bundle.stamp("install.ps1", ps1, version)
    # LF, as in the repo: PowerShell does not care and the file stays byte-identical to the release asset
    (out / "install.ps1").write_bytes(ps1.encode())

    # what the wizard shows as "setup <version>": the Paddock release it installs ("dev" = from source)
    (out / "VERSION").write_text((version or "dev") + "\n")

    shutil.copy2(ROOT / "docker-compose.lite.yml", out / "docker-compose.lite.yml")
    shutil.copy2(ROOT / ".env.example", out / ".env.example")
    for f in sorted((ROOT / "schema").rglob("*")):
        if f.is_file():
            dest = out / "schema" / f.relative_to(ROOT / "schema")
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)
    return sorted(str(p.relative_to(out)).replace("\\", "/") for p in out.rglob("*") if p.is_file())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", help="release version without the leading v; stamps install.ps1")
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args(argv)
    files = prepare(a.version, a.out)
    print(f"prepared {len(files)} files in {a.out}" + (f" (stamped {a.version})" if a.version else " (unstamped: builds from source)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
