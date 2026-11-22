#!/usr/bin/env python3
"""Copy shared/paddock_tenancy.py into each service as ``<svc>/app/tenancy.py``.

    python scripts/sync_tenancy_helper.py          # write the copies
    python scripts/sync_tenancy_helper.py --check  # exit 1 if any copy drifted
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "shared" / "paddock_tenancy.py"
TARGETS = [
    "intel", "correlation", "mlrisk", "triage", "ontology", "threatintel",
    "otdiscovery", "changewatch", "brain", "remediation", "sca", "codeanalysis",
    "graphsync", "wargame", "workers/passive", "workers/active",
]


def target_paths() -> list[Path]:
    return [ROOT / t / "app" / "tenancy.py" for t in TARGETS]


def main(argv: list[str]) -> int:
    check = "--check" in argv
    want = SRC.read_text()
    bad = 0
    for p in target_paths():
        have = p.read_text() if p.exists() else None
        if have == want:
            continue
        if check:
            print(f"DRIFT: {p.relative_to(ROOT)}")
            bad += 1
        else:
            p.write_text(want)
            print(f"wrote {p.relative_to(ROOT)}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
