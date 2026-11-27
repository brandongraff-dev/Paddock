# SPDX-License-Identifier: AGPL-3.0-or-later
"""Parse the UNVERIFIED register (contract 7.9) for ``test_registry_invariants``."""
from __future__ import annotations

import re
from pathlib import Path

CONTRACT = Path(__file__).resolve().parents[4] / "docs" / "GUARD_CONTRACT.md"
_CHECK_ID = re.compile(r"PG-[A-Z]{3,4}-\d{3}")


def parse_register(text: str) -> dict[str, dict]:
    """``{id: {"status": "OPEN"|"CONFIRMED", "checks": {check ids}}}`` from the 7.9 table."""
    out: dict[str, dict] = {}
    in_section = False
    for line in text.splitlines():
        if line.startswith("### 7.9"):
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if not in_section or not line.startswith("| U-"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 6:
            continue
        uid, used_by, status = cells[0], cells[2], cells[3]
        out[uid] = {
            "status": "OPEN" if status.upper().startswith("OPEN") else "CONFIRMED",
            "checks": set(_CHECK_ID.findall(used_by)),
        }
    return out


def load_register() -> dict[str, dict] | None:
    if not CONTRACT.is_file():
        return None
    return parse_register(CONTRACT.read_text(encoding="utf-8"))
