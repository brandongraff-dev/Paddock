"""MAC -> vendor resolution against the bundled OUI prefix table.

Purely offline: we look up the first 24 bits (the IEEE MA-L block) of a MAC
in a shipped JSON table. We never query the device or a remote OUI service.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib import resources
from typing import Any, Optional, TypedDict

_HEX_RE = re.compile(r"[0-9a-fA-F]")

# Locally-administered / multicast bit heuristics: a MAC with the
# locally-administered bit set has no meaningful OUI.
_LAA_SECOND_NIBBLE = {"2", "6", "a", "e", "A", "E"}


class OuiHit(TypedDict, total=False):
    vendor: str
    role: str
    type: str
    prefix: str


def normalize_mac(mac: str) -> Optional[str]:
    """Return a canonical ``aa:bb:cc:dd:ee:ff`` MAC, or None if not a MAC."""
    if not mac:
        return None
    hexd = "".join(_HEX_RE.findall(mac))
    if len(hexd) != 12:
        return None
    hexd = hexd.lower()
    return ":".join(hexd[i : i + 2] for i in range(0, 12, 2))


def oui_prefix(mac: str) -> Optional[str]:
    """Return the uppercase 6-hex-digit OUI prefix for a MAC, or None."""
    norm = normalize_mac(mac)
    if norm is None:
        return None
    return norm.replace(":", "")[:6].upper()


def is_locally_administered(mac: str) -> bool:
    """True when the MAC's locally-administered bit is set (randomized MAC)."""
    norm = normalize_mac(mac)
    if norm is None:
        return False
    return norm[1] in _LAA_SECOND_NIBBLE


@lru_cache(maxsize=1)
def _table() -> dict[str, Any]:
    raw = (
        resources.files("app.fingerprint.data")
        .joinpath("oui_prefixes.json")
        .read_text(encoding="utf-8")
    )
    data = json.loads(raw)
    return data.get("prefixes", {})


def lookup(mac: str) -> Optional[OuiHit]:
    """Resolve a MAC to a vendor hit, or None when unknown / randomized."""
    prefix = oui_prefix(mac)
    if prefix is None:
        return None
    entry = _table().get(prefix)
    if entry is None:
        return None
    hit: OuiHit = {"vendor": entry["vendor"], "prefix": prefix}
    if entry.get("role"):
        hit["role"] = entry["role"]
    if entry.get("type"):
        hit["type"] = entry["type"]
    return hit


def vendor_for(mac: str) -> Optional[str]:
    hit = lookup(mac)
    return hit.get("vendor") if hit else None
