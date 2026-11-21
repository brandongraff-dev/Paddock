"""Supply-chain risk detectors (DEFENSIVE detection only).

Each detector finds where the OWNER is exposed to a supply-chain attack -- a
vulnerable, confusing, typosquatted, abandoned, malicious, yanked, or unpinned
dependency the owner already depends on. None of them constructs an attack,
crafts a package, or claims a name. See the package docstring in
``app/__init__.py`` for the hard invariant.
"""
from __future__ import annotations

from . import abandoned, confusion, malicious, pinning, typosquat

__all__ = ["abandoned", "confusion", "malicious", "pinning", "typosquat"]
