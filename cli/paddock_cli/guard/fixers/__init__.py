# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fixer names only (contract 3.3, 4.0.6). G3 implements one module per name; no code here."""
from __future__ import annotations

FIXER_NAMES: tuple[str, ...] = (
    "gitignore_env",
    "strip_hidden_unicode",
    "workflow_permissions",
    "pin_from_lockfile",
    "secret_to_env",
)

BREAKING: frozenset[str] = frozenset({"pin_from_lockfile", "secret_to_env"})
