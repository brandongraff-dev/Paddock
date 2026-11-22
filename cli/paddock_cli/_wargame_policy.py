"""Stdlib-only stand-in for ``app.engine.policy`` (the two names Wargame's ``safety.py`` imports).

The real module also loads YAML rules and validates SQL, so it needs yaml and pydantic. Wargame
only uses its narrative filter, which is one regex. ``tests/test_wargame_cli.py`` checks this copy
against the service source whenever a checkout is present, so the two cannot drift silently.
"""
from __future__ import annotations

import re


class UnsafeRuleError(ValueError):
    """Raised when narrative text describes exploitation steps rather than impact."""


_FORBIDDEN_NARRATIVE_TOKENS = re.compile(
    r"\b(curl\s+-|wget\s+http|bash\s+-c|/bin/sh|nc\s+-e|msfvenom|"
    r"python\s+-c\s+['\"]|powershell\s+-enc|0x[0-9a-f]{8,}|"
    r"reverse\s+shell|rev\s*shell|drop\s+table|union\s+select)\b",
    re.IGNORECASE,
)


def validate_narrative_text(text: str) -> None:
    """Refuse narrative text that reads like an exploitation guide."""
    if not text:
        return
    m = _FORBIDDEN_NARRATIVE_TOKENS.search(text)
    if m:
        raise UnsafeRuleError(
            f"narrative/impact contains disallowed token: {m.group(0)!r} "
            "(impact text must describe outcomes, not exploitation steps)")
