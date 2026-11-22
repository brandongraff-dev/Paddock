"""Wargame safety guard.

Wargame is the most offensive-sounding feature in a deliberately
defensive product, so it carries its own guard on top of the engine-wide
rules. Two jobs:

1. **No exploit narrative.** Any free text that becomes a route narrative,
   a fix description, or a certificate claim is run through the same
   reject filter the chain/attack-path writers use
   (:func:`app.engine.policy.validate_narrative_text` plus the attack-path
   token list). Impact and fix only — never steps, payloads, or commands.

2. **No exploit action.** Replica verification may only run checks from the
   :class:`~app.engine.wargame.model.PreconditionKind` allowlist. Anything
   else — anything that would deliver a payload, execute code, or submit a
   credential — is refused here, in code, before a runner ever sees it.

This mirrors ``SECURITY.md`` §6 and ``CONTRIBUTING.md``: offensive
capability is excluded by construction, not by convention.
"""
from __future__ import annotations

from ..policy import UnsafeRuleError, validate_narrative_text
from .model import Precondition, PreconditionKind


class UnsafeWargameAction(ValueError):
    """Raised when Wargame is asked to do something outside the rules."""


# Mirror of ``attackpath._REJECT_TOKENS``. Kept here (rather than importing
# ``attackpath``) so this guard carries no database dependency and can be
# used anywhere, including pure unit tests. ``test_safety`` asserts this
# stays a superset of the attack-path list so the two can't drift apart.
_REJECT_TOKENS: tuple[str, ...] = (
    "exploit",
    "payload",
    "shell",
    "cmd",
    "reverse shell",
    "union select",
    "/bin/",
    "nc -e",
    "msfvenom",
    "powershell -enc",
)


def contains_unsafe_token(text: str) -> bool:
    """True if the text reads like exploitation guidance rather than impact.

    Same contract as ``app.engine.attackpath.contains_unsafe_token``: the
    local token list plus the policy module's narrative regex.
    """
    if not text:
        return False
    low = text.lower()
    if any(tok in low for tok in _REJECT_TOKENS):
        return True
    try:
        validate_narrative_text(text)
    except UnsafeRuleError:
        return True
    return False


# The only check kinds a replica run may perform. Keep in lock-step with
# PreconditionKind — a check kind not listed here cannot run.
_ALLOWED_PRECONDITION_KINDS: frozenset[PreconditionKind] = frozenset(
    {
        PreconditionKind.VERSION_IN_RANGE,
        PreconditionKind.FLAG_ENABLED,
        PreconditionKind.ENDPOINT_EXPOSED,
        PreconditionKind.CODE_REACHABLE,
        PreconditionKind.FILE_PRESENT,
        PreconditionKind.CONFIG_VALUE,
    }
)


def safe_text(text: str, fallback: str) -> str:
    """Return ``text`` only if it reads as impact/fix; else ``fallback``.

    Thin wrapper over the attack-path engine's filter so Wargame route and
    certificate text gets exactly the same treatment as existing
    narratives.
    """
    return fallback if contains_unsafe_token(text) else text


def assert_safe_text(text: str) -> None:
    """Raise if ``text`` reads like exploitation guidance."""
    if contains_unsafe_token(text):
        raise UnsafeWargameAction(
            "text reads like exploitation guidance; impact/fix wording only"
        )


def assert_precondition_allowed(pre: Precondition) -> None:
    """Raise unless ``pre`` is a safe, allowlisted precondition check.

    This is the line that keeps replica *verification* from becoming
    replica *exploitation*: only non-destructive existence/version/reach
    checks are permitted, and each must survive the narrative filter too.
    """
    if not isinstance(pre.kind, PreconditionKind):
        raise UnsafeWargameAction(f"unknown precondition kind: {pre.kind!r}")
    if pre.kind not in _ALLOWED_PRECONDITION_KINDS:
        raise UnsafeWargameAction(
            f"precondition kind {pre.kind.value!r} is not on the safe allowlist"
        )
    assert_safe_text(pre.description)


def assert_preconditions_allowed(preconditions: "list[Precondition]") -> None:
    for pre in preconditions:
        assert_precondition_allowed(pre)
