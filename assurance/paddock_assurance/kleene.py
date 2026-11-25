"""Kleene strong three-valued logic over ``True`` / ``False`` / ``None`` (``None`` is UNKNOWN).

The only place the truth tables live. ``all``: a False dominates, else an unknown, else True.
``any``: a True dominates, else an unknown, else False. ``not`` swaps True and False and leaves
UNKNOWN alone. The empty ``all`` is True and the empty ``any`` is False (the usual identities);
callers that must not accept an empty list reject it earlier.
"""
from __future__ import annotations

from typing import Iterable, Optional

Tri = Optional[bool]


def k_all(values: Iterable[Tri]) -> Tri:
    unknown = False
    for v in values:
        if v is False:
            return False
        if v is None:
            unknown = True
    return None if unknown else True


def k_any(values: Iterable[Tri]) -> Tri:
    unknown = False
    for v in values:
        if v is True:
            return True
        if v is None:
            unknown = True
    return None if unknown else False


def k_not(value: Tri) -> Tri:
    return None if value is None else (not value)
