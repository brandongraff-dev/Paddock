# SPDX-License-Identifier: Apache-2.0
"""Instants as integers (spec/01-conventions.md 2.6).

``YYYY-MM-DDTHH:MM:SSZ`` only, hand-parsed (``fromisoformat`` differs between Python versions) and calendar
validated: years 2000 to 9999, no ``:60`` leap second, no 30 February. Windows are end-exclusive.
"""
from __future__ import annotations

import re
from . import limits
from .jsonstrict import JsonError

CODE = "schema.time_format"
MIN_YEAR, MAX_YEAR = 2000, 9999

_T = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\Z", re.ASCII)
_DUR = re.compile(r"(0|[1-9][0-9]*)([smhd])\Z", re.ASCII)
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_MDAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


class TimeError(JsonError):
    """A timestamp or duration that does not follow the profile (code ``schema.time_format``)."""

    def __init__(self, message: str = "") -> None:
        super().__init__(CODE, message)


def _leap(y: int) -> bool:
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)


def _days_from_civil(y: int, m: int, d: int) -> int:
    y -= m <= 2
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(z: int):
    z += 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + (3 if mp < 10 else -9)
    return (y + (m <= 2), m, d)


def parse(text: str) -> int:
    """Seconds since the epoch for a strict timestamp."""
    if not isinstance(text, str):
        raise TimeError("a string is required")
    m = _T.match(text)
    if m is None:
        raise TimeError("not YYYY-MM-DDTHH:MM:SSZ")
    y, mo, d, h, mi, s = (int(g) for g in m.groups())
    if not MIN_YEAR <= y <= MAX_YEAR or not 1 <= mo <= 12:
        raise TimeError("year or month out of range")
    dim = _MDAYS[mo - 1] + (1 if mo == 2 and _leap(y) else 0)
    if not 1 <= d <= dim or h > 23 or mi > 59 or s > 59:
        raise TimeError("calendar value out of range")
    return _days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s


def format(epoch: int) -> str:  # noqa: A001 - the contract names this function ``format``
    """The strict timestamp for ``epoch`` seconds."""
    if isinstance(epoch, bool) or not isinstance(epoch, int):
        raise TimeError("an integer is required")
    lo = parse("%04d-01-01T00:00:00Z" % MIN_YEAR)
    hi = parse("%04d-12-31T23:59:59Z" % MAX_YEAR)
    if not lo <= epoch <= hi:
        raise TimeError("outside the supported years")
    days, rem = divmod(epoch, 86400)
    y, mo, d = _civil_from_days(days)
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (y, mo, d, rem // 3600, rem % 3600 // 60, rem % 60)


def parse_duration(text: str) -> int:
    """``<int>(s|m|h|d)`` as seconds."""
    if not isinstance(text, str):
        raise TimeError("a string is required")
    m = _DUR.match(text)
    if m is None:
        raise TimeError("a duration is <integer>(s|m|h|d)")
    seconds = int(m.group(1)) * _UNIT[m.group(2)]
    if seconds > limits.MAX_INT:
        raise TimeError("duration out of range")
    return seconds


def window_state(now: int, issued_at: int, valid_until: int, skew: int = limits.SKEW_SECONDS) -> str:
    """``expired`` when ``now >= valid_until``, ``not_yet_valid`` when ``now < issued_at - skew``, else ``ok``.

    End-exclusive: valid iff ``issued_at - skew <= now < valid_until``; expiry is judged first.
    """
    if now >= valid_until:
        return "expired"
    if now < issued_at - skew:
        return "not_yet_valid"
    return "ok"


def now_epoch() -> int:
    """The host clock in whole seconds (the verifier trusts its host clock; ``--now`` overrides it)."""
    import time
    return int(time.time())

