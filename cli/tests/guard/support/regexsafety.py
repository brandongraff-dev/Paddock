# SPDX-License-Identifier: AGPL-3.0-or-later
"""ReDoS probing for compiled patterns (used by test_regex_safety, contract 10 G0 build list).

For a pattern the probe derives a literal prefix and, for every repeated element, one concrete
character that the element matches (``re._parser`` output). It then builds
``prefix + pump * k + failing suffix`` for k and 2k and measures CPU time: doubling the input may
cost at most about 3.5x once the time is above a small floor, a bound that is linear in practice and
catches quadratic and exponential patterns. A wall-clock alarm turns a hang into a failure.
"""
from __future__ import annotations

import re
import signal
import time

try:
    from re import _constants as C
    from re import _parser as P
except ImportError:  # pragma: no cover
    import sre_constants as C  # type: ignore[no-redef]
    import sre_parse as P  # type: ignore[no-redef]

FLOOR_SECONDS = 0.004
RATIO_BOUND = 3.5
SIZES = (2000, 4000)
HANG_SECONDS = 4
GENERIC = (("a", 4000), ("=", 4000), ("{", 2000), ("ab", 2000), (" ", 4000))
_REPEATS = {C.MAX_REPEAT, C.MIN_REPEAT} | ({C.POSSESSIVE_REPEAT} if hasattr(C, "POSSESSIVE_REPEAT") else set())


class Hang(Exception):
    pass


def _one_char(op, av) -> str | None:
    """One concrete character an element can match."""
    if op == C.LITERAL:
        return chr(av)
    if op == C.NOT_LITERAL:
        return "a" if chr(av) != "a" else "b"
    if op == C.ANY:
        return "a"
    if op == C.IN:
        for iop, iav in av:
            if iop == C.LITERAL:
                return chr(iav)
            if iop == C.RANGE:
                return chr(iav[0])
            if iop == C.CATEGORY:
                s = str(iav)
                if "DIGIT" in s and "NOT" not in s:
                    return "0"
                if "SPACE" in s and "NOT" not in s:
                    return " "
                if "WORD" in s and "NOT" not in s:
                    return "a"
                return "a" if "NOT" in s else "a"
        return "a"
    if op == C.CATEGORY:
        s = str(av)
        if "DIGIT" in s and "NOT" not in s:
            return "0"
        if "SPACE" in s and "NOT" not in s:
            return " "
        return "a"
    if op == C.SUBPATTERN:
        return _first_char(av[-1])
    if op == C.BRANCH:
        for br in av[1]:
            c = _first_char(br)
            if c:
                return c
    return None


def _first_char(sub) -> str | None:
    for op, av in sub:
        c = _one_char(op, av)
        if c:
            return c
        if op in _REPEATS:
            return _first_char(av[2])
    return None


def _pumps(sub, acc: list[str]) -> None:
    for op, av in sub:
        if op in _REPEATS:
            c = _first_char(av[2])
            if c and c not in acc:
                acc.append(c)
            _pumps(av[2], acc)
        elif op == C.SUBPATTERN:
            _pumps(av[-1], acc)
        elif op == C.BRANCH:
            for br in av[1]:
                _pumps(br, acc)


def _prefix(sub) -> str:
    out = ""
    for op, av in sub:
        if op == C.LITERAL and len(out) < 40:
            out += chr(av)
        else:
            break
    return out


def inputs_for(rx: re.Pattern, adversarial=()) -> list[tuple[str, list[str]]]:
    """(label, [input at k, input at 2k]) pairs for one compiled pattern."""
    try:
        parsed = P.parse(rx.pattern, rx.flags & (re.I | re.M | re.S | re.X))
    except Exception:  # noqa: BLE001
        parsed = []
    prefix = _prefix(parsed)
    pumps: list[str] = []
    _pumps(parsed, pumps)
    pumps += [c for c in ("a", " ", "0", "=", "/", "-", "x") if c not in pumps]
    out: list[tuple[str, list[str]]] = []
    for pump in pumps[:10]:
        out.append(("pump %r" % pump, [prefix + pump * k + "\x00!" for k in SIZES]))
    anchored = bool(parsed) and any(op == C.AT and av in (C.AT_BEGINNING, C.AT_BEGINNING_STRING) for op, av in list(parsed)[:1])
    if not anchored:
        for unit, n in GENERIC:
            out.append(("generic %r*%d" % (unit, n), [unit * (n // 2) + "x", unit * n + "x"]))
        out.append(("spaces then x", [" " * 2000 + "x", " " * 4000 + "x"]))
    for sample in adversarial:
        out.append(("adversarial sample", [sample * 1, sample * 2]))
        out.append(("adversarial repeated", [sample * 20, sample * 40]))
    return out


def _alarm(signum, frame):  # pragma: no cover - timing dependent
    raise Hang()


def timed_search(rx: re.Pattern, text: str) -> float:
    use = hasattr(signal, "setitimer")
    if use:
        old = signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, HANG_SECONDS)
    t0 = time.process_time()
    try:
        rx.search(text)
    finally:
        dt = time.process_time() - t0
        if use:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old)
    return dt


def check_pattern(rx: re.Pattern, adversarial=()) -> list[str]:
    """Problems found for one pattern (empty when it grows linearly on every probe)."""
    problems: list[str] = []
    for label, pair in inputs_for(rx, adversarial):
        try:
            t1 = timed_search(rx, pair[0])
            t2 = timed_search(rx, pair[1])
        except Hang:
            problems.append("%s: no answer within %ds (%s)" % (rx.pattern[:60], HANG_SECONDS, label))
            return problems
        if t2 > FLOOR_SECONDS and t2 > RATIO_BOUND * max(t1, 1e-6):
            problems.append("%s: %s grew %.1fx when the input doubled (%.3fs to %.3fs)" % (rx.pattern[:60], label, t2 / max(t1, 1e-6), t1, t2))
    return problems
