"""Pure dpkg and rpm version comparison (contract 1.6.1).

``dpkg``: Debian Policy 5.6.12 / dpkg ``lib/dpkg/version.c`` (``parseversion`` + ``verrevcmp``).
``rpm``:  rpm ``lib/rpmvercmp.c`` (``rpmvercmp`` including ``~`` and ``^``) plus the ``E:V-R`` label order.

Every comparison returns -1, 0 or 1. Anything that is not a version raises :class:`VersionError`; a
caller turns that into UNKNOWN ``version_unparsable``, never into "patched". The parsers are
deliberately *stricter* than dpkg and rpm (ASCII only, a bounded length, an upstream part that starts
with a digit, a non-empty revision/release): refusing is always safe, accepting a shape the real tool
orders differently is not. Error messages never echo the offending text.
"""
from __future__ import annotations

import re
from typing import Callable

MAX_LEN = 256            # longest version string accepted
MAX_EPOCH_DIGITS = 9


class VersionError(ValueError):
    """The text is not a version this module will order."""


# ----------------------------------------------------------------------------------- shared
def _check(v: object, what: str) -> str:
    if type(v) is not str or not v or len(v) > MAX_LEN:
        raise VersionError("not a %s" % what)
    return v


def _split_epoch(v: str, allow_colon_after: bool) -> tuple[int, str]:
    if ":" not in v:
        return 0, v
    e, rest = v.split(":", 1)
    if not e.isascii() or not e.isdigit() or len(e) > MAX_EPOCH_DIGITS:
        raise VersionError("bad epoch")
    if not allow_colon_after and ":" in rest:
        raise VersionError("bad epoch")
    return int(e), rest


# ------------------------------------------------------------------------------------- dpkg
_DPKG_ALLOWED = re.compile(r"[A-Za-z0-9.+~:\-]+\Z")


def dpkg_parse(v: str) -> tuple[int, str, str]:
    """``[epoch:]upstream[-revision]`` -> ``(epoch, upstream, revision)``; the revision follows the LAST hyphen."""
    _check(v, "dpkg version")
    if not _DPKG_ALLOWED.match(v):
        raise VersionError("not a dpkg version")
    epoch, rest = _split_epoch(v, allow_colon_after=True)      # a colon after the epoch is upstream text
    if "-" in rest:
        up, rev = rest.rsplit("-", 1)
        if not rev:
            raise VersionError("empty revision")                # dpkg: "revision number is empty"
    else:
        up, rev = rest, ""
    if not up or not (up[0].isascii() and up[0].isdigit()):
        raise VersionError("upstream version must start with a digit")   # dpkg warns; we refuse
    return epoch, up, rev


def _order(c: str) -> int:
    if c == "" or (c.isascii() and c.isdigit()):
        return 0
    if c.isascii() and c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    na, nb = len(a), len(b)
    while i < na or j < nb:
        first_diff = 0
        while (i < na and not a[i].isdigit()) or (j < nb and not b[j].isdigit()):
            ac = _order(a[i] if i < na else "")
            bc = _order(b[j] if j < nb else "")
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < na and a[i] == "0":
            i += 1
        while j < nb and b[j] == "0":
            j += 1
        while i < na and j < nb and a[i].isdigit() and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < na and a[i].isdigit():
            return 1
        if j < nb and b[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def dpkg_cmp(a: str, b: str) -> int:
    ea, ua, ra = dpkg_parse(a)
    eb, ub, rb = dpkg_parse(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _verrevcmp(ua, ub)
    return c if c else _verrevcmp(ra, rb)


# -------------------------------------------------------------------------------------- rpm
def _isalnum(c: str) -> bool:
    return c.isascii() and c.isalnum()


def _isdigit(c: str) -> bool:
    return c.isascii() and c.isdigit()


def _isalpha(c: str) -> bool:
    return c.isascii() and c.isalpha()


def rpmvercmp(a: str, b: str) -> int:
    """rpm's segment comparison (``lib/rpmvercmp.c``)."""
    _check(a, "rpm version segment")
    _check(b, "rpm version segment")
    if a == b:
        return 0
    i = j = 0
    na, nb = len(a), len(b)
    while i < na or j < nb:
        while i < na and not _isalnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < nb and not _isalnum(b[j]) and b[j] not in "~^":
            j += 1
        ca = a[i] if i < na else ""
        cb = b[j] if j < nb else ""
        if ca == "~" or cb == "~":                       # "~" sorts before everything, even the end
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i += 1
            j += 1
            continue
        if ca == "^" or cb == "^":                       # "^" sorts after the end, before anything else
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (ca and cb):
            break
        s1, s2 = i, j
        if _isdigit(ca):
            while s1 < na and _isdigit(a[s1]):
                s1 += 1
            while s2 < nb and _isdigit(b[s2]):
                s2 += 1
            isnum = True
        else:
            while s1 < na and _isalpha(a[s1]):
                s1 += 1
            while s2 < nb and _isalpha(b[s2]):
                s2 += 1
            isnum = False
        if i == s1:
            return -1
        if j == s2:
            return 1 if isnum else -1                    # numeric segments are newer than alpha ones
        x, y = a[i:s1], b[j:s2]
        if isnum:
            x, y = x.lstrip("0"), y.lstrip("0")
            if len(x) != len(y):
                return 1 if len(x) > len(y) else -1
        if x != y:
            return -1 if x < y else 1
        i, j = s1, s2
    if i >= na and j >= nb:
        return 0
    return 1 if i < na else -1


_RPM_ALLOWED = re.compile(r"[A-Za-z0-9._+~^:\-]+\Z")


def rpm_parse(evr: str) -> tuple[int, str, str]:
    """``[epoch:]version-release`` -> ``(epoch, version, release)``; the release follows the LAST hyphen."""
    _check(evr, "rpm EVR")
    if not _RPM_ALLOWED.match(evr):
        raise VersionError("not an rpm EVR")
    epoch, rest = _split_epoch(evr, allow_colon_after=False)
    if "-" not in rest:
        raise VersionError("rpm EVR needs a release")
    v, r = rest.rsplit("-", 1)
    if not v or not r:
        raise VersionError("empty version or release")
    return epoch, v, r


def rpm_cmp(a: str, b: str) -> int:
    ea, va, ra = rpm_parse(a)
    eb, vb, rb = rpm_parse(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = rpmvercmp(va, vb)
    return c if c else rpmvercmp(ra, rb)


# ---------------------------------------------------------------------------------- helpers
def cmp_for(family: str) -> Callable[[str, str], int]:
    """The comparator for a package family: ``deb`` or ``rpm``."""
    if family == "deb":
        return dpkg_cmp
    if family == "rpm":
        return rpm_cmp
    raise ValueError("unknown package family")


_ESM = re.compile(r"[~+]esm\d*(?![A-Za-z])", re.I)
_MODULAR = re.compile(r"module[+_]el\d", re.I)


def is_esm_version(v: str) -> bool:
    """An Ubuntu Pro / ESM build tag (``~esm1``, ``+esm2``): its fixes are not in the public feed."""
    return type(v) is str and _ESM.search(v) is not None


def is_modular_evr(evr: str) -> bool:
    """An rpm built for a module stream (``1.module+el9.3.0+...``): not comparable across streams."""
    return type(evr) is str and _MODULAR.search(evr) is not None
