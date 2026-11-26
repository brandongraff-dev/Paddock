# SPDX-License-Identifier: Apache-2.0
"""PCJ, the signed-JSON profile (spec/01-conventions.md 2.1): a strict subset of RFC 8785.

* ``loads(data)``      strict parse (jsonstrict) with the PCJ size and depth limits; returns plain values.
* ``dumps(value)``     the one canonical encoding; raises ``CanonError`` for anything PCJ cannot hold.
* ``roundtrip(data)``  ``loads`` then require ``dumps(value) == data``; this is what signed bytes must pass.

Every failure is a ``CanonError`` (a ``ValueError``; catch it before ``ValueError`` or it is relabelled) with a
stable ``code`` from codes.py.
"""
from __future__ import annotations

from typing import Any

from . import jsonstrict, limits
from .jsonstrict import JsonError

NOT_CANONICAL = "schema.payload_not_canonical"


class CanonError(JsonError):
    """Parse failure (an ``input.*`` code) or a document that is not canonical (``schema.payload_not_canonical``)."""


def loads(data: Any, *, max_depth: int = limits.MAX_PCJ_DEPTH) -> Any:
    try:
        return jsonstrict.parse(data, max_depth=max_depth, max_bytes=limits.MAX_PCJ_BYTES)
    except CanonError:
        raise
    except JsonError as e:
        raise CanonError(e.code, e.detail, e.pos) from None


def dumps(value: Any) -> bytes:
    """Encode ``value`` as PCJ. Producers call this and nothing else."""
    out = []
    _enc(value, 0, out)
    return "".join(out).encode("ascii")


def roundtrip(data: Any, *, max_depth: int = limits.MAX_PCJ_DEPTH) -> Any:
    value = loads(data, max_depth=max_depth)
    try:
        again = dumps(value)
    except CanonError as e:
        raise CanonError(NOT_CANONICAL, str(e)) from None
    if again != bytes(data):
        raise CanonError(NOT_CANONICAL, "re-encoding differs from the received bytes")
    return value


def _bad(msg: str) -> CanonError:
    return CanonError(NOT_CANONICAL, msg)


def _check_chars(s: str, what: str) -> None:
    for ch in s:
        o = ord(ch)
        if o < 0x20 or o > 0x7E or ch == '"' or ch == "\\":
            raise _bad("%s has a character outside printable ASCII or one of the two excluded ones" % what)


def _enc(v: Any, depth: int, out: list) -> None:
    if v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif v is None:
        raise _bad("null is not allowed")
    elif isinstance(v, int):
        if not 0 <= v <= limits.MAX_INT:
            raise _bad("integer outside 0..2^53-1")
        out.append(str(int(v)))
    elif isinstance(v, str):
        _check_chars(v, "a string")
        out.append('"' + v + '"')
    elif isinstance(v, list):
        if depth >= limits.MAX_PCJ_DEPTH:
            raise _bad("nesting deeper than %d" % limits.MAX_PCJ_DEPTH)
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _enc(x, depth + 1, out)
        out.append("]")
    elif isinstance(v, dict):
        if depth >= limits.MAX_PCJ_DEPTH:
            raise _bad("nesting deeper than %d" % limits.MAX_PCJ_DEPTH)
        for k in v:
            if not isinstance(k, str) or k == "":
                raise _bad("object keys are non-empty strings")
            _check_chars(k, "a key")
        out.append("{")
        for i, k in enumerate(sorted(v)):
            if i:
                out.append(",")
            out.append('"' + k + '":')
            _enc(v[k], depth + 1, out)
        out.append("}")
    else:
        raise _bad("type %s is not allowed" % type(v).__name__)
