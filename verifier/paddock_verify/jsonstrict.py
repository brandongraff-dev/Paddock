# SPDX-License-Identifier: Apache-2.0
"""A strict JSON reader (spec/01-conventions.md 2.1, step 0 of the verification procedure).

Stricter than RFC 8259 in exactly the ways a signature verifier needs:

* the input must be ASCII (a BOM or any byte >= 0x7F is ``input.not_ascii``);
* duplicate object keys are an error (also when they differ only by an escape: ``{"a":1,"\\u0061":2}``);
* numbers are plain non-negative integers up to 2**53 - 1; ``-0``, ``01``, ``+1``, ``1.0``, ``1e2``, ``NaN``
  and ``Infinity`` are ``input.number_invalid``;
* ``null`` is not a value of this profile (``input.not_json``);
* nesting depth and input size are limits checked while reading, never by catching ``RecursionError``;
* a lone surrogate escape is an error.

Whitespace between tokens and string escapes are *parsed* (unsigned files such as ``keys.json`` may be
pretty-printed); whether they are *canonical* is decided by ``canon.roundtrip`` for signed bytes.

The reader is an explicit-stack tokenizer: linear in the input size, no recursion.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from . import limits


class JsonError(ValueError):
    """The input is not acceptable. ``code`` is a stable reason code (codes.py), ``pos`` a byte offset."""

    def __init__(self, code: str, message: str = "", pos: Optional[int] = None) -> None:
        super().__init__("%s%s%s" % (code, (": " + message) if message else "", (" at byte %d" % pos) if pos is not None else ""))
        self.code = code
        self.detail = message
        self.pos = pos


_NON_ASCII = re.compile(b"[\x7f-\xff]")
_WS = re.compile(r"[ \t\n\r]*")
_NUMBER = re.compile(r"[-+0-9.eE]+")
_BARE = re.compile(r"[A-Za-z]+")
_STRCHUNK = re.compile(r'[^"\\\x00-\x1f]*')
_PLAIN_INT = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_HEX4 = re.compile(r"[0-9a-fA-F]{4}\Z")
_SIMPLE_ESC = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}

_OBJ, _ARR = 1, 2


def parse(data: Any, *, max_depth: int = limits.MAX_PCJ_DEPTH, max_bytes: Optional[int] = limits.MAX_PCJ_BYTES) -> Any:
    """Parse ``data`` (bytes) under the strict profile and return plain Python values.

    ``max_depth`` counts nested containers (``[[1]]`` has depth 2). The size and ASCII checks run first.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise JsonError("input.unreadable", "bytes required")
    data = bytes(data)
    if max_bytes is not None and len(data) > max_bytes:
        raise JsonError("input.too_large", "%d bytes (limit %d)" % (len(data), max_bytes))
    bad = _NON_ASCII.search(data)
    if bad is not None:
        raise JsonError("input.not_ascii", pos=bad.start())
    text = data.decode("ascii")
    n = len(text)
    pos = _skip(text, 0)
    if pos >= n:
        raise JsonError("input.not_json", "empty input", pos)

    stack = []    # entries: [kind, container, pending_key]
    result = None  # type: Any
    have_result = False
    # state machine: expecting a value
    while True:
        # ---- read one value at pos
        if pos >= n:
            raise JsonError("input.not_json", "unexpected end", pos)
        ch = text[pos]
        value = None  # type: Any
        is_container = False
        if ch == "{" or ch == "[":
            if len(stack) >= max_depth:
                raise JsonError("input.depth_exceeded", "more than %d levels" % max_depth, pos)
            if ch == "{":
                cont = {}  # type: Any
                stack.append([_OBJ, cont, None])
            else:
                cont = []
                stack.append([_ARR, cont, None])
            is_container = True
            pos = _skip(text, pos + 1)
            # empty container?
            if pos < n and text[pos] == ("}" if ch == "{" else "]"):
                value = stack.pop()[1]
                pos += 1
                is_container = False
            else:
                if ch == "{":
                    key, pos = _read_key(text, pos)
                    stack[-1][2] = key
                    pos = _skip(text, pos)
                    if pos >= n or text[pos] != ":":
                        raise JsonError("input.not_json", "expected ':'", pos)
                    pos = _skip(text, pos + 1)
                continue          # read the first element / first member value
        elif ch == '"':
            value, pos = _read_string(text, pos)
        elif ch == "t" and text.startswith("true", pos) and not _word_after(text, pos + 4):
            value, pos = True, pos + 4
        elif ch == "f" and text.startswith("false", pos) and not _word_after(text, pos + 5):
            value, pos = False, pos + 5
        elif ch in "-+0123456789.":
            m = _NUMBER.match(text, pos)
            tok = m.group(0)
            if not _PLAIN_INT.match(tok) or len(tok) > 16 or int(tok) > limits.MAX_INT:
                raise JsonError("input.number_invalid", pos=pos)
            value, pos = int(tok), m.end()
            if pos < n and (text[pos].isalnum() or text[pos] in "._+-"):
                raise JsonError("input.number_invalid", pos=pos)
        elif ch.isalpha():
            m = _BARE.match(text, pos)
            word = m.group(0)
            if word in ("NaN", "Infinity"):
                raise JsonError("input.number_invalid", word, pos)
            raise JsonError("input.not_json", "unexpected token", pos)
        else:
            raise JsonError("input.not_json", "unexpected character", pos)
        if is_container:
            continue
        # ---- a complete value: attach it, then close containers as far as the input allows
        while True:
            if not stack:
                result, have_result = value, True
                break
            kind, cont, key = stack[-1]
            if kind == _OBJ:
                if key in cont:
                    raise JsonError("input.duplicate_key", pos=pos)
                cont[key] = value
            else:
                cont.append(value)
            pos = _skip(text, pos)
            if pos >= n:
                raise JsonError("input.not_json", "unexpected end", pos)
            c = text[pos]
            if c == ",":
                pos = _skip(text, pos + 1)
                if kind == _OBJ:
                    key, pos = _read_key(text, pos)
                    stack[-1][2] = key
                    pos = _skip(text, pos)
                    if pos >= n or text[pos] != ":":
                        raise JsonError("input.not_json", "expected ':'", pos)
                    pos = _skip(text, pos + 1)
                break            # read the next value
            if c == ("}" if kind == _OBJ else "]"):
                stack.pop()
                value = cont
                pos += 1
                continue         # the closed container is itself a value of its parent
            raise JsonError("input.not_json", "expected ',' or closing bracket", pos)
        if have_result:
            break
    pos = _skip(text, pos)
    if pos != n:
        raise JsonError("input.not_json", "trailing data", pos)
    return result


def _skip(text: str, pos: int) -> int:
    return _WS.match(text, pos).end()


def _word_after(text: str, pos: int) -> bool:
    return pos < len(text) and (text[pos].isalnum() or text[pos] == "_")


def _read_key(text: str, pos: int):
    if pos >= len(text) or text[pos] != '"':
        raise JsonError("input.not_json", "expected a string key", pos)
    return _read_string(text, pos)


def _read_string(text: str, pos: int):
    """Read the string starting at the opening quote. Returns (value, position after the closing quote)."""
    start = pos
    pos += 1
    parts = []
    n = len(text)
    while True:
        m = _STRCHUNK.match(text, pos)
        parts.append(m.group(0))
        pos = m.end()
        if pos >= n:
            raise JsonError("input.not_json", "unterminated string", start)
        c = text[pos]
        if c == '"':
            return "".join(parts), pos + 1
        if c != "\\":
            raise JsonError("input.not_json", "control character in string", pos)
        pos += 1
        if pos >= n:
            raise JsonError("input.not_json", "unterminated string", start)
        e = text[pos]
        if e in _SIMPLE_ESC:
            parts.append(_SIMPLE_ESC[e])
            pos += 1
        elif e == "u":
            hexs = text[pos + 1:pos + 5]
            if not _HEX4.match(hexs):
                raise JsonError("input.not_json", "bad \\u escape", pos)
            cp = int(hexs, 16)
            pos += 5
            if 0xD800 <= cp <= 0xDBFF:
                if text[pos:pos + 2] == "\\u" and _HEX4.match(text[pos + 2:pos + 6]):
                    lo = int(text[pos + 2:pos + 6], 16)
                    if 0xDC00 <= lo <= 0xDFFF:
                        parts.append(chr(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)))
                        pos += 6
                        continue
                raise JsonError("input.not_json", "lone surrogate", pos)
            if 0xDC00 <= cp <= 0xDFFF:
                raise JsonError("input.not_json", "lone surrogate", pos)
            parts.append(chr(cp))
        else:
            raise JsonError("input.not_json", "bad escape", pos)
