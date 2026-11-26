# SPDX-License-Identifier: Apache-2.0
"""Canonical standard base64 (spec/01-conventions.md 2.2).

Standard alphabet, padding required, no whitespace, no line breaks, and ``encode(decode(x)) == x`` (which
rejects non-zero trailing bits). The URL-safe alphabet and missing padding are errors.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Union

from .jsonstrict import JsonError

CODE = "schema.base64_invalid"


class B64Error(JsonError):
    """Not canonical standard base64 (code ``schema.base64_invalid``)."""

    def __init__(self, message: str = "") -> None:
        super().__init__(CODE, message)


_SHAPE = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z", re.ASCII)


def strict_decode(value: Union[str, bytes]) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("ascii")
        except UnicodeDecodeError:
            raise B64Error("not ASCII") from None
    if not isinstance(value, str):
        raise B64Error("a string is required")
    if len(value) % 4 != 0 or not _SHAPE.match(value):
        raise B64Error("not canonical standard base64")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError):
        raise B64Error("not canonical standard base64") from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise B64Error("non-zero trailing bits")
    return raw


def encode(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")
