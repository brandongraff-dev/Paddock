"""Lockfile parsers (one module per ecosystem) + a filename dispatcher.

Every parser is a pure function ``parse(content) -> list[{ecosystem, name,
version, direct, depth, paths}]`` that treats its input as untrusted DATA:
it is loaded/parsed as text, never executed, and malformed input is skipped
rather than raised.
"""
from __future__ import annotations

from . import cargo, go, maven, npm, python, ruby
from .registry import (
    SUPPORTED_FILENAMES,
    basename,
    is_supported,
    parse_files,
    parse_one,
)

__all__ = [
    "cargo", "go", "maven", "npm", "python", "ruby",
    "SUPPORTED_FILENAMES", "basename", "is_supported", "parse_files", "parse_one",
]
