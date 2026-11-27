# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exceptions raised by Paddock Guard. Messages never carry file contents or secrets."""
from __future__ import annotations


class GuardError(Exception):
    """Base class: a runtime error Guard understands (exit code 2)."""


class ConfigError(GuardError):
    """A configuration file, root, ref or option is invalid or refused."""


class UsageError(GuardError):
    """The command line is wrong."""
