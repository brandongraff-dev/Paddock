# SPDX-License-Identifier: Apache-2.0
"""paddock-verify: an independent verifier for Paddock containment attestations (spec v1).

This package depends on the standard library and ``cryptography`` only. The byte-level modules (strict JSON,
PCJ, base64, time, DSSE, Ed25519 pre-checks, Merkle, reason codes, wording) are import-light; the pipeline
entry points ``verify`` and ``verify_envelope`` are resolved lazily from ``paddock_verify.checks``.
"""
from __future__ import annotations

import importlib
from typing import Any

NAME = "paddock-verify"
__version__ = "0.1.0"
SPEC_VERSION = "1.0"

_LAZY = {"verify": "checks", "verify_envelope": "checks"}


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError("module %r has no attribute %r" % (__name__, name))
    return getattr(importlib.import_module("." + module, __name__), name)
