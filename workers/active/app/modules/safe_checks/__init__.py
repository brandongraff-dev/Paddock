"""Safe verification checks: prove a finding is (still) real, without harm.

``resolve(finding)`` picks the check for a finding's rule; ``run(finding, env)``
executes it. See docs/VERIFICATION.md for the catalogue and the safety rules.
"""
from __future__ import annotations

from .base import (
    ALLOWED_METHODS,
    CheckEnv,
    CheckResult,
    FindingCtx,
    MethodRefused,
    SafeFetcher,
    ScopeDenied,
    Verdict,
    cap_evidence,
    redact_text,
)
from .registry import REGISTRY, SafeCheck, catalogue, resolve, run

__all__ = [
    "ALLOWED_METHODS", "CheckEnv", "CheckResult", "FindingCtx", "MethodRefused", "REGISTRY",
    "SafeCheck", "SafeFetcher", "ScopeDenied", "Verdict", "cap_evidence", "catalogue",
    "redact_text", "resolve", "run",
]
