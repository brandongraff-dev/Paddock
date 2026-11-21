"""palantir-asm remediation service.

An AUTO-REMEDIATION engine that PROPOSES pull requests fixing findings. Every
fix is constrained to an allowlisted change class, the diff is generated
DETERMINISTICALLY by code (never emitted by an LLM), and the whole pipeline is
hardened against prompt injection so a malicious finding/evidence string cannot
trick it into writing a bad patch.

Pull requests are PROPOSED, never auto-merged. A human always approves.

The guardrails ARE the feature. See app/gate.py, app/injection.py,
app/verify.py and app/generators.py.
"""

__version__ = "0.1.0"
