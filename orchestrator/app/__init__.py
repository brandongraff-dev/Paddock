"""paddock orchestrator: HTTP API, scope service, job dispatcher.

Defensive ASM platform orchestrator. This package is intentionally scoped to
discovery, inventory and audit. It MUST NOT expose any endpoint, helper, or
hook that assists offensive operations (exploit launchers, credential testers,
stealth-scan modes). See docs/CONTRACTS.md "Do-not-build list".
"""
__version__ = "0.1.0"
