"""paddock fleet host agent.

A small, opt-in agent that runs ON a host. It enrolls with the orchestrator with a one-time token and
its own Ed25519 key, reports a signed posture (docs/ASSURANCE_P2.md), and can apply HOST-LOCAL
defensive blocks -- but ONLY through the orchestrator's propose -> approve -> apply gate, dry-run by
default, reversible, and fully audited server-side.

The agent has NO offensive capability: it blocks inbound/outbound on its OWN machine and never scans,
probes, or acts on any other host.

Standard library only, Python >= 3.8 (the ``cryptography`` package is used for Ed25519 when it is
importable; otherwise a vendored pure-Python RFC 8032 signer produces byte-identical signatures).
"""
from __future__ import annotations

__version__ = "0.2.0"

ALLOWED_ACTIONS = frozenset(
    {"block_ip", "block_domain", "quarantine_file", "firewall_rule", "revert"}
)
