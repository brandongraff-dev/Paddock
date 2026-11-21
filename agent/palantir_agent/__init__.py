"""palantir-asm fleet host agent.

A small, opt-in agent that runs ON a host. It enrolls with the orchestrator,
reports inventory, and can apply HOST-LOCAL defensive blocks -- but ONLY through
the orchestrator's propose -> approve -> apply gate, dry-run by default,
reversible, and fully audited server-side.

The agent has NO offensive capability: it blocks inbound/outbound on its OWN
machine and never scans, probes, or acts on any other host.
"""
from __future__ import annotations

__version__ = "0.1.0"

ALLOWED_ACTIONS = frozenset(
    {"block_ip", "block_domain", "quarantine_file", "firewall_rule", "revert"}
)
