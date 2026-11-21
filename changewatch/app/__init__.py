"""changewatch: surface-change detection + alerting for palantir-asm.

This service gives the platform a memory. It periodically (and in response to
``stream:events``) diffs the asset/finding graph against a cursor, writes a
ledger of what changed to ``surface_changes``, and fires matching alert rules.

Safety invariant: changewatch probes NOTHING. Its only outbound traffic is a
POST to a user-configured alert webhook/slack target URL. It never touches a
scope target, never resolves a URL out of asset/change data, and handles no
credentials beyond the opaque ``alert_rules.target``.
"""

__version__ = "1.0.0"
