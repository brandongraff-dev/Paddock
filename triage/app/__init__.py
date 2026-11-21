"""triage: ownership routing + ticketing + SLA tracking for palantir-asm.

This service turns findings into accountable work. On a periodic pass (and in
response to ``finding_opened`` on ``stream:events``) it takes every open
finding at or above ``TRIAGE_MIN_SEVERITY`` that has no ticket yet, resolves
the owning team from the finding's asset via the ``asset_owners`` rule table,
looks up the severity's SLA from ``sla_policies``, and opens a ``tickets`` row
with an SLA clock. Each pass also sweeps for tickets past their ``sla_due`` and
marks them breached. ``ticket_opened`` / ``ticket_breached`` are published back
to ``stream:events``.

Safety invariant: triage probes NOTHING. Its only outbound traffic is a POST
of the ticket JSON to a user-configured ticket target URL (the owner rule's
contact when it is an http(s) URL, else ``TRIAGE_WEBHOOK_URL``). It never
contacts a scope target, never derives a URL from asset data, and makes no
other outbound request.
"""

__version__ = "1.0.0"
