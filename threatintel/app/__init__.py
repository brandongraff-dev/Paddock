"""paddock threat-intel fusion service.

Ingests threat indicators (IOCs) from STIX 2.1 bundles and TAXII 2.1
collections, then matches them DEFENSIVELY against the owner's OWN assets
and findings: "is any of my attack surface a known-bad indicator, or does it
touch known threat infrastructure?".

SAFETY INVARIANT (enforced by tests/test_outbound_safety.py):
  * The ONLY outbound HTTP this service makes is to user-configured feed URLs
    (TAXII servers / STIX bundle URLs stored in `ti_feeds`, or a URL passed
    explicitly to POST /ingest/stix). It NEVER contacts an indicator's value
    (we never resolve, connect to, probe, scan, or exploit an IOC).
  * Matching is READ-ONLY over the owner's own tables (assets, findings).
  * Writes go to our own tables (ti_feeds / ti_indicators / ti_matches) and,
    for a matched asset, a `threat_intel` finding via the orchestrator API.
  * No scanning. No exploitation. Data in, matches out.
"""

__version__ = "0.1.0"
