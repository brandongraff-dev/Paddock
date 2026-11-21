"""palantir-asm ontology service.

Projects the raw ASM tables (assets, asset_edges, findings, attack_paths,
tickets, sbom_components, ...) into a typed object + link model so analysts
navigate Entities (Host, Service, Vulnerability, ...) and their relationships
instead of rows.

Read-only over the existing tables; writes only its own ``ontology_*`` tables.
This service does not probe, resolve, exploit, or reach the network. It is a
pure projection: deterministic, idempotent, keyed by provenance.
"""

__version__ = "0.1.0"
