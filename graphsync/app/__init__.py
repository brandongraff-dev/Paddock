"""palantir-asm graphsync service.

Mirrors the Postgres asset graph (assets, asset_edges, open findings) into
Neo4j and serves fast, read-only Cypher-powered graph queries: exploit-weighted
attack paths, blast radius, and neighborhood subgraphs.

This service only READS Postgres and only runs READ-only Cypher for its query
endpoints. It never exploits, probes, or mutates the source graph. If Neo4j is
unreachable the service stays up and degrades gracefully.
"""

__version__ = "0.1.0"
