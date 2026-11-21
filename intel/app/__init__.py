"""palantir-asm intel service.

Pulls NVD / EPSS / KEV / OSV public feeds and matches CVEs against the
asset inventory held by the orchestrator. Data in, matches out; this
service does not probe, exploit, or fetch exploit code.
"""

__version__ = "0.1.0"
