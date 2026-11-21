"""Single source of truth for enumerations mirrored in the DB schema.

``RULE_SOURCES`` mirrors the Postgres CHECK constraint on
``findings.rule_source`` (declared in ``schema/003_findings.sql`` and extended
by the ALTERs in ``008/009/010/013``). The database is the authority; this
tuple is kept in lockstep with it, and ``tests/test_rule_source_sync.py``
reads the live constraint and fails loudly the moment the two drift apart.

Historically this list lived only as a hand-written ``Literal`` in
``models.py`` and silently fell behind the schema three separate times
(each a production 422). Keeping the one tuple here and deriving the pydantic
type from it removes that seam.
"""
from __future__ import annotations

# Order mirrors the schema's CHECK clause (003 base set, then the tier ALTERs
# in 008/009/010 and the threat-intel ALTER in 013).
RULE_SOURCES: tuple[str, ...] = (
    "nuclei",
    "cve_match",
    "policy",
    "chain",
    "secret_scan",
    "tls_check",
    "header_check",
    "exposed_file",
    "manual",
    "takeover",
    "tls_grade",
    "sca",
    "sast",
    "threat_intel",
)
