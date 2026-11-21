"""Duplicate-group lookups are batched per ingest batch (hardening: a 20k-result
SARIF used to run one full-asset scan per row)."""
from __future__ import annotations

import uuid

from app import lifecycle


class _Con:
    def __init__(self, canonical=None):
        self.calls = 0
        self.canonical = canonical

    async def fetchval(self, sql, *args):
        self.calls += 1
        return self.canonical


def _ident(keys, fp="f1", ak="repo:x"):
    return {"asset_key": ak, "vuln_keys": keys, "fingerprint": fp}


def _f():
    return {"id": uuid.uuid4(), "first_seen": None}


async def test_group_is_resolved_once_per_batch():
    con, cache = _Con(), {}
    first, second, third = _f(), _f(), _f()
    assert await lifecycle._duplicate_of_cached(con, first, _ident(["rule:sast:A"]), cache) is None
    assert await lifecycle._duplicate_of_cached(con, second, _ident(["rule:sast:A"]), cache) == first["id"]
    assert await lifecycle._duplicate_of_cached(con, third, _ident(["rule:sast:A"]), cache) == first["id"]
    assert con.calls == 1
    # the canonical row itself, seen again in the same batch, is not its own duplicate
    assert await lifecycle._duplicate_of_cached(con, first, _ident(["rule:sast:A"]), cache) is None
    # another group / another asset asks the database
    await lifecycle._duplicate_of_cached(con, _f(), _ident(["rule:sast:B"], fp="f2"), cache)
    await lifecycle._duplicate_of_cached(con, _f(), _ident(["rule:sast:A"], ak="repo:y"), cache)
    assert con.calls == 3


async def test_existing_canonical_in_db_is_reused_for_the_whole_group():
    old = uuid.uuid4()
    con, cache = _Con(canonical=old), {}
    assert await lifecycle._duplicate_of_cached(con, _f(), _ident(["rule:sast:A"]), cache) == old
    assert await lifecycle._duplicate_of_cached(con, _f(), _ident(["rule:sast:A"]), cache) == old
    assert con.calls == 1


async def test_multi_key_identities_always_ask_the_database():
    """Several CVEs can overlap across different fingerprints: never memoised."""
    con, cache = _Con(), {}
    for _ in range(3):
        await lifecycle._duplicate_of_cached(con, _f(), _ident(["cve:CVE-1", "cve:CVE-2"]), cache)
    assert con.calls == 3
