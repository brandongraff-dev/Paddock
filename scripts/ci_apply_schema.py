#!/usr/bin/env python3
"""Apply schema/*.sql, in filename order, to the CI test database.

The services' DB-backed suites expect TEST_DATABASE_URL to point at a
migrated database (brain's ask tests, mlrisk's model store, ...). CI's
Postgres service starts empty, so this runs once per job before pytest.

Deliberately minimal (asyncpg only), so a service job doesn't need the
orchestrator's dependencies. Production migrations go through the versioned
runner (python -m app.migrate) instead; this script is for throwaway test
databases only.

    python scripts/ci_apply_schema.py            # uses TEST_DATABASE_URL
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import asyncpg

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schema"


def _sql(path: Path) -> str:
    # Same workaround as orchestrator/tests/conftest.py::_schema_transform: the
    # old 003_findings.sql declares an unquoted `references` column, which
    # Postgres 16 rejects as a reserved word.
    return path.read_text().replace("  references    TEXT[]", '  "references"    TEXT[]')


async def main() -> int:
    dsn = os.environ.get("TEST_DATABASE_URL")
    if not dsn:
        print("TEST_DATABASE_URL is not set", file=sys.stderr)
        return 2
    con = await asyncpg.connect(dsn)
    try:
        if await con.fetchval("SELECT to_regclass('public.findings') IS NOT NULL"):
            print("schema already present; nothing to do")
            return 0
        files = sorted(SCHEMA_DIR.glob("*.sql"))
        for f in files:
            await con.execute(_sql(f))
        print(f"applied {len(files)} schema files")
    finally:
        await con.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
