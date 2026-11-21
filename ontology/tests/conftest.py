"""Test fixtures.

Pure mapping/type tests need nothing. The DB-backed projection test needs a
reachable Postgres via ``TEST_DATABASE_URL`` and is skipped when it is unset,
mirroring the intel service's convention.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
import pytest_asyncio

from app.config import _normalize_dsn
from app.db import Database

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schema"

# Data tables we touch; truncated before and after each DB test for isolation.
_DATA_TABLES = [
    "ontology_links", "ontology_objects",
    "ontology_link_types", "ontology_object_types",
    "sbom_components", "sca_projects",
    "attack_paths", "tickets", "finding_chains", "findings",
    "asset_edges", "assets",
]


def _apply_references_fix(sql: str) -> str:
    # 003_findings.sql declares an unquoted `references` column; PG16 rejects
    # the reserved word. Quote it (same workaround the orchestrator tests use).
    return sql.replace("  references    TEXT[]", '  "references"    TEXT[]')


@pytest_asyncio.fixture
async def db():
    dsn = os.environ.get("TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("TEST_DATABASE_URL not set; skipping DB-backed projection test")
    database = Database(_normalize_dsn(dsn))
    await database.connect()
    async with database.acquire() as con:
        # Apply the full schema in order (later files depend on earlier ones),
        # but only to an empty database: the files are migrations, not
        # re-runnable scripts (036 rekeys tables that 020/021 seed with
        # ON CONFLICT (id)), and an already-migrated DB has everything.
        if await con.fetchval("SELECT to_regclass('public.ontology_objects') IS NULL"):
            for path in sorted(SCHEMA_DIR.glob("*.sql")):
                await con.execute(_apply_references_fix(path.read_text()))
        await con.execute("TRUNCATE " + ", ".join(_DATA_TABLES) + " CASCADE")
    try:
        yield database
    finally:
        try:
            async with database.acquire() as con:
                await con.execute("TRUNCATE " + ", ".join(_DATA_TABLES) + " CASCADE")
        finally:
            await database.close()
