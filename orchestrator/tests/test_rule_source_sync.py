"""Guard against rule_source drift between the DB and the Python type.

`findings.rule_source` is constrained in two places that have drifted three
times (each a production 422):

  * the Postgres CHECK constraint (schema/003 + the ALTERs in 008/009/010/013)
  * ``app.constants.RULE_SOURCES`` (from which ``models.RuleSource`` is derived)

The database is the authority. This test reads the *live* CHECK constraint
from the freshly-applied schema and asserts its allowed set equals
``RULE_SOURCES``. If anyone extends the schema without updating the constant
(or vice versa), this fails loudly with the exact symmetric difference.
"""
from __future__ import annotations

import re

import pytest

from app.constants import RULE_SOURCES


async def _rule_source_check_values(conn) -> set[str]:
    """Return the set of values allowed by findings.rule_source's CHECK."""
    constraintdef = await conn.fetchval(
        """
        SELECT pg_get_constraintdef(c.oid)
          FROM pg_constraint c
          JOIN pg_class t ON t.oid = c.conrelid
         WHERE t.relname = 'findings'
           AND c.contype = 'c'
           AND pg_get_constraintdef(c.oid) ILIKE '%rule_source%'
         LIMIT 1
        """
    )
    assert constraintdef, "no CHECK constraint found on findings.rule_source"
    # Postgres normalises `IN (...)`/`= ANY (ARRAY[...])` to single-quoted
    # string literals; pull every quoted token out of the definition.
    return set(re.findall(r"'([^']*)'", constraintdef))


@pytest.mark.asyncio
async def test_rule_source_matches_db_check(db_pool):
    async with db_pool.acquire() as conn:
        db_values = await _rule_source_check_values(conn)

    code_values = set(RULE_SOURCES)

    missing_in_code = db_values - code_values
    missing_in_db = code_values - db_values
    assert db_values == code_values, (
        "rule_source drift between DB CHECK and app.constants.RULE_SOURCES — "
        f"in DB but not in code: {sorted(missing_in_code)}; "
        f"in code but not in DB: {sorted(missing_in_db)}"
    )


def test_rule_sources_has_no_duplicates():
    # The tuple is ordered to mirror the schema; a copy/paste dup would make
    # the set comparison above pass while the ordering lies.
    assert len(RULE_SOURCES) == len(set(RULE_SOURCES))
