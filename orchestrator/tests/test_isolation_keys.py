"""Natural keys must not collide across tenants (schema 036 regression guard)."""
from __future__ import annotations

from app import tenancy

from .test_isolation_sweep import TENANT_A, TENANT_B, _make_row, _relations

#: Natural keys that are deliberately GLOBAL even on tenant tables (the lookup
#: happens before any tenant is known, or the value is globally random).
GLOBAL_UNIQUE_OK = {
    "app_users": "usernames are globally unique (login resolves the tenant)",
    "api_keys": "random key prefix is the credential lookup handle",
    "identity_providers": "SSO slug is the unauthenticated login URL",
    "scim_tokens": "random token prefix/hash are the lookup handle",
    "sensors": "random credential prefix is the lookup handle",
    "sensor_enroll_tokens": "random token prefix is the lookup handle",
    "fleet_agents": "random token prefix is the lookup handle",
    "fleet_enroll_tokens": "random token prefix is the lookup handle",
    "integrations": "random inbound webhook token is the lookup handle",
    "msp_invites": "random invite token hash is the lookup handle",
    "trust_links": "random public token hash is the lookup handle",
    "sso_exchange_codes": "random one-time code hash",
    "sso_login_states": "random state hash",
    "scope_proofs": "keyed by the global scope_entries serial id (generator artefact: both tenants got id 1)",
    "ontology_objects": "keyed by globally unique backing ids (generator artefact)",
    "exposure_leads": "public lead capture, written by the platform tenant only",
    "sso_replay_cache": "assertion ids are globally unique by construction",
}


async def test_natural_keys_do_not_collide_across_tenants(db_pool):
    """Two tenants must be able to hold a row with the SAME natural key.

    A globally unique key (PK like ``id = 1``, ``UNIQUE(display_name)``, ``PK(day)``)
    makes the second tenant's insert fail or, with ``ON CONFLICT DO NOTHING``,
    silently vanish. Schema 036 fixed six such tables; this keeps it that way.
    """
    async with db_pool.acquire() as con:
        rels = await _relations(con)
    for slug, tid in (("sweep-a", TENANT_A), ("sweep-b", TENANT_B)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)
    tables = [r["relname"] for r in rels if r["relkind"] in ("r", "p") and r["has_tenant"]]
    collisions: dict[str, str] = {}
    checked = 0
    for table in tables:
        async with db_pool.acquire() as su:
            await su.execute("SET session_replication_role = replica")
            try:
                _, why_a = await _make_row(su, table, TENANT_A)
                if why_a:
                    continue
                checked += 1
                _, why_b = await _make_row(su, table, TENANT_B)
            finally:
                await su.execute("SET session_replication_role = DEFAULT")
        if why_b and why_b.startswith("UniqueViolationError") and table not in GLOBAL_UNIQUE_OK:
            collisions[table] = why_b
    assert checked >= 60
    assert not collisions, f"globally-unique natural keys on tenant tables: {collisions}"
