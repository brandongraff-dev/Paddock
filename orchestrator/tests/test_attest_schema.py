"""P3.2: migrations 060 to 064 (docs/ASSURANCE_P3.md 5.8, 5.9).

Covers: the tables and their tenancy (099 adds tenant FK and RLS after 060-064), the one narrow public lookup policy
and the one global partial unique index, CHECK constraints, the immutability triggers (verified both as the schema
owner and as the non-superuser ``paddock_app``, which cannot disable triggers), idempotent re-application and
application on top of 039-042, and that no key material hides in any column outside the sealed-secrets table.
"""
from __future__ import annotations

import datetime as dt
import shutil
import uuid
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio

from app import migrate, tenancy

from .conftest import SCHEMA_DIR, _schema_transform

TA = "00000000-0000-0000-0000-0000000000a1"
TB = "00000000-0000-0000-0000-0000000000b1"
NEW_FILES = [
    "060_attest_keys.sql", "061_attest_publications.sql", "062_attest_statements.sql",
    "063_attest_targets.sql", "064_attest_immutability.sql",
]
ATTEST_TABLES = [
    "attest_estates", "attest_keys", "attest_key_secrets", "attest_revocations", "attest_domains",
    "attest_publications", "attest_statements", "attest_anchors", "attest_disclosures", "attest_bundle_objects",
    "attest_push_targets", "attest_push_jobs",
]
H1, H2 = "a" * 64, "b" * 64
KID1, KID2, KID3 = "1" * 32, "2" * 32, "3" * 32


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


@pytest_asyncio.fixture
async def tenants(db_pool):
    for slug, tid in (("sch-a", TA), ("sch-b", TB)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)


@pytest_asyncio.fixture(params=["owner", "app"])
async def pool(request, db_pool, app_pool):
    """Run the trigger and constraint tests as the schema owner and again as the non-superuser app role."""
    return db_pool if request.param == "owner" else app_pool


async def _exec(pool, tenant, sql, *args):
    with tenancy.tenant_context(tenant):
        async with pool.acquire() as con:
            return await con.execute(sql, *args)


async def _val(pool, tenant, sql, *args):
    with tenancy.tenant_context(tenant):
        async with pool.acquire() as con:
            return await con.fetchval(sql, *args)


async def _rejects(pool, tenant, sql, *args, exc=asyncpg.PostgresError):
    with pytest.raises(exc) as ei:
        await _exec(pool, tenant, sql, *args)
    return ei.value


async def _stmt(pool, tenant, pub, seq, *, age_days=0, kid=KID1):
    await _exec(
        pool, tenant,
        "INSERT INTO attest_statements (tenant_id, publication_id, seq, issued_at, kid, envelope) "
        "VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)",
        tenant, pub, seq, _now() - dt.timedelta(days=age_days), kid, b"{}",
    )


async def _key(pool, tenant, kid, *, usage="attest", status="pending", pub=b"\x01" * 32, **extra):
    await _exec(
        pool, tenant,
        "INSERT INTO attest_keys (tenant_id, kid, usage, status, public_key) VALUES ($1::uuid, $2, $3, $4, $5)",
        tenant, kid, usage, status, pub,
    )


# --------------------------------------------------------------------------- #
# Existence and tenancy (099 runs after 060-064 and adds tenant_id default, FK and RLS)
# --------------------------------------------------------------------------- #

async def test_migration_files_exist_and_are_in_the_reserved_range():
    names = sorted(p.name for p in SCHEMA_DIR.glob("06[0-4]_*.sql"))
    assert names == NEW_FILES
    # 065 to 069 are reserved (D30); P3.2 must not take them
    assert not list(SCHEMA_DIR.glob("06[5-9]_*.sql"))


async def test_every_attest_table_is_tenant_scoped_with_forced_rls_and_default(db_pool):
    async with db_pool.acquire() as con:
        for t in ATTEST_TABLES:
            row = await con.fetchrow(
                "SELECT c.relrowsecurity, c.relforcerowsecurity, "
                "(SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid AND p.polname = 'tenant_isolation') AS iso, "
                "(SELECT count(*) FROM pg_constraint k WHERE k.conrelid = c.oid AND k.conname = $2) AS fk, "
                "(SELECT pg_get_expr(d.adbin, d.adrelid) FROM pg_attrdef d JOIN pg_attribute a "
                "   ON a.attrelid = d.adrelid AND a.attnum = d.adnum WHERE d.adrelid = c.oid AND a.attname = 'tenant_id') AS dflt "
                "FROM pg_class c WHERE c.relname = $1 AND c.relnamespace = 'public'::regnamespace",
                t, f"{t}_tenant_fk",
            )
            assert row is not None, f"{t} missing"
            assert row["relrowsecurity"] and row["relforcerowsecurity"], t
            assert row["iso"] == 1 and row["fk"] == 1, t
            assert "paddock_current_tenant" in row["dflt"], t


async def test_tenant_isolation_between_two_tenants_on_every_table(db_pool, app_pool, tenants):
    """Tenant B sees none of tenant A's rows and cannot write into them (the generic sweep also covers this)."""
    pub = str(uuid.uuid4())
    await _exec(app_pool, TA, "INSERT INTO attest_estates (tenant_id, estate_id) VALUES ($1::uuid, $2)", TA, "e_" + "a" * 26)
    await _key(app_pool, TA, KID1)
    await _exec(app_pool, TA, "INSERT INTO attest_publications (tenant_id) VALUES ($1::uuid)", TA)
    await _stmt(app_pool, TA, pub, 1)
    for t in ("attest_estates", "attest_keys", "attest_publications", "attest_statements"):
        assert await _val(app_pool, TA, f"SELECT count(*) FROM {t}") == 1
        assert await _val(app_pool, TB, f"SELECT count(*) FROM {t}") == 0, t
    # B cannot insert a row that claims tenant A
    await _rejects(app_pool, TB, "INSERT INTO attest_keys (tenant_id, kid) VALUES ($1::uuid, $2)", TA, KID2,
                   exc=asyncpg.InsufficientPrivilegeError)


async def test_no_table_name_or_column_carries_key_material_outside_the_secrets_table(db_pool):
    """no_key_material_anywhere (schema half): the only places a secret can live are attest_key_secrets.sealed (AEAD
    blob) and attest_push_targets.secret_blob (a push credential, never returned by the API)."""
    async with db_pool.acquire() as con:
        rows = await con.fetch(
            "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public' "
            "AND table_name LIKE 'attest\\_%' "
            "AND column_name ~* '(private|seed|secret|sealed|passphrase|password|token|hmac|commit_key|kek)'"
        )
    found = {(r["table_name"], r["column_name"]) for r in rows}
    assert found == {("attest_key_secrets", "sealed"), ("attest_key_secrets", "kek_id"),
                     ("attest_push_targets", "secret_blob")}, found
    # attest_keys is what the API lists: nothing in it can hold a private key
    async with db_pool.acquire() as con:
        cols = {r["column_name"] for r in await con.fetch(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'attest_keys'")}
    assert {"kid", "public_key", "cert", "backend", "key_ref"} <= cols
    assert not {c for c in cols if "secret" in c or "seed" in c or "sealed" in c or "private" in c}


# --------------------------------------------------------------------------- #
# Constraints
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("sql,args", [
    ("INSERT INTO attest_estates (tenant_id, estate_id) VALUES ($1::uuid, $2)", (TA, "e_short")),
    ("INSERT INTO attest_estates (tenant_id, estate_id) VALUES ($1::uuid, $2)", (TA, "E_" + "a" * 26)),
    ("INSERT INTO attest_estates (tenant_id, estate_id) VALUES ($1::uuid, $2)", (TA, "e_" + "1" * 26)),  # 1 is not base32
    ("INSERT INTO attest_estates (tenant_id, ttl_h) VALUES ($1::uuid, 0)", (TA,)),
    ("INSERT INTO attest_estates (tenant_id, ttl_h) VALUES ($1::uuid, 73)", (TA,)),
    ("INSERT INTO attest_estates (tenant_id, hold_reason) VALUES ($1::uuid, $2)", (TA, "x" * 65)),
    ("INSERT INTO attest_keys (tenant_id, kid) VALUES ($1::uuid, $2)", (TA, "ABC")),
    ("INSERT INTO attest_keys (tenant_id, kid) VALUES ($1::uuid, $2)", (TA, "z" * 32)),
    ("INSERT INTO attest_keys (tenant_id, usage) VALUES ($1::uuid, $2)", (TA, "issue-cert")),
    ("INSERT INTO attest_keys (tenant_id, alg) VALUES ($1::uuid, $2)", (TA, "rsa")),
    ("INSERT INTO attest_keys (tenant_id, custody) VALUES ($1::uuid, $2)", (TA, "escrow")),
    ("INSERT INTO attest_keys (tenant_id, status) VALUES ($1::uuid, $2)", (TA, "paused")),
    ("INSERT INTO attest_keys (tenant_id, public_key) VALUES ($1::uuid, $2)", (TA, b"\x01" * 31)),
    ("INSERT INTO attest_key_secrets (tenant_id, kind) VALUES ($1::uuid, $2)", (TA, "disclosure")),
    ("INSERT INTO attest_revocations (tenant_id, reason_code) VALUES ($1::uuid, $2)", (TA, "oops")),
    ("INSERT INTO attest_domains (tenant_id, domain) VALUES ($1::uuid, $2)", (TA, "Example.com")),
    ("INSERT INTO attest_domains (tenant_id, domain) VALUES ($1::uuid, $2)", (TA, "nodots")),
    ("INSERT INTO attest_domains (tenant_id, domain) VALUES ($1::uuid, $2)", (TA, "-bad-.example.com")),
    ("INSERT INTO attest_domains (tenant_id, domain) VALUES ($1::uuid, $2)", (TA, "a b.example.com")),
    ("INSERT INTO attest_domains (tenant_id, domain_key) VALUES ($1::uuid, $2)", (TA, "xyz")),
    ("INSERT INTO attest_domains (tenant_id, binding_status) VALUES ($1::uuid, $2)", (TA, "maybe")),
    ("INSERT INTO attest_publications (tenant_id, subject_kind) VALUES ($1::uuid, $2)", (TA, "tenant")),
    ("INSERT INTO attest_publications (tenant_id, verdicts) VALUES ($1::uuid, $2)", (TA, "some")),
    ("INSERT INTO attest_publications (tenant_id, last_seq) VALUES ($1::uuid, -1)", (TA,)),
    ("INSERT INTO attest_publications (tenant_id, serving_reason) VALUES ($1::uuid, $2)", (TA, "x" * 65)),
    ("INSERT INTO attest_publications (tenant_id, subject_kind, domain) VALUES ($1::uuid, 'domain', '')", (TA,)),
    ("INSERT INTO attest_publications (tenant_id, subject_kind, domain) VALUES ($1::uuid, 'estate', 'example.com')", (TA,)),
    ("INSERT INTO attest_publications (tenant_id, domain_key) VALUES ($1::uuid, $2)", (TA, "nothex")),
    ("INSERT INTO attest_statements (tenant_id, seq) VALUES ($1::uuid, -1)", (TA,)),
    ("INSERT INTO attest_statements (tenant_id, envelope) VALUES ($1::uuid, $2)", (TA, b"x" * 524289)),
    ("INSERT INTO attest_bundle_objects (tenant_id, domain_key) VALUES ($1::uuid, $2)", (TA, "nothex")),
    ("INSERT INTO attest_bundle_objects (tenant_id, path) VALUES ($1::uuid, $2)", (TA, "p" * 129)),
    ("INSERT INTO attest_bundle_objects (tenant_id, body) VALUES ($1::uuid, $2)", (TA, b"x" * 524289)),
    ("INSERT INTO attest_push_targets (tenant_id, kind) VALUES ($1::uuid, $2)", (TA, "ftp")),
    ("INSERT INTO attest_push_jobs (tenant_id, state) VALUES ($1::uuid, $2)", (TA, "stuck")),
])
async def test_check_constraints_reject(pool, tenants, sql, args):
    err = await _rejects(pool, TA, sql, *args)
    assert isinstance(err, (asyncpg.CheckViolationError, asyncpg.StringDataRightTruncationError)), err


async def test_valid_rows_are_accepted(pool, tenants):
    pub = str(uuid.uuid4())
    await _exec(pool, TA, "INSERT INTO attest_estates (tenant_id, estate_id) VALUES ($1::uuid, $2)", TA, "e_" + "abcdefg234567" * 2)
    await _exec(pool, TA, "INSERT INTO attest_domains (tenant_id, domain, domain_key) VALUES ($1::uuid, 'sub.example.com', $2)", TA, H1)
    await _exec(pool, TA, "INSERT INTO attest_publications (tenant_id, subject_kind, domain, domain_key) "
                          "VALUES ($1::uuid, 'domain', 'sub.example.com', $2)", TA, H1)
    await _exec(pool, TA, "INSERT INTO attest_publications (tenant_id) VALUES ($1::uuid)", TA)
    await _stmt(pool, TA, pub, 1)
    await _key(pool, TA, KID1, pub=b"\x01" * 32)
    await _key(pool, TA, KID2, usage="anchor", pub=b"\x02" * 33)


async def test_tenant_id_is_part_of_every_unique(pool, tenants):
    """Two tenants may each hold the same natural key (the sweep proves it generically; this pins the schema rows)."""
    for tid in (TA, TB):
        await _key(pool, tid, KID1)
        await _exec(pool, tid, "INSERT INTO attest_domains (tenant_id, domain) VALUES ($1::uuid, 'example.com')", tid)
        await _exec(pool, tid, "INSERT INTO attest_revocations (tenant_id, kid) VALUES ($1::uuid, $2)", tid, KID1)
    await _rejects(pool, TA, "INSERT INTO attest_domains (tenant_id, domain) VALUES ($1::uuid, 'example.com')", TA,
                   exc=asyncpg.UniqueViolationError)
    await _rejects(pool, TA, "INSERT INTO attest_keys (tenant_id, kid) VALUES ($1::uuid, $2)", TA, KID1,
                   exc=asyncpg.UniqueViolationError)


async def test_one_estate_publication_and_unique_domain_publication_per_tenant(pool, tenants):
    await _exec(pool, TA, "INSERT INTO attest_publications (tenant_id) VALUES ($1::uuid)", TA)
    await _rejects(pool, TA, "INSERT INTO attest_publications (tenant_id) VALUES ($1::uuid)", TA, exc=asyncpg.UniqueViolationError)
    await _exec(pool, TB, "INSERT INTO attest_publications (tenant_id) VALUES ($1::uuid)", TB)


async def test_one_estate_row_per_tenant(pool, tenants):
    await _exec(pool, TA, "INSERT INTO attest_estates (tenant_id) VALUES ($1::uuid)", TA)
    await _rejects(pool, TA, "INSERT INTO attest_estates (tenant_id) VALUES ($1::uuid)", TA, exc=asyncpg.UniqueViolationError)


async def test_seq_is_unique_per_publication_so_a_fork_cannot_be_stored(pool, tenants):
    pub = str(uuid.uuid4())
    await _stmt(pool, TA, pub, 1)
    with pytest.raises(asyncpg.UniqueViolationError):
        await _stmt(pool, TA, pub, 1)
    await _stmt(pool, TA, str(uuid.uuid4()), 1)       # another publication may use seq 1


async def test_idempotency_key_is_unique_per_publication_when_present(pool, tenants):
    pub = str(uuid.uuid4())
    ins = ("INSERT INTO attest_statements (tenant_id, publication_id, seq, idempotency_key) "
           "VALUES ($1::uuid, $2::uuid, $3, $4)")
    await _exec(pool, TA, ins, TA, pub, 1, "k1")
    await _rejects(pool, TA, ins, TA, pub, 2, "k1", exc=asyncpg.UniqueViolationError)
    await _exec(pool, TA, ins, TA, pub, 2, None)
    await _exec(pool, TA, ins, TA, pub, 3, None)


async def test_at_most_one_active_estate_wide_key_per_usage(pool, tenants):
    await _key(pool, TA, KID1, status="active")
    await _rejects(pool, TA, "INSERT INTO attest_keys (tenant_id, kid, status) VALUES ($1::uuid, $2, 'active')", TA, KID2,
                   exc=asyncpg.UniqueViolationError)
    await _key(pool, TA, KID2, usage="anchor", status="active")           # another usage is fine
    await _key(pool, TA, KID3, status="pending")                          # not active is fine
    await _key(pool, TB, KID1, status="active")                           # another tenant is fine


# --------------------------------------------------------------------------- #
# Immutability triggers (064)
# --------------------------------------------------------------------------- #

async def test_statements_can_never_be_updated(pool, tenants):
    pub = str(uuid.uuid4())
    await _stmt(pool, TA, pub, 1)
    for sql in ("UPDATE attest_statements SET envelope = '\\x7b7d'::bytea", "UPDATE attest_statements SET seq = seq",
                "UPDATE attest_statements SET summary = '{}'::jsonb", "UPDATE attest_statements SET kid = 'x'"):
        err = await _rejects(pool, TA, sql)
        assert "immutable" in str(err).lower() or "append-only" in str(err).lower(), err


async def test_statement_delete_needs_age_over_90_days_and_not_the_head(pool, tenants):
    pub = str(uuid.uuid4())
    await _stmt(pool, TA, pub, 1, age_days=200)
    await _stmt(pool, TA, pub, 2, age_days=150)
    await _stmt(pool, TA, pub, 3, age_days=120)
    await _stmt(pool, TA, pub, 4, age_days=0)         # recent and not the head: must stay (age rule)
    await _stmt(pool, TA, pub, 5, age_days=89)        # the head (newest seq) and under 90 days: must stay
    await _rejects(pool, TA, "DELETE FROM attest_statements WHERE seq = 4")
    await _rejects(pool, TA, "DELETE FROM attest_statements WHERE seq = 5")
    await _rejects(pool, TA, "DELETE FROM attest_statements WHERE seq IN (1, 4)")     # one bad row aborts the statement
    assert await _val(pool, TA, "SELECT count(*) FROM attest_statements") == 5
    for seq in (1, 2, 3):                             # old and not the head: may go
        assert await _exec(pool, TA, "DELETE FROM attest_statements WHERE seq = $1", seq) == "DELETE 1"
    assert await _val(pool, TA, "SELECT array_agg(seq ORDER BY seq) FROM attest_statements") == [4, 5]


async def test_an_old_row_that_is_the_head_cannot_be_deleted_while_an_older_one_can(pool, tenants):
    pub = str(uuid.uuid4())
    await _stmt(pool, TA, pub, 1, age_days=400)
    await _stmt(pool, TA, pub, 2, age_days=300)
    await _rejects(pool, TA, "DELETE FROM attest_statements WHERE seq = 2")           # head, though 300 days old
    assert await _exec(pool, TA, "DELETE FROM attest_statements WHERE seq = 1") == "DELETE 1"


async def test_the_only_statement_of_a_publication_is_the_head_even_when_ancient(pool, tenants):
    pub = str(uuid.uuid4())
    await _stmt(pool, TA, pub, 1, age_days=1000)
    await _rejects(pool, TA, "DELETE FROM attest_statements")
    assert await _val(pool, TA, "SELECT count(*) FROM attest_statements") == 1


async def test_head_is_per_publication_and_per_tenant(pool, tenants):
    p1, p2 = str(uuid.uuid4()), str(uuid.uuid4())
    await _stmt(pool, TA, p1, 1, age_days=200)
    await _stmt(pool, TA, p2, 1, age_days=200)
    await _stmt(pool, TA, p2, 2, age_days=0)
    # p1 seq 1 is its publication's head even though p2 has newer rows
    await _rejects(pool, TA, "DELETE FROM attest_statements WHERE publication_id = $1::uuid", p1)
    assert await _exec(pool, TA, "DELETE FROM attest_statements WHERE publication_id = $1::uuid AND seq = 1", p2) == "DELETE 1"
    # the same publication id under another tenant does not make A's row a non-head
    await _stmt(pool, TB, p1, 2, age_days=0)
    await _rejects(pool, TA, "DELETE FROM attest_statements WHERE publication_id = $1::uuid", p1)


async def test_revocations_are_append_only(pool, tenants):
    await _exec(pool, TA, "INSERT INTO attest_revocations (tenant_id, kid, reason_code) VALUES ($1::uuid, $2, 'superseded')", TA, KID1)
    await _rejects(pool, TA, "UPDATE attest_revocations SET reason_code = 'cessation'")
    await _rejects(pool, TA, "UPDATE attest_revocations SET justification = 'x'")
    await _rejects(pool, TA, "DELETE FROM attest_revocations")
    assert await _val(pool, TA, "SELECT reason_code FROM attest_revocations") == "superseded"


async def test_keys_are_never_deleted(pool, tenants):
    await _key(pool, TA, KID1, status="retired")
    await _rejects(pool, TA, "DELETE FROM attest_keys")
    assert await _val(pool, TA, "SELECT count(*) FROM attest_keys") == 1


@pytest.mark.parametrize("col,val", [
    ("kid", KID2), ("public_key", b"\x09" * 32), ("alg", "ecdsa-p256-sha256"), ("usage", "anchor"),
    ("custody", "byok-kms"), ("backend", "aws-kms"), ("key_ref", "arn:aws:kms:x"),
])
async def test_key_identity_columns_are_frozen(pool, tenants, col, val):
    await _key(pool, TA, KID1, status="active")
    err = await _rejects(pool, TA, f"UPDATE attest_keys SET {col} = $1", val)
    assert "immutable" in str(err).lower() or "frozen" in str(err).lower(), err


async def test_key_tenant_cannot_be_moved(db_pool, tenants):
    await _key(db_pool, TA, KID1)
    await _rejects(db_pool, TA, "UPDATE attest_keys SET tenant_id = $1::uuid", TB)


async def test_key_operational_columns_may_change(pool, tenants):
    await _key(pool, TA, KID1, status="pending")
    now = _now()
    await _exec(pool, TA, "UPDATE attest_keys SET cert = '{\"a\":1}'::jsonb, cert_serial = 3, cert_expires_at = $1, "
                          "not_before = $1, not_after = $1, created_by = 'x'", now)
    await _exec(pool, TA, "UPDATE attest_keys SET status = 'active', activated_at = $1", now)
    assert await _val(pool, TA, "SELECT cert_serial FROM attest_keys") == 3


ORDER = ["pending", "active", "retiring", "retired"]


@pytest.mark.parametrize("old", ["pending", "active", "retiring", "retired", "revoked"])
@pytest.mark.parametrize("new", ["pending", "active", "retiring", "retired", "revoked"])
async def test_key_status_moves_only_forward_and_revoked_is_terminal(pool, tenants, old, new):
    await _key(pool, TA, KID1, status=old)
    if old == "revoked":
        ok = new == "revoked"
    elif new == "revoked":
        ok = True
    else:
        ok = ORDER.index(new) >= ORDER.index(old)
    if ok:
        await _exec(pool, TA, "UPDATE attest_keys SET status = $1", new)
        assert await _val(pool, TA, "SELECT status FROM attest_keys") == new
    else:
        err = await _rejects(pool, TA, "UPDATE attest_keys SET status = $1", new)
        assert "status" in str(err).lower(), err
        assert await _val(pool, TA, "SELECT status FROM attest_keys") == old


# --------------------------------------------------------------------------- #
# Public lookup policy and the one global unique index
# --------------------------------------------------------------------------- #

async def _seed_objects(db_pool):
    async with db_pool.acquire() as con:
        await con.execute("SET session_replication_role = replica")
        for tid, dk, path, public, body in (
            (TA, H1, "latest.json", True, b"A-latest"), (TA, H1, "private.json", False, b"A-private"),
            (TA, H2, "latest.json", True, b"A-other-domain"), (TB, "c" * 64, "latest.json", True, b"B-latest"),
        ):
            await con.execute(
                "INSERT INTO attest_bundle_objects (tenant_id, publication_id, domain_key, path, public, body) "
                "VALUES ($1::uuid, gen_random_uuid(), $2, $3, $4, $5)", tid, dk, path, public, body)
        await con.execute("SET session_replication_role = DEFAULT")


async def _lookup(app_pool, domain, *, lookup="on", sql="SELECT body FROM attest_bundle_objects ORDER BY body"):
    async with app_pool.acquire() as con:          # no tenant context: the public route has no tenant
        async with con.transaction():
            await con.execute("SELECT set_config('app.attest_lookup', $1, true), set_config('app.attest_domain', $2, true)",
                              lookup, domain)
            return [r["body"] for r in await con.fetch(sql)]


async def test_public_lookup_is_exact_match_and_public_only(db_pool, app_pool, tenants):
    await _seed_objects(db_pool)
    assert await _lookup(app_pool, H1) == [b"A-latest"]                       # not private.json, not other domains
    assert await _lookup(app_pool, H2) == [b"A-other-domain"]
    assert await _lookup(app_pool, "c" * 64) == [b"B-latest"]                 # cross-tenant by design: one route, no tenant
    for dom in ("d" * 64, "", H1.upper(), H1[:-1], H1 + "a"):
        assert await _lookup(app_pool, dom) == [], dom
    assert await _lookup(app_pool, H1, lookup="off") == []
    assert await _lookup(app_pool, H1, lookup="ON") == []
    assert await _lookup(app_pool, H1, lookup="") == []


async def test_a_public_row_with_an_empty_domain_key_is_never_reachable(db_pool, app_pool, tenants):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO attest_bundle_objects (tenant_id, publication_id, domain_key, path, public, body) "
            "VALUES ($1::uuid, gen_random_uuid(), '', 'latest.json', true, 'x')", TA)
    assert await _lookup(app_pool, "") == []


async def test_public_lookup_is_off_without_the_settings(db_pool, app_pool, tenants):
    await _seed_objects(db_pool)
    async with app_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM attest_bundle_objects") == 0
        async with con.transaction():
            await con.execute("SELECT set_config('app.attest_lookup', 'on', true)")           # no domain
            assert await con.fetchval("SELECT count(*) FROM attest_bundle_objects") == 0
        async with con.transaction():
            await con.execute("SELECT set_config('app.attest_domain', $1, true)", H1)         # no lookup flag
            assert await con.fetchval("SELECT count(*) FROM attest_bundle_objects") == 0


async def test_public_lookup_cannot_write_or_read_other_tables(db_pool, app_pool, tenants):
    await _seed_objects(db_pool)
    async with app_pool.acquire() as con:
        async with con.transaction():
            await con.execute("SELECT set_config('app.attest_lookup', 'on', true), set_config('app.attest_domain', $1, true)", H1)
            assert await con.execute("UPDATE attest_bundle_objects SET body = '\\x00'::bytea") == "UPDATE 0"
            assert await con.execute("DELETE FROM attest_bundle_objects") == "DELETE 0"
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                async with con.transaction():
                    await con.execute("INSERT INTO attest_bundle_objects (tenant_id, domain_key, path, public) "
                                      "VALUES ($1::uuid, $2, 'x', true)", TA, H1)
            for t in ("attest_statements", "attest_keys", "attest_estates", "attest_publications", "attest_key_secrets",
                      "attest_domains", "attest_disclosures"):
                assert await con.fetchval(f"SELECT count(*) FROM {t}") == 0, t
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM attest_bundle_objects") == 4


async def test_the_lookup_policy_is_select_only_with_no_check_expression(db_pool):
    async with db_pool.acquire() as con:
        pol = await con.fetchrow(
            "SELECT polcmd::text AS polcmd, pg_get_expr(polqual, polrelid) AS qual, polwithcheck IS NULL AS no_chk "
            "FROM pg_policy WHERE polname = 'attest_public_lookup' AND polrelid = 'attest_bundle_objects'::regclass")
        others = await con.fetch(
            "SELECT p.polname, p.polcmd::text FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid "
            "WHERE c.relname LIKE 'attest\\_%' AND p.polname <> 'tenant_isolation'")
    assert pol["polcmd"] == "r" and pol["no_chk"]
    assert "app.attest_lookup" in pol["qual"] and "app.attest_domain" in pol["qual"] and "public" in pol["qual"]
    assert [(r["polname"]) for r in others] == ["attest_public_lookup"]


async def test_the_global_partial_unique_index_covers_public_rows_only(pool, tenants):
    ins = ("INSERT INTO attest_bundle_objects (tenant_id, publication_id, domain_key, path, public) "
           "VALUES ($1::uuid, gen_random_uuid(), $2, 'latest.json', $3)")
    await _exec(pool, TA, ins, TA, H1, False)
    await _exec(pool, TA, ins, TA, H1, False)                       # private duplicates are fine
    await _exec(pool, TA, ins, TA, H1, True)
    err = await _rejects(pool, TA, ins, TA, H1, True, exc=asyncpg.UniqueViolationError)
    assert "uq_attest_public_object" in str(err)


async def test_two_tenants_cannot_both_publish_the_same_domain_key_and_path(db_pool, tenants):
    ins = ("INSERT INTO attest_bundle_objects (tenant_id, publication_id, domain_key, path, public) "
           "VALUES ($1::uuid, gen_random_uuid(), $2, 'latest.json', true)")
    await _exec(db_pool, TA, ins, TA, H1)
    await _rejects(db_pool, TB, ins, TB, H1, exc=asyncpg.UniqueViolationError)


# --------------------------------------------------------------------------- #
# Applying and re-applying the migrations
# --------------------------------------------------------------------------- #

async def _snapshot(con):
    return {
        "tables": [r["relname"] for r in await con.fetch(
            "SELECT relname FROM pg_class WHERE relname LIKE 'attest\\_%' AND relkind = 'r' ORDER BY 1")],
        "indexes": [r["indexname"] for r in await con.fetch(
            "SELECT indexname FROM pg_indexes WHERE tablename LIKE 'attest\\_%' ORDER BY 1")],
        "policies": [f"{r['tablename']}.{r['policyname']}" for r in await con.fetch(
            "SELECT tablename, policyname FROM pg_policies WHERE tablename LIKE 'attest\\_%' ORDER BY 1, 2")],
        "triggers": [f"{r['relname']}.{r['tgname']}" for r in await con.fetch(
            "SELECT c.relname, t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
            "WHERE c.relname LIKE 'attest\\_%' AND NOT t.tgisinternal ORDER BY 1, 2")],
        "constraints": [f"{r['relname']}.{r['conname']}" for r in await con.fetch(
            "SELECT c.relname, k.conname FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid "
            "WHERE c.relname LIKE 'attest\\_%' ORDER BY 1, 2")],
    }


async def test_reapplying_060_to_064_and_099_is_idempotent(db_pool):
    async with db_pool.acquire() as con:
        before = await _snapshot(con)
        for name in NEW_FILES + ["099_tenancy.sql"]:
            sql = (SCHEMA_DIR / name).read_text()
            await con.execute(sql)
            await con.execute(sql)
        after = await _snapshot(con)
    assert before == after
    assert before["tables"] == sorted(ATTEST_TABLES)
    assert before["triggers"] == ["attest_keys.trg_attest_keys_guard", "attest_revocations.trg_attest_revocations_guard",
                                  "attest_statements.trg_attest_statements_guard"]


@pytest_asyncio.fixture
async def empty_db(postgresql_my_proc):
    p = postgresql_my_proc
    auth = f"{p.user}:{p.password}" if p.password else p.user
    base = f"postgresql://{auth}@{p.host}:{p.port}"
    name = f"p3_P3_2_mig_{uuid.uuid4().hex[:10]}"
    admin = await asyncpg.connect(f"{base}/postgres")
    await admin.execute(f'CREATE DATABASE "{name}"')
    await admin.close()
    try:
        yield f"{base}/{name}"
    finally:
        admin = await asyncpg.connect(f"{base}/postgres")
        await admin.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                            "WHERE datname = $1 AND pid <> pg_backend_pid()", name)
        await admin.execute(f'DROP DATABASE "{name}"')
        await admin.close()


async def _up(dsn, d):
    con = await asyncpg.connect(dsn)
    try:
        return await migrate.migrate_up(con, schema_dir=d, transform=_schema_transform)
    finally:
        await con.close()


async def test_060_to_064_apply_on_top_of_039_to_042_and_099_reasserts_tenancy(empty_db, tmp_path):
    """The migrations apply on a database that only has the files up to 042 (044 to 059 belong to P2.1 and may not be
    present), and 099 re-run afterwards gives every new table its tenant_id default, FK and RLS."""
    d = tmp_path / "schema"
    shutil.copytree(SCHEMA_DIR, d)
    for name in NEW_FILES:
        (d / name).rename(tmp_path / name)
    first = await _up(empty_db, d)
    assert "042_agent_v2_hardening.sql" in first.applied and not any(n in first.applied for n in NEW_FILES)
    for name in NEW_FILES:
        shutil.copy(tmp_path / name, d / name)
    second = await _up(empty_db, d)
    assert second.applied == NEW_FILES
    assert second.reasserted == [migrate.TENANCY_FILE]
    con = await asyncpg.connect(empty_db)
    try:
        snap = await _snapshot(con)
        assert snap["tables"] == sorted(ATTEST_TABLES)
        forced = await con.fetchval(
            "SELECT count(*) FROM pg_class WHERE relname LIKE 'attest\\_%' AND relkind = 'r' AND relforcerowsecurity")
        assert forced == len(ATTEST_TABLES)
        assert "attest_bundle_objects.attest_public_lookup" in snap["policies"]
        third = await migrate.migrate_up(con, schema_dir=d, transform=_schema_transform)
        assert third.applied == []
    finally:
        await con.close()


async def test_a_database_with_a_p2_1_gap_still_applies_in_order(empty_db, tmp_path):
    """044 to 059 are P2.1's: a stand-in file in that range must not disturb 060 to 064."""
    d = tmp_path / "schema"
    shutil.copytree(SCHEMA_DIR, d)
    (d / "050_p21_standin.sql").write_text("CREATE TABLE IF NOT EXISTS p21_standin (id INTEGER PRIMARY KEY);\n")
    res = await _up(empty_db, d)
    names = res.applied
    assert names.index("050_p21_standin.sql") < names.index("060_attest_keys.sql") < names.index("064_attest_immutability.sql")


def test_new_files_have_no_destructive_statements_and_use_if_not_exists():
    for name in NEW_FILES:
        text = (SCHEMA_DIR / name).read_text()
        upper = text.upper()
        assert "DROP TABLE" not in upper and "TRUNCATE" not in upper and "DROP COLUMN" not in upper, name
        if name != "064_attest_immutability.sql":
            for line in text.splitlines():
                if line.upper().startswith("CREATE TABLE "):
                    assert "IF NOT EXISTS" in line.upper(), (name, line)
