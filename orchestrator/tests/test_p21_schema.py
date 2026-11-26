"""P2.1 seam (WP0): migrations 044 (advisories + manifests), 045 (pairing + conflict acks), 046 (lifecycle).

docs/ASSURANCE_P2_1.md 1.3, 4.2, 6.1, 6.2. The sweep tests (test_isolation_sweep, test_isolation_keys) classify every
table generically; this file pins what is specific to the new ones: which are global and who may write them, the
per-tenant content addressing, the constraints the application relies on, the service-role grants and the idempotent,
per-tenant backfill of 046.
"""
from __future__ import annotations

import datetime as dt
import uuid

import asyncpg
import pytest

from app import migrate, tenancy

from .conftest import SCHEMA_DIR
from .test_isolation_sweep import TENANT_A, TENANT_B

PLATFORM = tenancy.DEFAULT_TENANT_ID
SHA1 = "1" * 64
SHA2 = "2" * 64

GLOBAL_TABLES = ("kev_entries", "advisory_scopes", "advisory_snapshots", "advisory_fixes")
TENANT_TABLES = ("agent_manifests", "agent_manifest_refs", "fleet_agent_pairings", "fleet_conflict_acks")


async def _tenants(db_pool):
    for slug, tid in (("p21-a", TENANT_A), ("p21-b", TENANT_B)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)


def _files():
    return {f.filename: f for f in migrate.discover(SCHEMA_DIR)}


# --------------------------------------------------------------------------- #
# the files themselves
# --------------------------------------------------------------------------- #

def test_the_three_migrations_exist_in_order_and_043_stays_unused():
    names = list(_files())
    assert "044_advisories.sql" in names and "045_agent_identity.sql" in names
    assert "046_assurance_lifecycle.sql" in names
    assert not any(n.startswith("043_") for n in names), "043 stays unused (D2)"
    i = {n: names.index(n) for n in names}
    assert i["042_agent_v2_hardening.sql"] < i["044_advisories.sql"] < i["045_agent_identity.sql"] \
        < i["046_assurance_lifecycle.sql"] < i["098_audit_keyed.sql"] < i["099_tenancy.sql"]


@pytest.mark.parametrize("name", ["044_advisories.sql", "045_agent_identity.sql", "046_assurance_lifecycle.sql"])
async def test_each_migration_is_idempotent_and_reapplies_cleanly(db_pool, name):
    sql = (SCHEMA_DIR / name).read_text()
    await db_pool.execute(sql)
    await db_pool.execute(sql)
    # 099 re-asserts RLS after a later table: the whole set still passes the classification afterwards
    await db_pool.execute((SCHEMA_DIR / "099_tenancy.sql").read_text())


def test_the_new_migrations_destroy_nothing_and_say_which_tables_are_global():
    """044 marks its four global tables for 099 (and only those); no file drops, truncates or deletes data."""
    sql44 = (SCHEMA_DIR / "044_advisories.sql").read_text()
    assert sql44.count("@paddock:global") >= len(GLOBAL_TABLES)
    for name in ("044_advisories.sql", "045_agent_identity.sql", "046_assurance_lifecycle.sql"):
        up = (SCHEMA_DIR / name).read_text().upper()
        assert "DROP TABLE" not in up and "TRUNCATE" not in up and "DELETE FROM" not in up, name
    assert "@paddock:global" not in (SCHEMA_DIR / "045_agent_identity.sql").read_text()


# --------------------------------------------------------------------------- #
# classification
# --------------------------------------------------------------------------- #

async def test_the_four_advisory_tables_are_global_and_the_four_tenant_tables_are_not(db_pool):
    async with db_pool.acquire() as con:
        for t in GLOBAL_TABLES:
            row = await con.fetchrow(
                "SELECT c.relrowsecurity, COALESCE(obj_description(c.oid,'pg_class'),'') AS cmt, "
                "EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant_id' "
                "AND NOT a.attisdropped) AS has_tenant FROM pg_class c WHERE c.relname=$1 AND c.relkind='r'", t)
            assert row is not None, t
            assert row["relrowsecurity"] and "@paddock:global" in row["cmt"] and not row["has_tenant"], t
            pols = {r["polname"] for r in await con.fetch(
                "SELECT polname FROM pg_policy WHERE polrelid=$1::regclass", t)}
            assert pols == {"global_read", "global_platform_write"}, (t, pols)
        for t in TENANT_TABLES:
            row = await con.fetchrow(
                "SELECT c.relrowsecurity, c.relforcerowsecurity, COALESCE(obj_description(c.oid,'pg_class'),'') AS cmt "
                "FROM pg_class c WHERE c.relname=$1 AND c.relkind='r'", t)
            assert row["relrowsecurity"] and row["relforcerowsecurity"], t
            # a tenant table must NEVER carry the global marker: 099 would drop its tenant_id and RLS
            assert "@paddock:global" not in row["cmt"], t
            assert await con.fetchval(
                "SELECT count(*) FROM pg_policy WHERE polrelid=$1::regclass AND polname='tenant_isolation'", t) == 1
            assert await con.fetchval(
                "SELECT count(*) FROM pg_policy WHERE polrelid=$1::regclass", t) == 1, f"{t}: extra policy"


async def test_the_sweep_allow_list_names_exactly_the_global_tables():
    from .test_isolation_sweep import GLOBAL_ALLOWLIST

    for t in GLOBAL_TABLES:
        assert t in GLOBAL_ALLOWLIST and GLOBAL_ALLOWLIST[t], t
    for t in TENANT_TABLES:
        assert t not in GLOBAL_ALLOWLIST, t


# --------------------------------------------------------------------------- #
# attack 9: write a global advisory table / read another tenant's manifest
# --------------------------------------------------------------------------- #

async def _ins_kev(con, cve="CVE-2024-0001"):
    await con.execute("INSERT INTO kev_entries (cve_id, date_added) VALUES ($1, DATE '2024-01-01')", cve)


async def test_a_tenant_cannot_write_a_global_advisory_table_but_every_tenant_can_read_it(db_pool, app_pool):
    await _tenants(db_pool)
    with tenancy.tenant_context(PLATFORM):
        async with app_pool.acquire() as con:
            await _ins_kev(con)
            await con.execute("INSERT INTO advisory_scopes (scope, family, vendor, release, status, primary_source) "
                              "VALUES ('debian:bookworm','deb','debian','bookworm','supported','debian-tracker')")
    for tid in (TENANT_A, TENANT_B):
        with tenancy.tenant_context(tid):
            async with app_pool.acquire() as con:
                assert await con.fetchval("SELECT count(*) FROM kev_entries") == 1
                assert await con.fetchval("SELECT count(*) FROM advisory_scopes") == 1
                for sql in (
                    "INSERT INTO kev_entries (cve_id, date_added) VALUES ('CVE-2024-0002', DATE '2024-01-01')",
                    "INSERT INTO advisory_scopes (scope, family, vendor, release, status, primary_source) "
                    "VALUES ('debian:trixie','deb','debian','trixie','supported','x')",
                    "INSERT INTO advisory_snapshots (source, fetched_at, sha256, bytes, status, parser_version) "
                    f"VALUES ('s', now(), '{SHA1}', 1, 'current', 1)",
                ):
                    with pytest.raises(asyncpg.InsufficientPrivilegeError):
                        await con.execute(sql)
                # RLS hides rows from UPDATE/DELETE of a non-platform tenant: zero rows, never an error that says "exists"
                assert await con.execute("UPDATE kev_entries SET vendor='evil'") == "UPDATE 0"
                assert await con.execute("DELETE FROM kev_entries") == "DELETE 0"
                assert await con.execute("UPDATE advisory_scopes SET vendor='evil'") == "UPDATE 0"
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM kev_entries WHERE vendor='evil'") == 0


async def test_the_same_manifest_sha_in_two_tenants_is_two_rows_nobody_else_can_read(db_pool, app_pool):
    await _tenants(db_pool)
    for tid, blob in ((TENANT_A, b"a-list"), (TENANT_B, b"b-list")):
        with tenancy.tenant_context(tid):
            async with app_pool.acquire() as con:
                await con.execute(
                    "INSERT INTO agent_manifests (sha256, mgr, pkg_count, packages_gz, size_bytes) "
                    "VALUES ($1, 'dpkg', 1, $2, $3)", SHA1, blob, len(blob))
    for tid, want in ((TENANT_A, b"a-list"), (TENANT_B, b"b-list")):
        with tenancy.tenant_context(tid):
            async with app_pool.acquire() as con:
                assert [bytes(r["packages_gz"]) for r in await con.fetch("SELECT packages_gz FROM agent_manifests")] == [want]
                assert await con.execute("UPDATE agent_manifests SET packages_gz = ''::bytea WHERE sha256 <> $1", SHA1) \
                    == "UPDATE 0"
    # within one tenant the sha is the content address: a second row for it is refused
    with tenancy.tenant_context(TENANT_A):
        async with app_pool.acquire() as con:
            with pytest.raises(asyncpg.UniqueViolationError):
                await con.execute("INSERT INTO agent_manifests (sha256, mgr) VALUES ($1, 'rpm')", SHA1)
            # ON CONFLICT (tenant_id, sha256) is the ingest upsert (1.5)
            await con.execute("INSERT INTO agent_manifests (sha256) VALUES ($1) "
                              "ON CONFLICT (tenant_id, sha256) DO UPDATE SET last_ref_at = NOW()", SHA1)


# --------------------------------------------------------------------------- #
# constraints
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("sql", [
    "INSERT INTO kev_entries (cve_id, date_added) VALUES ('cve-2024-1', DATE '2024-01-01')",
    "INSERT INTO kev_entries (cve_id, date_added) VALUES ('CVE-2024-123', DATE '2024-01-01')",
    "INSERT INTO kev_entries (cve_id, date_added) VALUES ('CVE-2024-1234; DROP', DATE '2024-01-01')",
    "INSERT INTO kev_entries (cve_id, date_added, vendor) VALUES ('CVE-2024-1234', DATE '2024-01-01', repeat('x',201))",
    "INSERT INTO advisory_scopes (scope, family, vendor, release, status, primary_source) "
    "VALUES ('Debian:Bookworm','deb','d','r','supported','x')",
    "INSERT INTO advisory_scopes (scope, family, vendor, release, status, primary_source) "
    "VALUES ('debian:bookworm','apk','d','r','supported','x')",
    "INSERT INTO advisory_scopes (scope, family, vendor, release, status, primary_source) "
    "VALUES ('debian:bookworm','deb','d','r','maybe','x')",
    "INSERT INTO advisory_snapshots (source, fetched_at, sha256, bytes, status, parser_version) "
    "VALUES ('s', now(), 'abc', 1, 'current', 1)",
    "INSERT INTO advisory_snapshots (source, fetched_at, sha256, bytes, status, parser_version) "
    f"VALUES ('s', now(), '{SHA1}', 1, 'pending', 1)",
])
async def test_global_table_constraints_refuse_bad_rows(db_pool, sql):
    async with db_pool.acquire() as con:
        with pytest.raises(asyncpg.CheckViolationError):
            await con.execute(sql)


async def test_a_kev_row_without_a_date_is_rejected_never_defaulted_to_now(db_pool):
    async with db_pool.acquire() as con:
        with pytest.raises(asyncpg.NotNullViolationError):
            await con.execute("INSERT INTO kev_entries (cve_id) VALUES ('CVE-2024-1234')")
        assert not await con.fetchval(
            "SELECT column_default FROM information_schema.columns WHERE table_name='kev_entries' AND column_name='date_added'")


async def test_one_current_snapshot_per_source_and_scope(db_pool):
    async with db_pool.acquire() as con:
        ins = ("INSERT INTO advisory_snapshots (source, scope, fetched_at, sha256, bytes, status, parser_version) "
               "VALUES ($1, $2, now(), $3, 1, $4, 1)")
        await con.execute(ins, "debian-tracker", "debian:bookworm", SHA1, "current")
        with pytest.raises(asyncpg.UniqueViolationError):
            await con.execute(ins, "debian-tracker", "debian:bookworm", SHA2, "current")
        # superseded and rejected rows accumulate; another scope or source has its own current row
        await con.execute(ins, "debian-tracker", "debian:bookworm", SHA2, "superseded")
        await con.execute(ins, "debian-tracker", "debian:bookworm", SHA2, "rejected")
        await con.execute(ins, "debian-tracker", "debian:trixie", SHA1, "current")
        await con.execute(ins, "kev", "", SHA1, "current")


async def test_advisory_fix_rows_reference_their_scope_and_snapshot(db_pool):
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO advisory_scopes (scope, family, vendor, release, status, primary_source) "
                          "VALUES ('debian:bookworm','deb','debian','bookworm','supported','debian-tracker')")
        sid = await con.fetchval(
            "INSERT INTO advisory_snapshots (source, scope, fetched_at, sha256, bytes, status, parser_version) "
            "VALUES ('debian-tracker','debian:bookworm', now(), $1, 1, 'current', 1) RETURNING id", SHA1)
        ins = ("INSERT INTO advisory_fixes (scope, cve_id, pkg, pkg_kind, state, first_seen_at, last_seen_snapshot) "
               "VALUES ($1, 'CVE-2024-0001', 'libc6', $2, $3, now(), $4)")
        await con.execute(ins, "debian:bookworm", "source", "fixed", sid)
        with pytest.raises(asyncpg.ForeignKeyViolationError):
            await con.execute(ins, "debian:nope", "source", "fixed", sid)
        with pytest.raises(asyncpg.ForeignKeyViolationError):
            await con.execute(ins, "debian:bookworm", "source", "open", sid + 999)
        with pytest.raises(asyncpg.CheckViolationError):
            await con.execute(ins, "debian:bookworm", "package", "fixed", sid)
        with pytest.raises(asyncpg.CheckViolationError):
            await con.execute(ins, "debian:bookworm", "source", "patched", sid)
        with pytest.raises(asyncpg.UniqueViolationError):                   # (scope, cve, pkg, state, fixed_evr, advisory)
            await con.execute(ins, "debian:bookworm", "source", "fixed", sid)
        # the lookup index the matcher needs is partial on live rows
        idx = await con.fetchval("SELECT indexdef FROM pg_indexes WHERE indexname='idx_advisory_fixes_lookup'")
        assert "removed_at IS NULL" in idx and "(scope, pkg)" in idx


async def test_manifest_and_ref_constraints(db_pool):
    await _tenants(db_pool)
    async with db_pool.acquire() as con:
        for sql in (
            "INSERT INTO agent_manifests (tenant_id, sha256) VALUES ($1, 'abc')",           # a content address is 64 hex
            "INSERT INTO agent_manifests (tenant_id, sha256) VALUES ($1, repeat('G', 64))",
            "INSERT INTO agent_manifests (tenant_id, sha256) VALUES ($1, repeat('A', 64))",
            f"INSERT INTO agent_manifests (tenant_id, sha256, mgr) VALUES ($1, '{SHA1}', 'apk')",
            f"INSERT INTO agent_manifests (tenant_id, sha256, size_bytes) VALUES ($1, '{SHA1}', 1048577)",
            "INSERT INTO agent_manifest_refs (tenant_id, agent_id, manifest_sha) VALUES ($1, gen_random_uuid(), 'zz')",
        ):
            with pytest.raises(asyncpg.CheckViolationError):
                await con.execute(sql, uuid.UUID(TENANT_A))
        await con.execute("SET session_replication_role = replica")        # FKs off: only the keys under test
        try:
            ag = uuid.uuid4()
            ref = ("INSERT INTO agent_manifest_refs (tenant_id, agent_id, manifest_sha) VALUES ($1, $2, $3)")
            await con.execute(ref, uuid.UUID(TENANT_A), ag, SHA1)
            with pytest.raises(asyncpg.UniqueViolationError):                # one CURRENT list per (tenant, agent)
                await con.execute(ref, uuid.UUID(TENANT_A), ag, SHA2)
            await con.execute(ref, uuid.UUID(TENANT_B), ag, SHA1)           # the same agent id in another tenant is fine
        finally:
            await con.execute("SET session_replication_role = DEFAULT")
        # the ref follows its agent: deleting the agent drops the ref (ON DELETE CASCADE)
        fk = await con.fetchval(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='agent_manifest_refs'::regclass "
            "AND contype='f' AND confrelid='fleet_agents'::regclass")
        assert "ON DELETE CASCADE" in fk
        assert "USING GIN" in (await con.fetchval(
            "SELECT indexdef FROM pg_indexes WHERE indexname='idx_agent_manifests_src'")).upper()


# --------------------------------------------------------------------------- #
# 045: pairing ledger + conflict acks (one real agent per row)
# --------------------------------------------------------------------------- #

async def _agent(con, tid, host):
    return await con.fetchval(
        "INSERT INTO fleet_agents (tenant_id, hostname, token_prefix, token_hash) VALUES ($1,$2,$3,$4) RETURNING id",
        uuid.UUID(tid), host, uuid.uuid4().hex[:12], "h")


async def test_the_database_forbids_two_active_pairings_per_agent_or_per_asset(db_pool):
    await _tenants(db_pool)
    async with db_pool.acquire() as con:
        a1, a2, b1 = await _agent(con, TENANT_A, "h1"), await _agent(con, TENANT_A, "h2"), await _agent(con, TENANT_B, "h3")
        asset = uuid.uuid4()
        ins = ("INSERT INTO fleet_agent_pairings (tenant_id, agent_id, asset_id, justification) VALUES ($1,$2,$3,'why')")
        await con.execute(ins, uuid.UUID(TENANT_A), a1, asset)
        with pytest.raises(asyncpg.UniqueViolationError):                     # a second agent on the same asset (attack 19)
            await con.execute(ins, uuid.UUID(TENANT_A), a2, asset)
        with pytest.raises(asyncpg.UniqueViolationError):                     # a second active pairing of one agent
            await con.execute(ins, uuid.UUID(TENANT_A), a1, uuid.uuid4())
        # the same asset id in another tenant is a different asset
        await con.execute(ins, uuid.UUID(TENANT_B), b1, asset)
        # ended rows are history: any number, and the asset is free again
        await con.execute("UPDATE fleet_agent_pairings SET status='ended', ended_at=now(), ended_by='x', "
                          "ended_reason='unpaired' WHERE agent_id=$1", a1)
        await con.execute(ins, uuid.UUID(TENANT_A), a2, asset)
        await con.execute(ins, uuid.UUID(TENANT_A), a1, uuid.uuid4())
        assert await con.fetchval("SELECT count(*) FROM fleet_agent_pairings WHERE tenant_id=$1 AND status='ended'",
                                  uuid.UUID(TENANT_A)) == 1


async def test_a_pairing_is_ended_iff_it_has_an_end_time(db_pool):
    await _tenants(db_pool)
    async with db_pool.acquire() as con:
        a = await _agent(con, TENANT_A, "h1")
        for status, ended in (("ended", None), ("active", dt.datetime.now(dt.timezone.utc))):
            with pytest.raises(asyncpg.CheckViolationError):
                await con.execute("INSERT INTO fleet_agent_pairings (tenant_id, agent_id, status, ended_at) "
                                  "VALUES ($1,$2,$3,$4)", uuid.UUID(TENANT_A), a, status, ended)
        with pytest.raises(asyncpg.CheckViolationError):
            await con.execute("INSERT INTO fleet_agent_pairings (tenant_id, agent_id, status) VALUES ($1,$2,'paused')",
                              uuid.UUID(TENANT_A), a)
        # the asset has NO foreign key on purpose: a deleted asset makes the pairing inert, never erased
        assert not await con.fetchval(
            "SELECT count(*) FROM pg_constraint WHERE conrelid='fleet_agent_pairings'::regclass AND contype='f' "
            "AND confrelid='assets'::regclass")
        # the ledger follows its agent
        assert "ON DELETE CASCADE" in await con.fetchval(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='fleet_agent_pairings'::regclass "
            "AND contype='f' AND confrelid='fleet_agents'::regclass")
        idx = await con.fetchval("SELECT indexdef FROM pg_indexes WHERE indexname='uq_pairing_active_asset'")
        assert "UNIQUE" in idx and "tenant_id, asset_id" in idx and "active" in idx


async def test_conflict_acks_constraints_and_one_active_ack_per_conflict(db_pool):
    await _tenants(db_pool)
    async with db_pool.acquire() as con:
        a = await _agent(con, TENANT_A, "h1")
        ins = ("INSERT INTO fleet_conflict_acks (tenant_id, agent_id, kind, proto, port, status, justification) "
               "VALUES ($1,$2,$3,$4,$5,$6,'because')")
        t = uuid.UUID(TENANT_A)
        await con.execute(ins, t, a, "agent_closed_scan_open", "tcp", 22, "active")
        with pytest.raises(asyncpg.UniqueViolationError):
            await con.execute(ins, t, a, "agent_closed_scan_open", "tcp", 22, "active")
        await con.execute(ins, t, a, "agent_closed_scan_open", "udp", 22, "active")        # per (proto, port)
        await con.execute(ins, t, a, "agent_closed_scan_open", "tcp", 22, "superseded")    # history rows pile up
        for kind, proto, port, status in (
            ("agent_scan_check_budget_exceeded", "tcp", 22, "active"),     # only agent_closed_scan_open is ackable (D30)
            ("paired_peer_mismatch", "tcp", 22, "active"),
            ("agent_closed_scan_open", "icmp", 22, "active"),
            ("agent_closed_scan_open", "tcp", 0, "active"),
            ("agent_closed_scan_open", "tcp", 65536, "active"),
            ("agent_closed_scan_open", "tcp", 22, "forever"),
        ):
            with pytest.raises(asyncpg.CheckViolationError):
                await con.execute(ins, t, a, kind, proto, port, status)
        row = await con.fetchrow("SELECT acked_at, expires_at FROM fleet_conflict_acks WHERE proto='udp'")
        assert dt.timedelta(days=6, hours=23) < row["expires_at"] - row["acked_at"] <= dt.timedelta(days=7, seconds=5)


# --------------------------------------------------------------------------- #
# service roles (029's function re-created by 044)
# --------------------------------------------------------------------------- #

async def _grants(con, role, table):
    return {p for p in ("SELECT", "INSERT", "UPDATE", "DELETE")
            if await con.fetchval("SELECT has_table_privilege($1,$2,$3)", role, table, p)}


async def test_the_intel_role_appends_the_advisory_tables_and_nothing_else_new(db_pool):
    async with db_pool.acquire() as con:
        for t in GLOBAL_TABLES + ("cves", "intel_cursors"):
            assert await _grants(con, "paddock_svc_intel", t) == {"SELECT", "INSERT", "UPDATE"}, t
        for t in TENANT_TABLES + ("agent_posture", "fleet_agents", "findings", "assets"):
            assert await _grants(con, "paddock_svc_intel", t) == set(), t
        # the sequences behind the BIGSERIAL ids: an INSERT through the role needs them
        for seq in ("advisory_snapshots_id_seq", "advisory_fixes_id_seq"):
            assert await con.fetchval("SELECT has_sequence_privilege('paddock_svc_intel', $1, 'USAGE')", seq), seq
        # no other service gets any of the new tables
        for role in await con.fetch("SELECT rolname FROM pg_roles WHERE rolname LIKE 'paddock\\_svc\\_%' "
                                    "AND rolname <> 'paddock_svc_intel'"):
            for t in GLOBAL_TABLES + TENANT_TABLES:
                assert await _grants(con, role["rolname"], t) == set(), (role["rolname"], t)


async def test_the_intel_role_can_really_ingest_as_the_platform_tenant_and_only_as_it(db_pool):
    await _tenants(db_pool)
    async with db_pool.acquire() as con:
        async def as_intel(tenant, sql, *args):
            async with con.transaction():
                await con.execute("SET LOCAL ROLE paddock_svc_intel")
                await con.execute("SELECT set_config('app.tenant_id', $1, true)", tenant)
                return await con.fetchval(sql, *args)

        await as_intel(PLATFORM, "INSERT INTO advisory_scopes (scope, family, vendor, release, status, primary_source) "
                                 "VALUES ('debian:bookworm','deb','debian','bookworm','supported','p') RETURNING scope")
        sid = await as_intel(PLATFORM, "INSERT INTO advisory_snapshots (source, scope, fetched_at, sha256, bytes, status, "
                                       "parser_version) VALUES ('p','debian:bookworm', now(), $1, 1, 'current', 1) "
                                       "RETURNING id", SHA1)
        await as_intel(PLATFORM, "INSERT INTO advisory_fixes (scope, cve_id, pkg, pkg_kind, state, first_seen_at, "
                                 "last_seen_snapshot) VALUES ('debian:bookworm','CVE-2024-0001','libc6','source','fixed',"
                                 "now(), $1) RETURNING id", sid)
        await as_intel(PLATFORM, "INSERT INTO kev_entries (cve_id, date_added) VALUES ('CVE-2024-0001', DATE '2024-01-01') "
                                 "RETURNING cve_id")
        await as_intel(PLATFORM, "UPDATE advisory_snapshots SET status='superseded' WHERE id=$1 RETURNING id", sid)
        # a tenant-stamped session is refused by RLS, whatever the grant says
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await as_intel(TENANT_A, "INSERT INTO kev_entries (cve_id, date_added) VALUES ('CVE-2024-0009', "
                                     "DATE '2024-01-01') RETURNING cve_id")
        # append-only: no DELETE privilege at all
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await as_intel(PLATFORM, "DELETE FROM kev_entries RETURNING cve_id")
        # and the tenant data is out of reach
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await as_intel(PLATFORM, "SELECT count(*) FROM agent_manifests")


async def test_re_creating_the_grant_function_changed_no_other_services_grants(db_pool):
    """044 re-states the whole of 029's function with one list extended: every other service keeps its tables."""
    async with db_pool.acquire() as con:
        before = {(r["grantee"], r["table_name"], r["privilege_type"]) for r in await con.fetch(
            "SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee LIKE 'paddock\\_svc\\_%'")}
        await con.execute("SELECT paddock_apply_service_grants()")
        after = {(r["grantee"], r["table_name"], r["privilege_type"]) for r in await con.fetch(
            "SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee LIKE 'paddock\\_svc\\_%'")}
        assert before == after, "the function is idempotent"
        corr = {t for g, t, p in after if g == "paddock_svc_correlation" and p == "SELECT"}
        assert {"assets", "asset_edges", "findings", "attack_technique_map", "attack_paths"} <= corr
        triage = {t for g, t, p in after if g == "paddock_svc_triage" and p == "UPDATE"}
        assert triage == {"tickets"}
        assert await _grants(con, "paddock_svc_sca", "sbom_components") == {"SELECT", "INSERT", "UPDATE", "DELETE"}
        # the function stays an operator tool, not application surface
        assert not await con.fetchval("SELECT has_function_privilege('paddock_app', 'paddock_apply_service_grants()', 'EXECUTE')")


# --------------------------------------------------------------------------- #
# 046
# --------------------------------------------------------------------------- #

async def test_046_columns_and_indexes(db_pool):
    async with db_pool.acquire() as con:
        cols = {(r["table_name"], r["column_name"]): r for r in await con.fetch(
            "SELECT table_name, column_name, data_type, is_nullable, column_default FROM information_schema.columns "
            "WHERE table_name IN ('invariants','invariant_runs')")}
        for c in ("archived_at", "disabled_at"):
            assert cols[("invariants", c)]["data_type"] == "timestamp with time zone"
            assert cols[("invariants", c)]["is_nullable"] == "YES"
        assert cols[("invariants", "disabled_by")]["data_type"] == "text"
        assert cols[("invariant_runs", "compacted_at")]["is_nullable"] == "YES"
        pinned = cols[("invariant_runs", "pinned")]
        assert pinned["data_type"] == "boolean" and pinned["is_nullable"] == "NO" and "false" in pinned["column_default"]
        idx = {r["indexname"]: r["indexdef"] for r in await con.fetch(
            "SELECT indexname, indexdef FROM pg_indexes WHERE indexname IN ('idx_findings_invariant_state',"
            "'idx_invariant_runs_evaluated','idx_invariant_runs_uncompacted')")}
        assert set(idx) == {"idx_findings_invariant_state", "idx_invariant_runs_evaluated", "idx_invariant_runs_uncompacted"}
        assert "invariant_state" in idx["idx_findings_invariant_state"] and "rule_source" in idx["idx_findings_invariant_state"]
        assert "compacted_at IS NULL" in idx["idx_invariant_runs_uncompacted"]
        assert "(tenant_id, evaluated_at)" in idx["idx_invariant_runs_evaluated"]


async def test_046_backfills_disabled_at_per_tenant_without_touching_enabled_or_dated_rows(db_pool):
    """The backfill runs under FORCE ROW LEVEL SECURITY once per tenant (041/042 pattern) and is idempotent."""
    await _tenants(db_pool)
    old = dt.datetime(2026, 3, 1, 12, 0, tzinfo=dt.timezone.utc)
    async with db_pool.acquire() as con:
        ids = {}
        for tid, name, enabled in ((TENANT_A, "a:off", False), (TENANT_A, "a:on", True), (TENANT_B, "b:off", False)):
            ids[name] = await con.fetchval(
                "INSERT INTO invariants (tenant_id, invariant_id, enabled, updated_at) VALUES ($1,$2,$3,$4) RETURNING id",
                uuid.UUID(tid), name, enabled, old)
        dated = dt.datetime(2026, 5, 5, tzinfo=dt.timezone.utc)
        ids["a:dated"] = await con.fetchval(
            "INSERT INTO invariants (tenant_id, invariant_id, enabled, updated_at, disabled_at, disabled_by) "
            "VALUES ($1,'a:dated',false,$2,$3,'alice') RETURNING id", uuid.UUID(TENANT_A), old, dated)
        sql = (SCHEMA_DIR / "046_assurance_lifecycle.sql").read_text()
        await con.execute(sql)
        await con.execute(sql)
        rows = {r["invariant_id"]: r for r in await con.fetch("SELECT * FROM invariants WHERE id = ANY($1::uuid[])",
                                                              list(ids.values()))}
        assert rows["a:off"]["disabled_at"] == old and rows["b:off"]["disabled_at"] == old
        assert rows["a:on"]["disabled_at"] is None and rows["a:on"]["archived_at"] is None
        assert rows["a:dated"]["disabled_at"] == dated and rows["a:dated"]["disabled_by"] == "alice"
        # no archived_at is invented: a deleted invariant is indistinguishable from a disabled one before 046
        assert all(r["archived_at"] is None for r in rows.values())
        # the session leaves no tenant behind
        assert (await con.fetchval("SELECT current_setting('app.tenant_id', true)")) in (None, "")


async def test_046_findings_index_is_partial_on_annotated_invariant_findings(db_pool):
    async with db_pool.acquire() as con:
        d = await con.fetchval("SELECT indexdef FROM pg_indexes WHERE indexname='idx_findings_invariant_state'")
    assert "invariant_state" in d and "rule_source" in d and "invariant" in d.split("WHERE", 1)[1]


async def test_the_whole_migration_set_is_clean_for_the_runner(db_pool):
    async with db_pool.acquire() as con:
        plan = await migrate.migration_status(con, SCHEMA_DIR)
        assert plan.clean
        done = {r["filename"] for r in await con.fetch("SELECT filename FROM schema_migrations")}
    assert {"044_advisories.sql", "045_agent_identity.sql", "046_assurance_lifecycle.sql"} <= done
