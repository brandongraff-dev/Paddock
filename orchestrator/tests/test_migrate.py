"""Versioned migration runner (app/migrate.py).

Each test gets an EMPTY database (no schema) and, where it mutates schema
files, a private copy of schema/ in tmp_path, so the real files are never
touched.
"""
from __future__ import annotations

import asyncio
import datetime
import shutil
import uuid

import asyncpg
import pytest
import pytest_asyncio

from app import migrate

from .conftest import SCHEMA_DIR, _schema_transform


@pytest_asyncio.fixture
async def empty_db(postgresql_my_proc):
    p = postgresql_my_proc
    auth = f"{p.user}:{p.password}" if p.password else p.user
    base = f"postgresql://{auth}@{p.host}:{p.port}"
    name = f"mig_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(f"{base}/postgres")
    await admin.execute(f'CREATE DATABASE "{name}"')
    await admin.close()
    try:
        yield f"{base}/{name}"
    finally:
        admin = await asyncpg.connect(f"{base}/postgres")
        await admin.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = $1 AND pid <> pg_backend_pid()",
            name,
        )
        await admin.execute(f'DROP DATABASE "{name}"')
        await admin.close()


@pytest.fixture
def schema_copy(tmp_path):
    d = tmp_path / "schema"
    shutil.copytree(SCHEMA_DIR, d)
    return d


async def _up(dsn, **kw):
    con = await asyncpg.connect(dsn)
    try:
        kw.setdefault("transform", _schema_transform)
        return await migrate.migrate_up(con, **kw)
    finally:
        await con.close()


async def _rows(dsn):
    con = await asyncpg.connect(dsn)
    try:
        return {r["filename"]: r for r in await con.fetch("SELECT * FROM schema_migrations")}
    finally:
        await con.close()


def test_discover_orders_and_filters(schema_copy):
    (schema_copy / "README.sql").write_text("-- not a migration\n")
    (schema_copy / "notes.txt").write_text("x")
    files = migrate.discover(schema_copy)
    names = [f.filename for f in files]
    assert names == sorted(names)
    assert "README.sql" not in names
    assert names[0].startswith("001_")
    assert all(len(f.checksum) == 64 for f in files)


def test_tables_created_ignores_comments():
    sql = """
    -- CREATE TABLE commented_out (id int);
    /* CREATE TABLE also_not (id int); */
    CREATE TABLE IF NOT EXISTS a_real (id int);
    create unlogged table "Quoted" (id int);
    CREATE TABLE public.qualified (id int);
    """
    assert migrate.tables_created(sql) == ["a_real", "Quoted", "public.qualified"]


def test_checksum_normalises_crlf():
    assert migrate.checksum_of("a\r\nb\n") == migrate.checksum_of("a\nb\n")


async def test_fresh_database_applies_everything_once(empty_db):
    res = await _up(empty_db, schema_dir=SCHEMA_DIR)
    files = migrate.discover(SCHEMA_DIR)
    assert res.applied == [f.filename for f in files]
    assert res.baselined == []
    rows = await _rows(empty_db)
    assert set(rows) == {f.filename for f in files}
    for f in files:
        assert rows[f.filename]["checksum"] == f.checksum
        assert rows[f.filename]["baselined"] is False
        assert rows[f.filename]["duration_ms"] >= 0
    # Idempotent second run.
    again = await _up(empty_db, schema_dir=SCHEMA_DIR)
    assert again.applied == [] and again.baselined == []
    con = await asyncpg.connect(empty_db)
    try:
        plan = await migrate.migration_status(con, SCHEMA_DIR)
        assert plan.clean
        assert await con.fetchval("SELECT to_regclass('findings') IS NOT NULL")
    finally:
        await con.close()


async def test_new_numbered_file_is_picked_up(empty_db, schema_copy):
    await _up(empty_db, schema_dir=schema_copy)
    (schema_copy / "099_zz_test.sql").write_text(
        "CREATE TABLE IF NOT EXISTS zz_mig_probe (id int);\n"
    )
    res = await _up(empty_db, schema_dir=schema_copy)
    assert res.applied == ["099_zz_test.sql"]


async def test_out_of_order_file_applied_with_warning_or_refused(empty_db, schema_copy):
    (schema_copy / "099_last.sql").write_text("SELECT 1;\n")
    await _up(empty_db, schema_dir=schema_copy)
    (schema_copy / "050_late_merge.sql").write_text("CREATE TABLE late_merge (id int);\n")
    with pytest.raises(migrate.OutOfOrderError):
        await _up(empty_db, schema_dir=schema_copy, strict_order=True)
    res = await _up(empty_db, schema_dir=schema_copy)
    assert res.applied == ["050_late_merge.sql"]
    assert res.out_of_order == ["050_late_merge.sql"]


async def test_checksum_drift_refused_then_allowed(empty_db, schema_copy):
    await _up(empty_db, schema_dir=schema_copy)
    target = sorted(schema_copy.glob("002_*.sql"))[0]
    target.write_text(target.read_text() + "\n-- harmless trailing comment\n")
    with pytest.raises(migrate.ChecksumDriftError) as ei:
        await _up(empty_db, schema_dir=schema_copy)
    assert target.name in str(ei.value)
    # Allowing a DIFFERENT file does not help.
    with pytest.raises(migrate.ChecksumDriftError):
        await _up(empty_db, schema_dir=schema_copy, allow_checksum_drift="001_scope.sql")
    res = await _up(empty_db, schema_dir=schema_copy, allow_checksum_drift=target.name)
    assert res.restamped == [target.name] and res.applied == []
    rows = await _rows(empty_db)
    assert rows[target.name]["checksum"] == migrate.checksum_of(target.read_text())
    assert "re-stamped" in rows[target.name]["notes"]
    # And now it is clean without the flag.
    assert (await _up(empty_db, schema_dir=schema_copy)).restamped == []


async def test_failed_migration_rolls_back_and_stops(empty_db, schema_copy):
    (schema_copy / "990_bad.sql").write_text(
        "CREATE TABLE half_done (id int);\nSELECT * FROM no_such_table;\n"
    )
    (schema_copy / "991_after.sql").write_text("CREATE TABLE after_bad (id int);\n")
    with pytest.raises(migrate.MigrationError, match="990_bad.sql"):
        await _up(empty_db, schema_dir=schema_copy)
    rows = await _rows(empty_db)
    assert "990_bad.sql" not in rows and "991_after.sql" not in rows
    assert "001_scope.sql" in rows  # earlier files committed individually
    con = await asyncpg.connect(empty_db)
    try:
        assert not await con.fetchval("SELECT to_regclass('half_done') IS NOT NULL")
        assert not await con.fetchval("SELECT to_regclass('after_bad') IS NOT NULL")
        assert not await con.fetchval(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = $1",
            migrate.MIGRATION_LOCK_KEY & 0xFFFFFFFF,
        )
    finally:
        await con.close()
    # Fix the file -> the run resumes from it.
    (schema_copy / "990_bad.sql").write_text("CREATE TABLE half_done (id int);\n")
    res = await _up(empty_db, schema_dir=schema_copy)
    assert res.applied == ["990_bad.sql", "991_after.sql"]


async def test_no_transaction_marker(empty_db, schema_copy):
    await _up(empty_db, schema_dir=schema_copy)
    # Two statements: as one simple-query string Postgres would wrap them in an
    # implicit transaction and refuse CONCURRENTLY.
    (schema_copy / "099_concurrently.sql").write_text(
        "-- migrate: no-transaction\n"
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_probe_conc ON assets(source);\n"
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_probe_conc2 ON assets(confidence);\n"
    )
    res = await _up(empty_db, schema_dir=schema_copy)
    assert res.applied == ["099_concurrently.sql"]
    con = await asyncpg.connect(empty_db)
    try:
        assert await con.fetchval("SELECT to_regclass('idx_probe_conc2') IS NOT NULL")
    finally:
        await con.close()


def test_split_statements_respects_quotes_and_dollar_bodies():
    sql = (
        "-- header; with semicolon\n"
        "CREATE TABLE t (v text DEFAULT 'a;b');\n"
        "/* block; comment */\n"
        "DO $$ BEGIN PERFORM 1; END $$;\n"
        "CREATE FUNCTION f() RETURNS int AS $fn$ SELECT 1; $fn$ LANGUAGE sql;\n"
        'SELECT "odd;name" FROM t\n'
    )
    stmts = migrate.split_statements(sql)
    assert len(stmts) == 4
    assert stmts[0].endswith("DEFAULT 'a;b')")
    assert stmts[1].startswith("/* block; comment */") and "PERFORM 1; END $$" in stmts[1]
    assert "$fn$ SELECT 1; $fn$" in stmts[2]
    assert stmts[3] == 'SELECT "odd;name" FROM t'


async def _legacy_apply(dsn, files):
    """The pre-runner approach: execute files directly, record nothing."""
    con = await asyncpg.connect(dsn)
    try:
        for f in files:
            await con.execute(_schema_transform(f))
    finally:
        await con.close()


async def test_baseline_legacy_database(empty_db, schema_copy):
    files = migrate.discover(schema_copy)
    await _legacy_apply(empty_db, files)
    res = await _up(empty_db, schema_dir=schema_copy)
    # Baseline = every file up to the last one whose tables all exist; files
    # after that frontier that create no table (index/patch-only, idempotent)
    # are simply re-run.
    frontier = max(i for i, f in enumerate(files) if f.tables)
    assert res.baselined == [f.filename for f in files[: frontier + 1]]
    assert res.applied == [f.filename for f in files[frontier + 1 :]]
    rows = await _rows(empty_db)
    assert len(rows) == len(files)
    assert all(rows[f.filename]["baselined"] for f in files[: frontier + 1])
    # A file added after the baseline is applied normally.
    (schema_copy / "099_post_baseline.sql").write_text("CREATE TABLE post_bl (id int);\n")
    res = await _up(empty_db, schema_dir=schema_copy)
    assert res.applied == ["099_post_baseline.sql"] and res.baselined == []


async def test_baseline_partial_legacy_database(empty_db, schema_copy):
    """A legacy DB created when only 001-010 existed: those are baselined,
    the rest run for real."""
    files = migrate.discover(schema_copy)
    old = [f for f in files if f.filename < "011"]
    new = [f for f in files if f.filename >= "011"]
    await _legacy_apply(empty_db, old)
    res = await _up(empty_db, schema_dir=schema_copy)
    assert res.baselined == [f.filename for f in old]
    assert res.applied == [f.filename for f in new]


async def test_concurrent_runners_apply_each_file_once(empty_db):
    results = await asyncio.gather(*[_up(empty_db, schema_dir=SCHEMA_DIR) for _ in range(4)])
    applied = [name for r in results for name in r.applied]
    files = [f.filename for f in migrate.discover(SCHEMA_DIR)]
    assert sorted(applied) == sorted(files)  # each exactly once, across runners
    assert len(await _rows(empty_db)) == len(files)


async def test_lock_timeout(empty_db):
    holder = await asyncpg.connect(empty_db)
    try:
        await holder.execute("SELECT pg_advisory_lock($1)", migrate.MIGRATION_LOCK_KEY)
        with pytest.raises(migrate.MigrationLockTimeout):
            await _up(empty_db, schema_dir=SCHEMA_DIR, lock_timeout_sec=1)
    finally:
        await holder.close()


def test_cli_status_verify_up(empty_db, capsys):
    # verify on an empty DB fails (everything pending), up fixes it.
    assert migrate.main(["verify", "--dsn", empty_db, "--schema-dir", str(SCHEMA_DIR)]) == 1
    assert migrate.main(["up", "--dsn", empty_db, "--schema-dir", str(SCHEMA_DIR)]) == 0
    assert migrate.main(["verify", "--dsn", empty_db, "--schema-dir", str(SCHEMA_DIR)]) == 0
    assert migrate.main(["status", "--dsn", empty_db, "--schema-dir", str(SCHEMA_DIR)]) == 0
    out = capsys.readouterr().out
    assert "verify: OK" in out and "0 pending" in out


def test_cli_reports_drift_exit_code(empty_db, schema_copy, capsys):
    assert migrate.main(["up", "--dsn", empty_db, "--schema-dir", str(schema_copy)]) == 0
    f = sorted(schema_copy.glob("001_*.sql"))[0]
    f.write_text(f.read_text() + "\n-- edit\n")
    assert migrate.main(["up", "--dsn", empty_db, "--schema-dir", str(schema_copy)]) == 2
    assert migrate.main(["verify", "--dsn", empty_db, "--schema-dir", str(schema_copy)]) == 1
    assert "DRIFT" in capsys.readouterr().out
    assert migrate.main(
        ["up", "--dsn", empty_db, "--schema-dir", str(schema_copy), "--allow-checksum-drift"]
    ) == 0


async def test_wait_for_until_file(empty_db):
    last = migrate.discover(SCHEMA_DIR)[-1].filename
    # Nothing applied yet: times out.
    assert await migrate.wait_for(empty_db, last, timeout_sec=0.5, poll_sec=0.1) is False
    # Runs concurrently with a migration and returns once it lands.
    waiter = asyncio.create_task(migrate.wait_for(empty_db, last, timeout_sec=60, poll_sec=0.1))
    await _up(empty_db, schema_dir=SCHEMA_DIR)
    assert await waiter is True
    assert await migrate.wait_for(empty_db, "999_never.sql", timeout_sec=0.3, poll_sec=0.1) is False


async def test_tables_added_after_tenancy_get_rls_on_upgrade(empty_db, schema_copy):
    """An install that already ran 099_tenancy.sql must still isolate tables
    created by later migrations: the runner re-asserts tenancy after them."""
    await _up(empty_db, schema_dir=schema_copy)
    (schema_copy / "026_zz_new_feature.sql").write_text(
        "CREATE TABLE IF NOT EXISTS zz_new_feature (id serial PRIMARY KEY, note text);\n"
    )
    res = await _up(empty_db, schema_dir=schema_copy)
    assert res.applied == ["026_zz_new_feature.sql"]
    assert res.reasserted == [migrate.TENANCY_FILE]
    con = await asyncpg.connect(empty_db)
    try:
        rls = await con.fetchrow(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'zz_new_feature'"
        )
        assert rls["relrowsecurity"] and rls["relforcerowsecurity"]
        assert await con.fetchval(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = 'zz_new_feature' AND column_name = 'tenant_id'"
        )
        assert await con.fetchval(
            "SELECT 1 FROM pg_policies WHERE tablename = 'zz_new_feature' AND policyname = 'tenant_isolation'"
        )
    finally:
        await con.close()
    # nothing pending -> nothing re-asserted
    res = await _up(empty_db, schema_dir=schema_copy)
    assert res.applied == [] and res.reasserted == []


async def test_startup_as_non_owner_role_checks_instead_of_migrating(empty_db, schema_copy, monkeypatch):
    """The hardened stack connects the app as a role that may not run DDL. On
    startup it must not try to migrate (that crashed it), but it must refuse
    to serve against a schema that is behind."""
    from app.opsconfig import ops_settings

    await _up(empty_db, schema_dir=schema_copy)
    role = f"nonowner_{uuid.uuid4().hex[:8]}"
    con = await asyncpg.connect(empty_db)
    try:
        await con.execute(f'CREATE ROLE "{role}" LOGIN')
        await con.execute(f'GRANT USAGE ON SCHEMA public TO "{role}"')
    finally:
        await con.close()
    head, _, dbname = empty_db.rpartition("/")
    scheme, _, rest = head.partition("://")
    host = rest.rpartition("@")[2]
    role_dsn = f"{scheme}://{role}@{host}/{dbname}"
    monkeypatch.setattr(ops_settings, "schema_dir", str(schema_copy))

    # can't even read schema_migrations: warn and carry on (the owner migrates)
    assert (await migrate.run_startup_migrations(role_dsn)).applied == []
    con = await asyncpg.connect(empty_db)
    try:
        await con.execute(f'GRANT SELECT ON schema_migrations TO "{role}"')
    finally:
        await con.close()
    # up to date: fine, and nothing applied
    assert (await migrate.run_startup_migrations(role_dsn)).applied == []
    # a pending migration it may not apply: refuse to start
    (schema_copy / "990_zz_pending.sql").write_text("CREATE TABLE zz_pending (id int);\n")
    with pytest.raises(migrate.MigrationError, match="pending"):
        await migrate.run_startup_migrations(role_dsn)
    con = await asyncpg.connect(empty_db)
    try:
        assert await con.fetchval("SELECT to_regclass('zz_pending') IS NULL")
        await con.execute(f'DROP OWNED BY "{role}"; DROP ROLE "{role}"')
    finally:
        await con.close()


# --------------------------------------------------------------------------- #
# P2.1 (WP0): migrations 044 / 045 / 046 (docs/ASSURANCE_P2_1.md D2)
# --------------------------------------------------------------------------- #

P21_FILES = ["044_advisories.sql", "045_agent_identity.sql", "046_assurance_lifecycle.sql"]


async def test_p21_migrations_apply_once_in_order_on_a_fresh_database(empty_db):
    res = await _up(empty_db, schema_dir=SCHEMA_DIR)
    applied = [n for n in res.applied if n in P21_FILES]
    assert applied == P21_FILES
    names = res.applied
    assert names.index("042_agent_v2_hardening.sql") < names.index(P21_FILES[0]) < names.index("099_tenancy.sql")
    assert not any(n.startswith("043_") for n in names)       # 043 stays unused: a numbering gap is tolerated (035 too)
    con = await asyncpg.connect(empty_db)
    try:
        assert (await migrate.migration_status(con, SCHEMA_DIR)).clean
        for t in ("kev_entries", "advisory_snapshots", "agent_manifests", "fleet_agent_pairings", "fleet_conflict_acks"):
            assert await con.fetchval("SELECT to_regclass($1) IS NOT NULL", t), t
    finally:
        await con.close()
    again = await _up(empty_db, schema_dir=SCHEMA_DIR)
    assert again.applied == []


async def test_a_database_at_042_upgrades_to_p21_keeping_its_data_and_getting_rls(empty_db, schema_copy):
    """The real upgrade path: 099 is already recorded, so 044..046 are 'out of order' (applied with a warning) and the
    runner re-asserts tenancy afterwards, which is what gives the new tables their RLS."""
    stash = schema_copy.parent / "stash"
    stash.mkdir()
    for n in P21_FILES:
        shutil.move(str(schema_copy / n), str(stash / n))
    await _up(empty_db, schema_dir=schema_copy)
    con = await asyncpg.connect(empty_db)
    try:
        assert not await con.fetchval("SELECT to_regclass('kev_entries') IS NOT NULL")
        old = datetime.datetime(2026, 2, 2, 10, 0, tzinfo=datetime.timezone.utc)
        await con.execute("INSERT INTO invariants (invariant_id, enabled, updated_at) VALUES ('acme:off', false, $1),"
                          " ('acme:on', true, $1)", old)
        await con.execute("INSERT INTO invariant_runs (invariant_id) VALUES ('acme:on')")
    finally:
        await con.close()
    for n in P21_FILES:
        shutil.move(str(stash / n), str(schema_copy / n))
    res = await _up(empty_db, schema_dir=schema_copy)
    assert res.applied == P21_FILES
    assert res.out_of_order == P21_FILES
    assert res.reasserted == [migrate.TENANCY_FILE]
    con = await asyncpg.connect(empty_db)
    try:
        off = await con.fetchrow("SELECT enabled, disabled_at, archived_at FROM invariants WHERE invariant_id='acme:off'")
        assert off["disabled_at"].isoformat().startswith("2026-02-02T10:00:00") and off["archived_at"] is None
        assert (await con.fetchval("SELECT disabled_at FROM invariants WHERE invariant_id='acme:on'")) is None
        assert await con.fetchval("SELECT pinned FROM invariant_runs WHERE invariant_id='acme:on'") is False
        for t in ("agent_manifests", "agent_manifest_refs", "fleet_agent_pairings", "fleet_conflict_acks"):
            rls = await con.fetchrow("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname=$1", t)
            assert rls["relrowsecurity"] and rls["relforcerowsecurity"], t
            assert await con.fetchval("SELECT count(*) FROM pg_policies WHERE tablename=$1 AND policyname='tenant_isolation'", t) == 1
        for t in ("kev_entries", "advisory_scopes", "advisory_snapshots", "advisory_fixes"):
            pols = {r[0] for r in await con.fetch("SELECT policyname FROM pg_policies WHERE tablename=$1", t)}
            assert pols == {"global_read", "global_platform_write"}, t
            assert not await con.fetchval("SELECT 1 FROM information_schema.columns WHERE table_name=$1 AND column_name='tenant_id'", t)
        assert await con.fetchval("SELECT has_table_privilege('paddock_svc_intel','kev_entries','INSERT')")
        assert (await _up(empty_db, schema_dir=schema_copy)).applied == []
    finally:
        await con.close()


@pytest.mark.parametrize("name", P21_FILES)
async def test_a_p21_migration_edited_after_it_was_applied_is_refused_as_drift(empty_db, schema_copy, name):
    """Applied files are immutable (D2): a later edit is a checksum drift, never silently re-run."""
    await _up(empty_db, schema_dir=schema_copy)
    f = schema_copy / name
    f.write_text(f.read_text() + "\n-- edit after apply\n")
    with pytest.raises(migrate.ChecksumDriftError) as ei:
        await _up(empty_db, schema_dir=schema_copy)
    assert name in str(ei.value)


def test_the_p21_files_declare_the_tables_the_baseliner_looks_for():
    by = {f.filename: f for f in migrate.discover(SCHEMA_DIR)}
    assert set(by["044_advisories.sql"].tables) == {"kev_entries", "advisory_scopes", "advisory_snapshots",
                                                    "advisory_fixes", "agent_manifests", "agent_manifest_refs"}
    assert set(by["045_agent_identity.sql"].tables) == {"fleet_agent_pairings", "fleet_conflict_acks"}
    assert by["046_assurance_lifecycle.sql"].tables == []        # column and index changes only
