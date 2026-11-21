"""Versioned migration runner (app/migrate.py).

Each test gets an EMPTY database (no schema) and, where it mutates schema
files, a private copy of schema/ in tmp_path, so the real files are never
touched.
"""
from __future__ import annotations

import asyncio
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
