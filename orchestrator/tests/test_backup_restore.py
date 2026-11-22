"""Round-trip scripts/backup.sh -> scripts/restore.sh into a fresh database.

Uses the test Postgres server (the db_pool fixture's migrated DB as the
source, a brand-new empty DB as the target). Skipped when pg_dump /
pg_restore / psql are not on PATH. The age variant also needs `age` and
`age-keygen`.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import asyncpg
import pytest

from app import audit

REPO = Path(__file__).resolve().parents[2]
BACKUP = REPO / "scripts" / "backup.sh"
RESTORE = REPO / "scripts" / "restore.sh"

pytestmark = pytest.mark.skipif(
    not all(shutil.which(b) for b in ("pg_dump", "pg_restore", "psql", "bash", "sha256sum")),
    reason="needs pg_dump/pg_restore/psql/sha256sum on PATH",
)

TABLES = ("scope_entries", "assets", "findings", "audit_log", "schema_migrations")


def _dsn_of(proc, db: str) -> str:
    auth = f"{proc.user}:{proc.password}" if proc.password else proc.user
    return f"postgresql://{auth}@{proc.host}:{proc.port}/{db}"


async def _fingerprint(dsn: str) -> dict[str, object]:
    con = await asyncpg.connect(dsn)
    try:
        out: dict[str, object] = {}
        for t in TABLES:
            out[t] = await con.fetchval(f"SELECT md5(string_agg(t::text, '|' ORDER BY t::text)) FROM {t} t")
            out[t + "#"] = await con.fetchval(f"SELECT count(*) FROM {t}")
        return out
    finally:
        await con.close()


def _run(script: Path, env: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    full = {**os.environ, **env}
    full.pop("PGHOST", None)
    return subprocess.run(
        ["bash", str(script), *args], env=full, capture_output=True, text=True, timeout=300
    )


async def _seed(db_pool):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO scope_entries (kind, value, added_by) VALUES ('domain','bk.example','t')"
        )
        aid = await con.fetchval(
            "INSERT INTO assets (kind, value, canonical, source) "
            "VALUES ('domain','bk.example','bk.example','t') RETURNING id"
        )
        await con.execute(
            "INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description, "
            '"references") VALUES ($1, \'r1\', \'manual\', \'high\', \'T\', \'D\', ARRAY[\'x\'])',
            aid,
        )
    for i in range(5):
        await audit.record(db_pool, action="create", actor=f"backup-test-{i}", details={"i": i})


async def _fresh_db(proc) -> tuple[str, str]:
    name = f"restore_{uuid.uuid4().hex[:10]}"
    admin = await asyncpg.connect(_dsn_of(proc, "postgres"))
    await admin.execute(f'CREATE DATABASE "{name}"')
    await admin.close()
    return name, _dsn_of(proc, name)


async def _drop_db(proc, name: str) -> None:
    admin = await asyncpg.connect(_dsn_of(proc, "postgres"))
    await admin.execute(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1", name
    )
    await admin.execute(f'DROP DATABASE IF EXISTS "{name}"')
    await admin.close()


@pytest.mark.parametrize("encrypt,via_sql", [("none", False), ("age", False), ("none", True)])
async def test_backup_restore_round_trip(db_pool, postgresql_my_proc, tmp_path, encrypt, via_sql):
    if encrypt == "age" and not (shutil.which("age") and shutil.which("age-keygen")):
        pytest.skip("age not installed")
    await _seed(db_pool)
    async with db_pool.acquire() as con:
        src_db = await con.fetchval("SELECT current_database()")
    src = _dsn_of(postgresql_my_proc, src_db)
    before = await _fingerprint(src)

    env = {"DATABASE_URL": src, "BACKUP_DIR": str(tmp_path / "bk"), "BACKUP_ENCRYPT": encrypt}
    if encrypt == "age":
        key = tmp_path / "age.key"
        subprocess.run(["age-keygen", "-o", str(key)], check=True, capture_output=True)
        pub = subprocess.run(["age-keygen", "-y", str(key)], check=True,
                             capture_output=True, text=True).stdout.strip()
        env["AGE_RECIPIENT"] = pub
    res = _run(BACKUP, env)
    assert res.returncode == 0, res.stderr
    artifact = Path(res.stdout.strip().splitlines()[-1])
    assert artifact.exists() and Path(f"{artifact}.sha256").exists()
    meta = Path(f"{artifact}.meta").read_text()
    assert re.search(r"^last_migration=\d{3,}_\w+\.sql$", meta, re.M), meta
    assert f"encryption={encrypt}" in meta
    assert oct(artifact.stat().st_mode & 0o777) == "0o600"
    if encrypt == "age":
        assert artifact.suffix == ".age"
        assert not list((tmp_path / "bk").glob("*.dump"))  # no plaintext left behind

    name, target = await _fresh_db(postgresql_my_proc)
    try:
        # via_sql: the path taken when client tools are newer than the server
        # (pg_restore 17+ against a 16 server); forced here so it is always tested.
        renv = {"RESTORE_DATABASE_URL": target, "RESTORE_VIA_SQL": "1" if via_sql else "0"}
        if encrypt == "age":
            renv["AGE_IDENTITY"] = str(tmp_path / "age.key")
        res = _run(RESTORE, renv, str(artifact))
        assert res.returncode == 0, res.stderr
        assert await _fingerprint(target) == before

        # The restored audit hash chain still verifies end to end.
        pool = await asyncpg.create_pool(target, min_size=1, max_size=2)
        try:
            v = await audit.verify(pool)
            assert v["ok"] is True and v["checked"] >= 5
        finally:
            await pool.close()

        # Non-empty target: refused without confirmation, then allowed.
        res = _run(RESTORE, renv, str(artifact))
        assert res.returncode != 0 and "OVERWRITTEN" in res.stderr
        res = _run(RESTORE, {**renv, "RESTORE_CONFIRM": "yes"}, str(artifact))
        assert res.returncode == 0, res.stderr
        assert await _fingerprint(target) == before
    finally:
        await _drop_db(postgresql_my_proc, name)


async def test_restore_refuses_tampered_backup(db_pool, postgresql_my_proc, tmp_path):
    async with db_pool.acquire() as con:
        src_db = await con.fetchval("SELECT current_database()")
    res = _run(BACKUP, {"DATABASE_URL": _dsn_of(postgresql_my_proc, src_db),
                        "BACKUP_DIR": str(tmp_path)})
    assert res.returncode == 0, res.stderr
    artifact = Path(res.stdout.strip().splitlines()[-1])
    with open(artifact, "ab") as fh:
        fh.write(b"tamper")
    name, target = await _fresh_db(postgresql_my_proc)
    try:
        res = _run(RESTORE, {"RESTORE_DATABASE_URL": target}, str(artifact))
        assert res.returncode != 0 and "checksum mismatch" in res.stderr
    finally:
        await _drop_db(postgresql_my_proc, name)


def test_backup_retention_keeps_min_and_prunes_old(tmp_path):
    """Retention logic only (no DB): fake old artifacts get pruned."""
    bk = tmp_path / "bk"
    bk.mkdir()
    for i in range(6):
        f = bk / f"paddock-asm-2020010{i}T000000Z.dump"
        f.write_bytes(b"x")
        (bk / (f.name + ".sha256")).write_text("x")
        os.utime(f, (946684800 + i, 946684800 + i))  # year 2000: very old
    script = BACKUP.read_text()
    retention = script[script.index("# ---- retention"):script.index('printf \'%s\\n\' "$final"')]
    prog = (
        "set -euo pipefail\nlog(){ :; }\n"
        f"BACKUP_DIR={bk}\nBACKUP_RETENTION_DAYS=14\nBACKUP_MIN_KEEP=3\n" + retention
    )
    subprocess.run(["bash", "-c", prog], check=True)
    left = sorted(p.name for p in bk.glob("*.dump"))
    assert left == [f"paddock-asm-2020010{i}T000000Z.dump" for i in (3, 4, 5)]
    assert len(list(bk.glob("*.sha256"))) == 3
