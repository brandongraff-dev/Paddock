"""Versioned schema migrations for the raw-SQL files in ``schema/``.

Usage::

    python -m app.migrate up       [--allow-checksum-drift[=FILES]] [--strict-order]
    python -m app.migrate status
    python -m app.migrate verify   # exit 1 on pending / drifted / missing files
    python -m app.migrate wait --until 022_ops.sql --wait 300   # init containers

How it works
------------
* Every ``schema/NNN_<name>.sql`` is a migration, applied in filename order.
* Applied files are recorded in ``schema_migrations`` (filename, sha256
  checksum, applied_at, duration_ms, baselined). The runner creates that
  table itself; it is not part of any numbered file.
* Each file runs in its own transaction (a file whose first lines contain
  ``-- migrate: no-transaction`` runs outside one, for statements such as
  ``CREATE INDEX CONCURRENTLY``). A failing file rolls back and stops the run;
  nothing after it is applied.
* The whole run holds a session-level Postgres advisory lock, so any number of
  orchestrator replicas / Jobs / compose one-shots can start at once: one
  migrates, the others wait, then see nothing pending.

Policy: applied files are immutable
-----------------------------------
A file's checksum is recorded when it is applied. If an applied file later
changes on disk, ``up`` refuses to run (and ``verify`` fails): a change to an
applied file never reaches databases that already ran it, so the schema would
silently fork. Put every change in a NEW numbered file. The single escape
hatch is ``--allow-checksum-drift`` (or ``MIGRATE_ALLOW_CHECKSUM_DRIFT``),
which re-stamps the recorded checksum WITHOUT re-running the file; it exists
for edits proven harmless (comments, whitespace) to the historical,
idempotent files 001-014. See docs/OPERATIONS.md.

Baselining databases created before this runner
------------------------------------------------
Older deployments applied every file through Postgres' initdb hook, so they
have the tables but no ``schema_migrations`` rows. On the first run against
such a database (empty ``schema_migrations`` and any table a schema file
creates already present) the runner baselines: it walks the files in order up
to the last file whose tables all exist, and marks every file in that prefix
whose tables exist (or which creates no table) as applied with
``baselined = TRUE``. Files whose tables are missing are left pending and run
normally; the historical files are ``IF NOT EXISTS`` idempotent, so this is
safe.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import os
import re
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

import asyncpg

logger = logging.getLogger("app.migrate")

# Fixed advisory-lock key ("PADDMIGR"-ish). Distinct from the audit lock.
MIGRATION_LOCK_KEY = 0x5041_4444_4D47

MIGRATION_RE = re.compile(r"^(\d{3,})_[A-Za-z0-9_.\-]+\.sql$")
NO_TX_MARKER = re.compile(r"^\s*--\s*migrate:\s*no-transaction\b", re.IGNORECASE | re.MULTILINE)
_CREATE_TABLE_RE = re.compile(
    r"\bCREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"((?:\"?[A-Za-z_][\w$]*\"?\.)?\"?[A-Za-z_][\w$]*\"?)",
    re.IGNORECASE,
)

SCHEMA_MIGRATIONS_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
  filename     TEXT PRIMARY KEY,
  checksum     TEXT NOT NULL,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  duration_ms  INTEGER NOT NULL DEFAULT 0,
  baselined    BOOLEAN NOT NULL DEFAULT FALSE,
  applied_by   TEXT,
  notes        TEXT
)
"""


class MigrationError(RuntimeError):
    """Base class: the run stopped and the database was left consistent."""


class ChecksumDriftError(MigrationError):
    pass


class MigrationLockTimeout(MigrationError):
    pass


class OutOfOrderError(MigrationError):
    pass


# --------------------------------------------------------------------------- #
# Files
# --------------------------------------------------------------------------- #

TENANCY_FILE = "099_tenancy.sql"  # re-applied after any later migration (step 5)


@dataclass(frozen=True)
class MigrationFile:
    filename: str
    path: Path
    checksum: str
    sql: str
    no_transaction: bool

    @property
    def tables(self) -> list[str]:
        return tables_created(self.sql)


def checksum_of(text: str) -> str:
    """sha256 of the file text with line endings normalised (CRLF checkouts)."""
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def _strip_comments(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    return re.sub(r"--[^\n]*", " ", sql)


def tables_created(sql: str) -> list[str]:
    """Names of the tables a file CREATEs (comments ignored), unquoted."""
    out: list[str] = []
    for m in _CREATE_TABLE_RE.finditer(_strip_comments(sql)):
        name = m.group(1).replace('"', "")
        if name.lower() not in {n.lower() for n in out}:
            out.append(name)
    return out


def split_statements(sql: str) -> list[str]:
    """Split SQL on top-level ``;`` (quotes, dollar-quotes, comments aware).

    Used for ``no-transaction`` files: Postgres runs a multi-statement simple
    query as ONE implicit transaction, which ``CREATE INDEX CONCURRENTLY``
    refuses, so such files are executed one statement at a time.
    """
    out: list[str] = []
    buf: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c == "-" and sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j == -1 else j
            buf.append(sql[i:j])
            i = j
            continue
        if c == "/" and sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            j = n if j == -1 else j + 2
            buf.append(sql[i:j])
            i = j
            continue
        if c in ("'", '"'):
            j = i + 1
            while j < n:
                if sql[j] == c:
                    if j + 1 < n and sql[j + 1] == c:  # doubled quote escape
                        j += 2
                        continue
                    break
                j += 1
            buf.append(sql[i : j + 1])
            i = j + 1
            continue
        if c == "$":
            m = re.match(r"\$[A-Za-z_]*\$", sql[i:])
            if m:
                tag = m.group(0)
                j = sql.find(tag, i + len(tag))
                j = n if j == -1 else j + len(tag)
                buf.append(sql[i:j])
                i = j
                continue
        if c == ";":
            stmt = "".join(buf).strip()
            if _strip_comments(stmt).strip():
                out.append(stmt)
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    tail = "".join(buf).strip()
    if _strip_comments(tail).strip():
        out.append(tail)
    return out


def resolve_schema_dir(explicit: str | os.PathLike[str] | None = None) -> Path:
    from .opsconfig import ops_settings

    candidates: list[Path] = []
    for c in (explicit, os.environ.get("SCHEMA_DIR"), ops_settings.schema_dir):
        if c:
            candidates.append(Path(c))
    here = Path(__file__).resolve()
    candidates += [here.parents[1] / "schema", here.parents[2] / "schema", Path("/schema")]
    for c in candidates:
        if c.is_dir() and any(c.glob("*.sql")):
            return c
    raise MigrationError(
        "schema directory not found; set SCHEMA_DIR (tried: "
        + ", ".join(str(c) for c in candidates) + ")"
    )


def discover(schema_dir: str | os.PathLike[str] | None = None) -> list[MigrationFile]:
    """Every NNN_*.sql in the schema dir, in filename order."""
    d = resolve_schema_dir(schema_dir)
    files: list[MigrationFile] = []
    for p in sorted(d.iterdir(), key=lambda p: p.name):
        if not p.is_file() or not MIGRATION_RE.match(p.name):
            if p.suffix == ".sql":
                logger.warning("migrate_ignoring_file", extra={"file": p.name})
            continue
        text = p.read_text(encoding="utf-8")
        head = "\n".join(text.splitlines()[:5])
        files.append(
            MigrationFile(
                filename=p.name,
                path=p,
                checksum=checksum_of(text),
                sql=text,
                no_transaction=bool(NO_TX_MARKER.search(head)),
            )
        )
    return files


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #

@dataclass
class Plan:
    files: list[MigrationFile]
    applied: dict[str, asyncpg.Record]
    pending: list[MigrationFile] = field(default_factory=list)
    drifted: list[tuple[MigrationFile, str]] = field(default_factory=list)  # (file, recorded)
    missing: list[str] = field(default_factory=list)  # recorded but no longer on disk
    out_of_order: list[str] = field(default_factory=list)
    baseline: list[MigrationFile] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.pending or self.drifted or self.missing or self.baseline)


async def _table_exists(con: asyncpg.Connection, name: str) -> bool:
    return bool(await con.fetchval("SELECT to_regclass($1) IS NOT NULL", name))


async def _baseline_candidates(
    con: asyncpg.Connection, files: list[MigrationFile]
) -> list[MigrationFile]:
    """Files a legacy (pre-runner) database already has applied."""
    exists: dict[str, bool] = {}
    for f in files:
        for t in f.tables:
            if t not in exists:
                exists[t] = await _table_exists(con, t)
    if not any(exists.values()):
        return []  # brand-new database: nothing to baseline
    frontier = -1
    for i, f in enumerate(files):
        if f.tables and all(exists[t] for t in f.tables):
            frontier = i
    return [
        f for f in files[: frontier + 1]
        if not f.tables or all(exists[t] for t in f.tables)
    ]


async def build_plan(con: asyncpg.Connection, files: list[MigrationFile]) -> Plan:
    has_table = await _table_exists(con, "schema_migrations")
    rows = await con.fetch("SELECT * FROM schema_migrations") if has_table else []
    applied = {r["filename"]: r for r in rows}
    plan = Plan(files=files, applied=applied)
    on_disk = {f.filename for f in files}
    plan.missing = sorted(n for n in applied if n not in on_disk)

    if not applied:
        plan.baseline = await _baseline_candidates(con, files)
    baselined = {f.filename for f in plan.baseline}

    last_applied = max(applied) if applied else ""
    for f in files:
        rec = applied.get(f.filename)
        if rec is None:
            if f.filename in baselined:
                continue
            plan.pending.append(f)
            if last_applied and f.filename < last_applied:
                plan.out_of_order.append(f.filename)
        elif rec["checksum"] != f.checksum:
            plan.drifted.append((f, rec["checksum"]))
    return plan


# --------------------------------------------------------------------------- #
# Locking + execution
# --------------------------------------------------------------------------- #

async def _acquire_lock(con: asyncpg.Connection, timeout_sec: float) -> None:
    deadline = time.monotonic() + timeout_sec
    waited = False
    while True:
        if await con.fetchval("SELECT pg_try_advisory_lock($1)", MIGRATION_LOCK_KEY):
            if waited:
                logger.info("migrate_lock_acquired_after_wait")
            return
        if not waited:
            logger.info("migrate_waiting_for_lock (another runner is migrating)")
            waited = True
        if time.monotonic() >= deadline:
            raise MigrationLockTimeout(
                f"could not acquire migration lock within {timeout_sec:.0f}s"
            )
        await asyncio.sleep(0.5)


async def _release_lock(con: asyncpg.Connection) -> None:
    try:
        await con.execute("SELECT pg_advisory_unlock($1)", MIGRATION_LOCK_KEY)
    except Exception:  # noqa: BLE001 -- the lock dies with the session anyway
        logger.warning("migrate_lock_release_failed")


def _parse_allow(allow: str | Iterable[str] | bool | None) -> set[str] | bool:
    if allow is True:
        return True
    if not allow:
        return set()
    if isinstance(allow, str):
        items = [a.strip() for a in allow.split(",") if a.strip()]
    else:
        items = [str(a).strip() for a in allow]
    if any(a in {"*", "all", "true", "1"} for a in items):
        return True
    return set(items)


@dataclass
class RunResult:
    applied: list[str] = field(default_factory=list)
    baselined: list[str] = field(default_factory=list)
    restamped: list[str] = field(default_factory=list)
    out_of_order: list[str] = field(default_factory=list)
    durations_ms: dict[str, int] = field(default_factory=dict)
    reasserted: list[str] = field(default_factory=list)


async def migrate_up(
    con: asyncpg.Connection,
    *,
    schema_dir: str | os.PathLike[str] | None = None,
    allow_checksum_drift: str | Iterable[str] | bool | None = None,
    strict_order: bool = False,
    lock_timeout_sec: float = 300,
    transform: Callable[[MigrationFile], str] | None = None,
    applied_by: str | None = None,
) -> RunResult:
    """Apply every pending migration on ``con`` under the advisory lock.

    ``transform`` may rewrite a file's SQL before execution (tests use it for
    a historical keyword workaround); the RECORDED checksum is always that of
    the file on disk.
    """
    files = discover(schema_dir)
    allow = _parse_allow(allow_checksum_drift)
    applied_by = applied_by or os.environ.get("HOSTNAME") or "migrate"
    result = RunResult()

    await _acquire_lock(con, lock_timeout_sec)
    try:
        await con.execute(SCHEMA_MIGRATIONS_DDL)
        plan = await build_plan(con, files)

        # 1. Drift: refuse unless explicitly allowed for that file.
        refused = [
            (f, old) for f, old in plan.drifted
            if not (allow is True or f.filename in allow)  # type: ignore[operator]
        ]
        if refused:
            names = ", ".join(f.filename for f, _ in refused)
            raise ChecksumDriftError(
                f"applied migration(s) changed on disk: {names}. Applied files "
                "are immutable -- put the change in a new numbered file. If the "
                "edit is provably harmless (comments/whitespace in an idempotent "
                "historical file) re-run with --allow-checksum-drift=" + names
            )
        for f, old in plan.drifted:
            await con.execute(
                "UPDATE schema_migrations SET checksum = $2, notes = "
                "concat_ws('; ', notes, $3::text) WHERE filename = $1",
                f.filename,
                f.checksum,
                f"checksum re-stamped from {old[:12]} at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
            )
            logger.warning("migrate_checksum_restamped", extra={"file": f.filename})
            result.restamped.append(f.filename)

        if plan.missing:
            logger.warning(
                "migrate_applied_files_missing_on_disk",
                extra={"files": plan.missing},
            )

        # 2. Baseline a legacy database.
        if plan.baseline:
            async with con.transaction():
                for f in plan.baseline:
                    await con.execute(
                        "INSERT INTO schema_migrations "
                        "(filename, checksum, duration_ms, baselined, applied_by, notes) "
                        "VALUES ($1, $2, 0, TRUE, $3, 'baselined: objects pre-existed') "
                        "ON CONFLICT (filename) DO NOTHING",
                        f.filename,
                        f.checksum,
                        applied_by,
                    )
                    result.baselined.append(f.filename)
            logger.info("migrate_baselined", extra={"count": len(plan.baseline)})

        # 3. Out-of-order files (merged after a later number was applied).
        if plan.out_of_order:
            if strict_order:
                raise OutOfOrderError(
                    "pending file(s) sort before the last applied migration: "
                    + ", ".join(plan.out_of_order)
                )
            logger.warning("migrate_out_of_order", extra={"files": plan.out_of_order})
            result.out_of_order = list(plan.out_of_order)

        # 4. Apply.
        for f in plan.pending:
            sql = transform(f) if transform else f.sql
            t0 = time.perf_counter()
            try:
                if f.no_transaction:
                    # Not atomic: a failure part-way leaves earlier statements
                    # applied and the file unrecorded, so write such files to
                    # be re-runnable (IF NOT EXISTS).
                    for stmt in split_statements(sql):
                        await con.execute(stmt)
                    ms = int((time.perf_counter() - t0) * 1000)
                    await _record(con, f, ms, applied_by)
                else:
                    async with con.transaction():
                        await con.execute(sql)
                        ms = int((time.perf_counter() - t0) * 1000)
                        await _record(con, f, ms, applied_by)
            except Exception as exc:
                raise MigrationError(f"{f.filename} failed: {exc}") from exc
            result.applied.append(f.filename)
            result.durations_ms[f.filename] = ms
            logger.info("migrate_applied", extra={"file": f.filename, "duration_ms": ms})

        # 5. Re-assert tenancy. 099_tenancy.sql walks EVERY table and adds
        #    tenant_id + row-level security; it is idempotent. On an upgrade it
        #    is already recorded, so a table created by a newer file (026, 027…)
        #    would otherwise ship with no tenant isolation at all.
        tenancy = next((f for f in files if f.filename == TENANCY_FILE), None)
        if tenancy is not None and any(n != TENANCY_FILE for n in result.applied):
            sql = transform(tenancy) if transform else tenancy.sql
            try:
                async with con.transaction():
                    await con.execute(sql)
            except Exception as exc:
                raise MigrationError(f"re-applying {TENANCY_FILE} failed: {exc}") from exc
            result.reasserted.append(TENANCY_FILE)
            logger.info("migrate_tenancy_reasserted", extra={"after": result.applied})
    finally:
        await _release_lock(con)
    return result


async def _record(con: asyncpg.Connection, f: MigrationFile, ms: int, by: str) -> None:
    await con.execute(
        "INSERT INTO schema_migrations (filename, checksum, duration_ms, applied_by) "
        "VALUES ($1, $2, $3, $4)",
        f.filename,
        f.checksum,
        ms,
        by,
    )


async def migration_status(
    con: asyncpg.Connection, schema_dir: str | os.PathLike[str] | None = None
) -> Plan:
    return await build_plan(con, discover(schema_dir))


# --------------------------------------------------------------------------- #
# DSN / startup helpers
# --------------------------------------------------------------------------- #

def default_dsn() -> str:
    from .config import settings
    from .db import _coerce_dsn
    from .opsconfig import ops_settings

    return _coerce_dsn(
        os.environ.get("MIGRATE_DATABASE_URL")
        or ops_settings.migrate_database_url
        or settings.database_url
    )


async def connect(dsn: str | None = None, wait_sec: float = 60) -> asyncpg.Connection:
    """Connect with retries (the DB may still be starting in compose / k8s)."""
    dsn = dsn or default_dsn()
    deadline = time.monotonic() + wait_sec
    delay = 0.5
    while True:
        try:
            return await asyncpg.connect(dsn, command_timeout=None, timeout=10)
        except (OSError, asyncpg.CannotConnectNowError, asyncpg.PostgresConnectionError) as exc:
            if time.monotonic() >= deadline:
                raise MigrationError(f"database not reachable: {exc}") from exc
            logger.info("migrate_waiting_for_database")
            await asyncio.sleep(delay)
            delay = min(delay * 2, 5)


async def run_startup_migrations(dsn: str | None = None) -> RunResult:
    """Called from the orchestrator lifespan when MIGRATE_ON_STARTUP is on."""
    from .opsconfig import ops_settings

    con = await connect(dsn)
    try:
        return await migrate_up(
            con,
            schema_dir=ops_settings.schema_dir,
            allow_checksum_drift=ops_settings.migrate_allow_checksum_drift,
            lock_timeout_sec=ops_settings.migrate_lock_timeout_sec,
        )
    finally:
        await con.close()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _print_status(plan: Plan) -> None:
    drift = {f.filename for f, _ in plan.drifted}
    pending = {f.filename for f in plan.pending}
    base = {f.filename for f in plan.baseline}
    print(f"{'STATE':<10} {'FILE':<40} {'APPLIED_AT':<26} {'MS':>7}")
    for f in plan.files:
        rec = plan.applied.get(f.filename)
        if f.filename in drift:
            state = "DRIFT"
        elif f.filename in pending:
            state = "PENDING"
        elif f.filename in base:
            state = "BASELINE"  # would be baselined on next `up`
        elif rec is not None and rec["baselined"]:
            state = "baselined"
        else:
            state = "applied"
        at = rec["applied_at"].isoformat(timespec="seconds") if rec else "-"
        ms = str(rec["duration_ms"]) if rec else "-"
        print(f"{state:<10} {f.filename:<40} {at:<26} {ms:>7}")
    for name in plan.missing:
        print(f"{'MISSING':<10} {name:<40} (recorded as applied, not on disk)")
    print(
        f"\n{len(plan.applied)} applied, {len(plan.pending)} pending, "
        f"{len(plan.drifted)} drifted, {len(plan.missing)} missing, "
        f"{len(plan.baseline)} to baseline"
    )


async def wait_for(
    dsn: str | None, until: str | None, timeout_sec: float, poll_sec: float = 2.0
) -> bool:
    """Block until ``until`` (a filename) is recorded in schema_migrations --
    or, without ``until``, until nothing on disk is pending. Used by pod init
    containers so app pods never start against a half-migrated schema."""
    deadline = time.monotonic() + timeout_sec
    while True:
        try:
            con = await connect(dsn, wait_sec=max(1.0, deadline - time.monotonic()))
            try:
                if await _table_exists(con, "schema_migrations"):
                    if until:
                        if await con.fetchval(
                            "SELECT 1 FROM schema_migrations WHERE filename = $1", until
                        ):
                            return True
                    else:
                        plan = await migration_status(con)
                        if not (plan.pending or plan.baseline):
                            return True
            finally:
                await con.close()
        except MigrationError:
            pass
        if time.monotonic() >= deadline:
            return False
        logger.info("migrate_wait_pending", extra={"until": until})
        await asyncio.sleep(poll_sec)


async def _amain(args: argparse.Namespace) -> int:
    from .opsconfig import ops_settings

    if args.command == "wait":
        ok = await wait_for(args.dsn, args.until, args.wait)
        print("schema ready" if ok else "timed out waiting for schema migrations")
        return 0 if ok else 1

    con = await connect(args.dsn, wait_sec=args.wait)
    try:
        if args.command == "up":
            allow = args.allow_checksum_drift
            if allow is None:
                allow = ops_settings.migrate_allow_checksum_drift
            res = await migrate_up(
                con,
                schema_dir=args.schema_dir or ops_settings.schema_dir,
                allow_checksum_drift=allow,
                strict_order=args.strict_order,
                lock_timeout_sec=args.lock_timeout or ops_settings.migrate_lock_timeout_sec,
            )
            for name in res.baselined:
                print(f"baselined  {name}")
            for name in res.restamped:
                print(f"re-stamped {name} (checksum drift allowed)")
            for name in res.applied:
                print(f"applied    {name} ({res.durations_ms[name]} ms)")
            if not (res.applied or res.baselined or res.restamped):
                print("schema up to date")
            return 0
        plan = await migration_status(con, args.schema_dir or ops_settings.schema_dir)
        _print_status(plan)
        if args.command == "verify":
            if plan.clean:
                print("verify: OK")
                return 0
            print("verify: FAILED (pending, drifted, missing or un-baselined files)")
            return 1
        return 0
    finally:
        await con.close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.migrate", description=__doc__.split("\n")[0])
    p.add_argument("command", choices=["up", "status", "verify", "wait"])
    p.add_argument("--until", default=None, metavar="FILE",
                   help="wait: block until FILE is recorded as applied")
    p.add_argument("--dsn", default=None, help="override MIGRATE_DATABASE_URL / DATABASE_URL")
    p.add_argument("--schema-dir", default=None, help="override SCHEMA_DIR")
    p.add_argument(
        "--allow-checksum-drift",
        nargs="?",
        const="*",
        default=None,
        metavar="FILES",
        help="re-stamp changed applied files (comma list; bare flag = all)",
    )
    p.add_argument("--strict-order", action="store_true",
                   help="refuse pending files that sort before the last applied one")
    p.add_argument("--lock-timeout", type=float, default=None, help="seconds to wait for the lock")
    p.add_argument("--wait", type=float, default=60, help="seconds to wait for the database")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    try:
        return asyncio.run(_amain(args))
    except MigrationError as exc:
        print(f"migrate: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
