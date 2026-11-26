"""P2.1 retention policies (WP0): docs/ASSURANCE_P2_1.md 1.11 (advisories, manifests) and 6.2 (invariant_runs, D34).

Existing purge behaviour is covered by test_ops.py and test_fleet_principal.py; this file pins what P2.1 adds:
  * ``invariant_runs`` older than RETENTION_INVARIANT_RUNS_DAYS (365; <= 0 keeps all) go, EXCEPT the newest row of each
    (tenant, invariant) (the "since when" anchor) and pinned rows;
  * unreferenced ``agent_manifests`` after 7 days (a referenced one never);
  * ``advisory_snapshots``: the last 14 per (source, scope) stay, every ``rejected`` row goes after 90 days, a snapshot a
    live advisory row still points at never goes; ``advisory_fixes`` removed rows go after 30 days;
  * the global tables are purged as the platform tenant only.
"""
from __future__ import annotations

import datetime as dt
import uuid

import pytest

from app import retention, tenancy

from .test_isolation_sweep import TENANT_A, TENANT_B

PLATFORM = tenancy.DEFAULT_TENANT_ID
NOW = dt.datetime.now(dt.timezone.utc)


def _ago(days: float) -> dt.datetime:
    return NOW - dt.timedelta(days=days)


def _sha(n: int) -> str:
    return f"{n:064x}"


def _by_table(pols):
    out: dict[str, list] = {}
    for p in pols:
        out.setdefault(p.table, []).append(p)
    return out


# --------------------------------------------------------------------------- #
# the policy list
# --------------------------------------------------------------------------- #

def test_the_p21_policies_are_registered_with_the_contract_horizons(monkeypatch):
    for v in ("RETENTION_INVARIANT_RUNS_DAYS", "RETENTION_AGENT_MANIFESTS_DAYS", "RETENTION_ADVISORY_REJECTED_DAYS",
              "RETENTION_ADVISORY_FIXES_DAYS", "RETENTION_ADVISORY_SNAPSHOTS_DAYS"):
        monkeypatch.delenv(v, raising=False)
    by = _by_table(retention.configured_policies())
    assert [(p.column, p.days) for p in by["invariant_runs"]] == [("evaluated_at", 365)]
    assert [(p.column, p.days) for p in by["agent_manifests"]] == [("last_ref_at", 7)]
    assert [(p.column, p.days) for p in by["advisory_fixes"]] == [("removed_at", 30)]
    snaps = {p.days: p for p in by["advisory_snapshots"]}
    assert 90 in snaps and "status = 'rejected'" in snaps[90].where
    assert len(by["advisory_snapshots"]) == 2
    for p in by["invariant_runs"] + by["agent_manifests"] + by["advisory_fixes"] + by["advisory_snapshots"]:
        p.validate()
        assert p.table not in retention.NEVER_PURGE


def test_the_invariant_runs_policy_guards_the_anchor_and_pinned_rows():
    (p,) = _by_table(retention.configured_policies())["invariant_runs"]
    w = " ".join(p.where.split())
    assert "NOT pinned" in w and "EXISTS" in w
    assert "n.invariant_id = invariant_runs.invariant_id" in w and "n.tenant_id = invariant_runs.tenant_id" in w
    assert "n.evaluated_at > invariant_runs.evaluated_at" in w


def test_the_global_policies_are_platform_only_and_the_tenant_ones_are_not():
    by = _by_table(retention.configured_policies())
    for t in ("advisory_snapshots", "advisory_fixes"):
        assert all(p.platform_only for p in by[t]), t
    for t in ("invariant_runs", "agent_manifests", "agent_posture", "agent_inventory"):
        assert not any(p.platform_only for p in by[t]), t


def test_fixes_are_purged_before_the_snapshots_they_point_at():
    tables = [p.table for p in retention.configured_policies()]
    assert tables.index("advisory_fixes") < tables.index("advisory_snapshots")


def test_the_environment_overrides_and_zero_disables(monkeypatch):
    monkeypatch.setenv("RETENTION_INVARIANT_RUNS_DAYS", "30")
    monkeypatch.setenv("RETENTION_AGENT_MANIFESTS_DAYS", "0")
    monkeypatch.setenv("RETENTION_ADVISORY_FIXES_DAYS", "3")
    monkeypatch.setenv("RETENTION_ADVISORY_REJECTED_DAYS", "9")
    by = _by_table(retention.configured_policies())
    assert by["invariant_runs"][0].days == 30
    assert by["agent_manifests"][0].days == 0                     # <= 0 is disabled by run_retention
    assert by["advisory_fixes"][0].days == 3
    assert sorted(p.days for p in by["advisory_snapshots"] if "status = 'rejected'" in p.where) == [9]
    monkeypatch.setenv("RETENTION_INVARIANT_RUNS_DAYS", "not-a-number")
    assert _by_table(retention.configured_policies())["invariant_runs"][0].days == 365   # falls back, never crashes


def test_the_module_docstring_lists_every_p21_table():
    for t in ("invariant_runs", "agent_manifests", "advisory_snapshots", "advisory_fixes"):
        assert t in retention.__doc__, t
    assert "RETENTION_INVARIANT_RUNS_DAYS" in retention.__doc__


def test_audit_log_and_the_ledger_stay_unpurgeable():
    for t in ("audit_log", "schema_migrations"):
        with pytest.raises(retention.RetentionPolicyError):
            retention.Policy(t, "ts", 1).validate()


# --------------------------------------------------------------------------- #
# invariant_runs (6.2): "delete rows older than N days EXCEPT the newest row of each (tenant, invariant)"
# --------------------------------------------------------------------------- #

async def _tenants(db_pool):
    for slug, tid in (("ret-a", TENANT_A), ("ret-b", TENANT_B)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)


async def _run(con, tenant, inv, age_days, *, pinned=False):
    return await con.fetchval(
        "INSERT INTO invariant_runs (tenant_id, invariant_id, evaluated_at, pinned) VALUES ($1,$2,$3,$4) RETURNING id",
        uuid.UUID(tenant), inv, _ago(age_days), pinned)


async def _alive(con, ids):
    rows = await con.fetch("SELECT id FROM invariant_runs WHERE id = ANY($1::uuid[])", list(ids))
    return {r["id"] for r in rows}


async def test_old_runs_are_purged_but_the_newest_row_of_each_invariant_and_pinned_rows_stay(db_pool):
    await _tenants(db_pool)
    async with db_pool.acquire() as con:
        a_old = [await _run(con, TENANT_A, "acme:x", d) for d in (400, 380, 370)]
        a_new = await _run(con, TENANT_A, "acme:x", 10)
        a_recent_old = await _run(con, TENANT_A, "acme:x", 300)            # inside the horizon: stays
        a_only = await _run(con, TENANT_A, "acme:y", 500)                  # the ONLY row, older than the horizon: the anchor
        a_pinned = await _run(con, TENANT_A, "acme:x", 450, pinned=True)   # pinned: never deleted
        b_old = await _run(con, TENANT_B, "acme:x", 401)                   # same invariant id, other tenant
        b_newest_old = await _run(con, TENANT_B, "acme:x", 400)            # newest of ITS invariant: stays
        z_old = await _run(con, TENANT_A, "acme:z", 700)
        z_old2 = await _run(con, TENANT_A, "acme:z", 366)                  # newest of acme:z although older than the horizon
    counts = await retention.run_retention(db_pool)
    assert counts["invariant_runs"] == 3 + 1 + 1                           # a_old x3, b_old, z_old
    async with db_pool.acquire() as con:
        alive = await _alive(con, a_old + [a_new, a_recent_old, a_only, a_pinned, b_old, b_newest_old, z_old, z_old2])
    assert alive == {a_new, a_recent_old, a_only, a_pinned, b_newest_old, z_old2}
    # idempotent: a second run has nothing more to do
    assert (await retention.run_retention(db_pool))["invariant_runs"] == 0


async def test_the_newest_row_survives_even_when_every_row_is_old(db_pool):
    async with db_pool.acquire() as con:
        ids = [await _run(con, PLATFORM, "acme:old", d) for d in (900, 800, 700, 600)]
    await retention.run_retention(db_pool)
    async with db_pool.acquire() as con:
        assert await _alive(con, ids) == {ids[-1]}                         # the 600-day-old row is the anchor


async def test_a_zero_horizon_keeps_every_run(db_pool, monkeypatch):
    monkeypatch.setenv("RETENTION_INVARIANT_RUNS_DAYS", "0")
    async with db_pool.acquire() as con:
        ids = [await _run(con, PLATFORM, "acme:keep", d) for d in (900, 800, 5)]
    counts = await retention.run_retention(db_pool)
    assert counts.get("invariant_runs", 0) == 0
    async with db_pool.acquire() as con:
        assert await _alive(con, ids) == set(ids)


async def test_the_purge_runs_per_tenant_under_rls_and_never_touches_another_tenants_anchor(db_pool, app_pool):
    await _tenants(db_pool)
    async with db_pool.acquire() as con:
        a = [await _run(con, TENANT_A, "acme:x", d) for d in (500, 20)]
        b = [await _run(con, TENANT_B, "acme:x", d) for d in (500, 20)]
    counts = await retention.run_retention(app_pool)                       # the non-superuser role: RLS enforced
    assert counts["invariant_runs"] == 2
    async with db_pool.acquire() as con:
        assert await _alive(con, a + b) == {a[1], b[1]}


# --------------------------------------------------------------------------- #
# agent_manifests (1.11): GC of UNREFERENCED lists after 7 days
# --------------------------------------------------------------------------- #

async def _manifest(con, tenant, sha, age_days):
    return await con.fetchval(
        "INSERT INTO agent_manifests (tenant_id, sha256, last_ref_at, created_at) VALUES ($1,$2,$3,$3) RETURNING id",
        uuid.UUID(tenant), sha, _ago(age_days))


async def _ref(con, tenant, sha):
    await con.execute("SET session_replication_role = replica")           # FK to fleet_agents off: only the key under test
    try:
        await con.execute("INSERT INTO agent_manifest_refs (tenant_id, agent_id, manifest_sha) VALUES ($1,$2,$3)",
                          uuid.UUID(tenant), uuid.uuid4(), sha)
    finally:
        await con.execute("SET session_replication_role = DEFAULT")


async def test_unreferenced_manifests_expire_after_seven_days_and_referenced_ones_never(db_pool, app_pool):
    await _tenants(db_pool)
    async with db_pool.acquire() as con:
        old_unref = await _manifest(con, TENANT_A, _sha(1), 30)
        old_ref = await _manifest(con, TENANT_A, _sha(2), 400)             # referenced: age is irrelevant
        fresh_unref = await _manifest(con, TENANT_A, _sha(3), 3)           # inside the 7 days
        edge_old = await _manifest(con, TENANT_A, _sha(4), 8)
        # tenant B holds the SAME sha as A's referenced one but nobody in B references it: B's copy is garbage
        b_same = await _manifest(con, TENANT_B, _sha(2), 30)
        b_ref = await _manifest(con, TENANT_B, _sha(5), 30)
        await _ref(con, TENANT_A, _sha(2))
        await _ref(con, TENANT_B, _sha(5))
    counts = await retention.run_retention(app_pool)
    assert counts["agent_manifests"] == 3
    async with db_pool.acquire() as con:
        alive = {r["id"] for r in await con.fetch("SELECT id FROM agent_manifests")}
    assert alive == {old_ref, fresh_unref, b_ref}
    assert old_unref not in alive and edge_old not in alive and b_same not in alive


# --------------------------------------------------------------------------- #
# advisory tables (1.11): global, purged as the platform tenant only
# --------------------------------------------------------------------------- #

async def _snap(con, source, scope, age_days, status, n):
    return await con.fetchval(
        "INSERT INTO advisory_snapshots (source, scope, fetched_at, sha256, bytes, status, parser_version) "
        "VALUES ($1,$2,$3,$4,1,$5,1) RETURNING id", source, scope, _ago(age_days), _sha(n), status)


async def _scope(con, scope="debian:bookworm"):
    await con.execute("INSERT INTO advisory_scopes (scope, family, vendor, release, status, primary_source) "
                      "VALUES ($1,'deb','debian','bookworm','supported','p') ON CONFLICT DO NOTHING", scope)


async def test_snapshots_keep_the_last_fourteen_per_feed_and_never_the_current_one_or_a_referenced_one(db_pool, app_pool):
    async with db_pool.acquire() as con:
        await _scope(con)
        sup = [await _snap(con, "tracker", "debian:bookworm", 2 + i, "superseded", 100 + i) for i in range(20)]   # newest first
        cur = await _snap(con, "tracker", "debian:bookworm", 0.1, "current", 1)
        other = [await _snap(con, "tracker", "debian:trixie", 5 + i, "superseded", 200 + i) for i in range(5)]
        kev = [await _snap(con, "kev", "", 3 + i, "superseded", 300 + i) for i in range(16)]
        # a snapshot beyond the 14 that a LIVE advisory row still points at must stay (the row would lose its anchor)
        await con.execute(
            "INSERT INTO advisory_fixes (scope, cve_id, pkg, pkg_kind, state, first_seen_at, last_seen_snapshot) "
            "VALUES ('debian:bookworm','CVE-2024-0001','libc6','source','fixed', now(), $1)", sup[19])
    counts = await retention.run_retention(app_pool)
    # bookworm: current + 20 superseded = 21 -> keep 14 -> 7 candidates, minus the referenced one; kev: 16 -> 2 go
    assert counts["advisory_snapshots"] == 6 + 2
    async with db_pool.acquire() as con:
        alive = {r["id"] for r in await con.fetch("SELECT id FROM advisory_snapshots")}
    assert cur in alive and sup[19] in alive and set(other) <= alive
    assert set(sup[:13]) <= alive                                           # the 13 newest superseded + current = 14
    assert not (set(sup[13:19]) & alive)
    assert set(kev[:14]) <= alive and not (set(kev[14:]) & alive)


async def test_rejected_snapshots_expire_after_ninety_days_and_do_not_count_toward_the_fourteen(db_pool, app_pool):
    async with db_pool.acquire() as con:
        rej_old = [await _snap(con, "tracker", "debian:bookworm", d, "rejected", 400 + d) for d in (91, 120, 400)]
        rej_new = [await _snap(con, "tracker", "debian:bookworm", d, "rejected", 500 + d) for d in (1, 30, 89)]
        keep = [await _snap(con, "tracker", "debian:bookworm", 2 + i, "superseded", 600 + i) for i in range(14)]
    counts = await retention.run_retention(app_pool)
    assert counts["advisory_snapshots"] == 3
    async with db_pool.acquire() as con:
        alive = {r["id"] for r in await con.fetch("SELECT id FROM advisory_snapshots")}
    assert alive == set(rej_new) | set(keep)
    assert not (set(rej_old) & alive)


async def test_removed_advisory_rows_expire_after_thirty_days_and_their_snapshot_goes_in_the_same_run(db_pool, app_pool):
    async with db_pool.acquire() as con:
        await _scope(con)
        snaps = [await _snap(con, "tracker", "debian:bookworm", 5 + i, "superseded", 700 + i) for i in range(16)]
        ins = ("INSERT INTO advisory_fixes (scope, cve_id, pkg, pkg_kind, state, first_seen_at, last_seen_snapshot, "
               "removed_at) VALUES ('debian:bookworm',$1,'libc6','source','fixed', now(), $2, $3) RETURNING id")
        gone = await con.fetchval(ins, "CVE-2024-0001", snaps[15], _ago(40))       # removed 40 d ago, points at the oldest snapshot
        recent = await con.fetchval(ins, "CVE-2024-0002", snaps[14], _ago(5))      # removed 5 d ago: stays
        live = await con.fetchval(ins, "CVE-2024-0003", snaps[0], None)            # live: never
    counts = await retention.run_retention(app_pool)
    assert counts["advisory_fixes"] == 1
    # the oldest snapshot lost its last referrer in this very run, so the FK did not block its purge (fixes go first):
    # 16 superseded > 14, but snaps[14] is still referenced by the recent removed row, snaps[15] is free
    assert counts["advisory_snapshots"] == 1
    async with db_pool.acquire() as con:
        assert {r["id"] for r in await con.fetch("SELECT id FROM advisory_fixes")} == {recent, live}
        alive = {r["id"] for r in await con.fetch("SELECT id FROM advisory_snapshots")}
    assert snaps[15] not in alive and snaps[14] in alive


async def test_global_tables_are_purged_once_not_once_per_tenant_and_other_tenants_are_not_touched(
        db_pool, app_pool, monkeypatch):
    await _tenants(db_pool)
    async with db_pool.acquire() as con:
        await _scope(con)
        await con.execute(
            "INSERT INTO advisory_fixes (scope, cve_id, pkg, pkg_kind, state, first_seen_at, last_seen_snapshot, removed_at) "
            "VALUES ('debian:bookworm','CVE-2024-0001','p','source','fixed', now(), $1, $2)",
            await _snap(con, "tracker", "debian:bookworm", 1, "current", 1), _ago(60))
    # the superuser pool sees the global table in every tenant context: the count must still be exactly 1
    counts = await retention.run_retention(db_pool)
    assert counts["advisory_fixes"] == 1
    # with a policy list handed in directly, the platform-only flag decides who runs it (RLS makes it moot for app roles)
    seen: list[str] = []
    real = retention._purge_one

    async def spy(con, p, batch, max_batches):
        seen.append((tenancy.current_tenant_id(), p.table))
        return await real(con, p, batch, max_batches)

    monkeypatch.setattr(retention, "_purge_one", spy)
    pols = [retention.Policy("advisory_fixes", "removed_at", 30, platform_only=True),
            retention.Policy("invariant_runs", "evaluated_at", 365)]
    await retention.run_retention(app_pool, pols)
    fixes_tenants = {t for t, tbl in seen if tbl == "advisory_fixes"}
    runs_tenants = {t for t, tbl in seen if tbl == "invariant_runs"}
    assert fixes_tenants == {PLATFORM}
    assert {PLATFORM, TENANT_A, TENANT_B} <= runs_tenants


async def test_a_reference_in_one_tenant_never_protects_another_tenants_copy_even_without_rls(db_pool):
    """The superuser pool bypasses RLS, so only the policy's own ``tenant_id`` comparison stands between tenant A's
    reference and tenant B's identical sha (defence in depth: the guard must not rely on the row filter)."""
    await _tenants(db_pool)
    async with db_pool.acquire() as con:
        a = await _manifest(con, TENANT_A, _sha(9), 30)
        b = await _manifest(con, TENANT_B, _sha(9), 30)
        await _ref(con, TENANT_A, _sha(9))
    await retention.run_retention(db_pool)
    async with db_pool.acquire() as con:
        alive = {r["id"] for r in await con.fetch("SELECT id FROM agent_manifests")}
    assert alive == {a}
