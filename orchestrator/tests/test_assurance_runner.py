"""The assurance runner (docs/ASSURANCE_P1.md section 6): build, evaluate, record, findings.

Everything goes through ``app_pool`` (the non-superuser role, tenant stamped on acquire) so the
tenancy claims are real; ``db_pool`` (superuser) only seeds assets and inspects rows. The graph
is seeded through the real ``store.persist_build`` under a source name no real builder owns
(``seed``), and the real builders are patched out unless a test is about them. Time is a
parameter (``now=``): leases use the wall clock, data freshness uses the injected clock.
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import json
import subprocess
import sys
import types

import pytest

from app import tenancy
from app.assurance import builders as builders_pkg
from app.assurance import findings_sync, graph_loader, refs, runner, store
from app.assurance.types import BuildOutput, CoverageOut, EdgeOut, NodeOut
from app.config import settings

_REAL_LOAD = builders_pkg.load_builders
A = tenancy.DEFAULT_TENANT_ID
B = "00000000-0000-0000-0000-0000000000b2"
NOW = dt.datetime(2026, 12, 1, 9, 0, tzinfo=dt.timezone.utc)
H = dt.timedelta(hours=1)
STD_REACH = "std:no-internet-to-datastore"
CUSTOM = "acme:db-not-public"

CUSTOM_YAML = """\
apiVersion: paddock.dev/invariant/v1
id: acme:db-not-public
title: Databases are not reachable from the internet
severity: high
subjects:
  from: { zone: internet }
  to: { class: data_store }
assert: unreachable
via: { max_hops: 4 }
evidence: { min_tier: observed, max_age: 24h }
coverage: { require: 0.0 }
"""


@pytest.fixture(autouse=True)
def _isolate_runner(monkeypatch):
    """No real builders (they own other sources and would replace the seeded graph), a huge
    backstop and rebuild interval so each test controls exactly which trigger fires."""
    monkeypatch.setattr(builders_pkg, "load_builders", lambda: [])
    monkeypatch.setattr(settings, "assurance_backstop_min", 100_000)
    monkeypatch.setattr(settings, "assurance_rebuild_min", 100_000)
    runner._LAST_BUILD.clear()
    runner._LAST_EVAL.clear()
    runner._PLAN_CACHE.clear()
    yield
    runner._LAST_BUILD.clear()
    runner._LAST_EVAL.clear()
    runner._PLAN_CACHE.clear()


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

@contextlib.asynccontextmanager
async def conn_for(pool, tid=A):
    with tenancy.tenant_context(tid):
        async with pool.acquire() as con:
            yield con


async def seed_asset(db_pool, value, tid=A):
    return await db_pool.fetchval(
        "INSERT INTO assets (tenant_id, kind, value, canonical, source) "
        "VALUES ($1, 'cloud_resource', $2, $2, 'test') RETURNING id", tid, value)


class World:
    """One tenant's seeded graph: internet, a database and a web instance."""

    def __init__(self, pool, tid, db, web):
        self.pool, self.tid, self.db, self.web = pool, tid, db, web
        self.db_ref, self.web_ref = refs.asset_ref(db), refs.asset_ref(web)

    async def set(self, *, exposed=True, covered=True, now=NOW, directions=("in",)):
        edges = [EdgeOut("internet", self.db_ref, "tcp", 5432, 5432, "configured", "seed", now)] if exposed else []
        cov = [CoverageOut(r, d, "observed", now, "seed") for r in (self.db_ref, self.web_ref)
               for d in directions] if covered else []
        out = BuildOutput(
            source="seed", mode="replace", edges=edges, coverage=cov,
            nodes=[NodeOut("internet", "internet"), NodeOut(self.db_ref, "cloud_db", asset_id=str(self.db)),
                   NodeOut(self.web_ref, "cloud_instance", asset_id=str(self.web))])
        async with conn_for(self.pool, self.tid) as con:
            return await store.persist_build(con, out, now)


async def world(db_pool, app_pool, tid=A, **kw):
    w = World(app_pool, tid, await seed_asset(db_pool, f"db-{tid[-2:]}", tid), await seed_asset(db_pool, f"web-{tid[-2:]}", tid))
    await w.set(**kw)
    return w


async def enable_std(pool, std_id=STD_REACH, tid=A):
    async with conn_for(pool, tid) as con:
        await runner.install_std(con, std_id, actor="test")


async def enable_custom(pool, yaml=CUSTOM_YAML, tid=A, *, enabled=True):
    import paddock_assurance as lib
    plan = lib.compile_text(yaml)
    async with conn_for(pool, tid) as con:
        await con.execute(
            "INSERT INTO invariants (invariant_id, title, severity, enabled, source, yaml, digest, version) "
            "VALUES ($1, $2, $3, $4, 'custom', $5, $6, 1)",
            plan.id, plan.invariant.title, plan.invariant.severity, enabled, yaml, plan.digest)
    return plan


async def go(pool, tid=A, *, now=NOW, redis=None, **kw):
    return await runner.run_tenant(pool, tid, now=now, redis=redis, **kw)


async def inv(db_pool, invariant_id, tid=A):
    return await db_pool.fetchrow("SELECT * FROM invariants WHERE tenant_id = $1 AND invariant_id = $2", tid, invariant_id)


async def runs(db_pool, invariant_id, tid=A):
    return await db_pool.fetch("SELECT * FROM invariant_runs WHERE tenant_id = $1 AND invariant_id = $2 "
                               "ORDER BY evaluated_at, id", tid, invariant_id)


async def findings(db_pool, tid=A, rule_like="invariant:%"):
    return await db_pool.fetch("SELECT * FROM findings WHERE tenant_id = $1 AND rule_source = 'invariant' "
                               "AND rule_id LIKE $2 ORDER BY rule_id, first_seen", tid, rule_like)


def result_for(summary, invariant_id):
    return next(r for r in summary["results"] if r["invariant_id"] == invariant_id)


# --------------------------------------------------------------------------- #
# the full cycle
# --------------------------------------------------------------------------- #

async def test_full_cycle_open_dedupe_fix_close_recur_reopen(db_pool, app_pool, fake_redis):
    w = await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_std(app_pool)
    await enable_custom(app_pool)

    # 1. VIOLATED -> exactly one finding per invariant, on the database asset
    s = await go(app_pool, redis=fake_redis)
    assert s["ok"] and s["evaluated"] == 2, s
    assert result_for(s, CUSTOM)["verdict"] == "VIOLATED" and result_for(s, STD_REACH)["verdict"] == "VIOLATED"
    fr = await findings(db_pool)
    assert {(f["rule_id"], f["asset_id"], f["status"], f["severity"]) for f in fr} == {
        (f"invariant:{CUSTOM}", w.db, "open", "high"), (f"invariant:{STD_REACH}", w.db, "open", "critical")}
    ev = json.loads(fr[0]["evidence"])
    assert ev["target_ref"] == w.db_ref and ev["witness"]["hops"][-1]["dst"] == w.db_ref
    row = await inv(db_pool, CUSTOM)
    assert row["last_verdict"] == "VIOLATED" and row["last_graph_version"] == 1 and row["valid_until"] is None
    assert json.loads(row["last_result"])["violation_count"] == 1
    assert len(await runs(db_pool, CUSTOM)) == 1

    # 2. evaluating again changes nothing: no duplicate finding, no new ledger row
    s = await go(app_pool, force=True, redis=fake_redis, now=NOW + H)
    assert s["ok"] and s["evaluated"] == 2
    assert len(await findings(db_pool)) == 2 and len(await runs(db_pool, CUSTOM)) == 1
    assert len([e for e in (await fake_redis.xrange(settings.events_stream))
                if json.loads(e[1]["event"])["event"] == "finding_opened"]) == 2

    # 3. the fix: the edge is removed. The graph version moves, so the next (unforced) pass re-evaluates.
    rep = await w.set(exposed=False, covered=True, now=NOW + 2 * H)
    assert rep.changed
    s = await go(app_pool, redis=fake_redis, now=NOW + 2 * H)
    assert result_for(s, CUSTOM)["verdict"] == "HOLDS"
    # the std invariant's floor is measured over the nodes it is about (the database and the web
    # instance, both covered inbound); the internet pseudo-node is not coverable and does not count
    assert result_for(s, STD_REACH)["verdict"] == "HOLDS"
    by = {f["rule_id"]: f for f in await findings(db_pool)}
    fixed = by[f"invariant:{CUSTOM}"]
    assert fixed["status"] == "fixed" and fixed["status_by"] == "system:assurance"
    assert fixed["fix_verified_at"] == NOW + 2 * H           # observed-tier coverage: the HOLDS is the verification
    assert by[f"invariant:{STD_REACH}"]["status"] == "fixed"
    assert by[f"invariant:{STD_REACH}"]["fix_verified_at"] == NOW + 2 * H
    hist = await db_pool.fetch("SELECT from_status, to_status, actor FROM finding_status_history "
                               "WHERE finding_id = $1 ORDER BY at, id", fixed["id"])
    assert [(h["from_status"], h["to_status"]) for h in hist][-1] == ("open", "fixed") and hist[-1]["actor"] == "system:assurance"
    assert [r["verdict"] for r in await runs(db_pool, CUSTOM)] == ["VIOLATED", "HOLDS"]
    assert (await inv(db_pool, CUSTOM))["valid_until"] == NOW + 2 * H + dt.timedelta(hours=24)

    # 4. recurrence: the finding that was fixed reopens; the open one is still the same row
    await w.set(exposed=True, covered=True, now=NOW + 3 * H)
    s = await go(app_pool, redis=fake_redis, now=NOW + 3 * H)
    assert result_for(s, CUSTOM)["findings"]["reopened"] == 1
    again = {f["rule_id"]: f for f in await findings(db_pool)}
    assert len(again) == 2
    assert again[f"invariant:{CUSTOM}"]["id"] == fixed["id"] and again[f"invariant:{CUSTOM}"]["status"] == "open"
    assert again[f"invariant:{CUSTOM}"]["fix_verified_at"] is None
    assert again[f"invariant:{STD_REACH}"]["id"] == by[f"invariant:{STD_REACH}"]["id"]
    assert [r["verdict"] for r in await runs(db_pool, CUSTOM)] == ["VIOLATED", "HOLDS", "VIOLATED"]
    assert [r["verdict"] for r in await runs(db_pool, STD_REACH)] == ["VIOLATED", "HOLDS", "VIOLATED"]


async def test_unknown_leaves_open_findings_open_and_opens_none(db_pool, app_pool, fake_redis):
    w = await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    await go(app_pool, redis=fake_redis)
    (f,) = await findings(db_pool)
    assert f["status"] == "open"

    # silence the sensors AND remove the edge: nothing proves the path is gone
    await w.set(exposed=False, covered=False, now=NOW + H)
    s = await go(app_pool, redis=fake_redis, now=NOW + H)
    r = result_for(s, CUSTOM)
    assert r["verdict"] == "UNKNOWN" and r["reasons"] == ["possible_via_unknown_edges"]
    assert r["findings"]["skipped"] == "unknown" and r["findings"]["closed"] == 0
    (f2,) = await findings(db_pool)
    assert f2["id"] == f["id"] and f2["status"] == "open"
    # and an invariant that starts out UNKNOWN never opens anything
    w2_pool_rows = await db_pool.fetchval("SELECT count(*) FROM findings WHERE rule_source = 'invariant'")
    assert w2_pool_rows == 1


async def test_coverage_complete_names_each_blind_node_then_closes_when_both_directions_are_covered(db_pool, app_pool, fake_redis):
    w = await world(db_pool, app_pool, exposed=False, covered=True)              # inbound only
    await enable_std(app_pool, "std:coverage-complete")
    s = await go(app_pool, redis=fake_redis)
    r = result_for(s, "std:coverage-complete")
    assert r["verdict"] == "VIOLATED" and r["violation_count"] == 2 and r["findings"]["opened"] == 2
    fr = await findings(db_pool)
    assert {f["asset_id"] for f in fr} == {w.db, w.web} and {f["severity"] for f in fr} == {"medium"}
    assert all("outbound" in f["description"] for f in fr)
    # a sensor now reports both directions; the HOLDS rests on observed evidence, so it verifies
    await w.set(exposed=False, covered=True, directions=("in", "out"), now=NOW + H)
    s = await go(app_pool, redis=fake_redis, now=NOW + H)
    assert result_for(s, "std:coverage-complete")["verdict"] == "HOLDS"
    fr = await findings(db_pool)
    assert {f["status"] for f in fr} == {"fixed"} and all(f["fix_verified_at"] == NOW + H for f in fr)


async def test_a_fresh_tenant_that_is_blind_gets_unknown_and_no_findings(db_pool, app_pool, fake_redis):
    await world(db_pool, app_pool, exposed=False, covered=False)
    await enable_custom(app_pool)
    s = await go(app_pool, redis=fake_redis)
    assert result_for(s, CUSTOM)["verdict"] == "UNKNOWN"
    assert await findings(db_pool) == []


async def test_human_decisions_and_suppressions_survive_the_cycle(db_pool, app_pool, fake_redis):
    w = await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    await go(app_pool, redis=fake_redis)
    (f,) = await findings(db_pool)
    await db_pool.execute("UPDATE findings SET status = 'accepted', status_by = 'alice', status_reason = 'known', "
                          "accepted_until = NULL WHERE id = $1", f["id"])
    await w.set(exposed=False, now=NOW + H)
    await go(app_pool, redis=fake_redis, now=NOW + H)                     # HOLDS
    await w.set(exposed=True, now=NOW + 2 * H)
    await go(app_pool, redis=fake_redis, now=NOW + 2 * H)                 # VIOLATED again
    (f,) = await findings(db_pool)
    assert (f["status"], f["status_by"], f["status_reason"]) == ("accepted", "alice", "known")

    await db_pool.execute("INSERT INTO finding_suppressions (name, rule_id, reason, author) "
                          "VALUES ('q', 'invariant:*', 'noise', 'alice')")
    await db_pool.execute("UPDATE findings SET status = 'open', suppressed_by = NULL")
    await go(app_pool, force=True, redis=fake_redis, now=NOW + 3 * H)
    (f,) = await findings(db_pool)
    assert f["suppressed_by"] is not None


# --------------------------------------------------------------------------- #
# tenancy
# --------------------------------------------------------------------------- #

async def test_two_tenants_are_isolated_and_a_tick_visits_both(db_pool, app_pool, fake_redis):
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo", tenant_id=B)
    wa = await world(db_pool, app_pool, A, exposed=False, covered=True)          # A is clean and covered
    wb = await world(db_pool, app_pool, B, exposed=True, covered=True)           # B is violated
    await enable_custom(app_pool, tid=A)
    await enable_custom(app_pool, tid=B)

    out = await runner.tick_once(app_pool, redis=fake_redis, now=NOW)
    assert set(out) == {A, B}
    assert result_for(out[A], CUSTOM)["verdict"] == "HOLDS"
    assert result_for(out[B], CUSTOM)["verdict"] == "VIOLATED"
    assert await findings(db_pool, A) == []
    (fb,) = await findings(db_pool, B)
    assert fb["asset_id"] == wb.db
    # B's graph never leaked into A's: A's evidence and runs name only A's nodes
    ra = json.loads((await inv(db_pool, CUSTOM, A))["last_result"])
    assert wb.db_ref not in json.dumps(ra) and ra["coverage"]["universe"] == 2  # db + web; the internet pseudo-node is not coverable
    assert wa.db_ref not in json.dumps(json.loads((await inv(db_pool, CUSTOM, B))["last_result"]))
    # each tenant has its own state row and watermark
    async with conn_for(app_pool, A) as con:
        sa = await store.get_state(con)
    async with conn_for(app_pool, B) as con:
        sb = await store.get_state(con)
    assert sa.graph_version == sb.graph_version == 1 and sa.last_eval_version == sb.last_eval_version == 1

    # fixing B changes B only
    await wb.set(exposed=False, now=NOW + H)
    out = await runner.tick_once(app_pool, redis=fake_redis, now=NOW + H)
    assert result_for(out[B], CUSTOM)["verdict"] == "HOLDS" and out[A]["skipped"] == "up_to_date"
    assert (await findings(db_pool, B))[0]["status"] == "fixed"


async def test_evaluating_one_tenant_cannot_touch_anothers_invariants(db_pool, app_pool, fake_redis):
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo", tenant_id=B)
    await world(db_pool, app_pool, A, exposed=True)
    await world(db_pool, app_pool, B, exposed=True)
    await enable_custom(app_pool, tid=B)                                          # only B has an invariant
    s = await go(app_pool, A, redis=fake_redis)
    assert s["skipped"] == "no_invariants" and s["results"] == []
    assert await findings(db_pool, A) == [] and await findings(db_pool, B) == []
    # `only` naming B's row id from A's context matches nothing in A
    b_id = str((await inv(db_pool, CUSTOM, B))["id"])
    await enable_custom(app_pool, tid=A, yaml=CUSTOM_YAML.replace("acme:db-not-public", "acme:other"))
    s = await go(app_pool, A, force=True, only=[b_id], redis=fake_redis)
    assert s["results"] == []


# --------------------------------------------------------------------------- #
# lease
# --------------------------------------------------------------------------- #

async def test_two_concurrent_evaluations_never_overlap(db_pool, app_pool, fake_redis, monkeypatch):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    entered, release = asyncio.Event(), asyncio.Event()
    real = graph_loader.load_graph_doc_with_diagnostics
    calls = []

    async def slow(conn, now):
        calls.append(1)
        entered.set()
        await release.wait()
        return await real(conn, now)

    monkeypatch.setattr(graph_loader, "load_graph_doc_with_diagnostics", slow)
    first = asyncio.create_task(go(app_pool, force=True, redis=fake_redis))
    await asyncio.wait_for(entered.wait(), 20)
    second = await asyncio.wait_for(go(app_pool, force=True, redis=fake_redis), 15)   # must not block on the held lease
    assert second["skipped"] == "lease_held" and second["ok"] is False and second["results"] == []
    release.set()
    s = await asyncio.wait_for(first, 30)
    assert s["ok"] and s["evaluated"] == 1 and len(calls) == 1
    assert len(await findings(db_pool)) == 1
    async with conn_for(app_pool) as con:
        st = await store.get_state(con)
    assert st.lease_owner is None and st.lease_until is None            # released
    # and after release the next call is free to run
    monkeypatch.setattr(graph_loader, "load_graph_doc_with_diagnostics", real)
    assert (await go(app_pool, force=True, redis=fake_redis))["evaluated"] == 1


async def test_racing_evaluate_tenant_calls_evaluate_once(db_pool, app_pool, fake_redis):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    outs = await asyncio.gather(*[runner.evaluate_tenant(app_pool, A, force=True, redis=fake_redis) for _ in range(4)])
    evaluated = [o["evaluated"] for o in outs]
    assert sum(1 for o in outs if o["skipped"] == "lease_held") + sum(1 for e in evaluated if e) == 4
    assert 1 <= sum(evaluated) <= 4 and len(await findings(db_pool)) == 1     # however many ran, one finding


async def test_a_dead_replicas_expired_lease_does_not_block_forever(db_pool, app_pool, fake_redis):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    await db_pool.execute("UPDATE assurance_state SET lease_owner = 'dead', lease_until = $2 WHERE tenant_id = $1",
                          A, dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5))
    s = await go(app_pool, force=True, redis=fake_redis)
    assert s["skipped"] == "lease_held"
    await db_pool.execute("UPDATE assurance_state SET lease_until = NOW() - interval '1 minute'")
    s = await go(app_pool, force=True, redis=fake_redis)
    assert s["ok"] and s["evaluated"] == 1


async def test_the_lease_is_released_when_evaluation_fails(db_pool, app_pool, fake_redis, monkeypatch):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)

    async def boom(conn, now):
        raise RuntimeError("database went away")

    monkeypatch.setattr(graph_loader, "load_graph_doc_with_diagnostics", boom)
    s = await go(app_pool, force=True, redis=fake_redis)
    assert s["ok"] is False and any("database went away" in e for e in s["errors"])
    async with conn_for(app_pool) as con:
        st = await store.get_state(con)
    assert st.lease_owner is None and st.last_eval_version == -1        # not marked evaluated: retried next tick


# --------------------------------------------------------------------------- #
# definitions
# --------------------------------------------------------------------------- #

async def test_an_invalid_stored_definition_is_unknown_not_skipped_and_not_a_stale_holds(db_pool, app_pool, fake_redis):
    w = await world(db_pool, app_pool, exposed=False, covered=True)
    await enable_custom(app_pool)
    s = await go(app_pool, redis=fake_redis)
    assert result_for(s, CUSTOM)["verdict"] == "HOLDS"

    # somebody (or an older version) leaves unparsable YAML behind; a HOLDS must not linger
    await db_pool.execute("UPDATE invariants SET yaml = 'assert: [unclosed' WHERE invariant_id = $1", CUSTOM)
    s = await go(app_pool, redis=fake_redis, now=NOW + H)
    r = result_for(s, CUSTOM)
    assert r["verdict"] == "UNKNOWN" and r["reasons"] == ["invalid_definition"]
    row = await inv(db_pool, CUSTOM)
    stored = json.loads(row["last_result"])
    assert row["last_verdict"] == "UNKNOWN" and stored["reasons"] == ["invalid_definition"] and stored["error"]
    assert row["valid_until"] is None
    assert [x["verdict"] for x in await runs(db_pool, CUSTOM)] == ["HOLDS", "UNKNOWN"]
    # an open finding of that invariant is not closed by "we could not even read the rule"
    await w.set(exposed=True, now=NOW + 2 * H)
    await db_pool.execute("UPDATE invariants SET yaml = $1 WHERE invariant_id = $2", CUSTOM_YAML, CUSTOM)
    await go(app_pool, redis=fake_redis, now=NOW + 2 * H)
    assert (await findings(db_pool))[0]["status"] == "open"
    await db_pool.execute("UPDATE invariants SET yaml = 'nope: 1' WHERE invariant_id = $1", CUSTOM)
    await go(app_pool, redis=fake_redis, now=NOW + 3 * H)
    assert (await findings(db_pool))[0]["status"] == "open"


async def test_a_definition_stored_under_another_ones_id_is_invalid(db_pool, app_pool, fake_redis):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    other = CUSTOM_YAML.replace("acme:db-not-public", "acme:somebody-else")
    await db_pool.execute("UPDATE invariants SET yaml = $1 WHERE invariant_id = $2", other, CUSTOM)
    s = await go(app_pool, redis=fake_redis)
    r = result_for(s, CUSTOM)
    assert r["reasons"] == ["invalid_definition"] and await findings(db_pool) == []
    assert "does not match" in json.loads((await inv(db_pool, CUSTOM))["last_result"])["error"]


async def test_an_edited_definition_is_reevaluated_without_waiting_for_the_backstop(db_pool, app_pool, fake_redis):
    await world(db_pool, app_pool, exposed=False, covered=True)
    await enable_custom(app_pool)
    await go(app_pool, redis=fake_redis)
    assert (await go(app_pool, redis=fake_redis, now=NOW + H))["skipped"] == "up_to_date"
    import paddock_assurance as lib
    new = CUSTOM_YAML.replace("severity: high", "severity: critical")
    await db_pool.execute("UPDATE invariants SET yaml = $1, digest = $2 WHERE invariant_id = $3",
                          new, lib.compile_text(new).digest, CUSTOM)
    s = await go(app_pool, redis=fake_redis, now=NOW + 2 * H)
    assert s["evaluated"] == 1 and json.loads((await inv(db_pool, CUSTOM))["last_result"])["severity"] == "critical"
    assert len(await runs(db_pool, CUSTOM)) == 2                    # the digest changed: a ledger row


async def test_std_copies_are_refreshed_when_the_shipped_digest_changes(db_pool, app_pool, fake_redis):
    await world(db_pool, app_pool, exposed=False, covered=True)
    await enable_std(app_pool, STD_REACH)
    await enable_custom(app_pool)
    before = await inv(db_pool, STD_REACH)
    assert before["version"] == 1
    # the shipped text moved on: this tenant's copy is from an older release
    await db_pool.execute("UPDATE invariants SET yaml = 'old', digest = 'sha256:old', title = 'old title' "
                          "WHERE invariant_id = $1", STD_REACH)
    await db_pool.execute("UPDATE invariant_versions SET digest = 'sha256:old' WHERE invariant_id = $1", STD_REACH)
    await db_pool.execute("UPDATE invariants SET yaml = yaml || ' ', digest = 'sha256:custom-old' WHERE invariant_id = $1",
                          CUSTOM)
    s = await go(app_pool, redis=fake_redis)
    after = await inv(db_pool, STD_REACH)
    assert after["digest"] == before["digest"] and after["yaml"] == before["yaml"] and after["title"] == before["title"]
    assert after["version"] == 2 and after["updated_by"] == "system:assurance"
    vers = await db_pool.fetch("SELECT version, digest FROM invariant_versions WHERE invariant_id = $1 ORDER BY version",
                               STD_REACH)
    assert [(v["version"], v["digest"]) for v in vers] == [(1, "sha256:old"), (2, before["digest"])]
    assert result_for(s, STD_REACH)["verdict"] in ("HOLDS", "UNKNOWN")
    # a custom row is never overwritten from the library
    assert (await inv(db_pool, CUSTOM))["digest"] == "sha256:custom-old"
    # a refresh with nothing to do changes nothing
    assert await runner.refresh_std(app_pool) == []


async def test_install_std_is_idempotent_and_records_a_version(db_pool, app_pool):
    async with conn_for(app_pool) as con:
        assert await runner.install_std(con, STD_REACH) is True
        assert await runner.install_std(con, STD_REACH) is False
        with pytest.raises(KeyError):
            await runner.install_std(con, "std:does-not-exist")
    assert await db_pool.fetchval("SELECT count(*) FROM invariant_versions WHERE invariant_id = $1", STD_REACH) == 1


# --------------------------------------------------------------------------- #
# policy: which trigger re-evaluates, and what is recorded
# --------------------------------------------------------------------------- #

async def test_valid_until_expiry_triggers_reevaluation_when_nothing_else_does(db_pool, app_pool, fake_redis):
    await world(db_pool, app_pool, exposed=False, covered=True)
    await enable_custom(app_pool)
    s = await go(app_pool, redis=fake_redis)
    assert result_for(s, CUSTOM)["verdict"] == "HOLDS"
    row = await inv(db_pool, CUSTOM)
    assert row["valid_until"] == NOW + dt.timedelta(hours=24)

    # inside the evidence window, same graph version, backstop far away: nothing runs
    s = await go(app_pool, redis=fake_redis, now=NOW + 23 * H)
    assert s["skipped"] == "up_to_date" and s["evaluated"] == 0 and s["results"] == []
    assert (await inv(db_pool, CUSTOM))["last_evaluated_at"] == NOW

    # the evidence ran out (nobody refreshed it): re-evaluate, and the stale coverage makes it UNKNOWN
    s = await go(app_pool, redis=fake_redis, now=NOW + 25 * H)
    r = result_for(s, CUSTOM)
    assert s["evaluated"] == 1 and r["verdict"] == "UNKNOWN"
    stored = json.loads((await inv(db_pool, CUSTOM))["last_result"])
    assert {"direction": "in", "reason": "stale"}.items() <= next(
        b for b in stored["blind_spots"] if b["node"].startswith("asset:")).items()
    assert [x["verdict"] for x in await runs(db_pool, CUSTOM)] == ["HOLDS", "UNKNOWN"]


async def test_backstop_and_graph_version_each_trigger_on_their_own(db_pool, app_pool, fake_redis, monkeypatch):
    w = await world(db_pool, app_pool, exposed=False, covered=True)
    await enable_custom(app_pool)
    await go(app_pool, redis=fake_redis)
    assert (await go(app_pool, redis=fake_redis, now=NOW + 5 * 60 * dt.timedelta(seconds=1)))["evaluated"] == 0
    # a builder refresh of the same facts is not a change: still nothing
    assert not (await w.set(exposed=False, covered=True, now=NOW + 10 * dt.timedelta(minutes=1))).changed
    assert (await go(app_pool, redis=fake_redis, now=NOW + 10 * dt.timedelta(minutes=1)))["evaluated"] == 0
    # a real change does
    await w.set(exposed=True, now=NOW + 20 * dt.timedelta(minutes=1))
    assert (await go(app_pool, redis=fake_redis, now=NOW + 20 * dt.timedelta(minutes=1)))["evaluated"] == 1
    # the backstop
    monkeypatch.setattr(settings, "assurance_backstop_min", 15)
    assert (await go(app_pool, redis=fake_redis, now=NOW + 30 * dt.timedelta(minutes=1)))["evaluated"] == 0
    assert (await go(app_pool, redis=fake_redis, now=NOW + 36 * dt.timedelta(minutes=1)))["evaluated"] == 1


async def test_ledger_rows_only_on_transition_digest_change_or_a_days_heartbeat(db_pool, app_pool, fake_redis):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    for hrs in (0, 1, 5, 12, 23):
        await go(app_pool, force=True, redis=fake_redis, now=NOW + hrs * H)
    assert len(await runs(db_pool, CUSTOM)) == 1
    await go(app_pool, force=True, redis=fake_redis, now=NOW + 25 * H)
    rs = await runs(db_pool, CUSTOM)
    assert len(rs) == 2 and rs[1]["evaluated_at"] == NOW + 25 * H and rs[1]["verdict"] == "VIOLATED"
    assert rs[1]["violation_count"] == 1 and rs[1]["coverage_universe"] == 2 and rs[1]["graph_version"] == 1


async def test_only_selects_by_id_or_row_uuid_and_a_partial_run_does_not_advance_the_watermark(db_pool, app_pool, fake_redis):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_std(app_pool)
    await enable_custom(app_pool)
    row = await inv(db_pool, CUSTOM)
    s = await runner.evaluate_tenant(app_pool, A, force=True, only=[CUSTOM], redis=fake_redis)
    assert [r["invariant_id"] for r in s["results"]] == [CUSTOM]
    s = await runner.evaluate_tenant(app_pool, A, force=True, only=[str(row["id"])], redis=fake_redis)
    assert [r["invariant_id"] for r in s["results"]] == [CUSTOM]
    async with conn_for(app_pool) as con:
        assert (await store.get_state(con)).last_eval_version == -1          # the std one was never evaluated
    assert (await inv(db_pool, STD_REACH))["last_verdict"] is None
    # unforced: only the unevaluated one is due. Due-ness is per invariant now (P1X runner-5): CUSTOM was
    # already evaluated at this graph version and document, so re-running it would be wasted work
    # (and, under a time budget, would push the invariants that really are due to the back).
    s = await runner.evaluate_tenant(app_pool, A, redis=fake_redis)
    assert [r["invariant_id"] for r in s["results"]] == [STD_REACH]
    async with conn_for(app_pool) as con:
        assert (await store.get_state(con)).last_eval_version == 1


async def test_disabled_invariants_are_not_evaluated(db_pool, app_pool, fake_redis):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool, enabled=False)
    s = await go(app_pool, force=True, redis=fake_redis)
    assert s["skipped"] == "no_invariants" and await findings(db_pool) == []


async def test_the_tenant_time_budget_defers_instead_of_starving_and_the_rest_runs_next_tick(db_pool, app_pool, fake_redis, monkeypatch):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_std(app_pool)
    await enable_custom(app_pool)
    monkeypatch.setattr(runner, "TENANT_BUDGET_S", -1.0)                      # exhausted before the first
    s = await go(app_pool, redis=fake_redis)
    assert s["evaluated"] == 0 and s["deferred"] == 2 and s["ok"]
    async with conn_for(app_pool) as con:
        assert (await store.get_state(con)).last_eval_version == -1
    monkeypatch.setattr(runner, "TENANT_BUDGET_S", 30.0)
    s = await go(app_pool, redis=fake_redis)
    assert s["evaluated"] == 2 and "deferred" not in s
    # a forced run ignores the budget
    monkeypatch.setattr(runner, "TENANT_BUDGET_S", -1.0)
    assert (await go(app_pool, force=True, redis=fake_redis))["evaluated"] == 2


async def test_a_library_failure_on_one_invariant_is_unknown_and_the_others_still_run(db_pool, app_pool, fake_redis, monkeypatch):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_std(app_pool)
    await enable_custom(app_pool)
    import paddock_assurance as lib
    real = lib.evaluate

    def flaky(plan, graph, now):
        if plan.id == CUSTOM:
            raise ZeroDivisionError("library bug")
        return real(plan, graph, now)

    monkeypatch.setattr(lib, "evaluate", flaky)
    s = await go(app_pool, redis=fake_redis)
    assert result_for(s, CUSTOM)["reasons"] == ["evaluation_error"] and result_for(s, CUSTOM)["verdict"] == "UNKNOWN"
    assert result_for(s, STD_REACH)["verdict"] == "VIOLATED"
    assert [f["rule_id"] for f in await findings(db_pool)] == [f"invariant:{STD_REACH}"]


async def test_an_unusable_graph_makes_every_invariant_unknown_and_changes_no_finding(db_pool, app_pool, fake_redis, monkeypatch):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    await go(app_pool, redis=fake_redis)
    real = graph_loader.load_graph_doc_with_diagnostics

    async def bad(conn, now):
        doc, diag = await real(conn, now)
        return {**doc, "version": 99}, diag

    monkeypatch.setattr(graph_loader, "load_graph_doc_with_diagnostics", bad)
    s = await go(app_pool, force=True, redis=fake_redis, now=NOW + H)
    assert result_for(s, CUSTOM)["reasons"] == ["graph_unavailable"] and s["ok"] is False
    assert (await findings(db_pool))[0]["status"] == "open"
    async with conn_for(app_pool) as con:
        assert (await store.get_state(con)).last_eval_version != 99


async def test_findings_sync_failure_is_recorded_and_retried_next_tick(db_pool, app_pool, fake_redis, monkeypatch):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    real = findings_sync.sync_findings
    calls = {"n": 0}

    async def failing(*a, **k):
        calls["n"] += 1
        raise RuntimeError("findings table locked")

    monkeypatch.setattr(findings_sync, "sync_findings", failing)
    s = await go(app_pool, redis=fake_redis)
    assert s["ok"] is False and "findings" in result_for(s, CUSTOM) and calls["n"] == 1
    assert (await inv(db_pool, CUSTOM))["last_verdict"] == "VIOLATED"        # the verdict is still recorded
    monkeypatch.setattr(findings_sync, "sync_findings", real)
    s = await go(app_pool, redis=fake_redis, now=NOW + 1 * dt.timedelta(minutes=1))   # not forced, same graph
    assert s["evaluated"] == 1 and len(await findings(db_pool)) == 1


# --------------------------------------------------------------------------- #
# build + loop resilience
# --------------------------------------------------------------------------- #

def _fake_builder(source, *, load_error=None, build_error=None, edge=None):
    async def load(conn, now, **opts):
        if load_error:
            raise load_error
        return [source]

    def build(rows, now, **opts):
        if build_error:
            raise build_error
        return BuildOutput(source=source, mode="replace",
                           nodes=[NodeOut("internet", "internet")] if edge else [],
                           edges=[edge] if edge else [])

    return types.SimpleNamespace(SOURCE=source, load=load, build=build)


async def test_one_failing_builder_never_stops_the_others_or_the_evaluation(db_pool, app_pool, fake_redis, monkeypatch):
    w = await world(db_pool, app_pool, exposed=False, covered=True)
    await enable_custom(app_pool)
    good = _fake_builder("good", edge=EdgeOut("internet", w.db_ref, "tcp", 5432, 5432, "configured", "good", NOW))
    monkeypatch.setattr(builders_pkg, "load_builders", lambda: [
        _fake_builder("bad_load", load_error=RuntimeError("db gone")),
        _fake_builder("bad_build", build_error=ValueError("parse")),
        good])
    s = await go(app_pool, redis=fake_redis, rebuild=True)
    assert s["built"] and s["builders"]["bad_load"]["ok"] is False and "db gone" in s["builders"]["bad_load"]["error"]
    assert s["builders"]["bad_build"]["ok"] is False and s["builders"]["good"]["ok"] and s["builders"]["good"]["changed"]
    assert s["ok"] is False and len(s["errors"]) == 2
    assert result_for(s, CUSTOM)["verdict"] == "VIOLATED"                    # evaluated the graph the good one built
    assert len(await findings(db_pool)) == 1
    assert runner.last_build(A)["bad_load"]["ok"] is False and runner.last_build(A)["good"]["ok"]
    async with conn_for(app_pool) as con:
        assert (await store.get_state(con)).last_build_at == NOW             # a failing builder does not cause a hot retry loop


async def test_a_builder_registry_failure_is_reported_not_raised(db_pool, app_pool, fake_redis, monkeypatch):
    def broken():
        raise RuntimeError("builder x lacks build")

    monkeypatch.setattr(builders_pkg, "load_builders", broken)
    s = await go(app_pool, redis=fake_redis, rebuild=True)
    assert s["ok"] is False and s["builders"]["_registry"]["ok"] is False


async def test_rebuild_interval_gates_the_builders(db_pool, app_pool, fake_redis, monkeypatch):
    ran = []
    mod = _fake_builder("seed2")
    orig = mod.load

    async def counting(conn, now, **o):
        ran.append(now)
        return await orig(conn, now, **o)

    mod.load = counting
    monkeypatch.setattr(builders_pkg, "load_builders", lambda: [mod])
    monkeypatch.setattr(settings, "assurance_rebuild_min", 10)
    await go(app_pool, redis=fake_redis)
    await go(app_pool, redis=fake_redis, now=NOW + 5 * dt.timedelta(minutes=1))
    assert len(ran) == 1
    await go(app_pool, redis=fake_redis, now=NOW + 11 * dt.timedelta(minutes=1))
    assert len(ran) == 2


async def test_the_real_builders_run_on_an_empty_tenant(db_pool, app_pool, fake_redis, monkeypatch):
    monkeypatch.setattr(builders_pkg, "load_builders", _REAL_LOAD)
    out = await runner.build_tenant(app_pool, A, now=NOW)
    assert out and all(v["ok"] for v in out.values()), out
    assert {"aws_sg", "external_scan"} <= set(out)
    assert set(runner.last_build(A)) == set(out)
    async with conn_for(app_pool) as con:
        assert (await store.get_state(con)).last_build_at == NOW


async def test_the_loop_survives_a_tick_that_raises_and_stops_on_cancel(app_pool, fake_redis, monkeypatch):
    seen = []
    done = asyncio.Event()
    real_sleep = asyncio.sleep

    async def tick(pool, *, redis=None, now=None):
        seen.append(redis)
        if len(seen) == 1:
            raise RuntimeError("tick exploded")
        if len(seen) >= 3:
            done.set()
        return {}

    async def fast_sleep(_s):
        await real_sleep(0)

    monkeypatch.setattr(runner, "tick_once", tick)
    monkeypatch.setattr(runner.asyncio, "sleep", fast_sleep)
    app = types.SimpleNamespace(state=types.SimpleNamespace(pool=app_pool, redis=fake_redis))
    task = asyncio.create_task(runner.assurance_loop(app))
    await asyncio.wait_for(done.wait(), 10)
    assert len(seen) >= 3 and seen[0] is fake_redis                           # kept going after the exception
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_the_loop_idles_without_a_pool_or_library(fake_redis, monkeypatch):
    ticks = []
    done = asyncio.Event()
    real_sleep = asyncio.sleep
    n = {"i": 0}

    async def fast_sleep(_s):
        n["i"] += 1
        if n["i"] > 5:
            done.set()
        await real_sleep(0)

    async def tick(*a, **k):
        ticks.append(1)
        return {}

    monkeypatch.setattr(runner, "tick_once", tick)
    monkeypatch.setattr(runner.asyncio, "sleep", fast_sleep)
    app = types.SimpleNamespace(state=types.SimpleNamespace(redis=fake_redis))       # no pool yet
    task = asyncio.create_task(runner.assurance_loop(app))
    await asyncio.wait_for(done.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert ticks == []
    monkeypatch.setattr(runner, "_lib", lambda: None)
    s = await runner.run_tenant(object(), A)
    assert s["skipped"] == "library_missing" and s["ok"] is False


async def test_a_tick_isolates_a_tenant_that_raises_or_hangs(db_pool, app_pool, fake_redis, monkeypatch):
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo", tenant_id=B)
    seen = []

    async def run(pool, tid, **kw):
        seen.append(tid)
        if tid == A:
            raise RuntimeError("tenant A exploded")
        await asyncio.sleep(30)

    monkeypatch.setattr(runner, "run_tenant", run)
    monkeypatch.setattr(runner, "TENANT_HARD_TIMEOUT_S", 0.2)
    out = await runner.tick_once(app_pool, redis=fake_redis)
    assert seen == [A, B]
    assert out[A]["ok"] is False and "exploded" in out[A]["errors"][0]
    assert out[B]["ok"] is False and "timed out" in out[B]["errors"][0]


async def test_a_cancelled_pass_releases_its_lease(db_pool, app_pool, fake_redis, monkeypatch):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    entered = asyncio.Event()

    async def hang(conn, now):
        entered.set()
        await asyncio.sleep(60)

    monkeypatch.setattr(graph_loader, "load_graph_doc_with_diagnostics", hang)
    task = asyncio.create_task(go(app_pool, force=True, redis=fake_redis))
    await asyncio.wait_for(entered.wait(), 20)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    async with conn_for(app_pool) as con:
        st = await store.get_state(con)
    assert st.lease_owner is None


# --------------------------------------------------------------------------- #
# small things
# --------------------------------------------------------------------------- #

def test_evaluate_tenant_keeps_the_contract_signature():
    import inspect
    p = inspect.signature(runner.evaluate_tenant).parameters
    assert list(p)[:2] == ["pool", "tenant_id"]
    assert p["force"].kind is inspect.Parameter.KEYWORD_ONLY and p["force"].default is False
    assert p["only"].kind is inspect.Parameter.KEYWORD_ONLY and p["only"].default is None


async def test_a_bad_tenant_id_is_reported_not_raised(app_pool):
    s = await runner.evaluate_tenant(app_pool, "not-a-uuid")
    assert s["ok"] is False and s["skipped"] == "bad_tenant"


def test_the_runner_and_findings_sync_import_without_the_library():
    code = ("import sys\n"
            "import app.assurance.runner, app.assurance.findings_sync\n"
            "assert 'paddock_assurance' not in sys.modules, 'imported eagerly'\n")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr


def test_stored_results_cap_the_blind_spot_list_but_keep_the_summary():
    spots = [{"node": f"ip:10.0.{i // 250}.{i % 250}", "reason": "no_sensor", "relevant": i % 7 == 0, "direction": "both"}
             for i in range(2000)]
    rd = {"verdict": "UNKNOWN", "blind_spots": spots, "witnesses": []}
    out = runner.compact_result(rd, 5)
    assert len(out["blind_spots"]) == runner.MAX_STORED_BLIND_SPOTS and out["graph_version"] == 5
    assert out["blind_spot_summary"] == {"total": 2000, "stored": runner.MAX_STORED_BLIND_SPOTS,
                                         "by_reason": {"no_sensor": 2000}}
    assert all(s["relevant"] for s in out["blind_spots"])                  # the ones that matter come first
    assert len(rd["blind_spots"]) == 2000                                  # the input is not mutated


def test_accepted_opts_pass_only_what_a_builder_takes():
    def a(conn, now, *, max_age=None): ...
    def b(conn, now, **opts): ...
    def c(conn, now): ...
    o = {"max_age": 1, "window": 2}
    assert runner._accepted_opts(a, o) == {"max_age": 1}
    assert runner._accepted_opts(b, o) == o
    assert runner._accepted_opts(c, o) == {}



# --------------------------------------------------------------------------- #
# P1.5: configuration-only (AWS-style) evidence is enough for the std invariants
# --------------------------------------------------------------------------- #

async def _aws_style(db_pool, app_pool, *, db_covered=True, public_extra_port=None, now=NOW):
    """internet -> lb:443 only. Every node is covered INBOUND at tier 'configured' (a security
    group's rules say what can reach it and nothing about what it connects to), like aws_sg."""
    lb, db = await seed_asset(db_pool, "lb-p15"), await seed_asset(db_pool, "db-p15")
    lb_ref, db_ref = refs.asset_ref(lb), refs.asset_ref(db)
    edges = [EdgeOut("internet", lb_ref, "tcp", 443, 443, "configured", "seed", now)]
    if public_extra_port:
        edges.append(EdgeOut("internet", lb_ref, "tcp", public_extra_port, public_extra_port, "configured", "seed", now))
    cov = [CoverageOut(lb_ref, "in", "configured", now, "seed")]
    if db_covered:
        cov.append(CoverageOut(db_ref, "in", "configured", now, "seed"))
    out = BuildOutput(source="seed", mode="replace", edges=edges, coverage=cov, nodes=[
        NodeOut("internet", "internet"), NodeOut(lb_ref, "cloud_lb", asset_id=str(lb)),
        NodeOut(db_ref, "cloud_db", asset_id=str(db))])
    async with conn_for(app_pool) as con:
        await store.persist_build(con, out, now)


@pytest.mark.asyncio
async def test_inbound_only_configuration_evidence_lets_the_std_invariants_hold(db_pool, app_pool, fake_redis):
    await _aws_style(db_pool, app_pool)
    await enable_std(app_pool, STD_REACH)
    await enable_std(app_pool, "std:public-ports-allowlist")
    s = await go(app_pool, redis=fake_redis, force=True)
    assert s["ok"], s
    for sid in (STD_REACH, "std:public-ports-allowlist"):
        row = await inv(db_pool, sid)
        res = json.loads(row["last_result"])
        assert row["last_verdict"] == "HOLDS", (sid, res["reasons"])
        assert res["evidence_tier"] == "configured"      # said plainly: configuration, not observation
        assert res["coverage"]["relevant_ratio"] == 1.0
        assert row["valid_until"] == NOW + dt.timedelta(hours=24)
    assert await findings(db_pool) == []


@pytest.mark.asyncio
async def test_a_database_whose_rules_were_never_synced_stays_unknown_not_holds(db_pool, app_pool, fake_redis):
    """No coverage for the database: the internet is blind outbound and so is the database inbound,
    so an unknown edge between them is possible. The floor is irrelevant; the search says UNKNOWN."""
    await _aws_style(db_pool, app_pool, db_covered=False)
    await enable_std(app_pool, STD_REACH)
    await go(app_pool, redis=fake_redis, force=True)
    row = await inv(db_pool, STD_REACH)
    assert row["last_verdict"] == "UNKNOWN"
    assert json.loads(row["last_result"])["reasons"] == ["possible_via_unknown_edges"]
    assert row["valid_until"] is None


@pytest.mark.asyncio
async def test_configuration_evidence_still_finds_the_violation(db_pool, app_pool, fake_redis):
    await _aws_style(db_pool, app_pool, public_extra_port=22)
    await enable_std(app_pool, "std:public-ports-allowlist")
    await go(app_pool, redis=fake_redis, force=True)
    row = await inv(db_pool, "std:public-ports-allowlist")
    assert row["last_verdict"] == "VIOLATED"
    assert len(await findings(db_pool)) == 1


# =========================================================================== #
# P1X hardening
# =========================================================================== #

import logging  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402

JEWEL_YAML = CUSTOM_YAML.replace("acme:db-not-public", "acme:jewel-not-public").replace(
    "to: { class: data_store }", "to: { tag: crown-jewel }")


def named_yaml(name):
    return CUSTOM_YAML.replace("acme:db-not-public", name)


async def lease_state(db_pool, tid=A):
    return await db_pool.fetchrow("SELECT * FROM assurance_state WHERE tenant_id = $1", tid)


# ---- runner-1: fencing ---------------------------------------------------------------------

async def test_a_stale_evaluator_cannot_overwrite_a_newer_verdict_or_close_and_verify_its_finding(
        db_pool, app_pool, fake_redis, monkeypatch):
    """The lease lapses while replica A is between 'evaluated HOLDS' and 'recorded it'; replica B
    claims, sees the newer graph (VIOLATED) and opens a finding. A must not overwrite B's verdict,
    and must not close and verify B's finding. (Before the fence: HOLDS over VIOLATED, finding
    'fixed' with fix_verified_at, and the next tick said up_to_date.)"""
    w = await world(db_pool, app_pool, exposed=False, covered=True)
    await enable_custom(app_pool)
    real_record = runner._record
    reached, proceed, calls = asyncio.Event(), asyncio.Event(), {"n": 0}

    async def gated(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            reached.set()
            await proceed.wait()
        return await real_record(*a, **k)

    monkeypatch.setattr(runner, "_record", gated)
    a_task = asyncio.create_task(go(app_pool, force=True, redis=fake_redis))
    try:
        await asyncio.wait_for(reached.wait(), 20)            # A computed HOLDS@v1 and is about to write it
        await w.set(exposed=True, now=NOW + 5 * dt.timedelta(minutes=1))           # graph v2: the DB is exposed
        await db_pool.execute("UPDATE assurance_state SET lease_until = now() - interval '1 second'")   # A's lease lapses
        b = await go(app_pool, force=True, redis=fake_redis, now=NOW + 5 * dt.timedelta(minutes=1))
        assert result_for(b, CUSTOM)["verdict"] == "VIOLATED" and b["ok"]
        (f,) = await findings(db_pool)
        assert f["status"] == "open"
    finally:
        proceed.set()
    a = await asyncio.wait_for(a_task, 30)
    assert a["ok"] is False and any("lease lost" in e for e in a["errors"])
    assert result_for(a, CUSTOM).get("skipped") == "lease_lost"
    row = await inv(db_pool, CUSTOM)
    assert row["last_verdict"] == "VIOLATED" and row["last_graph_version"] == 2
    (f,) = await findings(db_pool)
    assert f["status"] == "open" and f["fix_verified_at"] is None
    # and the record is B's, intact: the ledger shows no HOLDS@v1 row after B's VIOLATED
    assert [x["verdict"] for x in await runs(db_pool, CUSTOM)][-1] == "VIOLATED"


async def test_the_lease_cannot_be_stolen_by_a_replica_whose_clock_runs_ahead(db_pool, app_pool, fake_redis, monkeypatch):
    """The lease was compared with each replica's own wall clock: one running 301 s ahead claimed a
    live lease at once (and then both wrote verdicts). Leases now use the database clock."""
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    entered, release = asyncio.Event(), asyncio.Event()
    real = graph_loader.load_graph_doc_with_diagnostics

    async def slow(conn, now):
        entered.set()
        await release.wait()
        return await real(conn, now)

    monkeypatch.setattr(graph_loader, "load_graph_doc_with_diagnostics", slow)
    first = asyncio.create_task(go(app_pool, force=True, redis=fake_redis))
    try:
        await asyncio.wait_for(entered.wait(), 20)
        skewed = runner._now() + dt.timedelta(seconds=301)
        monkeypatch.setattr(runner, "_now", lambda: skewed)
        second = await asyncio.wait_for(go(app_pool, force=True, redis=fake_redis), 15)
        assert second["skipped"] == "lease_held" and second["results"] == []
    finally:
        release.set()
    assert (await asyncio.wait_for(first, 30))["evaluated"] == 1


async def test_a_result_older_than_the_stored_one_is_discarded(db_pool, app_pool, fake_redis):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    await go(app_pool, redis=fake_redis)
    await db_pool.execute("UPDATE invariants SET last_graph_version = 9 WHERE invariant_id = $1", CUSTOM)
    s = await go(app_pool, force=True, redis=fake_redis, now=NOW + H)
    r = result_for(s, CUSTOM)
    assert r.get("skipped") == "stale_result" and s["ok"] is False
    row = await inv(db_pool, CUSTOM)
    assert row["last_graph_version"] == 9 and row["last_evaluated_at"] == NOW         # untouched
    async with conn_for(app_pool) as con:
        assert (await store.get_state(con)).last_eval_version == 1                     # no watermark advance from a discard


async def test_a_graph_that_moved_during_the_evaluation_closes_nothing_and_stays_due(db_pool, app_pool, fake_redis, monkeypatch):
    """HOLDS@v1 computed, a label/zone/builder bumps the graph to v2 before the findings sync:
    the verdict describes an older world, so it must not close (or verify) findings."""
    w = await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    await go(app_pool, redis=fake_redis)
    (f,) = await findings(db_pool)
    assert f["status"] == "open"
    await w.set(exposed=False, now=NOW + H)                                # fixed: graph v2
    real = findings_sync.sync_findings

    async def bump_then_sync(*a, **k):
        async with conn_for(app_pool) as con:
            await store.bump_graph_version(con)                                # v3 appears mid-evaluation
        return await real(*a, **k)

    monkeypatch.setattr(findings_sync, "sync_findings", bump_then_sync)
    s = await go(app_pool, redis=fake_redis, now=NOW + H)
    assert result_for(s, CUSTOM)["verdict"] == "HOLDS"
    assert result_for(s, CUSTOM)["findings"]["skipped"] == "graph_moved"
    assert (await findings(db_pool))[0]["status"] == "open"
    monkeypatch.setattr(findings_sync, "sync_findings", real)
    s = await go(app_pool, redis=fake_redis, now=NOW + H)                  # not forced: still due, then closes
    assert s["evaluated"] == 1
    assert (await findings(db_pool))[0]["status"] == "fixed"


# ---- runner-2: the input-document hash -----------------------------------------------------

async def test_an_input_change_that_does_not_move_graph_version_still_triggers_reevaluation(db_pool, app_pool, fake_redis):
    """Tagging an asset as a crown jewel (asset metadata) changes the evaluated document but not
    graph_version; the stored HOLDS used to stand until the backstop."""
    w = await world(db_pool, app_pool, exposed=True, covered=True)
    await db_pool.execute("UPDATE assets SET metadata = '{\"crown_jewel\": true}' WHERE id = $1", w.web)
    await enable_custom(app_pool, JEWEL_YAML)
    s = await go(app_pool, redis=fake_redis)
    assert result_for(s, "acme:jewel-not-public")["verdict"] == "HOLDS"       # the exposed DB is not a jewel; web is unreachable
    st = await lease_state(db_pool)
    assert st["last_eval_doc_sha"] and st["last_eval_version"] == st["graph_version"]
    # an idle tick changes nothing and does not spin (the hash ignores clocks and observed_at)
    s = await go(app_pool, redis=fake_redis, now=NOW + 2 * dt.timedelta(minutes=1))
    assert s["skipped"] == "up_to_date" and s["evaluated"] == 0
    v = st["graph_version"]
    await db_pool.execute("UPDATE assets SET metadata = '{\"crown_jewel\": true}' WHERE id = $1", w.db)
    assert (await lease_state(db_pool))["graph_version"] == v                    # the version did not move
    s = await go(app_pool, redis=fake_redis, now=NOW + 3 * dt.timedelta(minutes=1))   # NOT forced
    assert s["evaluated"] == 1 and result_for(s, "acme:jewel-not-public")["verdict"] == "VIOLATED"
    assert len(await findings(db_pool)) == 1
    assert (await lease_state(db_pool))["last_eval_doc_sha"] != st["last_eval_doc_sha"]
    s = await go(app_pool, redis=fake_redis, now=NOW + 4 * dt.timedelta(minutes=1))
    assert s["skipped"] == "up_to_date"


async def test_a_tenant_evaluated_before_the_hash_existed_is_reevaluated_once(db_pool, app_pool, fake_redis):
    await world(db_pool, app_pool, exposed=False, covered=True)
    await enable_custom(app_pool)
    await go(app_pool, redis=fake_redis)
    assert (await go(app_pool, redis=fake_redis, now=NOW + dt.timedelta(minutes=1)))["evaluated"] == 0
    await db_pool.execute("UPDATE assurance_state SET last_eval_doc_sha = NULL")       # as after migration 040
    await db_pool.execute("UPDATE invariants SET last_result = last_result - 'doc_sha'")
    assert (await go(app_pool, redis=fake_redis, now=NOW + 2 * dt.timedelta(minutes=1)))["evaluated"] == 1
    assert (await go(app_pool, redis=fake_redis, now=NOW + 3 * dt.timedelta(minutes=1)))["evaluated"] == 0


# ---- builders-6: an incomplete graph is never evaluated -----------------------------------

GUEST_YAML = CUSTOM_YAML.replace("acme:db-not-public", "acme:guest-not-db").replace(
    "from: { zone: internet }", "from: { zone: guest }").replace("min_tier: observed", "min_tier: configured")


async def _guest_world(db_pool, app_pool):
    db = await seed_asset(db_pool, "db-ov")
    db_ref, ip_ref = refs.asset_ref(db), "ip:10.9.0.5"
    async with conn_for(app_pool) as con:
        await store.upsert_zone(con, "guest", ["10.9.0.0/16"], set_by="t", justification="guests")
    out = BuildOutput(
        source="seed", mode="replace",
        nodes=[NodeOut(ip_ref, "ip"), NodeOut("cidr:10.0.0.0/8", "cidr"), NodeOut(db_ref, "cloud_db", asset_id=str(db))],
        edges=[EdgeOut("cidr:10.0.0.0/8", db_ref, "tcp", 5432, 5432, "configured", "seed", NOW)],
        coverage=[CoverageOut(ip_ref, "in", "observed", NOW, "seed"), CoverageOut(ip_ref, "out", "observed", NOW, "seed"),
                  CoverageOut(db_ref, "in", "configured", NOW, "seed")])
    async with conn_for(app_pool) as con:
        await store.persist_build(con, out, NOW)
    return db_ref


async def test_hitting_the_cidr_expansion_cap_makes_every_invariant_unknown_not_holds(db_pool, app_pool, fake_redis, monkeypatch):
    """With the cap hit the 10.9.0.5 -> db edge (implied by 'allow 10.0.0.0/8') is not in the
    document, 10.9.0.5 is covered outbound so no unknown edge replaces it, and the guest-cannot-
    reach-db invariant came out HOLDS although the rules admit it. The runner must refuse to
    evaluate that graph and say why."""
    await _guest_world(db_pool, app_pool)
    await enable_custom(app_pool, GUEST_YAML)
    await enable_custom(app_pool)
    s = await go(app_pool, force=True, redis=fake_redis)
    assert result_for(s, "acme:guest-not-db")["verdict"] == "VIOLATED"          # the real answer
    assert len(await findings(db_pool)) == 1
    assert runner.last_evaluation(A)["cidr_unexpanded"] == []

    monkeypatch.setattr(graph_loader, "MAX_EXPANDED_EDGES", 0)
    s = await go(app_pool, force=True, redis=fake_redis, now=NOW + H)
    assert s["ok"] is False and any("cidr_expansion_overflow" in e for e in s["errors"])
    assert {r["verdict"] for r in s["results"]} == {"UNKNOWN"} and len(s["results"]) == 2        # EVERY invariant
    assert {tuple(r["reasons"]) for r in s["results"]} == {("graph_incomplete:cidr_expansion_overflow",)}
    row = await inv(db_pool, "acme:guest-not-db")
    stored = json.loads(row["last_result"])
    assert row["last_verdict"] == "UNKNOWN" and stored["diagnostics"]["cidr_unexpanded_count"] == 1
    assert (await findings(db_pool))[0]["status"] == "open"                      # UNKNOWN changes no finding
    diag = runner.last_evaluation(A)
    assert diag["cidr_unexpanded"] and diag["cidr_unexpanded_count"] == 1 and diag["graph_ok"] is False
    assert s["diagnostics"]["cidr_unexpanded_count"] == 1
    # an unchanged incomplete graph is not re-evaluated every tick (the UNKNOWNs are current) ...
    assert (await go(app_pool, redis=fake_redis, now=NOW + H + dt.timedelta(minutes=1)))["evaluated"] == 0
    # ... and the incomplete evaluation did not stand in for a complete one: once the cap no longer
    # bites the (expanded) document differs, everything is re-evaluated without being forced
    monkeypatch.setattr(graph_loader, "MAX_EXPANDED_EDGES", 400_000)
    s = await go(app_pool, redis=fake_redis, now=NOW + 2 * H)
    assert result_for(s, "acme:guest-not-db")["verdict"] == "VIOLATED"


# ---- runner-3: close on a still-violated verdict, end to end -------------------------------

async def test_fixing_one_of_two_exposed_databases_closes_its_finding_while_the_other_stays_open(db_pool, app_pool, fake_redis):
    d1, d2 = await seed_asset(db_pool, "db-one"), await seed_asset(db_pool, "db-two")
    r1, r2 = refs.asset_ref(d1), refs.asset_ref(d2)

    async def put(*exposed, now=NOW):
        out = BuildOutput(
            source="seed", mode="replace",
            nodes=[NodeOut("internet", "internet"), NodeOut(r1, "cloud_db", asset_id=str(d1)), NodeOut(r2, "cloud_db", asset_id=str(d2))],
            edges=[EdgeOut("internet", r, "tcp", 5432, 5432, "configured", "seed", now) for r in exposed],
            coverage=[CoverageOut(r, "in", "observed", now, "seed") for r in (r1, r2)])
        async with conn_for(app_pool) as con:
            return await store.persist_build(con, out, now)

    await put(r1, r2)
    await enable_custom(app_pool)
    s = await go(app_pool, redis=fake_redis)
    assert result_for(s, CUSTOM)["violation_count"] == 2 and len(await findings(db_pool)) == 2
    await put(r2, now=NOW + H)                                                 # db-one is closed to the world
    s = await go(app_pool, redis=fake_redis, now=NOW + H)
    assert result_for(s, CUSTOM)["verdict"] == "VIOLATED"
    assert result_for(s, CUSTOM)["findings"]["closed"] == 1
    st = {f["asset_id"]: f for f in await findings(db_pool)}
    # fixed by the system, but NOT stamped verified: a VIOLATED result carries no evidence tier for the
    # targets that stopped violating (the library sets it for HOLDS only), so we cannot claim observed
    # evidence. The verified path is covered with hand-built results in test_assurance_findings.py.
    assert st[d1]["status"] == "fixed" and st[d1]["fix_verified_at"] is None and st[d1]["status_by"] == findings_sync.ACTOR
    assert st[d2]["status"] == "open"
    await put(now=NOW + 2 * H)
    s = await go(app_pool, redis=fake_redis, now=NOW + 2 * H)
    assert result_for(s, CUSTOM)["verdict"] == "HOLDS" and {f["status"] for f in await findings(db_pool)} == {"fixed"}


# ---- runner-5: budget and rotation ---------------------------------------------------------

def _slow_evaluate(monkeypatch, order, delay=0.25):
    import paddock_assurance as lib
    real = lib.evaluate

    def slow(plan, graph, now):
        order.append(plan.id)
        time.sleep(delay)
        return real(plan, graph, now)

    monkeypatch.setattr(lib, "evaluate", slow)


async def test_the_budget_clock_starts_after_the_graph_is_loaded(db_pool, app_pool, fake_redis, monkeypatch):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    real = graph_loader.load_graph_doc_with_diagnostics

    async def slow_load(conn, now):
        await asyncio.sleep(0.4)                 # a big estate: loading alone outlasts the budget
        return await real(conn, now)

    monkeypatch.setattr(graph_loader, "load_graph_doc_with_diagnostics", slow_load)
    monkeypatch.setattr(runner, "TENANT_BUDGET_S", 0.2)
    s = await go(app_pool, redis=fake_redis)
    assert s["evaluated"] == 1 and "deferred" not in s


async def test_deferred_invariants_go_first_next_tick_so_none_starves_and_the_deferral_is_logged(
        db_pool, app_pool, fake_redis, monkeypatch, caplog):
    await world(db_pool, app_pool, exposed=True, covered=True)
    for n in ("acme:a", "acme:b", "acme:c"):
        await enable_custom(app_pool, named_yaml(n))
    order: list[str] = []
    _slow_evaluate(monkeypatch, order)
    monkeypatch.setattr(runner, "TENANT_BUDGET_S", 0.2)
    with caplog.at_level(logging.WARNING, logger=runner.logger.name):
        s1 = await go(app_pool, redis=fake_redis, now=NOW)
    assert s1["evaluated"] == 1 and s1["deferred"] == 2 and s1["deferred_ids"] == ["acme:b", "acme:c"]
    assert any(r.getMessage() == "assurance_deferred" and r.levelno >= logging.WARNING for r in caplog.records)
    s2 = await go(app_pool, redis=fake_redis, now=NOW + dt.timedelta(minutes=1))
    assert [r["invariant_id"] for r in s2["results"]] == ["acme:b"] and s2["deferred"] == 1
    s3 = await go(app_pool, redis=fake_redis, now=NOW + 2 * dt.timedelta(minutes=1))
    assert [r["invariant_id"] for r in s3["results"]] == ["acme:c"] and "deferred" not in s3
    assert order == ["acme:a", "acme:b", "acme:c"]                           # each exactly once: no wasted re-runs
    for n in ("acme:a", "acme:b", "acme:c"):
        assert (await inv(db_pool, n))["last_verdict"] == "VIOLATED"
    async with conn_for(app_pool) as con:
        assert (await store.get_state(con)).last_eval_version == 1               # the watermark advanced once all were done


async def test_when_everything_is_due_again_the_longest_unevaluated_runs_first(db_pool, app_pool, fake_redis, monkeypatch):
    """Backstop-driven passes make every invariant due; with a budget that fits one, the order must
    rotate (oldest evaluation first) instead of always starting with 'a'."""
    await world(db_pool, app_pool, exposed=True, covered=True)
    for n in ("acme:a", "acme:b", "acme:c"):
        await enable_custom(app_pool, named_yaml(n))
    await go(app_pool, redis=fake_redis, now=NOW)                                # all three evaluated
    monkeypatch.setattr(settings, "assurance_backstop_min", 1)
    order: list[str] = []
    _slow_evaluate(monkeypatch, order)
    monkeypatch.setattr(runner, "TENANT_BUDGET_S", 0.2)
    for k in (2, 4, 6):
        await go(app_pool, redis=fake_redis, now=NOW + k * dt.timedelta(minutes=1))
    assert order == ["acme:a", "acme:b", "acme:c"]


# ---- runner-6 / security-3: compile once, off the event loop -----------------------------------

async def test_stored_definitions_are_compiled_once_per_digest_and_off_the_event_loop(db_pool, app_pool, fake_redis, monkeypatch):
    import paddock_assurance as lib
    await world(db_pool, app_pool, exposed=False, covered=True)
    await enable_custom(app_pool)
    await enable_std(app_pool)
    real = lib.compile_text
    seen: list[tuple[str, bool]] = []

    def counting(text):
        seen.append((text[:60], threading.current_thread() is threading.main_thread()))
        return real(text)

    monkeypatch.setattr(lib, "compile_text", counting)
    runner._PLAN_CACHE.clear()
    await go(app_pool, redis=fake_redis)
    first = len(seen)
    assert first == 2 and not any(on_loop for _t, on_loop in seen)             # one each, in a worker thread
    for k in range(1, 4):                                                       # idle ticks and a forced run
        await go(app_pool, redis=fake_redis, now=NOW + k * dt.timedelta(minutes=1))
    await go(app_pool, force=True, redis=fake_redis, now=NOW + 5 * dt.timedelta(minutes=1))
    assert len(seen) == first, seen
    # an edit (new yaml, new digest) is compiled once, and only that one
    row = await inv(db_pool, CUSTOM)
    edited = row["yaml"].replace("severity: high", "severity: medium")
    plan = real(edited)
    await db_pool.execute("UPDATE invariants SET yaml = $2, digest = $3, severity = 'medium' WHERE id = $1",
                          row["id"], edited, plan.digest)
    s = await go(app_pool, redis=fake_redis, now=NOW + 6 * dt.timedelta(minutes=1))
    assert s["evaluated"] == 1 and len(seen) == first + 1


async def test_an_invalid_definition_is_not_recompiled_every_tick(db_pool, app_pool, fake_redis, monkeypatch):
    import paddock_assurance as lib
    await world(db_pool, app_pool, exposed=False, covered=True)
    await enable_custom(app_pool)
    await db_pool.execute("UPDATE invariants SET yaml = 'not: [valid' WHERE invariant_id = $1", CUSTOM)
    real = lib.compile_text
    n = {"c": 0}

    def counting(text):
        n["c"] += 1
        return real(text)

    monkeypatch.setattr(lib, "compile_text", counting)
    for k in range(4):
        s = await go(app_pool, redis=fake_redis, now=NOW + k * dt.timedelta(minutes=1))
    assert n["c"] == 1
    assert (await inv(db_pool, CUSTOM))["last_verdict"] == "UNKNOWN"


# ---- runner-7: cancellation between record and sync --------------------------------------------

async def test_cancellation_between_record_and_findings_sync_makes_the_invariant_due_again(db_pool, app_pool, fake_redis, monkeypatch):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    await go(app_pool, redis=fake_redis)                                       # a complete pass: watermark == graph version
    await enable_std(app_pool)                                                 # a new invariant
    real = findings_sync.sync_findings
    entered = asyncio.Event()

    async def hang(*a, **k):
        entered.set()
        await asyncio.sleep(60)

    monkeypatch.setattr(findings_sync, "sync_findings", hang)
    task = asyncio.create_task(go(app_pool, redis=fake_redis, now=NOW + dt.timedelta(minutes=1)))
    await asyncio.wait_for(entered.wait(), 20)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    row = await inv(db_pool, STD_REACH)
    assert row["last_verdict"] is not None and row["last_graph_version"] is None      # verdict recorded, sync flagged for retry
    assert (await lease_state(db_pool))["lease_owner"] is None
    monkeypatch.setattr(findings_sync, "sync_findings", real)
    s = await go(app_pool, redis=fake_redis, now=NOW + 2 * dt.timedelta(minutes=1))       # not forced, graph unchanged
    assert [r["invariant_id"] for r in s["results"]] == [STD_REACH]
    assert len(await findings(db_pool, rule_like=f"invariant:{STD_REACH}%")) == 1


# ---- security-6: the loop honours the billing gate ---------------------------------------------

@pytest.fixture
def enforce(monkeypatch):
    from app.billing import config as bcfg
    monkeypatch.setattr(bcfg.settings, "enforce_editions", "on")
    yield


async def test_the_loop_skips_tenants_without_the_assurance_entitlement_when_editions_are_enforced(
        db_pool, app_pool, fake_redis, monkeypatch, enforce):
    w = await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    built = []
    good = _fake_builder("good", edge=EdgeOut("internet", w.db_ref, "tcp", 5432, 5432, "configured", "good", NOW))
    real_build = good.build
    good.build = lambda rows, now, **o: (built.append(1), real_build(rows, now, **o))[1]
    monkeypatch.setattr(builders_pkg, "load_builders", lambda: [good])
    out = await runner.tick_once(app_pool, redis=fake_redis, now=NOW)
    assert out[A]["skipped"] == "not_entitled" and out[A]["evaluated"] == 0 and out[A]["ok"] is True
    assert built == [] and await findings(db_pool) == []
    assert (await inv(db_pool, CUSTOM))["last_verdict"] is None
    # the API path (evaluate_tenant) is gated by its own dependency and is not changed here
    assert (await runner.evaluate_tenant(app_pool, A, force=True, redis=fake_redis))["evaluated"] == 1


async def test_an_entitled_tenant_is_served_and_lookup_failures_fail_open(db_pool, app_pool, fake_redis, monkeypatch, enforce):
    from app import licensing
    from app.billing import service as billing_service
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)

    async def paid(pool, lic, **kw):
        return types.SimpleNamespace(has=lambda f: f == "assurance")

    monkeypatch.setattr(billing_service, "resolve", paid)
    out = await runner.tick_once(app_pool, redis=fake_redis, now=NOW)
    assert out[A]["skipped"] is None and out[A]["evaluated"] == 1

    async def boom(pool):
        raise RuntimeError("billing is down")

    monkeypatch.undo()                                                          # drop the entitlement stub ...
    monkeypatch.setattr(builders_pkg, "load_builders", lambda: [])
    monkeypatch.setattr(settings, "assurance_backstop_min", 100_000)
    monkeypatch.setattr(settings, "assurance_rebuild_min", 100_000)
    from app.billing import config as bcfg
    monkeypatch.setattr(bcfg.settings, "enforce_editions", "on")
    monkeypatch.setattr(licensing, "load_active_license", boom)                 # ... and break the lookup
    assert await runner._entitled(app_pool, A) is True


async def test_without_enforcement_the_loop_is_unchanged(db_pool, app_pool, fake_redis):
    await world(db_pool, app_pool, exposed=True, covered=True)
    await enable_custom(app_pool)
    out = await runner.tick_once(app_pool, redis=fake_redis, now=NOW)
    assert out[A]["skipped"] is None and out[A]["evaluated"] == 1
