"""Disabled, deleted, invalid and unentitled invariants: annotate, never close (docs/ASSURANCE_P2_1.md 6.1, D33).

Before P2.1 ``PUT enabled=false`` and ``DELETE`` both just set ``enabled=false``: the runner only visits enabled
invariants, so the open findings of such an invariant were never touched again (correct: closing them would be a false
verification, nothing re-checked them) but looked exactly like live ones. Now:

  * the toggle annotates the open and triaged findings of the invariant in the SAME transaction
    (``metadata.invariant_state`` in {disabled, archived, invalid_definition, not_entitled}); status never changes;
  * the runner annotates ``invalid_definition`` and ``not_entitled`` findings and a per-tick reconcile repairs drift;
  * re-enabling clears the annotation and the ordinary rules decide after a fresh evaluation;
  * ``POST /v1/invariants/{id}/findings/release`` (admin, a human decision) sets ``wontfix`` with a reason, only for an
    invariant that is not active, and a later re-enable or violation never reopens it.

Hostile cases (contract 8.4 #24): nothing the machine does closes a finding of a non-enabled invariant, and a release is
sticky.
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import json
import uuid

import pytest
import pytest_asyncio

from app import tenancy
from app.assurance import builders as builders_pkg
from app.assurance import findings_sync as fs
from app.assurance import housekeeping, refs, runner, store
from app.assurance.types import BuildOutput, CoverageOut, EdgeOut, NodeOut
from app.config import settings

from .test_assurance_api import TENANT_B, _audit_rows, _create, billing, enforce, inv_yaml  # noqa: F401
from .test_assurance_findings import mk_asset, reach_witness, result
from .test_governance import _hdr, _seed_user_with_key
from .test_tenancy import _seed_admin

A = tenancy.DEFAULT_TENANT_ID
NOW = dt.datetime(2026, 12, 1, 9, 0, tzinfo=dt.timezone.utc)
CUSTOM = "acme:guest-cannot-reach-pos"
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
DB = "acme:db-not-public"


@pytest.fixture(autouse=True)
def _isolate_runner(monkeypatch):
    monkeypatch.setattr(builders_pkg, "load_builders", lambda: [])
    monkeypatch.setattr(settings, "assurance_backstop_min", 100_000)
    monkeypatch.setattr(settings, "assurance_rebuild_min", 100_000)
    for d in (runner._LAST_BUILD, runner._LAST_EVAL, runner._PLAN_CACHE):
        d.clear()
    if hasattr(runner, "_RECONCILE_LAST"):
        runner._RECONCILE_LAST.clear()
    yield
    for d in (runner._LAST_BUILD, runner._LAST_EVAL, runner._PLAN_CACHE):
        d.clear()


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

async def seed_findings(db_pool, redis, invariant_id=CUSTOM, n=2, *, estate=False):
    """``n`` open findings of ``invariant_id`` through the real sync (rule ids and metadata as production)."""
    ws = []
    for i in range(n):
        target = f"ip:203.0.113.{i + 1}" if estate else f"asset:{await mk_asset(db_pool, f'{invariant_id}-{i}.example')}"
        ws.append(reach_witness(target))
    await fs.sync_findings(db_pool, redis, invariant_id=invariant_id, title="Guests can reach the POS",
                           result=result("VIOLATED", *ws), graph_version=7, now=NOW)


async def frows(db_pool, like="invariant:%"):
    out = []
    for r in await db_pool.fetch("SELECT * FROM findings WHERE rule_source = 'invariant' AND rule_id LIKE $1 "
                                 "ORDER BY rule_id, first_seen", like):
        d = dict(r)
        d["metadata"] = json.loads(d["metadata"]) if isinstance(d["metadata"], str) else d["metadata"]
        out.append(d)
    return out


def states(rows):
    return [r["metadata"].get("invariant_state") for r in rows]


async def inv_row(db_pool, invariant_id=CUSTOM):
    return await db_pool.fetchrow("SELECT * FROM invariants WHERE invariant_id = $1", invariant_id)


async def history(db_pool, fid):
    return await db_pool.fetch("SELECT from_status, to_status, reason, actor FROM finding_status_history "
                               "WHERE finding_id = $1 ORDER BY at, id", fid)


async def set_state_via_api(client, inv, *, enabled):
    r = await client.put(f"/v1/invariants/{inv['id']}", json={"enabled": enabled})
    assert r.status_code == 200, r.text
    return r.json()


# --------------------------------------------------------------------------- #
# the toggle annotates and never changes a status
# --------------------------------------------------------------------------- #

async def test_disabling_annotates_open_and_triaged_findings_and_changes_no_status(client, db_pool, fake_redis):
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis, n=3)
    mine = await frows(db_pool)
    await db_pool.execute("UPDATE findings SET status = 'triaged' WHERE id = $1", mine[0]["id"])
    await db_pool.execute("UPDATE findings SET status = 'fixed' WHERE id = $1", mine[2]["id"])
    other = f"{CUSTOM}-extra"                                           # a prefix-sharing id must stay untouched
    await seed_findings(db_pool, fake_redis, other, n=1)
    before = {r["id"]: r["status"] for r in await frows(db_pool)}
    hist_before = await db_pool.fetchval("SELECT count(*) FROM finding_status_history")

    out = await set_state_via_api(client, inv, enabled=False)
    assert out["invariant"]["state"] == "disabled" and out["invariant"]["status"] == "DISABLED"

    after = await frows(db_pool)
    assert {r["id"]: r["status"] for r in after} == before                    # no status moved, nothing closed
    assert await db_pool.fetchval("SELECT count(*) FROM finding_status_history") == hist_before
    own = [r for r in after if r["rule_id"] == f"invariant:{CUSTOM}"]
    assert sorted(r["status"] for r in own) == ["fixed", "open", "triaged"]
    for r in own:
        if r["status"] in ("open", "triaged"):
            assert r["metadata"]["invariant_state"] == "disabled" and r["metadata"]["invariant_state_at"]
        else:
            assert "invariant_state" not in r["metadata"]                        # a closed finding is not annotated
    assert states([r for r in after if r["rule_id"] == f"invariant:{other}"]) == [None]
    row = await inv_row(db_pool)
    assert row["enabled"] is False and row["disabled_at"] is not None and row["archived_at"] is None
    assert row["disabled_by"]


async def test_estate_findings_with_the_at_suffix_are_annotated_too(client, db_pool, fake_redis):
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis, n=2, estate=True)
    rows = await frows(db_pool)
    assert all("@" in r["rule_id"] for r in rows)
    await set_state_via_api(client, inv, enabled=False)
    assert states(await frows(db_pool)) == ["disabled", "disabled"]


async def test_delete_archives_and_annotates_archived(client, db_pool, fake_redis):
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis)
    r = await client.delete(f"/v1/invariants/{inv['id']}")
    assert r.status_code == 200 and r.json()["invariant"]["state"] == "archived" and r.json()["changed"] is True
    assert states(await frows(db_pool)) == ["archived", "archived"]
    assert {x["status"] for x in await frows(db_pool)} == {"open"}
    row = await inv_row(db_pool)
    assert row["archived_at"] is not None and row["enabled"] is False
    # deleting again changes nothing and keeps the first timestamp
    stamp = row["archived_at"]
    again = (await client.delete(f"/v1/invariants/{inv['id']}")).json()
    assert again["changed"] is False and (await inv_row(db_pool))["archived_at"] == stamp


async def test_a_disabled_invariant_that_is_deleted_becomes_archived(client, db_pool, fake_redis):
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis)
    await set_state_via_api(client, inv, enabled=False)
    first = (await inv_row(db_pool))["disabled_at"]
    r = await client.delete(f"/v1/invariants/{inv['id']}")
    assert r.json()["changed"] is True and r.json()["invariant"]["state"] == "archived"
    assert states(await frows(db_pool)) == ["archived", "archived"]
    assert (await inv_row(db_pool))["disabled_at"] == first                      # history is kept


async def test_disabling_twice_keeps_the_first_disabled_at_and_by(client, db_pool):
    inv = await _create(client)
    await set_state_via_api(client, inv, enabled=False)
    row = await inv_row(db_pool)
    out = await set_state_via_api(client, inv, enabled=False)
    assert out["changed"] is False
    row2 = await inv_row(db_pool)
    assert (row2["disabled_at"], row2["disabled_by"]) == (row["disabled_at"], row["disabled_by"])


async def test_re_enabling_clears_the_annotation_the_timestamps_and_marks_the_invariant_due(client, db_pool, fake_redis):
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis)
    await set_state_via_api(client, inv, enabled=False)
    await client.delete(f"/v1/invariants/{inv['id']}")
    out = await set_state_via_api(client, inv, enabled=True)
    assert out["invariant"]["state"] == "active" and out["invariant"]["status"] == "PENDING"
    rows = await frows(db_pool)
    assert states(rows) == [None, None]
    assert all("invariant_state_at" not in r["metadata"] for r in rows)
    assert {r["status"] for r in rows} == {"open"}
    row = await inv_row(db_pool)
    assert row["enabled"] and row["disabled_at"] is None and row["archived_at"] is None and row["disabled_by"] is None
    assert row["last_graph_version"] is None                                      # evaluate first, then decide


async def test_the_annotation_survives_a_refresh_of_the_finding(client, db_pool, fake_redis):
    """``bulk_upsert`` merges metadata with ``||``: a late refresh of the same finding keeps the annotation."""
    inv = await _create(client)
    a = await mk_asset(db_pool, "refresh.example")
    res = result("VIOLATED", reach_witness(f"asset:{a}"))
    await fs.sync_findings(db_pool, fake_redis, invariant_id=CUSTOM, title="t", result=res, graph_version=7, now=NOW)
    await set_state_via_api(client, inv, enabled=False)
    await fs.sync_findings(db_pool, fake_redis, invariant_id=CUSTOM, title="t", result=res, graph_version=8, now=NOW)
    (row,) = await frows(db_pool)
    assert row["metadata"]["invariant_state"] == "disabled" and row["metadata"]["target_ref"] == f"asset:{a}"


async def test_std_enable_of_a_disabled_copy_clears_the_annotation(client, db_pool, fake_redis):
    r = await client.post("/v1/invariants/std/std:no-internet-to-datastore/enable")
    assert r.status_code in (200, 201), r.text
    rid = r.json()["invariant"]["id"]
    await seed_findings(db_pool, fake_redis, "std:no-internet-to-datastore", n=1)
    await client.put(f"/v1/invariants/{rid}", json={"enabled": False})
    assert states(await frows(db_pool)) == ["disabled"]
    assert (await client.post("/v1/invariants/std/std:no-internet-to-datastore/enable")).status_code == 200
    assert states(await frows(db_pool)) == [None]
    row = await inv_row(db_pool, "std:no-internet-to-datastore")
    assert row["enabled"] and row["disabled_at"] is None


async def test_a_definition_change_alone_neither_annotates_nor_clears(client, db_pool, fake_redis):
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis, n=1)
    await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": inv_yaml(title="Renamed guest rule")})
    assert states(await frows(db_pool)) == [None]


# --------------------------------------------------------------------------- #
# GET: state, open_findings, findings_not_rechecked
# --------------------------------------------------------------------------- #

async def test_get_reports_state_and_how_many_findings_nobody_is_rechecking(client, db_pool, fake_redis):
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis, n=3)
    got = (await client.get(f"/v1/invariants/{inv['id']}")).json()
    assert (got["state"], got["open_findings"], got["findings_not_rechecked"]) == ("active", 3, 0)
    await set_state_via_api(client, inv, enabled=False)
    got = (await client.get(f"/v1/invariants/{inv['id']}")).json()
    assert (got["state"], got["open_findings"], got["findings_not_rechecked"]) == ("disabled", 3, 3)
    await client.delete(f"/v1/invariants/{inv['id']}")
    got = (await client.get(f"/v1/invariants/{inv['id']}")).json()
    assert (got["state"], got["findings_not_rechecked"]) == ("archived", 3)
    listed = (await client.get("/v1/invariants")).json()["items"][0]
    assert listed["state"] == "archived"
    await db_pool.execute("UPDATE findings SET status = 'fixed' WHERE id = (SELECT id FROM findings LIMIT 1)")
    got = (await client.get(f"/v1/invariants/{inv['id']}")).json()
    assert (got["open_findings"], got["findings_not_rechecked"]) == (2, 2)


async def test_get_counts_do_not_leak_findings_of_other_invariants_or_tenants(client, db_pool, fake_redis):
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis, n=1)
    await seed_findings(db_pool, fake_redis, f"{CUSTOM}-extra", n=2)
    got = (await client.get(f"/v1/invariants/{inv['id']}")).json()
    assert got["open_findings"] == 1


# --------------------------------------------------------------------------- #
# the release route
# --------------------------------------------------------------------------- #

async def release(client, inv, why="the POS network was decommissioned in the move", **kw):
    return await client.post(f"/v1/invariants/{inv['id']}/findings/release", json={"justification": why}, **kw)


async def test_release_is_refused_for_an_active_invariant(client, db_pool, fake_redis):
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis)
    r = await release(client, inv)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "invariant_active"
    assert {x["status"] for x in await frows(db_pool)} == {"open"}
    assert not await _audit_rows(db_pool, "assurance_findings_release")


@pytest.mark.parametrize("how,state", [("disable", "disabled"), ("delete", "archived")])
async def test_release_marks_the_open_findings_wontfix_as_a_human_decision(client, db_pool, fake_redis, how, state):
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis, n=3)
    await db_pool.execute("UPDATE findings SET status = 'triaged' WHERE id = (SELECT id FROM findings LIMIT 1)")
    done = (await frows(db_pool))[2]
    await db_pool.execute("UPDATE findings SET status = 'accepted_risk', status_reason = 'known' WHERE id = $1", done["id"])
    if how == "disable":
        await set_state_via_api(client, inv, enabled=False)
    else:
        await client.delete(f"/v1/invariants/{inv['id']}")
    why = "the POS network was decommissioned in the move"
    r = await release(client, inv, why)
    assert r.status_code == 200 and r.json() == {"released": 2}
    rows = {x["id"]: x for x in await frows(db_pool)}
    released = [x for x in rows.values() if x["status"] == "wontfix"]
    assert len(released) == 2
    for x in released:
        assert x["status_reason"] == f"invariant {state}: {why}"
        assert x["status_by"] and x["status_changed_at"] is not None
        assert x["fix_verified_at"] is None                                 # a decision, never a verification
        h = await history(db_pool, x["id"])
        assert [(i["from_status"], i["to_status"]) for i in h][-1][1] == "wontfix"
        assert why in h[-1]["reason"]
    assert rows[done["id"]]["status"] == "accepted_risk"                       # another human decision is untouched
    (audit,) = await _audit_rows(db_pool, "assurance_findings_release")
    assert audit["resource_type"] == "invariants" and audit["resource_id"] == inv["id"]
    assert audit["justification"] == why
    assert audit["details"]["released"] == 2 and audit["details"]["state"] == state
    assert audit["details"]["invariant_id"] == CUSTOM
    # idempotent: nothing is left to release
    assert (await release(client, inv)).json() == {"released": 0}


async def test_a_release_is_sticky_a_re_enable_and_a_new_violation_never_reopen_it(client, db_pool, fake_redis):
    inv = await _create(client)
    a = await mk_asset(db_pool, "sticky.example")
    res = result("VIOLATED", reach_witness(f"asset:{a}"))
    await fs.sync_findings(db_pool, fake_redis, invariant_id=CUSTOM, title="t", result=res, graph_version=7, now=NOW)
    await set_state_via_api(client, inv, enabled=False)
    assert (await release(client, inv)).json() == {"released": 1}
    await set_state_via_api(client, inv, enabled=True)
    (row,) = await frows(db_pool)
    assert row["status"] == "wontfix" and "invariant_state" not in row["metadata"]
    # the invariant fires again: the machine does not undo a human's wontfix, in either direction
    await fs.sync_findings(db_pool, fake_redis, invariant_id=CUSTOM, title="t", result=res, graph_version=8, now=NOW)
    await fs.sync_findings(db_pool, fake_redis, invariant_id=CUSTOM, title="t",
                           result=result("HOLDS", tier="observed"), graph_version=9, now=NOW)
    (row,) = await frows(db_pool)
    assert row["status"] == "wontfix"


@pytest.mark.parametrize("body", [{}, {"justification": ""}, {"justification": "too short"},
                                  {"justification": "   " + "x" * 5 + "   "}, {"justification": "x" * 1001},
                                  {"justification": 12345678901}])
async def test_release_needs_a_real_justification(client, db_pool, fake_redis, body):
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis)
    await client.delete(f"/v1/invariants/{inv['id']}")
    r = await client.post(f"/v1/invariants/{inv['id']}/findings/release", json=body)
    assert r.status_code == 422, r.text
    assert {x["status"] for x in await frows(db_pool)} == {"open"}


@pytest.mark.parametrize("raw", ['"a reason with a \\u0000 NUL byte in it"', '"' + "x" * 20 + '\\u0000"'])
async def test_release_refuses_text_the_database_cannot_store_instead_of_a_500(client, db_pool, fake_redis, raw):
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis)
    await client.delete(f"/v1/invariants/{inv['id']}")
    r = await client.post(f"/v1/invariants/{inv['id']}/findings/release",
                          content=('{"justification": %s}' % raw).encode(), headers={"content-type": "application/json"})
    assert r.status_code == 422, r.text
    assert {x["status"] for x in await frows(db_pool)} == {"open"}
    assert not await _audit_rows(db_pool, "assurance_findings_release")


async def test_a_nul_byte_in_any_justification_is_a_422_not_a_500(client, db_pool):
    inv = await _create(client)
    bad = "a perfectly fine reason \u0000 with a NUL"
    assert (await client.put(f"/v1/invariants/{inv['id']}", json={"enabled": False, "justification": bad})
            ).status_code == 422
    assert (await client.delete(f"/v1/invariants/{inv['id']}", params={"justification": bad})).status_code == 422
    assert (await inv_row(db_pool)) ["enabled"] is True                       # nothing happened


async def test_a_validation_error_is_answered_before_any_lookup(client):
    r_known = await client.post(f"/v1/invariants/{uuid.uuid4()}/findings/release", json={"justification": "x"})
    assert r_known.status_code == 422                      # the body is judged first: unknown ids cannot be probed


async def test_release_unknown_invariant_is_the_uniform_404(client):
    r = await client.post(f"/v1/invariants/{uuid.uuid4()}/findings/release",
                          json={"justification": "a perfectly good reason"})
    assert r.status_code == 404 and r.json() == {"detail": "invariant not found"}


async def test_release_is_never_billing_gated(client, db_pool, fake_redis, billing):  # noqa: F811
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis)
    await client.delete(f"/v1/invariants/{inv['id']}")
    await db_pool.execute("UPDATE tenants SET created_at = NOW() - make_interval(days => 60) WHERE id = $1::uuid", A)
    # a paid action is refused for this lapsed tenant ...
    assert (await client.post("/v1/invariants", json={"yaml": inv_yaml("acme:new")})).status_code == 402
    # ... a release (cleanup of a decision) is not
    assert (await release(client, inv)).json() == {"released": 2}


async def test_release_rbac_admin_only(enforce, client, db_pool, fake_redis):  # noqa: F811
    admin = _hdr(await _seed_admin(db_pool, A, "ada-admin"))
    _, vk = await _seed_user_with_key(db_pool, "vera", "viewer", "public")
    inv = (await client.post("/v1/invariants", headers=admin, json={"yaml": inv_yaml()})).json()["invariant"]
    await seed_findings(db_pool, fake_redis)
    await client.delete(f"/v1/invariants/{inv['id']}", headers=admin)
    body = {"justification": "a perfectly good reason"}
    path = f"/v1/invariants/{inv['id']}/findings/release"
    assert (await client.post(path, json=body)).status_code == 401
    assert (await client.post(path, headers=_hdr(vk), json=body)).status_code == 403
    assert {x["status"] for x in await frows(db_pool)} == {"open"}
    assert (await client.post(path, headers=admin, json=body)).json() == {"released": 2}


async def test_counts_and_release_never_touch_findings_of_assets_above_the_callers_clearance(
        enforce, client, db_pool, fake_redis):  # noqa: F811
    admin = _hdr(await _seed_admin(db_pool, A, "ada-admin"))                   # full clearance
    _, low = await _seed_user_with_key(db_pool, "lowadmin", "admin", "public")   # an admin who may not see restricted assets
    inv = (await client.post("/v1/invariants", headers=admin, json={"yaml": inv_yaml()})).json()["invariant"]
    await seed_findings(db_pool, fake_redis, n=2)
    hidden, visible = (await frows(db_pool))[:2]
    await db_pool.execute("UPDATE assets SET classification = 'restricted' WHERE id = $1", hidden["asset_id"])
    await db_pool.execute("UPDATE assets SET classification = 'public' WHERE id = $1", visible["asset_id"])
    await client.delete(f"/v1/invariants/{inv['id']}", headers=admin)
    full = (await client.get(f"/v1/invariants/{inv['id']}", headers=admin)).json()
    seen = (await client.get(f"/v1/invariants/{inv['id']}", headers=_hdr(low))).json()
    assert (full["open_findings"], full["findings_not_rechecked"]) == (2, 2)
    assert (seen["open_findings"], seen["findings_not_rechecked"]) == (1, 1)    # the classified one is not even counted
    path = f"/v1/invariants/{inv['id']}/findings/release"
    body = {"justification": "a perfectly good reason"}
    assert (await client.post(path, headers=_hdr(low), json=body)).json() == {"released": 1}
    by = {r["id"]: r["status"] for r in await frows(db_pool)}
    assert by[hidden["id"]] == "open" and sorted(by.values()) == ["open", "wontfix"]
    assert (await client.post(path, headers=admin, json=body)).json() == {"released": 1}


async def test_release_cannot_cross_tenants(enforce, client, app, app_pool, db_pool, fake_redis):  # noqa: F811
    app.state.pool = app_pool
    await tenancy.create_tenant(db_pool, slug="bravo-life", name="Bravo", tenant_id=TENANT_B)
    ka = _hdr(await _seed_admin(db_pool, A, "alice-admin"))
    kb = _hdr(await _seed_admin(db_pool, TENANT_B, "bob-admin"))
    inv = (await client.post("/v1/invariants", headers=ka, json={"yaml": inv_yaml()})).json()["invariant"]
    await seed_findings(db_pool, fake_redis)
    await client.delete(f"/v1/invariants/{inv['id']}", headers=ka)
    body = {"justification": "a perfectly good reason"}
    foreign = await client.post(f"/v1/invariants/{inv['id']}/findings/release", headers=kb, json=body)
    unknown = await client.post(f"/v1/invariants/{uuid.uuid4()}/findings/release", headers=kb, json=body)
    assert foreign.status_code == unknown.status_code == 404 and foreign.json() == unknown.json()
    assert {x["status"] for x in await frows(db_pool)} == {"open"}


async def test_an_enabled_invariant_with_a_runner_annotation_may_be_released_but_a_clean_one_may_not(
        client, db_pool, fake_redis):
    inv = await _create(client)
    await seed_findings(db_pool, fake_redis, n=2)
    assert (await release(client, inv)).status_code == 409
    await db_pool.execute("UPDATE findings SET metadata = metadata || "
                          "'{\"invariant_state\": \"invalid_definition\"}'::jsonb "
                          "WHERE id = (SELECT id FROM findings ORDER BY id LIMIT 1)")
    r = await release(client, inv, "the definition was abandoned for good")
    assert r.status_code == 200 and r.json() == {"released": 1}               # only the annotated one
    rows = await frows(db_pool)
    assert sorted(x["status"] for x in rows) == ["open", "wontfix"]
    w = next(x for x in rows if x["status"] == "wontfix")
    assert w["status_reason"] == "invariant invalid_definition: the definition was abandoned for good"


async def test_release_of_an_enabled_invariant_does_not_reveal_flagged_findings_the_caller_may_not_see(
        enforce, client, db_pool, fake_redis):  # noqa: F811
    """409 versus 200 {released: 0} must not tell a low-clearance admin that a hidden finding is runner-flagged."""
    admin = _hdr(await _seed_admin(db_pool, A, "ada-admin"))
    _, low = await _seed_user_with_key(db_pool, "lowadmin", "admin", "public")
    inv = (await client.post("/v1/invariants", headers=admin, json={"yaml": inv_yaml()})).json()["invariant"]
    await seed_findings(db_pool, fake_redis, n=2)
    hidden, visible = (await frows(db_pool))[:2]
    await db_pool.execute("UPDATE assets SET classification = 'restricted' WHERE id = $1", hidden["asset_id"])
    await db_pool.execute("UPDATE assets SET classification = 'public' WHERE id = $1", visible["asset_id"])
    await db_pool.execute("UPDATE findings SET metadata = metadata || "
                          "'{\"invariant_state\": \"invalid_definition\"}'::jsonb WHERE id = $1", hidden["id"])
    path = f"/v1/invariants/{inv['id']}/findings/release"
    body = {"justification": "a perfectly good reason"}
    r = await client.post(path, headers=_hdr(low), json=body)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "invariant_active"      # as if nothing were flagged
    assert {x["status"] for x in await frows(db_pool)} == {"open"}
    assert (await client.post(path, headers=admin, json=body)).json() == {"released": 1}   # the full-clearance admin may


# --------------------------------------------------------------------------- #
# the runner: it never closes what it did not re-check, and it annotates what it cannot
# --------------------------------------------------------------------------- #

@contextlib.asynccontextmanager
async def conn_for(pool, tid=A):
    with tenancy.tenant_context(tid):
        async with pool.acquire() as con:
            yield con


class World:
    def __init__(self, pool, db, web):
        self.pool, self.db, self.web = pool, db, web
        self.db_ref, self.web_ref = refs.asset_ref(db), refs.asset_ref(web)

    async def set(self, *, exposed=True, now=NOW):
        edges = [EdgeOut("internet", self.db_ref, "tcp", 5432, 5432, "configured", "seed", now)] if exposed else []
        cov = [CoverageOut(r, "in", "observed", now, "seed") for r in (self.db_ref, self.web_ref)]
        out = BuildOutput(
            source="seed", mode="replace", edges=edges, coverage=cov,
            nodes=[NodeOut("internet", "internet"), NodeOut(self.db_ref, "cloud_db", asset_id=str(self.db)),
                   NodeOut(self.web_ref, "cloud_instance", asset_id=str(self.web))])
        async with conn_for(self.pool) as con:
            return await store.persist_build(con, out, now)


async def world(db_pool, app_pool):
    async def asset(v):
        return await db_pool.fetchval("INSERT INTO assets (tenant_id, kind, value, canonical, source) "
                                      "VALUES ($1, 'cloud_resource', $2, $2, 'test') RETURNING id", A, v)
    w = World(app_pool, await asset("db-a"), await asset("web-a"))
    await w.set()
    return w


async def custom(app_pool, *, enabled=True):
    import paddock_assurance as lib
    plan = lib.compile_text(CUSTOM_YAML)
    async with conn_for(app_pool) as con:
        await con.execute(
            "INSERT INTO invariants (invariant_id, title, severity, enabled, source, yaml, digest, version) "
            "VALUES ($1, $2, $3, $4, 'custom', $5, $6, 1)",
            plan.id, plan.invariant.title, plan.invariant.severity, enabled, CUSTOM_YAML, plan.digest)


async def go(app_pool, *, now=NOW, **kw):
    return await runner.run_tenant(app_pool, A, now=now, **kw)


async def set_enabled(db_pool, enabled, **cols):
    sets = ["enabled = $1"] + [f"{k} = ${i}" for i, k in enumerate(cols, 2)]
    await db_pool.execute(f"UPDATE invariants SET {', '.join(sets)} WHERE invariant_id = '{DB}'", enabled, *cols.values())


async def test_a_disabled_invariants_finding_stays_open_when_the_world_would_make_it_hold(db_pool, app_pool, client,
                                                                                         fake_redis):
    w = await world(db_pool, app_pool)
    await custom(app_pool)
    await go(app_pool, redis=fake_redis)
    (f,) = await frows(db_pool, f"invariant:{DB}")
    assert f["status"] == "open"
    # disable through the API (annotates), then fix the world: the database is no longer exposed
    row = await inv_row(db_pool, DB)
    assert (await client.put(f"/v1/invariants/{row['id']}", json={"enabled": False})).status_code == 200
    await w.set(exposed=False, now=NOW + dt.timedelta(minutes=5))
    summary = await go(app_pool, now=NOW + dt.timedelta(minutes=10), force=True, redis=fake_redis)
    assert summary["evaluated"] == 0                                           # nothing visited
    (f,) = await frows(db_pool, f"invariant:{DB}")
    assert f["status"] == "open" and f["metadata"]["invariant_state"] == "disabled"
    # re-enable: it is evaluated first and the ordinary rules decide (HOLDS now, so the finding closes by itself)
    assert (await client.put(f"/v1/invariants/{row['id']}", json={"enabled": True})).status_code == 200
    await go(app_pool, now=NOW + dt.timedelta(minutes=15), redis=fake_redis)
    (f,) = await frows(db_pool, f"invariant:{DB}")
    assert f["status"] == "fixed" and "invariant_state" not in f["metadata"]


async def test_a_disable_landing_between_the_record_and_the_findings_sync_closes_nothing(
        db_pool, app_pool, fake_redis, monkeypatch):
    w = await world(db_pool, app_pool)
    await custom(app_pool)
    await go(app_pool, redis=fake_redis)
    assert [f["status"] for f in await frows(db_pool, f"invariant:{DB}")] == ["open"]
    await w.set(exposed=False, now=NOW + dt.timedelta(minutes=5))          # the next evaluation would HOLD and close it
    real = runner._record

    async def record_then_disable(*a, **k):
        out = await real(*a, **k)                                          # the verdict is recorded ...
        await set_enabled(db_pool, False)                                  # ... and the operator switches it off
        return out

    monkeypatch.setattr(runner, "_record", record_then_disable)
    s = await go(app_pool, now=NOW + dt.timedelta(minutes=10), force=True, only=[DB], redis=fake_redis)
    assert [r.get("skipped") for r in s["results"]] == ["invariant_disabled"]
    (f,) = await frows(db_pool, f"invariant:{DB}")
    assert f["status"] == "open"                                           # never closed by a machine that was switched off


async def _race(db_pool, app_pool, client, fake_redis, monkeypatch, *, exposed, fire_before):
    """Run one forced evaluation; an operator's disable (the real PUT route, in another task) is fired just before
    (``fire_before``) or just after the runner's ``_note_state``, which runs after the enabled check and before the
    findings sync. Returns the state of the race."""
    w = await world(db_pool, app_pool)
    await custom(app_pool)
    await go(app_pool, redis=fake_redis)
    assert [f["status"] for f in await frows(db_pool, f"invariant:{DB}")] == ["open"]
    if not exposed:
        await w.set(exposed=False, now=NOW + dt.timedelta(minutes=5))      # the next evaluation HOLDS and would close it
    row = await inv_row(db_pool, DB)
    seen: dict = {}
    real = runner._note_state

    async def fire(*a, **k):
        out = None
        if not fire_before:
            out = await real(*a, **k)
        if "task" not in seen:
            seen["task"] = asyncio.ensure_future(
                client.put(f"/v1/invariants/{row['id']}", json={"enabled": False}))
            await asyncio.sleep(0.6)                                       # long enough for the toggle to commit
            seen["landed_before_the_sync_ended"] = seen["task"].done()
        if fire_before:
            out = await real(*a, **k)
        return out

    monkeypatch.setattr(runner, "_note_state", fire)
    await go(app_pool, now=NOW + dt.timedelta(minutes=10), force=True, only=[DB], redis=fake_redis)
    resp = await asyncio.wait_for(seen["task"], 30)
    assert resp.status_code == 200
    return seen


async def test_a_disable_cannot_land_between_the_enabled_check_and_the_findings_sync(
        client, db_pool, app_pool, fake_redis, monkeypatch):
    """The verifier's RACE1: with the check and the sync not serialised against the toggle, a disable landing in the
    gap left a finding of a switched-off invariant closed 'fixed'. The toggle now waits for the sync that was already
    admitted (the runner holds the invariant row share-locked from the check to the end of the sync), so a finding is
    closed only by an evaluation that finished while the invariant was still enabled, and a toggle is never between."""
    seen = await _race(db_pool, app_pool, client, fake_redis, monkeypatch, exposed=False, fire_before=False)
    assert seen["landed_before_the_sync_ended"] is False
    row = await inv_row(db_pool, DB)
    assert row["enabled"] is False and row["disabled_at"] is not None


async def test_a_disable_cannot_wipe_its_own_annotation_by_landing_before_the_runner_clears_it(
        client, db_pool, app_pool, fake_redis, monkeypatch):
    """The verifier's RACE2: a disable that landed just before the runner's 'a verdict is back' clear lost its
    annotation (the clear had no enabled guard) and the sync then closed the finding. Still violated here, so the
    finding must end open AND annotated disabled."""
    seen = await _race(db_pool, app_pool, client, fake_redis, monkeypatch, exposed=True, fire_before=True)
    assert seen["landed_before_the_sync_ended"] is False
    (f,) = await frows(db_pool, f"invariant:{DB}")
    assert f["status"] == "open" and f["metadata"].get("invariant_state") == "disabled"


async def test_when_the_enabled_check_cannot_be_made_nothing_is_closed_and_the_invariant_is_made_due(
        db_pool, app_pool, fake_redis, monkeypatch):
    """A toggle (or anything) holding the row for longer than the guard may wait leaves the runner unable to tell whether
    the invariant is still enabled. It must not guess 'enabled': no sync, no close, due again next tick."""
    w = await world(db_pool, app_pool)
    await custom(app_pool)
    await go(app_pool, redis=fake_redis)
    await w.set(exposed=False, now=NOW + dt.timedelta(minutes=5))              # HOLDS now: a sync would close it
    monkeypatch.setattr(runner, "_GUARD_LOCK_TIMEOUT", "200ms")
    real = runner._record
    held: dict = {}

    async def record_then_hold_the_row(*a, **k):
        out = await real(*a, **k)
        held["con"] = await db_pool.acquire()
        held["tx"] = held["con"].transaction()
        await held["tx"].start()
        await held["con"].execute("SELECT 1 FROM invariants WHERE invariant_id = $1 FOR UPDATE", DB)

        async def let_go():                                                    # the toggle commits a moment later
            await asyncio.sleep(1.0)
            await held.pop("tx").rollback()
            await db_pool.release(held.pop("con"))

        held["task"] = asyncio.ensure_future(let_go())
        return out

    monkeypatch.setattr(runner, "_record", record_then_hold_the_row)
    try:
        s = await go(app_pool, now=NOW + dt.timedelta(minutes=10), force=True, only=[DB], redis=fake_redis)
    finally:
        if "task" in held:
            await held["task"]
    assert [r.get("skipped") for r in s["results"]] == ["enabled_check_failed"]
    (f,) = await frows(db_pool, f"invariant:{DB}")
    assert f["status"] == "open"                                               # nothing was closed on a guess
    assert (await inv_row(db_pool, DB))["last_graph_version"] is None          # due again


async def test_the_runners_own_clear_is_guarded_even_if_the_row_lock_were_not_there(
        db_pool, app_pool, fake_redis, monkeypatch):
    """Defence in depth for RACE2: with the guard replaced by one that holds no lock, a disable landing right before the
    runner's 'a verdict is back' clear still keeps its annotation (still violated: the finding stays open)."""
    await world(db_pool, app_pool)
    await custom(app_pool)
    await go(app_pool, redis=fake_redis)

    @contextlib.asynccontextmanager
    async def no_lock_guard(pool, d):
        async with conn_for(app_pool) as con:                              # the operator disables right here
            await con.execute("UPDATE invariants SET enabled = FALSE, disabled_at = now() WHERE invariant_id = $1", DB)
            await housekeeping.annotate_findings(con, DB, housekeeping.STATE_DISABLED)
        yield True                                                         # ... and the runner still believes "enabled"

    monkeypatch.setattr(runner, "_enabled_guard", no_lock_guard)
    await go(app_pool, now=NOW + dt.timedelta(minutes=10), force=True, only=[DB], redis=fake_redis)
    (f,) = await frows(db_pool, f"invariant:{DB}")
    assert f["status"] == "open" and f["metadata"].get("invariant_state") == "disabled"


async def test_the_runner_clear_never_removes_the_annotation_of_a_disabled_invariant(db_pool, app_pool, fake_redis):
    """Belt and braces for RACE2: even called directly, the runner's clear is a no-op for an invariant that is not
    enabled (clear_annotations without the guard is what re-enable uses)."""
    await world(db_pool, app_pool)
    await custom(app_pool)
    await go(app_pool, redis=fake_redis)
    async with conn_for(app_pool) as con:
        await housekeeping.annotate_findings(con, DB, housekeeping.STATE_DISABLED)
        await con.execute("UPDATE invariants SET enabled = FALSE, disabled_at = now() WHERE invariant_id = $1", DB)
        assert await housekeeping.clear_annotations(con, DB, only_if_enabled=True) == 0
    (f,) = await frows(db_pool, f"invariant:{DB}")
    assert f["metadata"].get("invariant_state") == "disabled"
    async with conn_for(app_pool) as con:
        assert await housekeeping.clear_annotations(con, DB) == 1               # re-enable's clear still works


async def test_record_refuses_to_write_a_verdict_for_an_invariant_disabled_while_it_was_evaluated(db_pool, app_pool):
    await world(db_pool, app_pool)
    await custom(app_pool)
    async with conn_for(app_pool) as con:
        rows = await con.fetch(f"SELECT {runner._INV_COLS} FROM invariants WHERE invariant_id = $1", DB)
    (d,) = await runner._compile_defs(list(rows))
    async with conn_for(app_pool) as con:
        owner = "test-owner"
        assert await store.claim_eval(con, owner, None, 300)
    await set_enabled(db_pool, False)                     # the toggle lands between loading and recording
    rd = runner.synthetic_result(d, "evaluation_error", NOW)
    with pytest.raises(runner._Discarded) as gone:
        with tenancy.tenant_context(A):
            await runner._record(app_pool, owner, d, rd, None, 1, NOW)
    assert gone.value.reason == "invariant_disabled"
    row = await inv_row(db_pool, DB)
    assert row["last_verdict"] is None
    assert await db_pool.fetchval("SELECT count(*) FROM invariant_runs") == 0


async def test_an_invalid_definition_is_annotated_never_closed_and_clears_when_fixed(db_pool, app_pool, fake_redis):
    w = await world(db_pool, app_pool)
    await custom(app_pool)
    await go(app_pool, redis=fake_redis)
    assert [f["status"] for f in await frows(db_pool, f"invariant:{DB}")] == ["open"]
    # the world is fixed AND the definition gets corrupted: the stored text no longer compiles
    await w.set(exposed=False, now=NOW + dt.timedelta(minutes=5))
    await db_pool.execute("UPDATE invariants SET yaml = 'not: [valid', digest = digest || 'x' WHERE invariant_id = $1", DB)
    runner._PLAN_CACHE.clear()
    s = await go(app_pool, now=NOW + dt.timedelta(minutes=10), redis=fake_redis)
    assert [r["reasons"] for r in s["results"]] == [["invalid_definition"]]
    (f,) = await frows(db_pool, f"invariant:{DB}")
    assert f["status"] == "open" and f["metadata"]["invariant_state"] == "invalid_definition"
    # repaired: the next evaluation holds, the finding closes by the ordinary rule, the annotation is gone
    await db_pool.execute("UPDATE invariants SET yaml = $2, digest = $3, last_graph_version = NULL WHERE invariant_id = $1",
                          DB, CUSTOM_YAML, __import__("paddock_assurance").compile_text(CUSTOM_YAML).digest)
    runner._PLAN_CACHE.clear()
    await go(app_pool, now=NOW + dt.timedelta(minutes=20), redis=fake_redis)
    (f,) = await frows(db_pool, f"invariant:{DB}")
    assert f["status"] == "fixed" and "invariant_state" not in f["metadata"]


async def test_tick_annotates_findings_of_a_tenant_that_is_not_entitled_and_never_closes_them(
        db_pool, app_pool, fake_redis, monkeypatch):
    w = await world(db_pool, app_pool)
    await custom(app_pool)
    await go(app_pool, redis=fake_redis)
    await w.set(exposed=False, now=NOW + dt.timedelta(minutes=5))      # the estate was fixed meanwhile

    async def no(pool, tid):
        return False

    monkeypatch.setattr(runner, "_entitled", no)
    out = await runner.tick_once(app_pool, redis=fake_redis, now=NOW + dt.timedelta(minutes=10))
    assert out[A]["skipped"] == "not_entitled"
    (f,) = await frows(db_pool, f"invariant:{DB}")
    assert f["status"] == "open" and f["metadata"]["invariant_state"] == "not_entitled"

    async def yes(pool, tid):
        return True

    monkeypatch.setattr(runner, "_entitled", yes)
    runner._RECONCILE_LAST.clear()
    await runner.tick_once(app_pool, redis=fake_redis, now=NOW + dt.timedelta(minutes=20))
    (f,) = await frows(db_pool, f"invariant:{DB}")
    assert f["status"] == "fixed" and "invariant_state" not in f["metadata"]


# --------------------------------------------------------------------------- #
# reconcile_orphans: drift repair (invariants toggled somewhere else), idempotent
# --------------------------------------------------------------------------- #

async def reconcile(app_pool, **kw):
    return await housekeeping.reconcile_orphans(app_pool, A, **kw)


async def test_reconcile_annotates_an_invariant_disabled_behind_the_apis_back_and_clears_when_enabled(
        db_pool, app_pool, fake_redis):
    await custom(app_pool)
    await seed_findings(db_pool, fake_redis, DB, n=2)
    await set_enabled(db_pool, False)                       # e.g. a std invariant toggled by a script or a restore
    rep = await reconcile(app_pool)
    assert rep["annotated"] == 2
    assert states(await frows(db_pool)) == ["disabled", "disabled"]
    stamp = (await frows(db_pool))[0]["metadata"]["invariant_state_at"]
    assert (await reconcile(app_pool))["annotated"] == 0                       # idempotent, the stamp does not move
    assert (await frows(db_pool))[0]["metadata"]["invariant_state_at"] == stamp
    await set_enabled(db_pool, False, archived_at=NOW)
    await reconcile(app_pool)
    assert states(await frows(db_pool)) == ["archived", "archived"]
    await set_enabled(db_pool, True, archived_at=None)
    rep = await reconcile(app_pool)
    assert rep["cleared"] == 2 and states(await frows(db_pool)) == [None, None]
    assert {f["status"] for f in await frows(db_pool)} == {"open"}


async def test_reconcile_never_changes_a_status_and_leaves_other_invariants_alone(db_pool, app_pool, fake_redis):
    await custom(app_pool, enabled=False)
    await seed_findings(db_pool, fake_redis, DB, n=1)
    await seed_findings(db_pool, fake_redis, "acme:other", n=1)          # no invariants row: untouched
    await seed_findings(db_pool, fake_redis, f"{DB}-longer", n=1)        # prefix sibling: untouched
    await db_pool.execute("UPDATE findings SET status = 'fixed' WHERE rule_id = $1", f"invariant:{DB}-longer")
    await reconcile(app_pool)
    by = {f["rule_id"]: f for f in await frows(db_pool)}
    assert by[f"invariant:{DB}"]["metadata"]["invariant_state"] == "disabled"
    assert "invariant_state" not in by["invariant:acme:other"]["metadata"]
    assert "invariant_state" not in by[f"invariant:{DB}-longer"]["metadata"]
    assert {f["status"] for f in by.values()} == {"open", "fixed"}


async def test_reconcile_not_entitled_and_invalid_definition(db_pool, app_pool, fake_redis):
    await custom(app_pool)
    await seed_findings(db_pool, fake_redis, DB, n=1)
    rep = await reconcile(app_pool, entitled=False)
    assert rep["annotated"] == 1 and states(await frows(db_pool)) == ["not_entitled"]
    await reconcile(app_pool, entitled=True)
    assert states(await frows(db_pool)) == [None]
    # a stored invalid_definition verdict (and an evaluated graph) annotates; a pending re-evaluation does not
    await db_pool.execute("UPDATE invariants SET last_verdict = 'UNKNOWN', last_graph_version = 3, "
                          "last_result = '{\"reasons\": [\"invalid_definition\"]}'::jsonb WHERE invariant_id = $1", DB)
    await reconcile(app_pool)
    assert states(await frows(db_pool)) == ["invalid_definition"]
    await db_pool.execute("UPDATE invariants SET last_graph_version = NULL WHERE invariant_id = $1", DB)
    await reconcile(app_pool)
    assert states(await frows(db_pool)) == [None]


async def test_reconcile_only_touches_the_given_tenant(db_pool, app_pool, fake_redis):
    await tenancy.create_tenant(db_pool, slug="bravo-rec", name="Bravo", tenant_id=TENANT_B)
    await custom(app_pool, enabled=False)
    await seed_findings(db_pool, fake_redis, DB, n=1)
    await db_pool.execute("INSERT INTO invariants (tenant_id, invariant_id, title, severity, enabled, source, yaml, digest) "
                          "VALUES ($1, $2, 'b', 'high', FALSE, 'custom', 'y', 'd')", uuid.UUID(TENANT_B), DB)
    asset = await db_pool.fetchval("INSERT INTO assets (tenant_id, kind, value, canonical, source) "
                                   "VALUES ($1, 'domain', 'b.example', 'b.example', 't') RETURNING id", uuid.UUID(TENANT_B))
    await db_pool.execute("INSERT INTO findings (tenant_id, asset_id, rule_id, rule_source, severity, title, description) "
                          "VALUES ($1, $2, $3, 'invariant', 'high', 't', 'd')", uuid.UUID(TENANT_B), asset, f"invariant:{DB}")
    await reconcile(app_pool)
    b = await db_pool.fetchval("SELECT metadata FROM findings WHERE tenant_id = $1", uuid.UUID(TENANT_B))
    assert "invariant_state" not in (json.loads(b) if isinstance(b, str) else b)
    a = await db_pool.fetchval("SELECT metadata FROM findings WHERE tenant_id = $1", uuid.UUID(A))
    assert (json.loads(a) if isinstance(a, str) else a)["invariant_state"] == "disabled"


async def test_the_tick_reconciles_each_tenant_at_most_once_per_interval(db_pool, app_pool, fake_redis, monkeypatch):
    await custom(app_pool)
    await seed_findings(db_pool, fake_redis, DB, n=1)
    calls = []
    real = housekeeping.reconcile_orphans

    async def spy(pool, tid, **kw):
        calls.append(tid)
        return await real(pool, tid, **kw)

    monkeypatch.setattr(housekeeping, "reconcile_orphans", spy)
    await runner.tick_once(app_pool, redis=fake_redis, now=NOW)
    await runner.tick_once(app_pool, redis=fake_redis, now=NOW)
    assert calls.count(A) == 1


async def test_a_reconcile_failure_never_stops_the_tick(db_pool, app_pool, fake_redis, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(housekeeping, "reconcile_orphans", boom)
    out = await runner.tick_once(app_pool, redis=fake_redis, now=NOW)
    assert A in out


def test_runner_docstring_no_longer_claims_a_policy_gap():
    assert "Known policy gap" not in runner.__doc__
    assert "invariant_state" in runner.__doc__
