"""Verdicts -> findings (docs/ASSURANCE_P1.md section 6, app/assurance/findings_sync.py).

The pure helpers are unit-tested; the lifecycle rules (open once, reopen on recurrence, close on
HOLDS, never touch a human decision, UNKNOWN does nothing) run against a real Postgres through the
real in-process upsert. The runner-level cycle is in test_assurance_runner.py.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import uuid

import pytest

from app.assurance import findings_sync as fs
from app.config import settings
from app.verification import service as verification_service

NOW = dt.datetime(2026, 12, 1, 9, 0, tzinfo=dt.timezone.utc)
INV = "std:no-internet-to-datastore"
CVE_LIKE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
FORBIDDEN_KEYS = {"url", "matched_at", "matched-at", "target_url"}


# --------------------------------------------------------------------------- #
# synthetic results (same shape as paddock_assurance Result.to_dict())
# --------------------------------------------------------------------------- #

def hop(src, dst, ports="5432", basis="configured", source="aws_sg", proto="tcp"):
    return {"src": src, "dst": dst, "proto": proto, "ports": ports, "basis": basis, "source": source}


def reach_witness(target, via=()):
    hops = [hop("internet", via[0])] + [hop(a, b) for a, b in zip(via, via[1:])] if via else []
    hops.append(hop(via[-1] if via else "internet", target))
    return {"hops": hops, "weakest_basis": "configured", "confirmed": False, "detail": {}}


def covered_witness(node, direction="in", reason="no_sensor"):
    d = {"node": node, "direction": direction, "reason": reason}
    if direction in ("in", "out"):
        d[f"reason_{direction}"] = reason
    return {"hops": [], "weakest_basis": "unknown", "confirmed": False, "detail": d}


def result(verdict, *witnesses, assertion="unreachable", tier=None, severity="high", digest="sha256:abc"):
    return {"invariant": INV, "digest": digest, "severity": severity, "assertion": assertion,
            "verdict": verdict, "reasons": [], "evidence_tier": tier,
            "coverage": {"universe": 4, "covered": 2, "ratio": 0.5, "required": 0.95},
            "violation_count": len(witnesses), "witnesses": list(witnesses)}


async def mk_asset(pool, value="db.internal.example"):
    return await pool.fetchval(
        "INSERT INTO assets (kind, value, canonical, source) VALUES ('cloud_resource', $1, $1, 'test') "
        "RETURNING id", value)


async def sync(pool, redis, res, *, inv=INV, now=NOW, version=7, **kw):
    return await fs.sync_findings(pool, redis, invariant_id=inv, title="No internet path reaches a data store",
                                  result=res, graph_version=version, now=now, **kw)


async def rows(pool, rule_source="invariant"):
    return await pool.fetch(
        "SELECT f.*, a.kind AS a_kind, a.value AS a_value FROM findings f JOIN assets a ON a.id = f.asset_id "
        "WHERE f.rule_source = $1 ORDER BY f.rule_id, f.first_seen", rule_source)


async def history(pool, fid):
    return await pool.fetch("SELECT from_status, to_status, reason, actor FROM finding_status_history "
                            "WHERE finding_id = $1 ORDER BY at, id", fid)


async def events(redis, name=None):
    out = []
    for _id, fields in await redis.xrange(settings.events_stream):
        ev = json.loads(fields["event"])
        if name is None or ev.get("event") == name:
            out.append(ev)
    return out


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #

def test_target_of_is_the_last_hop_or_the_blind_node():
    assert fs.target_of("unreachable", reach_witness("asset:X", via=("ip:10.0.0.9",))) == "asset:X"
    assert fs.target_of("exposes-only", reach_witness("asset:X")) == "asset:X"
    assert fs.target_of("covered", covered_witness("asset:Y")) == "asset:Y"
    # a witness we cannot place never invents a target
    assert fs.target_of("unreachable", {"hops": []}) is None
    assert fs.target_of("covered", {"hops": [], "detail": {}}) is None
    assert fs.target_of("unreachable", {"hops": [{"src": "a"}]}) is None


def test_asset_uuid_parses_only_asset_refs():
    u = uuid.uuid4()
    assert fs.asset_uuid(f"asset:{u}") == u
    for ref in ("internet", "ip:10.0.0.1", "cidr:10.0.0.0/8", "asset:not-a-uuid", "asset:"):
        assert fs.asset_uuid(ref) is None


def test_rule_id_is_stable_per_invariant_and_discriminated_for_the_estate_asset():
    assert fs.rule_id_for(INV, "asset:1", estate=False) == f"invariant:{INV}"
    a = fs.rule_id_for(INV, "ip:10.0.0.1", estate=True)
    b = fs.rule_id_for(INV, "ip:10.0.0.2", estate=True)
    assert a != b and a.startswith(f"invariant:{INV}@") and b.startswith(f"invariant:{INV}@")
    long = fs.rule_id_for(INV, "cidr:" + "x" * 400, estate=True)
    assert len(long) <= 256 and long == fs.rule_id_for(INV, "cidr:" + "x" * 400, estate=True)


def test_describe_witness_reads_in_words_and_uses_labels():
    w = reach_witness("asset:db", via=("asset:web",))
    text = fs.describe_witness("unreachable", w, {"asset:db": "orders-db", "asset:web": "web-1"})
    assert "orders-db" in text and "web-1" in text and "internet" in text and "5432" in text
    assert "2 connections" in text
    cov = fs.describe_witness("covered", covered_witness("asset:db", "in", "stale"), {"asset:db": "orders-db"})
    assert "orders-db" in cov and "inbound" in cov and "out of date" in cov
    exp = fs.describe_witness("exposes-only", {"hops": [hop("internet", "asset:db", ports="22")],
                                               "detail": {"disallowed_ports": "22", "allowed_ports": "80,443"}}, {})
    assert "22" in exp and "80,443" in exp


@pytest.mark.parametrize("assertion,witness", [
    ("unreachable", reach_witness("asset:%s" % uuid.uuid4())),
    ("exposes-only", reach_witness("ip:10.1.1.1")),
    ("covered", covered_witness("asset:%s" % uuid.uuid4(), "both")),
])
def test_evidence_has_a_constant_key_set_and_no_verification_steering_keys(assertion, witness):
    items, targets = fs.build_items(
        invariant_id=INV, title="t", assertion=assertion, digest="sha256:d", severity="high",
        result=result("VIOLATED", witness, assertion=assertion), graph_version=3, proposed=["b", "a"],
        labels={}, live_assets={fs.asset_uuid(t) for t in [witness["detail"].get("node", "")] if fs.asset_uuid(t)}
        | {fs.asset_uuid(h["dst"]) for h in witness["hops"] if fs.asset_uuid(h["dst"])})
    (item,) = items
    assert tuple(item["evidence"]) == fs.EVIDENCE_KEYS
    assert not FORBIDDEN_KEYS & set(item["evidence"])
    assert not CVE_LIKE.search(json.dumps(item))
    assert item["rule_source"] == "invariant" and item["metadata"]["proposed_fixes"] == ["a", "b"]
    assert targets == [fs.target_of(assertion, witness)]


def test_one_item_per_target_even_with_several_witnesses():
    ws = [reach_witness("asset:%s" % uuid.UUID(int=1)), reach_witness("asset:%s" % uuid.UUID(int=1), via=("ip:1.1.1.1",)),
          reach_witness("ip:10.0.0.5")]
    items, targets = fs.build_items(invariant_id=INV, title="t", assertion="unreachable", digest="d", severity="low",
                                    result=result("VIOLATED", *ws), graph_version=1, proposed=[], labels={},
                                    live_assets={uuid.UUID(int=1)})
    assert targets == [f"asset:{uuid.UUID(int=1)}", "ip:10.0.0.5"]
    assert "asset_id" in items[0] and items[1]["asset_kind"] == "org" and items[1]["asset_value"] == "paddock-assurance"


def test_a_node_whose_asset_row_is_gone_falls_back_to_the_estate_asset():
    ghost = uuid.uuid4()
    items, _ = fs.build_items(invariant_id=INV, title="t", assertion="unreachable", digest="d", severity="high",
                              result=result("VIOLATED", reach_witness(f"asset:{ghost}")), graph_version=1,
                              proposed=[], labels={}, live_assets=set())
    assert items[0]["asset_kind"] == "org" and items[0]["rule_id"].endswith(f"@asset:{ghost}")


# --------------------------------------------------------------------------- #
# lifecycle against Postgres
# --------------------------------------------------------------------------- #

async def test_violated_opens_one_finding_per_root_cause_and_repeat_does_not_duplicate(db_pool, fake_redis):
    a1, a2 = await mk_asset(db_pool, "db-1.example"), await mk_asset(db_pool, "db-2.example")
    res = result("VIOLATED", reach_witness(f"asset:{a1}"), reach_witness(f"asset:{a2}", via=(f"asset:{a1}",)))
    rep = await sync(db_pool, fake_redis, res)
    assert (rep.targets, rep.opened, rep.updated) == (2, 2, 0)
    fr = await rows(db_pool)
    assert {r["rule_id"] for r in fr} == {f"invariant:{INV}"} and {r["asset_id"] for r in fr} == {a1, a2}
    f = next(r for r in fr if r["asset_id"] == a1)
    assert f["severity"] == "high" and f["status"] == "open" and "db-1.example" in f["title"]
    ev = json.loads(f["evidence"])
    assert set(ev) == set(fs.EVIDENCE_KEYS) and ev["graph_version"] == 7 and ev["target_ref"] == f"asset:{a1}"
    assert ev["verdict"] == "VIOLATED" and ev["invariant"] == INV

    again = await sync(db_pool, fake_redis, res, version=8)
    assert (again.opened, again.updated, again.reopened) == (0, 2, 0)
    assert len(await rows(db_pool)) == 2
    assert json.loads((await rows(db_pool))[0]["evidence"])["graph_version"] == 8   # refreshed, not accumulated
    opened = await events(fake_redis, "finding_opened")
    assert len(opened) == 2                                          # events only for the first sync


async def test_non_asset_targets_share_the_estate_asset_but_stay_distinct_findings(db_pool, fake_redis):
    res = result("VIOLATED", reach_witness("ip:203.0.113.5"), reach_witness("ip:203.0.113.6"))
    rep = await sync(db_pool, fake_redis, res)
    assert rep.opened == 2
    fr = await rows(db_pool)
    assert {(r["a_kind"], r["a_value"]) for r in fr} == {("org", "paddock-assurance")}
    assert len({r["rule_id"] for r in fr}) == 2 and all(r["duplicate_of"] is None for r in fr)
    assert await db_pool.fetchval("SELECT count(*) FROM assets WHERE kind = 'org' AND value = 'paddock-assurance'") == 1
    # one of them holds again -> only its own finding is the one that changes on the next HOLDS
    await sync(db_pool, fake_redis, result("HOLDS", tier="observed"))
    assert {r["status"] for r in await rows(db_pool)} == {"fixed"}   # the estate rows are found by prefix


async def test_holds_closes_open_findings_and_stamps_verification_only_with_observed_evidence(db_pool, fake_redis):
    a1, a2 = await mk_asset(db_pool, "d1"), await mk_asset(db_pool, "d2")
    await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{a1}")), inv="acme:one")
    await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{a2}")), inv="acme:two")
    # weak evidence: closed, but nothing claims it was verified
    weak = await sync(db_pool, fake_redis, result("HOLDS", tier="configured"), inv="acme:one")
    assert (weak.closed, weak.verified) == (1, 0)
    strong = await sync(db_pool, fake_redis, result("HOLDS", tier="observed"), inv="acme:two")
    assert (strong.closed, strong.verified) == (1, 1)
    by = {r["rule_id"]: r for r in await rows(db_pool)}
    one, two = by["invariant:acme:one"], by["invariant:acme:two"]
    assert one["status"] == two["status"] == "fixed"
    assert one["fix_verified_at"] is None and two["fix_verified_at"] == NOW
    assert two["status_by"] == fs.ACTOR and "holds" in two["status_reason"]
    h = await history(db_pool, two["id"])
    assert [(x["from_status"], x["to_status"], x["actor"]) for x in h][-1] == ("open", "fixed", fs.ACTOR)
    assert len(await events(fake_redis, "finding_closed")) == 2
    # closing is idempotent
    assert (await sync(db_pool, fake_redis, result("HOLDS", tier="observed"), inv="acme:two")).closed == 0


async def test_holds_of_one_invariant_never_closes_another_invariants_findings(db_pool, fake_redis):
    a = await mk_asset(db_pool)
    await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{a}")), inv="acme:aa")
    await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{a}")), inv="acme:aa-bb")
    await sync(db_pool, fake_redis, result("HOLDS", tier="tested"), inv="acme:aa")
    st = {r["rule_id"]: r["status"] for r in await rows(db_pool)}
    assert st == {"invariant:acme:aa": "fixed", "invariant:acme:aa-bb": "open"}   # prefix match needs the '@'


async def test_recurrence_reopens_a_fixed_finding_with_history_event_and_cleared_verification(db_pool, fake_redis):
    a = await mk_asset(db_pool)
    res = result("VIOLATED", reach_witness(f"asset:{a}"))
    await sync(db_pool, fake_redis, res)
    await sync(db_pool, fake_redis, result("HOLDS", tier="observed"))
    (fixed,) = await rows(db_pool)
    assert fixed["status"] == "fixed" and fixed["fix_verified_at"] is not None

    rep = await sync(db_pool, fake_redis, res, now=NOW + dt.timedelta(hours=1))
    assert (rep.reopened, rep.opened) == (1, 0)
    (back,) = await rows(db_pool)
    assert back["id"] == fixed["id"] and back["status"] == "open"
    assert back["fix_verified_at"] is None and back["status_by"] == fs.ACTOR
    assert back["status_reason"] == "invariant violated again"
    h = [(x["from_status"], x["to_status"], x["reason"], x["actor"]) for x in await history(db_pool, back["id"])]
    assert h[-1] == ("fixed", "open", "invariant violated again", fs.ACTOR)
    (ev,) = await events(fake_redis, "finding_reopened")
    assert ev["finding_id"] == str(back["id"])
    # and a second violating evaluation does not reopen anything again
    assert (await sync(db_pool, fake_redis, res)).reopened == 0


@pytest.mark.parametrize("status", ["accepted", "false_positive", "wontfix", "accepted_risk"])
async def test_human_decisions_survive_both_violation_and_holds(db_pool, fake_redis, status):
    a = await mk_asset(db_pool)
    res = result("VIOLATED", reach_witness(f"asset:{a}"))
    await sync(db_pool, fake_redis, res)
    (f,) = await rows(db_pool)
    await db_pool.execute("UPDATE findings SET status = $2, status_by = 'alice', status_reason = 'known' "
                          "WHERE id = $1", f["id"], status)
    rep = await sync(db_pool, fake_redis, res)
    assert (rep.reopened, rep.left_alone) == (0, 1)
    await sync(db_pool, fake_redis, result("HOLDS", tier="observed"))
    (after,) = await rows(db_pool)
    assert (after["status"], after["status_by"], after["status_reason"]) == (status, "alice", "known")
    assert after["fix_verified_at"] is None


async def test_suppressed_findings_stay_suppressed_and_are_not_closed_or_reopened(db_pool, fake_redis):
    await db_pool.execute("INSERT INTO finding_suppressions (name, rule_id, reason, author) "
                          "VALUES ('quiet', 'invariant:*', 'accepted noise', 'alice')")
    a = await mk_asset(db_pool)
    res = result("VIOLATED", reach_witness(f"asset:{a}"))
    rep = await sync(db_pool, fake_redis, res)
    assert rep.opened == 1 and rep.suppressed == 1
    (f,) = await rows(db_pool)
    assert f["suppressed_by"] is not None and f["status"] == "open"
    assert len(await events(fake_redis, "finding_suppressed")) == 1 and not await events(fake_redis, "finding_opened")
    # HOLDS does not close a suppressed finding...
    assert (await sync(db_pool, fake_redis, result("HOLDS", tier="observed"))).closed == 0
    # ...and a suppressed finding that is `fixed` is not reopened by a recurrence
    await db_pool.execute("UPDATE findings SET status = 'fixed' WHERE id = $1", f["id"])
    rep = await sync(db_pool, fake_redis, res)
    assert (rep.reopened, rep.left_alone) == (0, 1)
    (after,) = await rows(db_pool)
    assert after["status"] == "fixed" and after["suppressed_by"] is not None


async def test_unknown_never_opens_or_closes(db_pool, fake_redis):
    a = await mk_asset(db_pool)
    unk = result("UNKNOWN", reach_witness(f"asset:{a}"))     # even a "possible" witness opens nothing
    rep = await sync(db_pool, fake_redis, unk)
    assert rep.skipped == "unknown" and await rows(db_pool) == []
    await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{a}")))
    rep = await sync(db_pool, fake_redis, unk)
    assert (rep.closed, rep.opened, rep.updated, rep.reopened) == (0, 0, 0, 0)
    (f,) = await rows(db_pool)
    assert f["status"] == "open"
    await db_pool.execute("UPDATE findings SET status = 'fixed' WHERE id = $1", f["id"])
    await sync(db_pool, fake_redis, unk)
    assert (await rows(db_pool))[0]["status"] == "fixed"      # not reopened by "maybe"


async def test_a_violated_verdict_never_closes_findings_for_targets_missing_from_the_witness_list(db_pool, fake_redis):
    a1, a2 = await mk_asset(db_pool, "a1"), await mk_asset(db_pool, "a2")
    await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{a1}"), reach_witness(f"asset:{a2}")))
    await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{a1}")))
    assert {r["status"] for r in await rows(db_pool)} == {"open"}


async def test_findings_disabled_on_the_invariant_means_no_findings(db_pool, fake_redis):
    a = await mk_asset(db_pool)
    rep = await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{a}")), finding_enabled=False)
    assert rep.skipped == "findings_disabled" and await rows(db_pool) == []


async def test_a_missing_redis_does_not_break_the_sync(db_pool):
    a = await mk_asset(db_pool)
    rep = await sync(db_pool, None, result("VIOLATED", reach_witness(f"asset:{a}")))
    assert rep.opened == 1
    await db_pool.execute("UPDATE findings SET status = 'fixed'")
    assert (await sync(db_pool, None, result("VIOLATED", reach_witness(f"asset:{a}")))).reopened == 1


async def test_a_deleted_asset_does_not_poison_the_batch(db_pool, fake_redis):
    a = await mk_asset(db_pool)
    ghost = uuid.uuid4()
    rep = await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{ghost}"), reach_witness(f"asset:{a}")))
    assert rep.opened == 2
    assert {r["a_kind"] for r in await rows(db_pool)} == {"org", "cloud_resource"}


async def test_covered_findings_target_the_blind_node(db_pool, fake_redis):
    a = await mk_asset(db_pool, "web-9")
    rep = await sync(db_pool, fake_redis, result(
        "VIOLATED", covered_witness(f"asset:{a}", "in", "stale"), covered_witness("ip:10.9.9.9", "both"),
        assertion="covered", severity="medium"))
    assert rep.opened == 2
    by = {r["a_kind"]: r for r in await rows(db_pool)}
    assert "web-9" in by["cloud_resource"]["title"] and by["cloud_resource"]["severity"] == "medium"
    assert "out of date" in by["cloud_resource"]["description"]
    assert by["org"]["rule_id"].endswith("@ip:10.9.9.9")


# --------------------------------------------------------------------------- #
# verification of an invariant finding: unsupported, and never an exception
# --------------------------------------------------------------------------- #

async def test_verification_paths_do_not_raise_for_an_invariant_finding(db_pool, fake_redis, client, monkeypatch):
    monkeypatch.setattr(verification_service.cfg, "fix_delay_sec", 0)
    a = await mk_asset(db_pool)
    await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{a}")))
    (f,) = await rows(db_pool)

    # 1. an explicit verify request: refused with a reason (no URL target), a clean 4xx, never a 5xx
    r = await client.post(f"/v1/findings/{f['id']}/verify")
    assert r.status_code < 500, r.text
    assert r.status_code != 202                      # nothing was queued for a worker
    # 2. marking it fixed by hand schedules the fix check, which must also end cleanly
    r = await client.patch(f"/v1/findings/{f['id']}", json={"status": "fixed"})
    assert r.status_code == 200, r.text
    ledger = await db_pool.fetch("SELECT purpose, status, reason FROM finding_verifications WHERE finding_id = $1",
                                 f["id"])
    assert ledger and {x["status"] for x in ledger} <= {"refused", "unsupported", "cancelled"}
    assert await db_pool.fetchval("SELECT count(*) FROM scans WHERE kind = 'verify_finding'") == 0
    after = (await rows(db_pool))[0]
    assert after["exploitability"] == "unverified" and after["fix_verified_at"] is None


# =========================================================================== #
# P1X hardening: close on a still-VIOLATED verdict (runner-3) and the lease fence (runner-1)
# =========================================================================== #

def vres(targets, *, only_witness=None, tier="observed", truncated=False, blind=(), assertion="unreachable",
         key=True, severity="high", unproven=()):
    """A VIOLATED result as the library reports it: a capped witness sample plus the FULL sorted
    ``violating_targets`` list (pinned interface). ``key=False`` = an older library without it."""
    sample = targets if only_witness is None else only_witness
    mk = covered_witness if assertion == "covered" else reach_witness
    res = result("VIOLATED", *[mk(t) for t in sample], assertion=assertion, tier=tier, severity=severity)
    if key:
        res["violating_targets"] = sorted(targets)
        res["violating_truncated"] = truncated
        res["unproven_targets"] = sorted(unproven)    # reachable only through unknown edges (not proven safe)
    res["blind_spots"] = [{"node": n, "reason": "no_sensor", "relevant": True, "direction": d} for n, d in blind]
    return res


async def three_open(db_pool, fake_redis):
    ids = [await mk_asset(db_pool, f"db-{i}.example") for i in range(3)]
    refs_ = [f"asset:{i}" for i in ids]
    rep = await sync(db_pool, fake_redis, vres(refs_))
    assert rep.opened == 3
    return ids, refs_


def status_by_asset(fr):
    return {r["asset_id"]: r["status"] for r in fr}


async def test_violated_closes_findings_of_targets_that_stopped_violating_and_only_those(db_pool, fake_redis):
    ids, rs = await three_open(db_pool, fake_redis)
    # two are fixed; the verdict is still VIOLATED because the third is not
    rep = await sync(db_pool, fake_redis, vres([rs[2]]), now=NOW + dt.timedelta(minutes=5), version=8)
    assert (rep.closed, rep.verified, rep.close_skipped) == (2, 2, "")
    fr = await rows(db_pool)
    assert status_by_asset(fr) == {ids[0]: "fixed", ids[1]: "fixed", ids[2]: "open"}
    for r in fr:
        if r["asset_id"] != ids[2]:
            assert r["fix_verified_at"] == NOW + dt.timedelta(minutes=5) and r["status_by"] == fs.ACTOR
            assert "no longer violating" in r["status_reason"]
            h = await history(db_pool, r["id"])
            assert [(x["from_status"], x["to_status"], x["actor"]) for x in h][-1] == ("open", "fixed", fs.ACTOR)
    assert len(await events(fake_redis, "finding_closed")) == 2
    # idempotent, and the survivor keeps being refreshed
    assert (await sync(db_pool, fake_redis, vres([rs[2]]), version=9)).closed == 0


async def test_a_violated_close_is_not_verified_by_configuration_only_evidence(db_pool, fake_redis):
    ids, rs = await three_open(db_pool, fake_redis)
    rep = await sync(db_pool, fake_redis, vres([rs[0]], tier="configured"), version=8)
    assert (rep.closed, rep.verified) == (2, 0)
    assert all(r["fix_verified_at"] is None for r in await rows(db_pool) if r["status"] == "fixed")


@pytest.mark.parametrize("why,kw", [
    ("truncated", {"truncated": True}),            # the list is not the whole violator set
    ("no_target_list", {"key": False}),            # an older library: nothing to compare with
])
async def test_a_violated_verdict_closes_nothing_without_a_complete_violator_list(db_pool, fake_redis, why, kw):
    ids, rs = await three_open(db_pool, fake_redis)
    rep = await sync(db_pool, fake_redis, vres([rs[2]], **kw), version=8)
    assert rep.closed == 0 and rep.close_skipped == why
    assert {r["status"] for r in await rows(db_pool)} == {"open"}


async def test_an_empty_violator_list_on_a_violated_verdict_closes_nothing(db_pool, fake_redis):
    ids, rs = await three_open(db_pool, fake_redis)
    res = vres([rs[2]])
    res["violating_targets"] = []                    # inconsistent with VIOLATED: fail closed
    assert (await sync(db_pool, fake_redis, res, version=8)).closed == 0
    assert {r["status"] for r in await rows(db_pool)} == {"open"}


async def test_a_target_nobody_can_see_into_stays_open_even_when_no_known_path_remains(db_pool, fake_redis):
    """"No known path" is not "fixed" for a node that is blind inbound (it may have become merely
    unprovable); a node that is only blind outbound cannot hide a path into itself."""
    ids, rs = await three_open(db_pool, fake_redis)
    rep = await sync(db_pool, fake_redis, vres([rs[2]], blind=[(rs[0], "in"), (rs[1], "out")]), version=8)
    assert rep.closed == 1
    assert status_by_asset(await rows(db_pool)) == {ids[0]: "open", ids[1]: "fixed", ids[2]: "open"}


async def test_violated_close_works_for_estate_targets_and_never_touches_human_decisions_or_other_invariants(db_pool, fake_redis):
    await sync(db_pool, fake_redis, vres(["ip:203.0.113.5", "ip:203.0.113.6", "ip:203.0.113.7"]))
    await sync(db_pool, fake_redis, vres(["ip:203.0.113.5"]), inv="acme:other")
    await db_pool.execute("UPDATE findings SET status = 'accepted', status_by = 'alice', status_reason = 'known' "
                          "WHERE evidence->>'target_ref' = 'ip:203.0.113.6' AND rule_id LIKE $1", f"invariant:{INV}@%")
    rep = await sync(db_pool, fake_redis, vres(["ip:203.0.113.7"]), version=8)
    assert rep.closed == 1                                   # only .5 of INV: .6 is a human decision
    by = {(r["rule_id"].split("@")[0], json.loads(r["evidence"])["target_ref"]): r["status"] for r in await rows(db_pool)}
    assert by == {(f"invariant:{INV}", "ip:203.0.113.5"): "fixed", (f"invariant:{INV}", "ip:203.0.113.6"): "accepted",
                  (f"invariant:{INV}", "ip:203.0.113.7"): "open", ("invariant:acme:other", "ip:203.0.113.5"): "open"}


async def test_violated_close_for_the_covered_assertion_closes_nodes_that_got_covered(db_pool, fake_redis):
    a, b = await mk_asset(db_pool, "n1"), await mk_asset(db_pool, "n2")
    await sync(db_pool, fake_redis, vres([f"asset:{a}", f"asset:{b}"], assertion="covered"))
    rep = await sync(db_pool, fake_redis, vres([f"asset:{b}"], assertion="covered", tier="configured"), version=8)
    assert rep.closed == 1
    assert status_by_asset(await rows(db_pool)) == {a: "fixed", b: "open"}


# ---- the lease fence ------------------------------------------------------------------------

async def hold_lease(db_pool, owner="me", *, graph_version=7, live=True):
    await db_pool.execute("DELETE FROM assurance_state")
    await db_pool.execute(
        "INSERT INTO assurance_state (graph_version, lease_owner, lease_until) VALUES ($1, $2, "
        f"now() {'+' if live else '-'} interval '5 minutes')", graph_version, owner)


@pytest.mark.parametrize("owner,live,state_version,skipped", [
    ("someone-else", True, 7, "lease_lost"),        # another replica owns the lease
    ("me", False, 7, "lease_lost"),                 # ours, but it lapsed (database clock)
    ("me", True, 9, "graph_moved"),                 # the graph moved on while we evaluated
])
async def test_a_stale_evaluator_cannot_close_or_verify_a_finding(db_pool, fake_redis, owner, live, state_version, skipped):
    a = await mk_asset(db_pool)
    await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{a}")))
    await hold_lease(db_pool, owner, graph_version=state_version, live=live)
    rep = await sync(db_pool, fake_redis, result("HOLDS", tier="observed"), lease_owner="me")
    assert rep.skipped == skipped and rep.closed == 0 and rep.verified == 0
    (f,) = await rows(db_pool)
    assert f["status"] == "open" and f["fix_verified_at"] is None
    # the same fence holds for a close on a still-violated verdict
    rep = await sync(db_pool, fake_redis, vres([f"asset:{uuid.uuid4()}"]), lease_owner="me")
    assert rep.closed == 0
    assert [r["status"] for r in await rows(db_pool) if r["asset_id"] == a] == ["open"]


async def test_the_lease_holder_at_the_current_version_may_close(db_pool, fake_redis):
    a = await mk_asset(db_pool)
    await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{a}")))
    await hold_lease(db_pool, "me", graph_version=7)
    rep = await sync(db_pool, fake_redis, result("HOLDS", tier="observed"), lease_owner="me")
    assert (rep.closed, rep.verified, rep.skipped) == (1, 1, "")


async def test_a_stale_evaluator_opens_no_findings_either(db_pool, fake_redis):
    a = await mk_asset(db_pool)
    await hold_lease(db_pool, "someone-else")
    rep = await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{a}")), lease_owner="me")
    assert rep.skipped == "lease_lost" and rep.opened == 0 and await rows(db_pool) == []


# ---- verification pass: "absent from violating_targets" is not "proven safe" -----------------------

async def test_a_target_that_is_only_unproven_stays_open_while_the_verdict_is_violated(db_pool, fake_redis):
    """Old: the finding of a target that no KNOWN path reaches any more was closed as fixed even
    when an unknown edge could still reach it (the library would answer UNKNOWN for it alone)."""
    ids, rs = await three_open(db_pool, fake_redis)
    rep = await sync(db_pool, fake_redis, vres([rs[2]], unproven=[rs[0]]), version=8)
    assert rep.closed == 1
    assert status_by_asset(await rows(db_pool)) == {ids[0]: "open", ids[1]: "fixed", ids[2]: "open"}


async def test_a_violated_result_without_the_unproven_list_closes_nothing(db_pool, fake_redis):
    ids, rs = await three_open(db_pool, fake_redis)
    res = vres([rs[2]])
    del res["unproven_targets"]                    # a library that predates the list: fail closed
    rep = await sync(db_pool, fake_redis, res, version=8)
    assert rep.closed == 0 and rep.close_skipped == "no_target_list"
    assert {r["status"] for r in await rows(db_pool)} == {"open"}


# =========================================================================== #
# P2: host-config verdicts (hop-less witnesses, one finding per (invariant, host))
# =========================================================================== #

HOST_INV = "std:server-ssh-hardened"
AG1, AG2, AG3 = (f"agent:{uuid.UUID(int=i)}" for i in (1, 2, 3))


def hw(node, *, clause="0.0.1", field="host.sshd.password_login_possible",
       predicate="host.sshd.password_login_possible == false", op="==", expected="false", observed="true",
       tier="configured", seq="5"):
    """A host-config witness exactly as the library reports it (all-string detail, no hops)."""
    return {"hops": [], "weakest_basis": tier, "confirmed": False, "detail": {
        "node": node, "field": field, "clause": clause, "predicate": predicate, "op": op, "expected": expected,
        "observed": observed, "tier": tier, "observed_at": "2026-12-01T08:30:00Z", "source": "host_fw",
        "signed": "true", "key_id": "0f3a9c1d77b24e5a8c10d2e4b6a8f012", "seq": seq, "evidence_ref": f"posture:{seq}"}}


def hres(verdict, witnesses=(), *, violating=(), unproven=(), blind=(), tier="configured", truncated=False,
         digest="sha256:host"):
    r = result(verdict, *witnesses, assertion="host-config", tier=tier, digest=digest)
    r["invariant"] = HOST_INV
    r["violating_targets"] = sorted(violating)
    r["unproven_targets"] = sorted(unproven)
    r["violating_truncated"] = truncated
    r["blind_spots"] = [{"node": n, "reason": why, "relevant": True, "direction": "host", "collector": col}
                        for n, why, col in blind]
    return r


async def hsync(pool, redis, res, **kw):
    kw.setdefault("inv", HOST_INV)
    return await sync(pool, redis, res, **kw)


def by_target(fr):
    return {json.loads(r["evidence"])["target_ref"]: r["status"] for r in fr}


def test_target_of_a_host_witness_is_its_node():
    assert fs.target_of("host-config", hw(AG1)) == AG1
    assert fs.target_of("host-config", hw("asset:" + str(uuid.uuid4()))).startswith("asset:")
    assert fs.target_of("host-config", {"hops": [], "detail": {}}) is None
    assert fs.target_of("host-config", {"hops": [], "detail": {"node": ""}}) is None
    assert fs.target_of("host-config", {"hops": [], "detail": {"node": 5}}) is None
    # hops on a host witness are ignored: the host is the target, never a hop destination
    odd = hw(AG1)
    odd["hops"] = [hop("internet", "asset:other")]
    assert fs.target_of("host-config", odd) == AG1


def test_describe_a_host_witness_in_words_with_the_evidence():
    text = fs.describe_witness("host-config", hw(AG1), {AG1: "web-1"})
    for part in ("web-1", "host.sshd.password_login_possible == false", "found true", "required == false",
                 "configured evidence", "signed", "key 0f3a9c1d77b24e5a8c10d2e4b6a8f012", "seq 5", "2026-12-01T08:30:00Z"):
        assert part in text, part
    assert AG1 not in text                                   # the label replaces the raw ref


def test_agent_supplied_text_cannot_break_the_description():
    nasty = hw(AG1, observed="yes\n\r\x00\x1b[31m" + "A" * 500 + " done", predicate="p\nq")
    text = fs.describe_witness("host-config", nasty, {})
    assert "\n" not in text and "\x00" not in text and "\x1b" not in text and " " not in text
    assert len(text) < 700 and "..." in text


def test_several_failing_clauses_of_one_host_fold_into_one_finding_item():
    w1, w2 = hw(AG1, clause="0.0.1"), hw(AG1, clause="0.0.4", field="host.sshd.maxauthtries",
                                         predicate="host.sshd.maxauthtries <= 4", op="<=", expected="4", observed="6")
    w3 = hw(AG2)
    res = hres("VIOLATED", [w1, w3, w2], violating=[AG1, AG2])
    items, targets = fs.build_items(
        invariant_id=HOST_INV, title="Servers do not allow password or root SSH login", assertion="host-config",
        digest="sha256:d", severity="high", result=res, graph_version=3, proposed=["harden"],
        labels={AG1: "web-1"}, live_assets=set())
    assert targets == [AG1, AG2] and len(items) == 2
    one, two = items
    assert one["rule_id"] == f"invariant:{HOST_INV}@{AG1}" and two["rule_id"] == f"invariant:{HOST_INV}@{AG2}"
    assert one["asset_kind"] == "org" and one["asset_value"] == "paddock-assurance" and "asset_id" not in one
    assert "web-1" in one["title"] and "1) " in one["description"] and "2) " in one["description"]
    assert "maxauthtries <= 4" in one["description"] and "found 6" in one["description"]
    assert "1) " not in two["description"]
    assert tuple(one["evidence"]) == fs.EVIDENCE_KEYS and not FORBIDDEN_KEYS & set(one["evidence"])
    assert one["evidence"]["witness"] == w1 and one["evidence"]["target_ref"] == AG1
    assert one["remediation"] == fs._REMEDIATION["host-config"] and "configuration" in one["remediation"]
    assert not CVE_LIKE.search(json.dumps(one))


def test_a_corroborated_host_is_an_asset_finding_with_the_plain_rule_id():
    aid = uuid.uuid4()
    items, _ = fs.build_items(
        invariant_id=HOST_INV, title="t", assertion="host-config", digest="d", severity="high",
        result=hres("VIOLATED", [hw(f"asset:{aid}")], violating=[f"asset:{aid}"]), graph_version=1,
        proposed=[], labels={}, live_assets={aid})
    (item,) = items
    assert item["rule_id"] == f"invariant:{HOST_INV}" and item["asset_id"] == str(aid) and "asset_value" not in item


async def test_a_host_violation_opens_one_finding_per_host_and_repeats_do_not_duplicate(db_pool, fake_redis):
    res = hres("VIOLATED", [hw(AG1), hw(AG1, clause="0.0.4"), hw(AG2)], violating=[AG1, AG2])
    rep = await hsync(db_pool, fake_redis, res)
    assert (rep.opened, rep.targets) == (2, 2)
    fr = await rows(db_pool)
    assert by_target(fr) == {AG1: "open", AG2: "open"}
    assert {r["a_kind"] for r in fr} == {"org"}
    again = await hsync(db_pool, fake_redis, res, version=8)
    assert (again.opened, again.updated) == (0, 2) and len(await rows(db_pool)) == 2


async def test_a_hostname_titles_the_finding_when_the_agent_row_exists(db_pool, fake_redis):
    aid = uuid.uuid4()
    await db_pool.execute("INSERT INTO fleet_agents (id, hostname) VALUES ($1, 'web-7.example.com')", aid)
    ref = f"agent:{aid}"
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(ref)], violating=[ref]))
    (f,) = await rows(db_pool)
    assert "web-7.example.com" in f["title"] and "web-7.example.com" in f["description"]


async def test_unknown_for_a_host_never_opens_or_closes(db_pool, fake_redis):
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1)], violating=[AG1]))
    rep = await hsync(db_pool, fake_redis, hres("UNKNOWN", unproven=[AG1], blind=[(AG1, "stale", "sshd")]), version=8)
    assert rep.skipped == "unknown" and (rep.opened, rep.closed) == (0, 0)
    assert by_target(await rows(db_pool)) == {AG1: "open"}


async def test_a_violated_verdict_keeps_the_finding_of_a_host_that_is_merely_unknown(db_pool, fake_redis):
    """AG1 violated and went silent (UNKNOWN) while AG2 still violates: AG1's finding stays open;
    AG3 (checked and clean now) is the only one that closes."""
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1), hw(AG2), hw(AG3)], violating=[AG1, AG2, AG3]))
    res = hres("VIOLATED", [hw(AG2)], violating=[AG2], unproven=[AG1], blind=[(AG1, "stale", "sshd")])
    rep = await hsync(db_pool, fake_redis, res, version=8)
    assert rep.closed == 1
    assert by_target(await rows(db_pool)) == {AG1: "open", AG2: "open", AG3: "fixed"}


async def test_a_host_blind_spot_alone_also_keeps_the_finding_open(db_pool, fake_redis):
    """Defence in depth: an older library without ``unproven_targets`` entries for hosts still
    names the host in a ``direction: host`` blind spot."""
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1), hw(AG2)], violating=[AG1, AG2]))
    res = hres("VIOLATED", [hw(AG2)], violating=[AG2], blind=[(AG1, "unsigned", "sshd")])
    rep = await hsync(db_pool, fake_redis, res, version=8)
    assert rep.closed == 0 and by_target(await rows(db_pool)) == {AG1: "open", AG2: "open"}
    assert fs._blind_targets(res) == [AG1]


async def test_a_host_that_stops_violating_while_others_still_do_is_closed(db_pool, fake_redis):
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1), hw(AG2)], violating=[AG1, AG2]))
    rep = await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG2)], violating=[AG2]), version=8)
    assert rep.closed == 1 and by_target(await rows(db_pool)) == {AG1: "fixed", AG2: "open"}
    (fixed,) = [r for r in await rows(db_pool) if r["status"] == "fixed"]
    assert fixed["fix_verified_at"] is None                    # configured evidence is never "verified"


async def test_holds_closes_every_host_finding_when_nothing_is_undecided(db_pool, fake_redis):
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1), hw(AG2)], violating=[AG1, AG2]))
    rep = await hsync(db_pool, fake_redis, hres("HOLDS", tier="configured"), version=8)
    assert rep.closed == 2 and rep.verified == 0
    assert set(by_target(await rows(db_pool)).values()) == {"fixed"}


async def test_holds_over_a_lower_coverage_floor_does_not_close_the_hosts_it_did_not_prove(db_pool, fake_redis):
    """A custom floor below 1.0 lets HOLDS stand with unknown hosts. Those hosts' findings must
    stay open: 'silent' is not 'fixed'. The decided host's finding closes."""
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1), hw(AG2)], violating=[AG1, AG2]))
    res = hres("HOLDS", unproven=[AG1], blind=[(AG1, "stale", "sshd")])
    rep = await hsync(db_pool, fake_redis, res, version=8)
    assert rep.closed == 1 and by_target(await rows(db_pool)) == {AG1: "open", AG2: "fixed"}
    # and the host comes back clean later: now it closes
    rep = await hsync(db_pool, fake_redis, hres("HOLDS"), version=9)
    assert rep.closed == 1 and set(by_target(await rows(db_pool)).values()) == {"fixed"}


async def test_a_host_blind_spot_also_protects_a_holds_close(db_pool, fake_redis):
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1)], violating=[AG1]))
    rep = await hsync(db_pool, fake_redis, hres("HOLDS", blind=[(AG1, "approximate", "firewall")]), version=8)
    assert rep.closed == 0 and by_target(await rows(db_pool)) == {AG1: "open"}


@pytest.mark.parametrize("why,patch", [
    ("no list", lambda r: r.pop("unproven_targets")),
    ("bad list", lambda r: r.update(unproven_targets=[1, 2])),
    ("not a list", lambda r: r.update(unproven_targets="agent:x")),
    ("truncated", lambda r: r.update(violating_truncated=True)),
])
async def test_a_host_holds_without_a_trustworthy_undecided_list_closes_nothing(db_pool, fake_redis, why, patch):
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1)], violating=[AG1]))
    res = hres("HOLDS")
    patch(res)
    rep = await hsync(db_pool, fake_redis, res, version=8)
    assert rep.closed == 0 and rep.close_skipped in ("no_target_list", "truncated"), why
    assert by_target(await rows(db_pool)) == {AG1: "open"}


async def test_the_p1_holds_still_closes_everything_even_with_blind_spots(db_pool, fake_redis):
    """Unchanged for the reach assertions: HOLDS there is sound over unknown edges by construction."""
    a = await mk_asset(db_pool)
    await sync(db_pool, fake_redis, result("VIOLATED", reach_witness(f"asset:{a}")))
    res = result("HOLDS", tier="observed")
    res["unproven_targets"] = [f"asset:{a}"]
    res["blind_spots"] = [{"node": f"asset:{a}", "reason": "no_sensor", "relevant": True, "direction": "in"}]
    assert (await sync(db_pool, fake_redis, res, version=8)).closed == 1


async def test_a_host_recurrence_reopens_the_fixed_finding(db_pool, fake_redis):
    res = hres("VIOLATED", [hw(AG1)], violating=[AG1])
    await hsync(db_pool, fake_redis, res)
    await hsync(db_pool, fake_redis, hres("HOLDS"), version=8)
    (fixed,) = await rows(db_pool)
    assert fixed["status"] == "fixed"
    rep = await hsync(db_pool, fake_redis, res, version=9, now=NOW + dt.timedelta(hours=1))
    assert (rep.reopened, rep.opened) == (1, 0)
    (back,) = await rows(db_pool)
    assert back["id"] == fixed["id"] and back["status"] == "open"


async def test_human_decisions_on_host_findings_survive(db_pool, fake_redis):
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1), hw(AG2)], violating=[AG1, AG2]))
    await db_pool.execute("UPDATE findings SET status = 'accepted', status_by = 'alice', status_reason = 'known' "
                          "WHERE evidence->>'target_ref' = $1", AG1)
    await hsync(db_pool, fake_redis, hres("HOLDS"), version=8)
    assert by_target(await rows(db_pool)) == {AG1: "accepted", AG2: "fixed"}


async def test_a_stale_evaluator_cannot_close_host_findings(db_pool, fake_redis):
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1)], violating=[AG1]))
    rep = await hsync(db_pool, fake_redis, hres("HOLDS"), version=8, lease_owner="nobody")
    assert rep.skipped == "lease_lost" and by_target(await rows(db_pool)) == {AG1: "open"}
