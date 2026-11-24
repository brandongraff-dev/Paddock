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
