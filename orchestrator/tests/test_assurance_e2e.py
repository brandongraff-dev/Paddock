"""P1 end to end (docs/ASSURANCE_P1.md section 9, last bullet).

One tenant is seeded the way production fills it, and the REAL pieces run against it, nothing mocked
on the assurance side:

* the AWS connector pulls a moto world (instance, ALB, RDS, security groups) and
  ``apply_source_batch`` writes it into ``assets`` exactly as a sync does,
* an external full-port scan and port assets (``scans`` / ``assets`` / ``scope_entries`` rows),
* a Sentry sensor with passive flows (``sensors`` / ``reach_flow_obs`` rows),
* declared zones and labels through the store,
* the std invariants plus two custom ones, evaluated by ``runner.tick_once`` / ``run_tenant`` with
  the real builders, graph loader, library and findings sync.

The planted scenarios are the ones in ``assurance/examples``: SSH open to the world, a database
exposed to the internet, and a guest device reaching the POS segment through a printer. The test then
fixes each, silences the sensor, plants them again, and checks verdicts, findings (open, close with
and without verification, reopen) and that a second tenant sees none of it.

Everything runs through ``app_pool`` (the non-superuser role, RLS enforced); ``db_pool`` only seeds
rows a connector or a sensor would write and inspects the result.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import json
import uuid

import pytest

from app import tenancy
from app.assurance import graph_loader, refs, runner, store
from app.config import settings

A = tenancy.DEFAULT_TENANT_ID
B = "00000000-0000-0000-0000-0000000000b2"
UTC = dt.timezone.utc
H = dt.timedelta(hours=1)
M = dt.timedelta(minutes=1)

# Globally routable address, used as an inert string only (nothing is ever contacted).
EXPOSED = "93.184.216.34"
# the markers the active worker records for a clean full-port scan (external_exposure contract)
WORKER_FULL_SCAN_SUMMARY = json.dumps({"ports_scanned": "1-65535", "tool_exit_ok": True, "results_posted": True})
GUEST_LAPTOP, GUEST_AP, PRINTER, POS, POS_HUB = "10.20.0.5", "10.20.0.1", "10.10.0.9", "10.30.0.4", "10.30.0.1"
SENSOR = "11111111-1111-4111-8111-111111111111"
SENSOR_B = "22222222-2222-4222-8222-222222222222"

STD_IDS = ("std:no-internet-to-datastore", "std:public-ports-allowlist", "std:guest-cannot-reach-pos",
           "std:coverage-complete")

# Custom invariants whose evidence floor is ``configured`` (a complete security-group read), so a
# configuration-only fix can show HOLDS. The std ones demand ``observed`` and must NOT hold on it.
DB_PRIVATE = "acme:db-not-public"
WEB_ONLY = "acme:web-ports-only"
GUEST_POS = "acme:guest-pos"
CUSTOM = {
    DB_PRIVATE: """\
apiVersion: paddock.dev/invariant/v1
id: acme:db-not-public
title: Databases are not reachable from the internet
severity: critical
subjects:
  from: { zone: internet }
  to: { class: data_store }
assert: unreachable
via: { protocols: [tcp], max_hops: 6, stop_at: { tag: app-tier } }
evidence: { min_tier: configured, max_age: 24h }
coverage: { require: 0.0 }
""",
    WEB_ONLY: """\
apiVersion: paddock.dev/invariant/v1
id: acme:web-ports-only
title: Only web ports face the internet
severity: high
subjects:
  from: { zone: internet }
assert: exposes-only
ports: [80, 443]
via: { protocols: [tcp] }
evidence: { min_tier: configured, max_age: 24h }
coverage: { require: 0.0 }
""",
    GUEST_POS: """\
apiVersion: paddock.dev/invariant/v1
id: acme:guest-pos
title: Guests cannot reach the point of sale
severity: critical
subjects:
  from: { zone: guest }
  to: { zone: pos }
assert: unreachable
via: { max_hops: 6 }
evidence: { min_tier: observed, max_age: 24h }
coverage: { require: 0.0 }
""",
}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

@contextlib.asynccontextmanager
async def conn_for(pool, tid=A):
    with tenancy.tenant_context(tid):          # tenancy is set BEFORE acquire, as in production
        async with pool.acquire() as con:
            yield con


async def seed_sensor(db_pool, sid, tid, *, online, up):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO sensors (id, tenant_id, name, site, status, cred_prefix, cred_hash, online, last_upload_at) "
            "VALUES ($1, $2, $3, 'hq', 'active', $4, 'h', $5, $6) "
            "ON CONFLICT (id) DO UPDATE SET online = EXCLUDED.online, last_upload_at = EXCLUDED.last_upload_at",
            uuid.UUID(sid), uuid.UUID(tid), f"s-{sid[:4]}", f"pst_{sid[:8]}", online, up)
        # coverage needs a declared scope (schema 040 sensor_scopes): the lab mirrors all of 10.0.0.0/8
        await con.execute(
            "INSERT INTO sensor_scopes (tenant_id, sensor_id, cidrs, set_by, justification) "
            "VALUES ($1, $2, $3::text[], 'e2e', 'test lab') ON CONFLICT (tenant_id, sensor_id) DO NOTHING",
            uuid.UUID(tid), uuid.UUID(sid), ["10.0.0.0/8"])


async def seed_flow(db_pool, tid, src, dst, port, sid, last):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO reach_flow_obs (tenant_id, src_ip, dst_ip, proto, dst_port, sensor_id, first_seen, last_seen) "
            "VALUES ($1, $2, $3, 'tcp', $4, $5, $6, $6) "
            "ON CONFLICT (tenant_id, src_ip, dst_ip, proto, dst_port, sensor_id) DO UPDATE SET last_seen = EXCLUDED.last_seen",
            uuid.UUID(tid), src, dst, port, uuid.UUID(sid), last)


async def seed_flows(db_pool, tid, sid, at, *, bad):
    """Benign office traffic every cycle; the printer -> POS flow only when ``bad``."""
    benign = [(GUEST_LAPTOP, GUEST_AP, 443), (GUEST_LAPTOP, PRINTER, 9100), (POS, POS_HUB, 8443),
              (PRINTER, "10.10.0.20", 445)]
    for src, dst, port in benign + ([(PRINTER, POS, 9100)] if bad else []):
        await seed_flow(db_pool, tid, src, dst, port, sid, at)
    if not bad:
        async with db_pool.acquire() as con:
            await con.execute("DELETE FROM reach_flow_obs WHERE tenant_id = $1 AND src_ip = $2 AND dst_ip = $3",
                              uuid.UUID(tid), PRINTER, POS)


async def seed_exposed_host(db_pool, *, at, scan_finished):
    """A non-AWS database host: a port asset the scanner saw plus a completed full-port scan."""
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO scope_entries (kind, value, added_by, active) VALUES ('ipv4_cidr', "
                          "'93.184.216.0/24', 'test', TRUE) ON CONFLICT DO NOTHING")
        await con.execute(
            "INSERT INTO assets (kind, value, canonical, source, metadata, last_seen) VALUES "
            "('port', $1, $1, 'port_scan', $2::jsonb, $3)", f"{EXPOSED}:5432",
            json.dumps({"port": 5432, "protocol": "tcp"}), at)
        await con.execute(
            "INSERT INTO scans (kind, target, status, started_at, finished_at, config, result_summary) "
            "VALUES ('port_scan', $1, 'completed', $2, $2, $3::jsonb, $4::jsonb)",
            EXPOSED, scan_finished, json.dumps({"ports": "1-65535"}), WORKER_FULL_SCAN_SUMMARY)


async def close_exposed_host(db_pool, *, scan_finished):
    """The port is closed: its asset is gone and a fresh, clean, full scan says so."""
    async with db_pool.acquire() as con:
        await con.execute("DELETE FROM assets WHERE kind = 'port' AND canonical = $1", f"{EXPOSED}:5432")
        await con.execute(
            "INSERT INTO scans (kind, target, status, started_at, finished_at, config, result_summary) "
            "VALUES ('port_scan', $1, 'completed', $2, $2, $3::jsonb, $4::jsonb)",
            EXPOSED, scan_finished, json.dumps({"ports": "1-65535"}), WORKER_FULL_SCAN_SUMMARY)


async def install_invariants(pool, tid, *, custom=True):
    import paddock_assurance as lib

    async with conn_for(pool, tid) as con:
        for std_id in STD_IDS:
            await runner.install_std(con, std_id, actor="test")
        if not custom:
            return
        for iid, text in CUSTOM.items():
            plan = lib.compile_text(text)
            await con.execute(
                "INSERT INTO invariants (invariant_id, title, severity, enabled, source, yaml, digest, version) "
                "VALUES ($1, $2, $3, TRUE, 'custom', $4, $5, 1)",
                iid, plan.invariant.title, plan.invariant.severity, text, plan.digest)


async def verdicts(db_pool, tid=A):
    rows = await db_pool.fetch("SELECT invariant_id, last_verdict, last_result FROM invariants WHERE tenant_id = $1", tid)
    return {r["invariant_id"]: r["last_verdict"] for r in rows}


async def last_result(db_pool, invariant_id, tid=A):
    raw = await db_pool.fetchval("SELECT last_result FROM invariants WHERE tenant_id = $1 AND invariant_id = $2",
                                 tid, invariant_id)
    return json.loads(raw) if isinstance(raw, str) else raw


async def inv_findings(db_pool, invariant_id, tid=A):
    base = f"invariant:{invariant_id}"
    return await db_pool.fetch(
        "SELECT f.*, a.value AS asset_value, a.kind AS asset_kind FROM findings f JOIN assets a ON a.id = f.asset_id "
        "WHERE f.tenant_id = $1 AND f.rule_source = 'invariant' AND (f.rule_id = $2 OR starts_with(f.rule_id, $3)) "
        "ORDER BY f.rule_id", tid, base, base + "@")


def by_status(rows):
    out: dict[str, int] = {}
    for r in rows:
        out[r["status"]] = out.get(r["status"], 0) + 1
    return out


async def all_invariant_findings(db_pool, tid=A):
    return await db_pool.fetch("SELECT status, rule_id FROM findings WHERE tenant_id = $1 AND rule_source = 'invariant'", tid)


class Aws:
    """The moto world and the three states we pull from it (planted, fixed, planted again)."""

    def __init__(self, ec2, web_sg, db_sg, conn):
        self.ec2, self.web_sg, self.db_sg, self.conn = ec2, web_sg, db_sg, conn

    ssh = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    pg = {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}

    def plant(self):
        # _build_world already opens 22 and 443 on the web group; open the database to the world too.
        self.ec2.authorize_security_group_ingress(GroupId=self.db_sg, IpPermissions=[self.pg])

    def fix(self):
        self.ec2.revoke_security_group_ingress(GroupId=self.web_sg, IpPermissions=[self.ssh])
        self.ec2.revoke_security_group_ingress(GroupId=self.db_sg, IpPermissions=[self.pg])

    def replant(self):
        self.ec2.authorize_security_group_ingress(GroupId=self.web_sg, IpPermissions=[self.ssh])
        self.ec2.authorize_security_group_ingress(GroupId=self.db_sg, IpPermissions=[self.pg])

    async def pull(self):
        return await self.conn.pull()


@pytest.fixture
def small_windows(monkeypatch):
    """Observation windows of two hours so 'a few hours later' ages old observations out."""
    monkeypatch.setattr(settings, "assurance_edge_window_h", 2)
    monkeypatch.setattr(settings, "assurance_external_max_age_h", 2)
    runner._LAST_BUILD.clear()
    yield
    runner._LAST_BUILD.clear()


async def apply(db_pool, fake_redis, batch):
    from app.integrations.ingest import apply_source_batch

    await apply_source_batch(db_pool, fake_redis, batch, source="integration:aws")


# --------------------------------------------------------------------------- #
# the test
# --------------------------------------------------------------------------- #

async def test_p1_end_to_end(db_pool, app_pool, fake_redis, monkeypatch, small_windows):
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    from tests.test_aws_connector import REGION, SECRETS, _build_world, aws_mod

    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)

    t0 = dt.datetime.now(UTC).replace(microsecond=0)
    t1 = t0 + 3 * H                       # after the 2h windows: yesterday's observations are gone
    t2, t3 = t1 + 10 * M, t1 + 20 * M

    # ---- tenant B exists with a world of its own, and nothing of A's -------------------------
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo", tenant_id=B)
    await install_invariants(app_pool, B, custom=False)
    async with conn_for(app_pool, B) as con:
        await store.upsert_zone(con, "guest", ["192.168.50.0/24"], set_by="b-admin", justification="B's own guest wifi")
    await seed_sensor(db_pool, SENSOR_B, B, online=True, up=t0 - M)
    await seed_flow(db_pool, B, "192.168.50.7", "192.168.50.8", 22, SENSOR_B, t0 - 5 * M)

    # ---- tenant A: assets exactly as the connectors would write them ----------------------------
    with moto.mock_aws():
        world = _build_world()
        ec2 = boto3.client("ec2", region_name=REGION)
        sgs = {g["GroupName"]: g["GroupId"] for g in ec2.describe_security_groups()["SecurityGroups"]}
        aws = Aws(ec2, sgs["web"], sgs["db"], aws_mod.AwsConnector(
            {"regions": [REGION], "role_arn": "arn:aws:iam::123456789012:role/paddock-readonly"}, SECRETS, http=None))
        aws.plant()
        planted = await aws.pull()
        aws.fix()
        fixed = await aws.pull()
        aws.replant()
        replanted = await aws.pull()
    assert world["public_ip"], "moto should give the instance a public address"
    await apply(db_pool, fake_redis, planted)

    async with conn_for(app_pool) as con:
        for name, cidr in (("guest", "10.20.0.0/24"), ("pos", "10.30.0.0/24"), ("office", "10.10.0.0/24")):
            await store.upsert_zone(con, name, [cidr], set_by="admin", justification=f"{name} network per the site plan")
    await seed_exposed_host(db_pool, at=t0 - 10 * M, scan_finished=t0 - H)
    await seed_sensor(db_pool, SENSOR, A, online=True, up=t0 - M)
    await seed_flows(db_pool, A, SENSOR, t0 - 5 * M, bad=True)
    await install_invariants(app_pool, A)
    # the first build has to create the nodes before labels can be pointed at them; labels are
    # declared by a person (provenance recorded) and are verdict inputs.
    first = await runner.tick_once(app_pool, redis=fake_redis, now=t0)
    sa = first[A]
    assert sa["ok"], sa["errors"]
    assert sa["built"] and set(sa["builders"]) == {"aws_sg", "external_scan", "host_fw", "sentry_flow"}
    assert all(b["ok"] for b in sa["builders"].values()), sa["builders"]

    async with conn_for(app_pool) as con:
        nodes = {r["node_ref"]: r for r in await con.fetch("SELECT node_ref, kind, asset_id FROM reach_nodes")}
    inst = next(r for r in nodes.values() if r["kind"] == "cloud_instance")["node_ref"]
    alb = next(r for r in nodes.values() if r["kind"] == "cloud_lb")["node_ref"]
    rds = next(r for r in nodes.values() if r["kind"] == "cloud_db")["node_ref"]
    exposed = f"ip:{EXPOSED}"
    assert exposed in nodes and f"ip:{POS}" in nodes and "internet" in nodes
    async with conn_for(app_pool) as con:
        for ref in (inst, alb):
            await store.set_label(con, ref, "app-tier", "true", set_by="admin", justification="web tier: the DB sits behind it")
        await store.set_label(con, exposed, "class", "data_store", set_by="admin", justification="legacy database host")

    # ---- phase 1: everything planted -------------------------------------------------------------
    s1 = await runner.run_tenant(app_pool, A, now=t0, redis=fake_redis, rebuild=True)
    assert s1["ok"], s1["errors"]
    v = await verdicts(db_pool)
    assert v["std:public-ports-allowlist"] == "VIOLATED"        # SSH (22) and 5432 face the internet
    assert v[WEB_ONLY] == "VIOLATED"
    assert v["std:no-internet-to-datastore"] == "VIOLATED"      # the RDS rule and the exposed host
    assert v[DB_PRIVATE] == "VIOLATED"
    assert v["std:guest-cannot-reach-pos"] == "VIOLATED"        # guest -> printer -> POS, observed
    assert v[GUEST_POS] == "VIOLATED"
    assert v["std:coverage-complete"] == "VIOLATED"             # AWS nodes are blind outbound

    # the witnesses are the planted facts, not just any violation
    db_res = await last_result(db_pool, DB_PRIVATE)
    hops = {(h["src"], h["dst"], h["ports"]) for w in db_res["witnesses"] for h in w["hops"]}
    assert ("internet", rds, "5432") in hops and ("internet", exposed, "5432") in hops
    assert db_res["evidence_tier"] is None                      # only a HOLDS carries a tier
    gp_res = await last_result(db_pool, GUEST_POS)
    path = [(h["src"], h["dst"]) for h in gp_res["witnesses"][0]["hops"]]
    assert path == [(f"ip:{GUEST_LAPTOP}", f"ip:{PRINTER}"), (f"ip:{PRINTER}", f"ip:{POS}")]
    ssh = await last_result(db_pool, WEB_ONLY)
    assert any(w["detail"]["disallowed_ports"].startswith("22") for w in ssh["witnesses"])

    # findings: one per root-cause target, on the right asset, in plain words
    f_db = await inv_findings(db_pool, DB_PRIVATE)
    assert {r["status"] for r in f_db} == {"open"} and len(f_db) == 2
    assert {r["asset_kind"] for r in f_db} == {"cloud_resource", "org"}      # the RDS asset + the estate asset
    assert any(r["rule_id"] == f"invariant:{DB_PRIVATE}" for r in f_db)       # asset-backed: bare id
    assert any(r["rule_id"] == f"invariant:{DB_PRIVATE}@{exposed}" for r in f_db)
    assert all(r["severity"] == "critical" and r["rule_source"] == "invariant" for r in f_db)
    ev = json.loads(f_db[0]["evidence"]) if isinstance(f_db[0]["evidence"], str) else f_db[0]["evidence"]
    assert set(ev) == {"invariant", "digest", "verdict", "target_ref", "witness", "coverage", "graph_version"}
    f_pos = await inv_findings(db_pool, GUEST_POS)
    assert len(f_pos) == 1 and f_pos[0]["asset_value"] == "paddock-assurance"
    assert "->" in f_pos[0]["description"] and "9100" in f_pos[0]["description"]
    f_cov = await inv_findings(db_pool, "std:coverage-complete")
    assert len(f_cov) >= 4                                                    # inst, alb, rds, the exposed host

    # run the loop again with nothing changed: nothing is re-evaluated, nothing duplicated
    before = await all_invariant_findings(db_pool)
    again = (await runner.tick_once(app_pool, redis=fake_redis, now=t0 + M))[A]
    assert again["evaluated"] == 0 and again["skipped"] in ("up_to_date", None)
    assert len(await all_invariant_findings(db_pool)) == len(before)

    # ---- tenant B saw none of it ----------------------------------------------------------------
    await assert_b_sees_nothing(db_pool, app_pool, fake_redis, t0)

    # ---- phase 2: fix SSH and the database rule, close the printer path, close the host ---------------
    await apply(db_pool, fake_redis, fixed)
    await close_exposed_host(db_pool, scan_finished=t1 - 30 * M)
    await seed_sensor(db_pool, SENSOR, A, online=True, up=t1 - M)
    await seed_flows(db_pool, A, SENSOR, t1 - 5 * M, bad=False)
    s2 = await runner.run_tenant(app_pool, A, now=t1, redis=fake_redis, rebuild=True)
    assert s2["ok"], s2["errors"]
    v = await verdicts(db_pool)
    # configuration alone is complete enough for the configured-tier invariants ...
    assert v[DB_PRIVATE] == "HOLDS" and v[WEB_ONLY] == "HOLDS" and v[GUEST_POS] == "HOLDS"
    # ... and the std guest invariant now HOLDS too: Sentry gives observed evidence both ways for
    # the guest and POS devices, and the coverage floor is measured over the nodes it is about
    assert v["std:guest-cannot-reach-pos"] == "HOLDS"
    # the std internet invariants stay UNKNOWN, correctly: the closed host is known only from a
    # TCP port scan, which cannot rule out a UDP service, and the internet is blind outbound
    assert v["std:no-internet-to-datastore"] == "UNKNOWN"
    assert v["std:public-ports-allowlist"] == "UNKNOWN"
    for k in ("std:no-internet-to-datastore", "std:public-ports-allowlist"):
        assert (await last_result(db_pool, k))["reasons"] == ["possible_via_unknown_edges"]
    assert v["std:coverage-complete"] == "VIOLATED"             # unrelated gaps remain
    # the evidence tiers say what each HOLDS rests on
    assert (await last_result(db_pool, DB_PRIVATE))["evidence_tier"] == "configured"
    assert (await last_result(db_pool, GUEST_POS))["evidence_tier"] == "observed"
    assert (await last_result(db_pool, GUEST_POS))["valid_until"] is not None

    f_db = await inv_findings(db_pool, DB_PRIVATE)
    assert by_status(f_db) == {"fixed": 2}
    assert all(r["fix_verified_at"] is None for r in f_db)       # configured evidence: closed, not "verified"
    f_pos = await inv_findings(db_pool, GUEST_POS)
    assert by_status(f_pos) == {"fixed": 1} and f_pos[0]["fix_verified_at"] is not None
    assert by_status(await inv_findings(db_pool, WEB_ONLY)) == {"fixed": 4}
    # UNKNOWN closes nothing: the std findings are still open, as are the coverage gaps
    assert by_status(await inv_findings(db_pool, "std:no-internet-to-datastore")) == {"open": 2}
    assert set(by_status(await inv_findings(db_pool, "std:public-ports-allowlist"))) == {"open"}
    f_std_pos = await inv_findings(db_pool, "std:guest-cannot-reach-pos")
    assert set(by_status(f_std_pos)) == {"fixed"} and all(r["fix_verified_at"] is not None for r in f_std_pos)
    hist = await db_pool.fetch(
        "SELECT h.actor, h.to_status, h.reason FROM finding_status_history h WHERE h.finding_id = $1", f_pos[0]["id"])
    assert any(h["actor"] == "system:assurance" and h["to_status"] == "fixed" for h in hist)

    # ---- phase 3: the sensor goes silent -------------------------------------------------------------
    open_before = {r["rule_id"] for r in await all_invariant_findings(db_pool) if r["status"] == "open"}
    await seed_sensor(db_pool, SENSOR, A, online=False, up=t1 - M)
    s3 = await runner.run_tenant(app_pool, A, now=t2, redis=fake_redis, rebuild=True)
    assert s3["ok"], s3["errors"]
    v = await verdicts(db_pool)
    assert v[GUEST_POS] == "UNKNOWN"                              # nobody is watching the guest network
    gp = await last_result(db_pool, GUEST_POS)
    assert gp["reasons"] == ["possible_via_unknown_edges"] and gp["evidence_tier"] is None
    assert v[DB_PRIVATE] in ("HOLDS", "UNKNOWN") and v[WEB_ONLY] in ("HOLDS", "UNKNOWN")
    after = await all_invariant_findings(db_pool)
    # silence is not a verdict: nothing was opened, nothing that was fixed was reopened
    assert {r["rule_id"] for r in after if r["status"] == "open"} == open_before
    assert by_status(await inv_findings(db_pool, GUEST_POS)) == {"fixed": 1}
    async with conn_for(app_pool) as con:
        cov = await con.fetch("SELECT node_ref FROM reach_coverage WHERE source = 'sentry_flow'")
    assert cov == []                                               # the builder withdrew its coverage

    # ---- phase 4: sensor back, problems back -------------------------------------------------------------
    await apply(db_pool, fake_redis, replanted)
    await seed_exposed_host(db_pool, at=t3 - 5 * M, scan_finished=t3 - 30 * M)
    await seed_sensor(db_pool, SENSOR, A, online=True, up=t3 - M)
    await seed_flows(db_pool, A, SENSOR, t3 - 2 * M, bad=True)
    s4 = await runner.run_tenant(app_pool, A, now=t3, redis=fake_redis, rebuild=True)
    assert s4["ok"], s4["errors"]
    v = await verdicts(db_pool)
    assert v[DB_PRIVATE] == v[WEB_ONLY] == v[GUEST_POS] == "VIOLATED"
    for iid, n in ((DB_PRIVATE, 2), (WEB_ONLY, 4), (GUEST_POS, 1)):
        rows = await inv_findings(db_pool, iid)
        assert by_status(rows) == {"open": n}, (iid, by_status(rows))             # reopened, not duplicated
        assert all(r["fix_verified_at"] is None for r in rows)
    f_pos = await inv_findings(db_pool, GUEST_POS)
    hist = await db_pool.fetch(
        "SELECT actor, from_status, to_status, reason FROM finding_status_history WHERE finding_id = $1 ORDER BY at, id",
        f_pos[0]["id"])
    assert [(h["from_status"], h["to_status"]) for h in hist][-2:] == [("open", "fixed"), ("fixed", "open")]
    assert hist[-1]["actor"] == "system:assurance" and hist[-1]["reason"] == "invariant violated again"
    # ... and the transitions ledger has the story of one invariant
    ledger = await db_pool.fetch("SELECT verdict FROM invariant_runs WHERE tenant_id = $1 AND invariant_id = $2 "
                                 "ORDER BY evaluated_at, id", A, GUEST_POS)
    assert [r["verdict"] for r in ledger] == ["VIOLATED", "HOLDS", "UNKNOWN", "VIOLATED"]

    await assert_b_sees_nothing(db_pool, app_pool, fake_redis, t3)


async def assert_b_sees_nothing(db_pool, app_pool, fake_redis, now):
    """Tenant B is processed by the same loop and shares no row, finding or node with A."""
    out = await runner.tick_once(app_pool, redis=fake_redis, now=now + dt.timedelta(seconds=1))
    assert B in out and out[B]["ok"], out.get(B)
    async with conn_for(app_pool, B) as con:
        assert await con.fetchval("SELECT count(*) FROM asset_labels") == 0
        # B's only graph facts are its own sensor's flow and the coverage that sensor earns
        assert {(r["src_ref"], r["dst_ref"]) for r in await con.fetch("SELECT src_ref, dst_ref FROM reach_edges")} \
            <= {("ip:192.168.50.7", "ip:192.168.50.8")}      # (aged out of its window by phase 4)
        assert {r["node_ref"] for r in await con.fetch("SELECT node_ref FROM reach_coverage")} \
            <= {"ip:192.168.50.7", "ip:192.168.50.8"}
        assert {r["node_ref"] for r in await con.fetch("SELECT node_ref FROM reach_nodes")} \
            <= {"internet", "ip:192.168.50.7", "ip:192.168.50.8"}
        assert [r["name"] for r in await con.fetch("SELECT name FROM zones")] == ["guest"]
        assert {r["invariant_id"] for r in await con.fetch("SELECT invariant_id FROM invariants")} == set(STD_IDS)
        assert await con.fetchval("SELECT count(*) FROM findings WHERE rule_source = 'invariant'") == 0
        doc = await graph_loader.load_graph_doc(con, now)
    assert {n["id"] for n in doc["nodes"]} <= {"internet", "ip:192.168.50.7", "ip:192.168.50.8"} and not any(
        "10." in n["id"] or n["id"].startswith("asset:") for n in doc["nodes"])
    assert {(e["src"], e["dst"]) for e in doc["edges"]} <= {("ip:192.168.50.7", "ip:192.168.50.8")}
    # nothing in the whole database that belongs to B carries A's data, and the reverse
    stray = await db_pool.fetch(
        "SELECT 1 FROM reach_edges WHERE tenant_id = $1 AND (src_ref LIKE 'ip:10.%' OR dst_ref LIKE 'ip:10.%' "
        "OR src_ref LIKE 'asset:%' OR dst_ref LIKE 'asset:%')", B)
    assert stray == []
    a_nodes = await db_pool.fetch("SELECT node_ref FROM reach_nodes WHERE tenant_id = $1 AND node_ref LIKE 'ip:192.168.50.%'", A)
    assert a_nodes == []
    assert refs.INTERNET == "internet"


GUEST_TO_DB = """\
apiVersion: paddock.dev/invariant/v1
id: acme:guest-not-db
title: Guest devices cannot reach the legacy database
severity: high
subjects:
  from: { zone: guest }
  to: { class: data_store }
assert: unreachable
via: { protocols: [tcp], max_hops: 4 }
evidence: { min_tier: observed, max_age: 24h }
coverage: { require: 0.0 }
"""


async def test_an_outside_in_scan_never_rules_out_connections_from_inside(db_pool, app_pool, fake_redis, small_windows):
    """Found by the verification pass: a full TCP scan from outside proves the INTERNET cannot reach
    a host except on the ports it saw. It says nothing about a guest laptop on the inside, so an
    invariant about guests reaching that host must stay UNKNOWN until the guest network is watched.
    Reading the scan as plain inbound coverage would have made it HOLD."""
    import paddock_assurance as lib

    t0 = dt.datetime.now(UTC).replace(microsecond=0)
    plan = lib.compile_text(GUEST_TO_DB)
    async with conn_for(app_pool) as con:
        await store.upsert_zone(con, "guest", ["10.20.0.0/24"], set_by="admin", justification="guest wifi")
        await con.execute(
            "INSERT INTO invariants (invariant_id, title, severity, enabled, source, yaml, digest, version) "
            "VALUES ($1, $2, $3, TRUE, 'custom', $4, $5, 1)",
            plan.id, plan.invariant.title, plan.invariant.severity, GUEST_TO_DB, plan.digest)
    # the host is fully scanned, and nothing is open on it
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO scope_entries (kind, value, added_by, active) VALUES ('ipv4_cidr', "
                          "'93.184.216.0/24', 'test', TRUE)")
        await con.execute(
            "INSERT INTO scans (kind, target, status, started_at, finished_at, config, result_summary) "
            "VALUES ('port_scan', $1, 'completed', $2, $2, $3::jsonb, $4::jsonb)",
            EXPOSED, t0 - 30 * M, json.dumps({"ports": "1-65535"}), WORKER_FULL_SCAN_SUMMARY)
    # a guest laptop is only known from a flow, and its sensor is offline: nobody watches it
    await seed_sensor(db_pool, SENSOR, A, online=False, up=t0 - M)
    await seed_flow(db_pool, A, GUEST_LAPTOP, GUEST_AP, 443, SENSOR, t0 - 5 * M)
    s0 = await runner.run_tenant(app_pool, A, now=t0, redis=fake_redis, rebuild=True)
    assert s0["ok"], s0["errors"]
    async with conn_for(app_pool) as con:
        await store.set_label(con, f"ip:{EXPOSED}", "class", "data_store", set_by="admin", justification="database host")
        cov = await con.fetch("SELECT node_ref, direction, detail FROM reach_coverage WHERE source = 'external_scan'")
    assert [(c["node_ref"], c["direction"]) for c in cov] == [(f"ip:{EXPOSED}", "in")]
    async with conn_for(app_pool) as con:
        doc = await graph_loader.load_graph_doc(con, t0)
    scan_fact = next(n for n in doc["nodes"] if n["id"] == f"ip:{EXPOSED}")["coverage"][0]
    assert scan_fact["origin"] == "internet" and scan_fact["proto"] == "tcp"      # the loader keeps the scope

    r = await runner.run_tenant(app_pool, A, now=t0, redis=fake_redis, force=True)
    assert r["ok"], r["errors"]
    assert (await verdicts(db_pool))["acme:guest-not-db"] == "UNKNOWN"
    res = await last_result(db_pool, "acme:guest-not-db")
    assert res["reasons"] == ["possible_via_unknown_edges"] and res["evidence_tier"] is None
    hop = res["witnesses"][0]["hops"][-1]
    assert hop["src"] in (f"ip:{GUEST_LAPTOP}", f"ip:{GUEST_AP}")                  # a blind guest device
    assert (hop["dst"], hop["proto"]) == (f"ip:{EXPOSED}", "unknown")
    assert await all_invariant_findings(db_pool) == []                              # UNKNOWN files nothing

    # once the guest network is watched both ways, the same invariant can hold, on observed evidence
    await seed_sensor(db_pool, SENSOR, A, online=True, up=t0 - M)
    seen = await runner.run_tenant(app_pool, A, now=t0, redis=fake_redis, force=True, rebuild=True)
    assert seen["ok"], seen["errors"]
    assert (await verdicts(db_pool))["acme:guest-not-db"] == "HOLDS"
    assert (await last_result(db_pool, "acme:guest-not-db"))["evidence_tier"] == "observed"


GUEST_TO_APP = """\
apiVersion: paddock.dev/invariant/v1
id: acme:guest-not-app
title: Guest devices cannot reach the app tier
severity: high
subjects:
  from: { zone: guest }
  to: { zone: app }
assert: unreachable
via: { max_hops: 4 }
evidence: { min_tier: configured, max_age: 24h }
coverage: { require: 0.0 }
"""


async def test_a_cidr_rule_admits_the_devices_inside_it_even_when_another_source_found_them(
        db_pool, app_pool, fake_redis, small_windows):
    """Found by the verification pass: a security group that admits 10.0.0.0/8 is stored as an edge
    from a ``cidr:`` node that touches nothing else. A guest laptop at 10.20.0.5, known only from a
    Sentry flow, then had no edge to the server, the server was covered inbound by its
    configuration, and 'guests cannot reach the server' came out HOLDS while the rule admits them."""
    import paddock_assurance as lib
    from tests.test_assurance_aws import _seed, inst_row, rule, sg_row, uid

    t0 = dt.datetime.now(UTC).replace(microsecond=0)
    seen = t0 - 10 * M
    app_ref = refs.asset_ref(uid("app-priv"))
    plan = lib.compile_text(GUEST_TO_APP)
    admit = {"type": "cidr", "value": "10.0.0.0/8"}
    await _seed(db_pool, sg_row("sg-app", [rule("tcp", 8080, None, admit)], seen=seen), A)
    await _seed(db_pool, inst_row("app-priv", ["sg-app"], public=(), private=("172.16.0.5",), seen=seen), A)
    async with conn_for(app_pool) as con:
        await store.upsert_zone(con, "guest", ["10.20.0.0/24"], set_by="admin", justification="guest wifi")
        await con.execute(
            "INSERT INTO invariants (invariant_id, title, severity, enabled, source, yaml, digest, version) "
            "VALUES ($1, $2, $3, TRUE, 'custom', $4, $5, 1)",
            plan.id, plan.invariant.title, plan.invariant.severity, GUEST_TO_APP, plan.digest)
    await seed_sensor(db_pool, SENSOR, A, online=True, up=t0 - M)
    await seed_flow(db_pool, A, GUEST_LAPTOP, GUEST_AP, 443, SENSOR, t0 - 5 * M)
    first = await runner.run_tenant(app_pool, A, now=t0, redis=fake_redis, rebuild=True)
    assert first["ok"], first["errors"]
    async with conn_for(app_pool) as con:
        await store.set_label(con, app_ref, "zone", "app", set_by="admin", justification="app tier")

    r = await runner.run_tenant(app_pool, A, now=t0, redis=fake_redis, force=True)
    assert r["ok"], r["errors"]
    assert (await verdicts(db_pool))["acme:guest-not-app"] == "VIOLATED"
    res = await last_result(db_pool, "acme:guest-not-app")
    hop = res["witnesses"][0]["hops"][-1]
    assert (hop["dst"], hop["proto"], hop["ports"], hop["source"]) == (app_ref, "tcp", "8080", "aws_sg")
    assert hop["src"] in (f"ip:{GUEST_LAPTOP}", f"ip:{GUEST_AP}")

    # tighten the rule to a range that does not contain the guest network: now it holds
    async with db_pool.acquire() as con:
        md = json.loads(await con.fetchval("SELECT metadata FROM assets WHERE id = $1::uuid", uid("111111111111/us-east-1/sg-app")))
        md["ingress_rules"] = [rule("tcp", 8080, None, {"type": "cidr", "value": "192.168.0.0/16"})]
        await con.execute("UPDATE assets SET metadata = $2::jsonb WHERE id = $1::uuid",
                          uid("111111111111/us-east-1/sg-app"), json.dumps(md))
    s = await runner.run_tenant(app_pool, A, now=t0, redis=fake_redis, force=True, rebuild=True)
    assert s["ok"], s["errors"]
    assert (await verdicts(db_pool))["acme:guest-not-app"] == "HOLDS"


def _doc_parts():
    import ipaddress

    cov_in = [{"direction": "in", "tier": "configured", "observed_at": "2026-12-01T09:00:00+00:00", "source": "aws_sg"},
              {"direction": "out", "tier": "observed", "observed_at": "2026-12-01T09:00:00+00:00", "source": "x"}]
    nodes = [{"id": r, "kind": "host", "tags": []} for r in ("internet", "cidr:10.0.0.0/8", "ip:10.20.0.5",
                                                            "ip:192.168.1.1", "asset:aaaa", "asset:bbbb")]
    nodes.append({"id": "asset:srv", "kind": "cloud_instance", "tags": [], "coverage": cov_in})
    edges = [{"src": "cidr:10.0.0.0/8", "dst": "asset:srv", "proto": "tcp", "ports": "8080-8080",
              "basis": "configured", "source": "aws_sg"}]
    addrs = {"internet": [], "cidr:10.0.0.0/8": [], "ip:10.20.0.5": [ipaddress.ip_address("10.20.0.5")],
             "ip:192.168.1.1": [ipaddress.ip_address("192.168.1.1")],
             "asset:aaaa": [ipaddress.ip_address("10.9.9.9")], "asset:bbbb": [],      # bbbb: address unknown
             "asset:srv": [ipaddress.ip_address("10.1.1.1")]}
    return nodes, edges, addrs


def test_cidr_source_expands_to_the_nodes_inside_it_and_to_nodes_of_unknown_address():
    nodes, edges, addrs = _doc_parts()
    assert graph_loader._expand_cidr_sources(nodes, edges, addrs) == []
    srcs = sorted(e["src"] for e in edges if e["dst"] == "asset:srv")
    # inside 10/8 (ip, asset), unknown address (asset:bbbb, may be anywhere); NOT 192.168/16, NOT
    # the internet, NOT the destination itself; the original cidr edge stays.
    assert srcs == ["asset:aaaa", "asset:bbbb", "cidr:10.0.0.0/8", "ip:10.20.0.5"]
    assert all(e["basis"] == "configured" and e["source"] == "aws_sg" and e["ports"] == "8080-8080" for e in edges)


def test_when_the_expansion_cap_is_hit_inbound_coverage_is_withdrawn_not_assumed_complete(monkeypatch):
    monkeypatch.setattr(graph_loader, "MAX_EXPANDED_EDGES", 1)
    nodes, edges, addrs = _doc_parts()
    assert graph_loader._expand_cidr_sources(nodes, edges, addrs) == ["asset:srv"]
    srv = next(n for n in nodes if n["id"] == "asset:srv")
    assert [c["direction"] for c in srv["coverage"]] == ["out"]        # 'in' gone: the evaluator must assume
    assert len(edges) == 1                                               # nothing half-expanded
