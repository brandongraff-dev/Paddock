"""Sentry coverage only inside declared sensor scopes, and a truncated read gives no coverage.

Regression tests for the P1 adversarial review findings builders-3, builders-4, builders-5,
security-1 and security-8 (docs/ASSURANCE_P1.md section 12). The claim they protect: a Sentry
sensor that saw ONE flow to a host does not thereby see all of that host's traffic, so it may only
assert "no such traffic was seen" for addresses inside a network its operator declared
(``sensor_scopes``), and a read that lost rows must never be turned into coverage. A false HOLDS
is the worst bug; an extra UNKNOWN is fine.

Pure ``build`` tests feed the real ``paddock_assurance`` evaluator; the loader tests need Postgres.
"""
from __future__ import annotations

import datetime as dt
import json
import uuid

import pytest

from app import tenancy
from app.assurance.builders import _ipmap
from app.assurance.builders import sentry_flows as sen

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 12, 1, 12, 0, tzinfo=UTC)
H = dt.timedelta(hours=1)
S1 = "5e5e5e5e-0000-0000-0000-000000000001"
S2 = "5e5e5e5e-0000-0000-0000-000000000002"
UP = NOW - dt.timedelta(minutes=2)
TENANT_B = "00000000-0000-0000-0000-0000000000b4"

OFFICE = "10.20.0.5"          # a host in the office segment the sensor mirrors
CLOUD = "10.0.0.9"            # a cloud instance the sensor only ever saw as a flow endpoint


def flow(src, dst, port=443, *, proto="tcp", sensor=S1, oriented="syn", last=NOW - dt.timedelta(minutes=1)):
    return {"src_ip": src, "dst_ip": dst, "proto": proto, "dst_port": port, "sensor_id": sensor,
            "first_seen": last - dt.timedelta(minutes=5), "last_seen": last, "packets": 3, "bytes": 300,
            "oriented": oriented}


def sensor(sid=S1, *, status="active", online=True, up=UP):
    return {"id": sid, "name": f"s-{sid[-1]}", "status": status, "online": online, "last_upload_at": up}


def scope(sid=S1, *cidrs):
    return {"sensor_id": sid, "cidrs": list(cidrs)}


def instance(ips, aid=None):
    return {"id": aid or str(uuid.uuid4()), "kind": "cloud_resource", "value": "i-1", "canonical": "i-1",
            "metadata": {"resource_type": "instance", "private_ips": list(ips)}}


def device(ips, aid=None):
    return {"id": aid or str(uuid.uuid4()), "kind": "iot_device", "value": "dev", "canonical": "dev",
            "metadata": {"ips": list(ips)}}


def rows(flows=(), sensors=(sensor(),), scopes=(), assets=(), truncated=False):
    return {"flows": list(flows), "sensors": list(sensors), "scopes": list(scopes), "assets": list(assets),
            "truncated": truncated}


def covered(out):
    return {(c.node_ref, c.direction) for c in out.coverage}


def covered_refs(out):
    return {c.node_ref for c in out.coverage}


# --------------------------------------------------------------------------- #
# evaluator plumbing
# --------------------------------------------------------------------------- #

def _doc(out, zones, extra_nodes=(), extra_edges=()):
    cov: dict[str, list] = {}
    for c in out.coverage:
        cov.setdefault(c.node_ref, []).append({"direction": c.direction, "tier": c.tier,
                                               "observed_at": c.observed_at.isoformat(), "source": c.source})
    nodes = {n["id"]: n for n in extra_nodes}
    refs = {*zones, *cov, *(e.src_ref for e in out.edges), *(e.dst_ref for e in out.edges)}
    for ref in sorted(refs):
        n = nodes.setdefault(ref, {"id": ref, "kind": "host"})
        n["coverage"] = n.get("coverage", []) + cov.get(ref, [])
        if ref in zones:
            n["zone"] = zones[ref]
    edges = [{"src": e.src_ref, "dst": e.dst_ref, "proto": e.proto,
              "ports": "-".join(map(str, sorted({e.port_lo, e.port_hi}))) if e.proto != "icmp" else "",
              "basis": e.basis, "source": e.source, "last_seen": e.last_seen.isoformat()} for e in out.edges]
    return {"version": 1, "now": NOW.isoformat(), "nodes": list(nodes.values()), "edges": edges + list(extra_edges)}


def _verdict(out, zones, text, **kw):
    from paddock_assurance import ReachGraph, compile_text, evaluate
    return evaluate(compile_text(text), ReachGraph.from_dict(_doc(out, zones, **kw)), NOW)


GUEST_POS = ("apiVersion: paddock.dev/invariant/v1\nid: acme:guest-no-pos\ntitle: guest never reaches pos\n"
             "severity: high\nsubjects: {from: {zone: guest}, to: {zone: pos}}\nassert: unreachable\n"
             "evidence: {min_tier: observed, max_age: 24h}\n")
INTERNET_DATA = ("apiVersion: paddock.dev/invariant/v1\nid: acme:net-no-data\ntitle: internet never reaches data\n"
                 "severity: high\nsubjects: {from: {kind: internet}, to: {zone: data}}\nassert: unreachable\n"
                 "evidence: {min_tier: configured, max_age: 24h}\n")


# --------------------------------------------------------------------------- #
# builders-3: the original reproduction, at builder + evaluator level
# --------------------------------------------------------------------------- #

def _alb_estate(ec2_ref):
    """An internet-facing ALB with a world-open :443 SG (configured coverage), and a private data
    instance whose SG is NOT synced (blind): without outside evidence its reachability is UNKNOWN."""
    nodes = [{"id": "internet", "kind": "internet"},
             {"id": "asset:alb", "kind": "cloud_lb",
              "coverage": [{"direction": "in", "tier": "configured", "observed_at": NOW.isoformat(),
                            "source": "aws_sg"}]},
             {"id": ec2_ref, "kind": "cloud_instance"}]
    edges = [{"src": "internet", "dst": "asset:alb", "proto": "tcp", "ports": "443", "basis": "configured",
              "source": "aws_sg"}]
    return nodes, edges


def test_f2_a_remote_endpoint_flow_does_not_blind_out_the_unknown_edge():
    ec2 = instance([CLOUD])
    ref = f"asset:{ec2['id']}"
    nodes, edges = _alb_estate(ref)
    one_flow = flow(OFFICE, CLOUD, 5432)

    def verdict(scopes):
        out = sen.build(rows([one_flow], scopes=scopes, assets=[ec2]), NOW)
        return out, _verdict(out, {ref: "data"}, INTERNET_DATA, extra_nodes=nodes, extra_edges=edges)

    # the office sensor mirrors 10.20.0.0/24 only: it cannot see the cloud host's other traffic
    out, res = verdict([scope(S1, "10.20.0.0/24")])
    assert ref not in covered_refs(out)
    assert res.verdict.value == "UNKNOWN"                       # was HOLDS before scopes existed
    # no declared scope at all: the sensor covers nothing, not even the office host
    out, res = verdict([])
    assert out.coverage == [] and res.verdict.value == "UNKNOWN"
    # control: if the operator really declared the cloud subnet as visible, the claim is theirs
    out, res = verdict([scope(S1, "10.0.0.0/24", "10.20.0.0/24")])
    assert ref in covered_refs(out) and res.verdict.value == "HOLDS"


def test_an_ip_seen_once_but_outside_every_scope_gets_no_coverage():
    out = sen.build(rows([flow(OFFICE, CLOUD)], scopes=[scope(S1, "10.20.0.0/24")]), NOW)
    assert covered(out) == {(f"ip:{OFFICE}", "in"), (f"ip:{OFFICE}", "out")}
    assert any("outside every declared sensor scope" in n for n in out.notes)


def test_a_cloud_host_appearing_as_a_flow_endpoint_gets_none():
    ec2 = instance([CLOUD])
    out = sen.build(rows([flow(OFFICE, CLOUD)], scopes=[scope(S1, "10.20.0.0/24")], assets=[ec2]), NOW)
    assert f"asset:{ec2['id']}" not in covered_refs(out)
    # ...but the observed edge into it is still reported
    assert any(e.dst_ref == f"asset:{ec2['id']}" for e in out.edges)


@pytest.mark.parametrize("scopes", [[], [scope(S1)], [scope(S2, "10.0.0.0/8")], [{"sensor_id": S1, "cidrs": None}],
                                    [{"sensor_id": S1}]],
                         ids=["no-row", "empty-cidrs", "other-sensors-scope", "null-cidrs", "missing-cidrs"])
def test_an_online_sensor_without_a_declared_scope_covers_nothing(scopes):
    out = sen.build(rows([flow(OFFICE, CLOUD)], scopes=scopes), NOW)
    assert out.coverage == [] and len(out.edges) == 1
    assert any("no declared scope" in n for n in out.notes)


def test_scope_boundary_a_slash_32_covers_exactly_one_address():
    out = sen.build(rows([flow(OFFICE, "10.20.0.6")], scopes=[scope(S1, "10.20.0.5/32")]), NOW)
    assert covered_refs(out) == {f"ip:{OFFICE}"}
    # a bare address is the same /32
    out = sen.build(rows([flow(OFFICE, "10.20.0.6")], scopes=[scope(S1, "10.20.0.6")]), NOW)
    assert covered_refs(out) == {"ip:10.20.0.6"}
    # /24 boundary: first and last host in, the neighbours out
    fl = [flow("10.20.0.1", "10.20.1.1"), flow("10.20.0.254", "10.20.255.1")]
    out = sen.build(rows(fl, scopes=[scope(S1, "10.20.0.0/24")]), NOW)
    assert covered_refs(out) == {"ip:10.20.0.1", "ip:10.20.0.254"}


def test_scope_ipv6_and_family_mismatch():
    fl = [flow("2001:db8::1", "2001:db9::1"), flow("2001:db8::2", OFFICE)]
    out = sen.build(rows(fl, scopes=[scope(S1, "2001:db8::/64")]), NOW)
    assert covered_refs(out) == {"ip:2001:db8::1", "ip:2001:db8::2"}          # not db9, not the v4 host
    out = sen.build(rows(fl, scopes=[scope(S1, "10.20.0.0/24")]), NOW)
    assert covered_refs(out) == {f"ip:{OFFICE}"}                              # a v4 scope never matches v6


def test_a_v4_mapped_v6_scope_means_the_v4_network():
    out = sen.build(rows([flow(OFFICE, CLOUD)], scopes=[scope(S1, "::ffff:10.20.0.0/120")]), NOW)
    assert covered_refs(out) == {f"ip:{OFFICE}"}


def test_overlapping_scopes_of_two_sensors_use_the_oldest_online_vantage_point():
    fl = [flow(OFFICE, CLOUD, sensor=S1), flow(OFFICE, CLOUD, sensor=S2)]
    scopes = [scope(S1, "10.20.0.0/24"), scope(S2, "10.20.0.0/16", "10.0.0.0/24")]
    sens = [sensor(S1, up=NOW - dt.timedelta(minutes=1)), sensor(S2, up=NOW - 3 * H)]
    out = sen.build(rows(fl, sens, scopes), NOW)
    by = {c.node_ref: c for c in out.coverage}
    assert by[f"ip:{OFFICE}"].observed_at == NOW - 3 * H                      # both vantage points: oldest wins
    assert by[f"ip:{CLOUD}"].observed_at == NOW - 3 * H                       # only S2's scope has it
    assert by[f"ip:{CLOUD}"].detail["sensors"] == [S2]
    # S2 goes offline: OFFICE is still covered by S1 at S1's time, CLOUD is blind again
    out = sen.build(rows(fl, [sens[0], sensor(S2, online=False)], scopes), NOW)
    by = {c.node_ref: c for c in out.coverage}
    assert set(by) == {f"ip:{OFFICE}"} and by[f"ip:{OFFICE}"].observed_at == NOW - dt.timedelta(minutes=1)


def test_scope_of_one_sensor_cannot_be_used_by_another_sensors_sighting():
    """S1 saw CLOUD but its scope excludes it; S2's scope includes it but S2 never saw it."""
    out = sen.build(rows([flow(OFFICE, CLOUD, sensor=S1), flow("10.20.0.7", "10.20.0.8", sensor=S2)],
                         [sensor(S1), sensor(S2)],
                         [scope(S1, "10.20.0.0/24"), scope(S2, "10.0.0.0/24")]), NOW)
    assert f"ip:{CLOUD}" not in covered_refs(out)


def test_an_offline_or_revoked_sensor_with_a_scope_covers_nothing():
    for dead in (sensor(online=False), sensor(status="revoked"), sensor(up=None)):
        out = sen.build(rows([flow(OFFICE, CLOUD)], [dead], [scope(S1, "10.0.0.0/8")]), NOW)
        assert out.coverage == [] and len(out.edges) == 1


def test_a_multi_homed_node_with_an_address_outside_the_scope_stays_blind():
    """The pinned contract needs only ONE address in scope, but traffic on the other address is
    invisible to the sensor, so claiming both directions for the whole node would be unsound."""
    dev = device([OFFICE, "192.168.5.5"])
    out = sen.build(rows([flow(OFFICE, "10.20.0.9"), flow("192.168.5.5", "10.20.0.9")],
                         scopes=[scope(S1, "10.20.0.0/24")], assets=[dev]), NOW)
    assert f"asset:{dev['id']}" not in covered_refs(out)
    out = sen.build(rows([flow(OFFICE, "10.20.0.9"), flow("192.168.5.5", "10.20.0.9")],
                         scopes=[scope(S1, "10.20.0.0/24", "192.168.5.0/24")], assets=[dev]), NOW)
    assert {(f"asset:{dev['id']}", "in"), (f"asset:{dev['id']}", "out")} <= covered(out)


@pytest.mark.parametrize("bad", ["0.0.0.0/0", "::/0", "10.20.0.5/24", "10.0.0.0/33", "nonsense", "", "10.0.0.0/8 ",
                                 "fe80::/10%eth0", 5, None, "10.0.0.0/8/9"],
                         ids=repr)
def test_an_unusable_scope_entry_grants_nothing_and_is_reported(bad):
    out = sen.build(rows([flow(OFFICE, CLOUD)], scopes=[scope(S1, bad)]), NOW)
    if bad == "10.0.0.0/8 ":     # surrounding whitespace is the only thing we forgive
        assert covered_refs(out) == {f"ip:{OFFICE}", f"ip:{CLOUD}"}
    else:
        assert out.coverage == []
        assert any("scope" in n and ("ignored" in n or "no declared scope" in n) for n in out.notes)


def test_a_good_entry_survives_a_bad_one_in_the_same_scope():
    out = sen.build(rows([flow(OFFICE, CLOUD)], scopes=[scope(S1, "0.0.0.0/0", "10.20.0.0/24")]), NOW)
    assert covered_refs(out) == {f"ip:{OFFICE}"}


def test_an_oversized_scope_is_dropped_whole():
    cidrs = [f"10.{i // 256}.{i % 256}.0/24" for i in range(sen.MAX_SCOPE_CIDRS + 1)] + ["10.20.0.0/24"]
    out = sen.build(rows([flow(OFFICE, CLOUD)], scopes=[scope(S1, *cidrs)]), NOW)
    assert out.coverage == [] and any("too many" in n for n in out.notes)


def test_duplicate_scope_rows_for_one_sensor_are_not_merged_into_a_wider_claim():
    out = sen.build(rows([flow(OFFICE, CLOUD)], scopes=[scope(S1, "10.20.0.0/24"), scope(S1, "10.0.0.0/24")]), NOW)
    assert out.coverage == []


def test_scope_selection_is_order_independent():
    fl = [flow(OFFICE, CLOUD, sensor=S1), flow("10.20.0.7", "10.20.0.8", sensor=S2)]
    sc = [scope(S1, "10.20.0.0/24"), scope(S2, "10.20.0.0/24")]
    a = sen.build(rows(fl, [sensor(S1), sensor(S2)], sc), NOW)
    b = sen.build(rows(fl[::-1], [sensor(S2), sensor(S1)], sc[::-1]), NOW)
    assert a == b


# --------------------------------------------------------------------------- #
# builders-4: freshness
# --------------------------------------------------------------------------- #

def test_f3_observed_at_is_the_heartbeat_never_newer_than_now_and_the_sighting_is_disclosed():
    old = NOW - 23 * H
    out = sen.build(rows([flow(OFFICE, "10.20.0.9", last=old)], scopes=[scope(S1, "10.20.0.0/24")]), NOW)
    assert {c.observed_at for c in out.coverage} == {UP}
    # the node's own last sighting is in the evidence so a reader can see how old it is
    assert {c.detail["last_sighting"] for c in out.coverage} == {old.isoformat()}
    json.dumps([c.detail for c in out.coverage])                         # stays JSON-serialisable
    skew = sen.build(rows([flow(OFFICE, CLOUD)], [sensor(up=NOW + 10 * H)], [scope(S1, "10.0.0.0/8")]), NOW)
    assert {c.observed_at for c in skew.coverage} == {NOW}


# --------------------------------------------------------------------------- #
# builders-5 / security-1: truncation must degrade to UNKNOWN, never to HOLDS
# --------------------------------------------------------------------------- #

ZONES = {"ip:10.1.0.5": "guest", "ip:10.2.0.9": "pos"}
SC = [scope(S1, "10.0.0.0/8")]


def test_f4_truncated_read_emits_no_coverage_but_keeps_the_edges_it_has():
    fl = [flow("10.1.0.5", "10.9.9.9"), flow("10.8.8.8", "10.2.0.9")]
    ok = sen.build(rows(fl, scopes=SC), NOW)
    assert ok.coverage and _verdict(ok, ZONES, GUEST_POS).verdict.value == "HOLDS"
    cut = sen.build(rows(fl, scopes=SC, truncated=True), NOW)
    assert cut.coverage == [] and len(cut.edges) == len(ok.edges)
    assert any("TRUNCATED" in n and "row cap" in n and "no coverage" in n for n in cut.notes)
    assert _verdict(cut, ZONES, GUEST_POS).verdict.value == "UNKNOWN"


# --------------------------------------------------------------------------- #
# security-8: IPv6 scope ids
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("v", ["2001:db8::99%9", "fe80::1%eth0", "2001:db8::7%" + "z" * 100, "[2001:db8::1%1]",
                               "1" * 65, "[[::1]]", "]::1[", "::1%", None, 5])
def test_norm_ip_rejects_scope_ids_and_junk(v):
    assert _ipmap.norm_ip(v) is None


def test_norm_ip_still_canonicalises_the_honest_spellings():
    assert _ipmap.norm_ip(" [2001:0DB8::1] ") == "2001:db8::1"
    assert _ipmap.norm_ip("::ffff:10.1.0.20") == "10.1.0.20"
    assert _ipmap.norm_ip("10.1.0.20") == "10.1.0.20"


def test_a_scoped_flow_never_becomes_a_phantom_node_or_coverage():
    host = device(["2001:db8::99"])
    out = sen.build(rows([flow("2001:db8::99%9", "2001:db8::5"), flow("2001:db8::99", "2001:db8::5")],
                         scopes=[scope(S1, "2001:db8::/32")], assets=[host]), NOW)
    assert not any("%" in n.ref for n in out.nodes) and not any("%" in c.node_ref for c in out.coverage)
    assert {e.src_ref for e in out.edges} == {f"asset:{host['id']}"}
    assert any("1 flow record(s) skipped" in n for n in out.notes)


def test_a_scope_entry_with_a_scope_id_is_not_accepted():
    out = sen.build(rows([flow("fe80::1", "fe80::2")], scopes=[scope(S1, "fe80::%eth0/64")]), NOW)
    assert out.coverage == []


# --------------------------------------------------------------------------- #
# aggregated rows (SQL-side GROUP BY) are read as before
# --------------------------------------------------------------------------- #

def test_an_aggregated_row_with_several_sensors_counts_for_each_of_them():
    agg = flow(OFFICE, CLOUD)
    agg.pop("sensor_id")
    agg["sensor_ids"] = [S2, S1]
    out = sen.build(rows([agg], [sensor(S1), sensor(S2)], [scope(S1, "10.20.0.0/24"), scope(S2, "10.0.0.0/24")]), NOW)
    (e,) = out.edges
    assert e.evidence["sensors"] == [S1, S2]
    assert covered_refs(out) == {f"ip:{OFFICE}", f"ip:{CLOUD}"}


# --------------------------------------------------------------------------- #
# Loader on Postgres
# --------------------------------------------------------------------------- #

async def _seed_sensor(db_pool, sid, tenant=tenancy.DEFAULT_TENANT_ID, *, online=True, up=None):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO sensors (id, tenant_id, name, site, status, cred_prefix, cred_hash, online, last_upload_at) "
            "VALUES ($1,$2,$3,'site','active',$4,'h',$5,$6)",
            uuid.UUID(sid), uuid.UUID(tenant), f"s-{sid[-1]}", f"pst_{sid[-8:]}{tenant[-2:]}", online, up)


async def _seed_scope(db_pool, sid, cidrs, tenant=tenancy.DEFAULT_TENANT_ID):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO sensor_scopes (tenant_id, sensor_id, cidrs, set_by, justification) VALUES ($1,$2,$3,'t','test')",
            uuid.UUID(tenant), uuid.UUID(sid), cidrs)


async def _seed_flow(db_pool, tenant, src, dst, port, sid, last, *, proto="tcp", oriented="syn"):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO reach_flow_obs (tenant_id, src_ip, dst_ip, proto, dst_port, sensor_id, first_seen, last_seen, oriented) "
            "VALUES ($1,$2,$3,$7,$4,$5,$6,$6,$8)", uuid.UUID(tenant), src, dst, port, uuid.UUID(sid), last,
            proto, oriented)


async def _load(app_pool, now, tenant=tenancy.DEFAULT_TENANT_ID, **opts):
    with tenancy.tenant_context(tenant):
        async with app_pool.acquire() as con:
            return await sen.load(con, now, **opts)


async def test_loader_reads_the_tenants_scopes_only_and_builds_scoped_coverage(app_pool, db_pool):
    now = dt.datetime.now(UTC)
    await _seed_sensor(db_pool, S1, up=now - dt.timedelta(minutes=1))
    await _seed_scope(db_pool, S1, ["10.20.0.0/24"])
    await tenancy.create_tenant(db_pool, slug="bravo4", name="B", tenant_id=TENANT_B)
    await _seed_sensor(db_pool, S2, TENANT_B, up=now)
    await _seed_scope(db_pool, S2, ["10.0.0.0/8"], TENANT_B)
    await _seed_flow(db_pool, tenancy.DEFAULT_TENANT_ID, OFFICE, CLOUD, 5432, S1, now - dt.timedelta(minutes=3))
    loaded = await _load(app_pool, now)
    assert [(s["sensor_id"], list(s["cidrs"])) for s in loaded["scopes"]] == [(S1, ["10.20.0.0/24"])]
    out = sen.build(loaded, now)
    assert covered_refs(out) == {f"ip:{OFFICE}"}


async def test_f4_db_truncation_gives_unknown_not_holds(app_pool, db_pool, monkeypatch):
    """The review's repro: with a 2-row cap the older guest -> pos flow fell off, the newer flows kept
    both nodes 'covered', and the verdict was HOLDS (untruncated it is VIOLATED)."""
    now = dt.datetime.now(UTC)
    await _seed_sensor(db_pool, S1, up=now - dt.timedelta(minutes=1))
    await _seed_scope(db_pool, S1, ["10.0.0.0/8"])
    t = tenancy.DEFAULT_TENANT_ID
    await _seed_flow(db_pool, t, "10.1.0.5", "10.2.0.9", 445, S1, now - 10 * H)
    await _seed_flow(db_pool, t, "10.1.0.5", "10.1.0.77", 443, S1, now - H)
    await _seed_flow(db_pool, t, "10.2.0.9", "10.2.0.88", 8443, S1, now - dt.timedelta(minutes=30))
    zones = {"ip:10.1.0.5": "guest", "ip:10.2.0.9": "pos"}
    full = sen.build(await _load(app_pool, now), now)
    assert _verdict_at(full, zones, now).verdict.value == "VIOLATED"
    monkeypatch.setattr(sen, "MAX_FLOWS", 2)
    loaded = await _load(app_pool, now)
    assert loaded["truncated"] and len(loaded["flows"]) == 2
    cut = sen.build(loaded, now)
    assert cut.coverage == [] and any("TRUNCATED" in n for n in cut.notes)
    assert _verdict_at(cut, zones, now).verdict.value != "HOLDS"


async def test_row_multiplicity_alone_does_not_trigger_truncation(app_pool, db_pool, monkeypatch):
    """Two sensors reporting the same (src, dst, proto, port) are ONE aggregated row: the cap counts
    distinct flows, and the merged row remembers both sensors and keeps min/max timestamps."""
    now = dt.datetime.now(UTC)
    t = tenancy.DEFAULT_TENANT_ID
    for sid in (S1, S2):
        await _seed_sensor(db_pool, sid, up=now)
    await _seed_flow(db_pool, t, OFFICE, CLOUD, 443, S1, now - 5 * H, oriented="heuristic")
    await _seed_flow(db_pool, t, OFFICE, CLOUD, 443, S2, now - dt.timedelta(minutes=2), oriented="syn")
    await _seed_flow(db_pool, t, OFFICE, "10.20.0.6", 22, S1, now - dt.timedelta(minutes=1))
    monkeypatch.setattr(sen, "MAX_FLOWS", 2)
    loaded = await _load(app_pool, now)
    assert not loaded["truncated"] and len(loaded["flows"]) == 2
    merged = next(f for f in loaded["flows"] if f["dst_port"] == 443)
    assert sorted(merged["sensor_ids"]) == [S1, S2] and merged["oriented"] == "syn"
    assert merged["last_seen"] > merged["first_seen"] and merged["last_seen"] > now - dt.timedelta(minutes=3)


async def test_a_flood_of_distinct_flows_withdraws_coverage_instead_of_hiding_the_real_edge(app_pool, db_pool, monkeypatch):
    now = dt.datetime.now(UTC)
    t = tenancy.DEFAULT_TENANT_ID
    await _seed_sensor(db_pool, S1, up=now)
    await _seed_scope(db_pool, S1, ["10.0.0.0/8"])
    await _seed_flow(db_pool, t, "10.1.0.5", "10.2.0.9", 445, S1, now - 6 * H)       # the real violation
    async with db_pool.acquire() as con:                                                 # the junk sweep
        await con.execute(
            "INSERT INTO reach_flow_obs (tenant_id, src_ip, dst_ip, proto, dst_port, sensor_id, first_seen, last_seen) "
            "SELECT $1, '10.1.0.5', '10.9.9.9', 'udp', g, $2, $3, $3 FROM generate_series(1, 50) g",
            uuid.UUID(t), uuid.UUID(S1), now - dt.timedelta(minutes=2))
    monkeypatch.setattr(sen, "MAX_FLOWS", 40)
    out = sen.build(await _load(app_pool, now), now)
    assert out.coverage == []
    zones = {"ip:10.1.0.5": "guest", "ip:10.2.0.9": "pos"}
    assert _verdict_at(out, zones, now).verdict.value == "UNKNOWN"


def _verdict_at(out, zones, now):
    from paddock_assurance import ReachGraph, compile_text, evaluate
    doc = _doc(out, zones)
    doc["now"] = now.isoformat()
    return evaluate(compile_text(GUEST_POS), ReachGraph.from_dict(doc), now)
