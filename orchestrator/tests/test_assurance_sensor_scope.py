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


# =========================================================================== #
# P2.1 section F (docs/ASSURANCE_P2_1.md 6.5, D37): scope declaration is an accountability record, not an equality check.
# The API now tells the operator what the sensor actually saw (advisories), refuses a silently wide scope, and
# `GET /v1/sensors` says which sensors have one. Observed coverage proves "no such traffic was seen", not "impossible".
# =========================================================================== #

import json as _json  # noqa: E402

from app.routers import assurance as api  # noqa: E402

from .test_assurance_api import _audit_rows  # noqa: E402

A_TENANT = tenancy.DEFAULT_TENANT_ID


def pfx(prefix, flows=1, private=True):
    return {"prefix": prefix, "flows": flows, "last_seen": NOW, "private": private}


# --- the pure advisory builder ------------------------------------------------------------------------------

def test_advisories_say_what_was_seen_and_flag_the_gaps():
    seen = [pfx("10.20.0.0/24", 9), pfx("10.20.1.0/24", 4), pfx("10.99.5.0/24", 2), pfx("8.8.8.0/24", 50, private=False)]
    adv = api.scope_advisories(["10.20.0.0/24", "10.77.0.0/16"], seen, capped=False)
    assert [p["prefix"] for p in adv["observed"]["prefixes"]] == ["8.8.8.0/24", "10.20.0.0/24", "10.20.1.0/24", "10.99.5.0/24"]
    assert adv["observed"]["truncated"] is False and adv["observed"]["window_days"] == 7
    assert adv["declared_but_unobserved"] == ["10.77.0.0/16"]
    # a private prefix overlapping no declared CIDR is outside the scope; a PUBLIC one never is (every sensor sees the internet)
    assert adv["observed_outside_scope"] == ["10.20.1.0/24", "10.99.5.0/24"]
    assert adv["suggested_cidrs"] == ["10.20.0.0/23", "10.99.5.0/24"]
    assert "8.8.8.0/24" not in " ".join(adv["suggested_cidrs"])


def test_a_declared_cidr_containing_or_inside_an_observed_prefix_counts_as_observed():
    seen = [pfx("10.20.0.0/24")]
    assert api.scope_advisories(["10.20.0.0/16"], seen, capped=False)["declared_but_unobserved"] == []
    assert api.scope_advisories(["10.20.0.64/26"], seen, capped=False)["declared_but_unobserved"] == []     # inside the /24
    assert api.scope_advisories(["10.21.0.0/24"], seen, capped=False)["declared_but_unobserved"] == ["10.21.0.0/24"]
    assert api.scope_advisories(["10.20.0.64/26"], seen, capped=False)["observed_outside_scope"] == []     # overlap is not "outside"


def test_ipv6_scopes_are_not_judged_because_only_ipv4_is_observed():
    adv = api.scope_advisories(["fd00:1::/48", "10.20.0.0/24"], [pfx("10.20.0.0/24")], capped=False)
    assert adv["declared_but_unobserved"] == []
    assert any("IPv6" in n for n in adv["notes"])


def test_the_observed_list_is_capped_at_32_and_says_so():
    seen = [pfx(f"10.{i}.0.0/24", 100 - i) for i in range(40)]
    adv = api.scope_advisories([], seen, capped=False)
    assert len(adv["observed"]["prefixes"]) == 32 and adv["observed"]["truncated"] is True
    assert adv["observed"]["prefixes"][0]["prefix"] == "10.0.0.0/24"            # the busiest first


def test_when_the_scan_itself_was_capped_nothing_is_declared_unobserved():
    adv = api.scope_advisories(["10.250.0.0/24"], [pfx("10.1.0.0/24")], capped=True)
    assert adv["declared_but_unobserved"] == [] and adv["observed"]["truncated"] is True
    assert any("too many" in n for n in adv["notes"])


def test_suggestions_merge_to_at_most_16_supernets_never_shorter_than_slash_16():
    # 20 distinct /24s in 20 distinct /16s cannot fit 16 supernets even at /16: the busiest 16 /16s, and it says so
    seen = [pfx(f"10.{i}.1.0/24", 100 - i) for i in range(20)]
    adv = api.scope_advisories([], seen, capped=False)
    assert len(adv["suggested_cidrs"]) == 16
    assert all(int(c.split("/")[1]) >= 16 for c in adv["suggested_cidrs"])
    assert "10.19.0.0/16" not in adv["suggested_cidrs"] and "10.0.0.0/16" in adv["suggested_cidrs"]
    assert any("only the 16 busiest" in n for n in adv["notes"])
    # many /24s of ONE /16 widen to that /16 (never beyond)
    many = [pfx(f"172.16.{i}.0/24") for i in range(0, 200, 3)]
    out = api.scope_advisories([], many, capped=False)["suggested_cidrs"]
    assert out == [f"172.16.{16 * k}.0/20" for k in range(13)]                  # the tightest widening that fits 16
    one16 = [pfx(f"172.16.{i}.0/24") for i in range(0, 256, 5)]               # 52 /24s: /22 -> 52? /20 -> 16 groups
    out = api.scope_advisories([], one16, capped=False)["suggested_cidrs"]
    assert len(out) <= 16 and all(int(c.split("/")[1]) >= 16 for c in out)
    # 512 adjacent /24s collapse exactly, but never into a /15
    adj = [pfx(f"10.{a}.{b}.0/24") for a in (4, 5) for b in range(256)]
    out = api.scope_advisories([], adj, capped=False)["suggested_cidrs"]
    assert out == ["10.4.0.0/16", "10.5.0.0/16"]


def test_suggestions_are_exact_when_few_and_deterministic():
    seen = [pfx("10.20.2.0/24", 3), pfx("10.20.0.0/24", 9), pfx("10.20.3.0/24", 1), pfx("192.168.7.0/24", 2)]
    out = api.scope_advisories([], seen, capped=False)["suggested_cidrs"]
    assert out == ["10.20.0.0/24", "10.20.2.0/23", "192.168.7.0/24"]
    assert api.scope_advisories([], list(reversed(seen)), capped=False)["suggested_cidrs"] == out


def test_the_wide_check_follows_the_contract():
    assert api._wide_cidrs(["10.0.0.0/8", "10.0.0.0/15", "10.0.0.0/16", "10.0.0.0/24", "fd00::/47", "fd00::/48",
                            "2001:db8::/32"]) == ["10.0.0.0/8", "10.0.0.0/15", "fd00::/47", "2001:db8::/32"]


def test_the_wide_check_judges_a_v4_mapped_network_by_its_v4_prefix():
    """The builder (sentry_flows._parse_cidr) reads ::ffff:a.b.c.d/N as the IPv4 network a.b.c.d/(N-96); the guard must
    judge the same thing or a /8 can be declared silently (the verifier's bypass of contract 8.4 #27)."""
    wide = ["::ffff:0.0.0.0/97", "::ffff:10.0.0.0/104", "::ffff:10.0.0.0/105", "::ffff:172.16.0.0/108",
            "::ffff:0:0/96", "::ffff:10.20.0.0/111"]
    assert api._wide_cidrs(wide) == wide
    assert api._wide_cidrs(["::ffff:10.20.0.0/112", "::ffff:10.20.1.0/120", "::ffff:10.20.1.5/128"]) == []
    # ordinary IPv6 is still judged by its own prefix
    assert api._wide_cidrs(["::ffff:0:0/80", "2001:db8::/48"]) == []


def test_a_v4_mapped_scope_is_compared_with_the_observations_as_the_v4_network_it_means():
    out = api.scope_advisories(["::ffff:10.20.0.0/120"], [pfx("10.20.0.0/24", 5), pfx("10.30.0.0/24", 1)], capped=False)
    assert out["observed_outside_scope"] == ["10.30.0.0/24"]                   # 10.20.0.0/24 IS in the declared scope
    assert out["declared_but_unobserved"] == []
    assert not any("IPv6" in n for n in out["notes"])
    out = api.scope_advisories(["::ffff:10.99.0.0/120"], [pfx("10.20.0.0/24", 5)], capped=False)
    assert out["declared_but_unobserved"] == ["10.99.0.0/24"]


# --- API ----------------------------------------------------------------------------------------------------

async def _api_sensor(db_pool, sid=S1, *, online=True, status="active", tenant=A_TENANT):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO sensors (id, tenant_id, name, site, status, cred_prefix, cred_hash, online) "
            "VALUES ($1,$2,$3,'site',$4,$5,'h',$6)", uuid.UUID(sid), uuid.UUID(tenant), f"s-{sid[-1]}", status,
            f"pst_{sid[-8:]}{tenant[-2:]}", online)


def _ago(**kw):
    return dt.datetime.now(UTC) - dt.timedelta(**kw)


async def _scopes(client):
    r = await client.get("/v1/assurance/sensor-scopes")
    assert r.status_code == 200, r.text
    return r.json()


async def test_get_lists_what_each_sensor_actually_saw_in_the_last_7_days(client, db_pool):
    await _api_sensor(db_pool, S1)
    await _api_sensor(db_pool, S2)
    t = A_TENANT
    await _seed_flow(db_pool, t, "10.20.0.5", "10.20.0.9", 443, S1, _ago(hours=1))
    await _seed_flow(db_pool, t, "10.20.0.7", "8.8.8.8", 443, S1, _ago(hours=2))
    await _seed_flow(db_pool, t, "10.30.0.7", "10.30.1.1", 22, S1, _ago(days=6))
    await _seed_flow(db_pool, t, "10.40.0.1", "10.40.0.2", 22, S1, _ago(days=8))          # outside the 7 day window
    await _seed_flow(db_pool, t, "10.50.0.1", "10.50.0.2", 22, S2, _ago(hours=1))         # another sensor
    # rows that must never break the query or show up: not an IPv4 address
    for junk in ("999.1.1.1", "", "fe80::1", "10.0.0.1/8", "not-an-ip", "10.0.0.256", "1.2.3"):
        await _seed_flow(db_pool, t, junk, "10.20.0.9", 80, S1, _ago(hours=1), proto="udp")
    await _seed_scope(db_pool, S1, ["10.20.0.0/24"])
    d = await _scopes(client)
    (s1,) = [i for i in d["items"] if i["sensor_id"] == S1]
    obs = s1["observed"]
    by = {p["prefix"]: p for p in obs["prefixes"]}
    assert set(by) == {"10.20.0.0/24", "8.8.8.0/24", "10.30.0.0/24", "10.30.1.0/24"}
    assert by["10.20.0.0/24"]["flows"] == 9          # 2 real flows + 7 junk-source rows whose dst is here; counted once each
    assert by["10.20.0.0/24"]["private"] is True and by["8.8.8.0/24"]["private"] is False
    assert obs["truncated"] is False and obs["window_days"] == 7
    assert s1["observed_outside_scope"] == ["10.30.0.0/24", "10.30.1.0/24"]
    assert s1["declared_but_unobserved"] == []
    assert s1["suggested_cidrs"] == ["10.20.0.0/24", "10.30.0.0/23"]
    # the sensor without a scope still gets what it saw, so an operator knows what to declare
    (u2,) = [i for i in d["unscoped_sensors"] if i["sensor_id"] == S2]
    assert [p["prefix"] for p in u2["observed"]["prefixes"]] == ["10.50.0.0/24"]
    assert u2["suggested_cidrs"] == ["10.50.0.0/24"]
    assert "10.50.0.0/24" not in {p["prefix"] for p in obs["prefixes"]}          # per sensor, never pooled


async def test_the_observed_prefix_is_the_network_not_a_host_address(client, db_pool):
    """The contract's SQL sketch (`host(set_masklen(ip, 24)) || '/24'`) yields '10.20.0.5/24', a host with mask bits."""
    await _api_sensor(db_pool)
    await _seed_flow(db_pool, A_TENANT, "10.20.0.77", "10.20.0.200", 443, S1, _ago(hours=1))
    d = await _scopes(client)
    (u,) = d["unscoped_sensors"]
    assert [p["prefix"] for p in u["observed"]["prefixes"]] == ["10.20.0.0/24"]


async def test_declared_but_unobserved_and_the_empty_window(client, db_pool):
    await _api_sensor(db_pool)
    await _seed_scope(db_pool, S1, ["10.20.0.0/24", "10.60.0.0/16", "fd00::/48"])
    await _seed_flow(db_pool, A_TENANT, "10.20.0.5", "10.20.0.6", 443, S1, _ago(hours=1))
    (s,) = (await _scopes(client))["items"]
    assert s["declared_but_unobserved"] == ["10.60.0.0/16"]
    assert any("IPv6" in n for n in s["advisory_notes"])
    # no flows at all: every IPv4 declared CIDR is unobserved
    await db_pool.execute("DELETE FROM reach_flow_obs")
    (s,) = (await _scopes(client))["items"]
    assert s["declared_but_unobserved"] == ["10.20.0.0/24", "10.60.0.0/16"] and s["observed"]["prefixes"] == []


async def test_advisories_never_cross_tenants(client, app, app_pool, db_pool):
    app.state.pool = app_pool                                              # the RLS role, as in production
    await _api_sensor(db_pool, S1)
    await tenancy.create_tenant(db_pool, slug="bravo-adv", name="B", tenant_id=TENANT_B)
    await _api_sensor(db_pool, S2, tenant=TENANT_B)
    await _seed_flow(db_pool, TENANT_B, "10.99.0.1", "10.99.0.2", 22, S2, _ago(hours=1))
    await _seed_flow(db_pool, TENANT_B, "10.99.0.1", "10.99.0.2", 22, S1, _ago(hours=1))       # B's flow naming A's sensor id
    d = await _scopes(client)
    assert "10.99.0.0/24" not in _json.dumps(d)


async def test_a_wide_scope_is_refused_unless_justified_and_audited(client, db_pool):
    await _api_sensor(db_pool)
    path = f"/v1/assurance/sensor-scopes/{S1}"
    v0 = (await client.get("/v1/assurance/state")).json()["graph_version"]
    for cidrs in (["10.0.0.0/8"], ["10.20.0.0/24", "172.16.0.0/12"], ["10.0.0.0/15"], ["2001:db8::/32"], ["fd00::/47"]):
        r = await client.put(path, json={"cidrs": cidrs, "justification": "a short one"})
        assert r.status_code == 422, (cidrs, r.text)
        d = r.json()["detail"]
        assert d["error"] == "scope_too_wide" and d["cidrs"] and len(_json.dumps(d)) < 400
        # allow_wide without a 20 character justification is refused as well
        r = await client.put(path, json={"cidrs": cidrs, "justification": "x" * 19, "allow_wide": True})
        assert r.status_code == 422 and r.json()["detail"]["error"] == "scope_too_wide"
        r = await client.put(path, json={"cidrs": cidrs, "justification": "x" * 40, "allow_wide": False})
        assert r.status_code == 422
    assert await db_pool.fetchval("SELECT count(*) FROM sensor_scopes") == 0              # a refused call changed nothing
    assert (await client.get("/v1/assurance/state")).json()["graph_version"] == v0
    assert not await _audit_rows(db_pool, "assurance_sensor_scope_set")
    # the boundary: /16 and /48 are fine without any flag
    assert (await client.put(path, json={"cidrs": ["10.20.0.0/16", "fd00:1::/48"], "justification": "ok"})).status_code == 200
    # with the flag and a real reason it is accepted and the audit row says so
    why = "the whole campus is mirrored on the core switch"
    r = await client.put(path, json={"cidrs": ["10.0.0.0/8"], "justification": why, "allow_wide": True})
    assert r.status_code == 200 and r.json()["scope"]["cidrs"] == ["10.0.0.0/8"]
    audit = (await _audit_rows(db_pool, "assurance_sensor_scope_set"))[-1]
    assert audit["details"]["allow_wide"] is True and audit["details"]["wide_cidrs"] == ["10.0.0.0/8"]
    assert audit["justification"] == why


async def test_allow_wide_is_not_a_blanket_the_default_stays_false_and_is_audited_false(client, db_pool):
    await _api_sensor(db_pool)
    r = await client.put(f"/v1/assurance/sensor-scopes/{S1}", json={"cidrs": ["10.1.0.0/24"], "justification": "span"})
    assert r.status_code == 200
    assert (await _audit_rows(db_pool, "assurance_sensor_scope_set"))[-1]["details"]["wide_cidrs"] == []


async def test_put_warns_about_a_cidr_with_no_flows_and_about_a_sensor_that_cannot_cover(client, db_pool):
    await _api_sensor(db_pool, S1)
    await _api_sensor(db_pool, S2, online=False)
    await _seed_flow(db_pool, A_TENANT, "10.20.0.5", "10.20.0.6", 443, S1, _ago(hours=1))
    r = await client.put(f"/v1/assurance/sensor-scopes/{S1}",
                         json={"cidrs": ["10.20.0.0/24", "10.70.0.0/24"], "justification": "span port 1"})
    assert r.status_code == 200
    w = r.json()["warnings"]
    assert any("10.70.0.0/24" in x and "no flows" in x for x in w) and not any("10.20.0.0/24" in x for x in w)
    assert not any("offline" in x for x in w)
    r = await client.put(f"/v1/assurance/sensor-scopes/{S2}", json={"cidrs": ["10.20.0.0/24"], "justification": "span port 2"})
    assert any("offline" in x for x in r.json()["warnings"])
    async with db_pool.acquire() as con:
        await con.execute("UPDATE sensors SET status = 'revoked' WHERE id = $1", uuid.UUID(S1))
    r = await client.put(f"/v1/assurance/sensor-scopes/{S1}", json={"cidrs": ["10.20.0.0/24"], "justification": "again"})
    assert any("revoked" in x for x in r.json()["warnings"])


async def test_get_sensors_says_which_sensors_have_a_declared_scope(client, db_pool):
    await _api_sensor(db_pool, S1)
    await _api_sensor(db_pool, S2)
    await _seed_scope(db_pool, S1, ["10.20.0.0/24"])
    by = {s["id"]: s for s in (await client.get("/v1/sensors")).json()}
    assert by[S1]["scope_declared"] is True and by[S2]["scope_declared"] is False
    assert (await client.get(f"/v1/sensors/{S1}")).json()["scope_declared"] is True
    assert (await client.get(f"/v1/sensors/{S2}")).json()["scope_declared"] is False
    assert (await client.patch(f"/v1/sensors/{S1}", json={"site": "hq"})).json()["scope_declared"] is True
    assert (await client.patch(f"/v1/sensors/{S2}", json={"site": "hq"})).json()["scope_declared"] is False
    assert (await client.delete(f"/v1/assurance/sensor-scopes/{S1}?justification=removed")).status_code == 200
    assert (await client.get(f"/v1/sensors/{S1}")).json()["scope_declared"] is False
    # a scope with an empty CIDR list covers nothing and is not "declared"
    await db_pool.execute("INSERT INTO sensor_scopes (sensor_id, cidrs, set_by, justification) VALUES ($1, '{}', 't', 't')",
                          uuid.UUID(S2))
    assert (await client.get(f"/v1/sensors/{S2}")).json()["scope_declared"] is False


async def test_scope_declared_does_not_cross_tenants(client, app, app_pool, db_pool):
    app.state.pool = app_pool
    await tenancy.create_tenant(db_pool, slug="bravo-sd", name="B", tenant_id=TENANT_B)
    await _api_sensor(db_pool, S1)
    await _seed_scope(db_pool, S1, ["10.20.0.0/24"], TENANT_B)           # B declared a scope under A's sensor id
    assert (await client.get(f"/v1/sensors/{S1}")).json()["scope_declared"] is False


@pytest.mark.parametrize("cidrs", [["::ffff:0.0.0.0/97"], ["::ffff:10.0.0.0/104"], ["::ffff:10.0.0.0/105"],
                                   ["10.20.0.0/24", "::ffff:172.16.0.0/108"], ["::ffff:0:0/96"]])
async def test_a_v4_mapped_wide_scope_is_refused_like_the_plain_form(client, db_pool, cidrs):
    await _api_sensor(db_pool)
    path = f"/v1/assurance/sensor-scopes/{S1}"
    r = await client.put(path, json={"cidrs": cidrs, "justification": "short"})
    assert r.status_code == 422 and r.json()["detail"]["error"] == "scope_too_wide", r.text
    r = await client.put(path, json={"cidrs": cidrs, "justification": "x" * 19, "allow_wide": True})
    assert r.status_code == 422
    assert await db_pool.fetchval("SELECT count(*) FROM sensor_scopes") == 0
    assert not await _audit_rows(db_pool, "assurance_sensor_scope_set")
    why = "the whole campus is mirrored on the core switch"
    r = await client.put(path, json={"cidrs": cidrs, "justification": why, "allow_wide": True})
    assert r.status_code == 200, r.text
    audit = (await _audit_rows(db_pool, "assurance_sensor_scope_set"))[-1]
    assert audit["details"]["allow_wide"] is True and audit["details"]["wide_cidrs"]       # recorded, not []


async def test_a_narrow_v4_mapped_scope_needs_no_flag(client, db_pool):
    await _api_sensor(db_pool)
    r = await client.put(f"/v1/assurance/sensor-scopes/{S1}",
                         json={"cidrs": ["::ffff:10.20.0.0/120"], "justification": "span"})
    assert r.status_code == 200, r.text


async def test_special_use_prefixes_are_shown_but_never_suggested_or_called_outside_the_scope(client, db_pool):
    await _api_sensor(db_pool)
    t = A_TENANT
    await _seed_flow(db_pool, t, "10.20.0.5", "10.20.0.9", 443, S1, _ago(hours=1))
    for ip in ("0.0.0.0", "127.0.0.1", "255.255.255.255", "169.254.7.7", "224.0.0.251", "240.1.1.1", "100.64.3.3"):
        await _seed_flow(db_pool, t, ip, "10.20.0.9", 80, S1, _ago(hours=1), proto="udp")
    await _seed_scope(db_pool, S1, ["10.20.0.0/24"])
    (s1,) = (await _scopes(client))["items"]
    by = {p["prefix"]: p["private"] for p in s1["observed"]["prefixes"]}
    assert by["10.20.0.0/24"] is True and by["100.64.3.0/24"] is True       # RFC 1918 and shared address space (CGNAT)
    for special in ("0.0.0.0/24", "127.0.0.0/24", "255.255.255.0/24", "169.254.7.0/24", "224.0.0.0/24", "240.1.1.0/24"):
        assert by[special] is False, special                                 # shown, but not a LAN to declare
    assert s1["suggested_cidrs"] == ["10.20.0.0/24", "100.64.3.0/24"]
    assert s1["observed_outside_scope"] == ["100.64.3.0/24"]
