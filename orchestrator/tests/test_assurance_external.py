"""external_exposure builder + the shared IP identity map (docs/ASSURANCE_P1.md 4.2 and section 2).

Pure ``build`` tests need no database. The loader tests run the real SQL on Postgres under tenant
contexts (the non-superuser pool, RLS enforced) and feed ``load`` straight into ``build``.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import json
import random
import uuid
from dataclasses import replace

import pytest

from app import tenancy
from app.assurance import refs
from app.assurance.builders import _ipmap
from app.assurance.builders import external_exposure as ext
from app.assurance.builders.external_exposure import ExternalRows

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 12, 1, 12, 0, tzinfo=UTC)
H = dt.timedelta(hours=1)
MAX_AGE = dt.timedelta(hours=168)

# Globally routable addresses used only as inert strings in fixtures (nothing is ever contacted).
A = "93.184.216.34"
B = "93.184.216.35"
C = "8.8.4.4"
V6 = "2606:4700:4700::1111"
SCOPE = [
    {"id": 1, "kind": "ipv4_cidr", "value": "93.184.216.0/24", "expires_at": None},
    {"id": 2, "kind": "ipv4_cidr", "value": "8.8.4.0/24", "expires_at": None},
    {"id": 3, "kind": "ipv6_cidr", "value": "2606:4700::/32", "expires_at": None},
]


def port(host, p, *, source="port_scan", last=NOW - H, md=None, aid=None, canonical=None):
    return {"id": aid or str(uuid.uuid4()), "canonical": canonical or f"{host}:{p}",
            "value": f"{host}:{p}", "source": source, "confidence": 100, "last_seen": last,
            "metadata": {"port": p, "protocol": "tcp"} if md is None else md,
            "host_asset_id": None}


def scan(target, *, ports="1-65535", finished=NOW - H, failed=False, summary=None, config=None):
    return {"id": str(uuid.uuid4()), "target": target, "started_at": finished - H,
            "finished_at": finished, "config": {"ports": ports} if config is None else config,
            "result_summary": summary or {}, "error": None, "tool_failed": failed}


def cloud(ips_pub=(), ips_priv=(), rtype="instance"):
    return {"id": str(uuid.uuid4()), "kind": "cloud_resource", "value": "arn:x",
            "metadata": {"resource_type": rtype, "public_ips": list(ips_pub),
                         "private_ips": list(ips_priv)}}


def rows(ports=(), scans=(), assets=(), scope=None):
    return ExternalRows(ports=list(ports), scans=list(scans), assets=list(assets),
                        scope=list(SCOPE if scope is None else scope))


def build(r, now=NOW, **kw):
    return ext.build(r, now, max_age=kw.pop("max_age", MAX_AGE), **kw)


def dsts(out):
    return sorted((e.dst_ref, e.proto, e.port_lo) for e in out.edges)


# --------------------------------------------------------------------------- #
# edges
# --------------------------------------------------------------------------- #

def test_public_scoped_port_becomes_an_observed_internet_edge():
    out = build(rows([port(A, 443)]))
    assert out.source == ext.SOURCE == "external_scan"
    assert out.mode == "window" and out.window == MAX_AGE
    (e,) = out.edges
    assert (e.src_ref, e.dst_ref, e.proto, e.port_lo, e.port_hi) == (
        "internet", f"ip:{A}", "tcp", 443, 443)
    assert e.basis == "observed" and e.source == out.source and e.confidence == 100
    assert e.evidence["origin"] == "external_scan" and e.evidence["host"] == A
    assert e.last_seen == NOW - H
    assert {n.ref for n in out.nodes} == {"internet", f"ip:{A}"}
    assert all(refs.is_valid_ref(n.ref) for n in out.nodes)
    assert out.coverage == []                      # a port row alone proves nothing about the rest


def test_private_loopback_cgnat_and_unscoped_hosts_are_dropped():
    wide = SCOPE + [{"id": 9, "kind": "ipv4_cidr", "value": "10.0.0.0/8", "expires_at": None},
                    {"id": 10, "kind": "ipv4_cidr", "value": "100.64.0.0/10", "expires_at": None},
                    {"id": 11, "kind": "ipv4_cidr", "value": "127.0.0.0/8", "expires_at": None}]
    out = build(rows([port("10.1.2.3", 22), port("100.64.1.1", 22), port("127.0.0.1", 22),
                      port("9.9.9.9", 22),            # public but in no scope entry
                      port(A, 22)], scope=wide))
    assert dsts(out) == [(f"ip:{A}", "tcp", 22)]
    assert any("non-public or out-of-scope" in n for n in out.notes)


def test_expired_and_boundary_scope_entries_scope_nothing():
    expired = [{"id": 1, "kind": "ipv4_cidr", "value": "93.184.216.0/24", "expires_at": NOW - H},
               {"id": 2, "kind": "ipv4_cidr", "value": "8.8.4.0/24", "expires_at": NOW},
               {"id": 3, "kind": "ipv4_cidr", "value": "9.9.9.0/24", "expires_at": NOW + H}]
    out = build(rows([port(A, 80), port(C, 80), port("9.9.9.9", 80)], scope=expired))
    assert dsts(out) == [("ip:9.9.9.9", "tcp", 80)]


def test_stale_observations_dropped_and_age_boundary_is_inclusive():
    out = build(rows([port(A, 80, last=NOW - MAX_AGE - dt.timedelta(seconds=1)),
                      port(A, 81, last=NOW - MAX_AGE),
                      port(A, 82, last=NOW - H)]))
    assert [e.port_lo for e in out.edges] == [81, 82]
    assert any("older than the freshness window" in n for n in out.notes)


def test_future_timestamp_is_clamped_not_trusted():
    out = build(rows([port(A, 80, last=NOW + 30 * H)]))
    (e,) = out.edges
    assert e.last_seen == NOW


def test_shodan_gives_edges_with_lower_confidence_but_never_coverage():
    sh = port(A, 3306, source="shodan", md={"ip": A, "port": 3306})
    out = build(rows([sh]))
    (e,) = out.edges
    assert e.source == "external_scan"                       # one source per BuildOutput
    assert e.evidence["origin"] == "shodan_internetdb" and e.confidence == 60
    assert e.proto == "tcp" and e.basis == "observed"
    assert out.coverage == []


def test_scan_and_shodan_on_the_same_port_merge_to_one_edge_keeping_scan_origin():
    out = build(rows([port(A, 443, source="shodan"), port(A, 443, source="port_scan",
                                                           canonical=f"{A}:443")]))
    (e,) = out.edges
    assert e.evidence["origin"] == "external_scan"
    assert e.evidence["origins"] == ["external_scan", "shodan_internetdb"]
    assert e.confidence == 100


def test_protocol_defaults_to_tcp_and_unknown_transport_is_any():
    out = build(rows([port(A, 53, md={"port": 53, "protocol": "udp"}),
                      port(A, 80, md={}),
                      port(A, 132, md={"port": 132, "protocol": "sctp"})]))
    assert dsts(out) == [(f"ip:{A}", "any", 132), (f"ip:{A}", "tcp", 80), (f"ip:{A}", "udp", 53)]
    any_edge = next(e for e in out.edges if e.proto == "any")
    assert "protocol_assumed_any" in any_edge.evidence["assumptions"]


def test_canonical_and_metadata_port_disagreement_keeps_both_ports():
    out = build(rows([port(A, 8080, md={"port": 9090, "protocol": "tcp"})]))
    assert [e.port_lo for e in out.edges] == [8080, 9090]
    assert all("port_mismatch" in e.evidence["assumptions"] for e in out.edges)


def test_unparsable_port_assets_are_skipped_not_fatal():
    bad = [port(A, 80, canonical="not-an-ip:80"), port(A, 80, canonical=f"{A}:70000"),
           port(A, 80, canonical="justahost"), port(A, 80, canonical=f"{A}:0"), port(A, 22)]
    out = build(rows(bad))
    assert dsts(out) == [(f"ip:{A}", "tcp", 22)]
    assert any("unparsable" in n for n in out.notes)


# --------------------------------------------------------------------------- #
# ipv6 (right-anchored port parsing, kind not trusted)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("canonical,expect", [
    ("93.184.216.34:443", ("93.184.216.34", 443)),
    ("2606:4700:4700::1111:443", ("2606:4700:4700::1111", 443)),
    ("[2606:4700:4700::1111]:8443", ("2606:4700:4700::1111", 8443)),
    ("2606:4700:4700:0:0:0:0:1111:22", ("2606:4700:4700::1111", 22)),
    ("::ffff:93.184.216.34:80", ("93.184.216.34", 80)),
    ("2606:4700:4700::1111", None),            # no port: host would be "2606:4700:4700:"
    ("host.example.com:80", None), ("1.2.3.4:", None), ("1.2.3.4:65536", None), ("", None),
])
def test_split_host_port(canonical, expect):
    assert ext.split_host_port(canonical) == expect


def test_ipv6_exposure_edge_and_full_scan_coverage():
    out = build(rows([port(V6, 443, canonical=f"{V6}:443"),
                      port(V6, 22, canonical=f"[{V6}]:22")],
                     scans=[scan(V6)]))
    assert dsts(out) == [(f"ip:{V6}", "tcp", 22), (f"ip:{V6}", "tcp", 443)]
    (c,) = out.coverage
    assert c.node_ref == f"ip:{V6}" and c.direction == "in" and c.tier == "observed"


# --------------------------------------------------------------------------- #
# coverage
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("config", [
    {"ports": "top-100"}, {}, {"ports": "1-1000"}, {"ports": "1-65534"}, {"ports": "2-65535"},
    {"ports": "1-1024,2000-65535"}, {"ports": "u:53"}, {"ports": ""}, {"ports": None},
    {"ports": "0-65535"}, {"ports": "1-65536"}, {"ports": True}, {"ports": "top-1000"},
    {"ports": "1-65535", "exclude_ports": "22"}, {"ports": "1-65535", "exclude-ports": [80]},
    {"top_ports": 100}, {"ports": [80, 443]},
])
def test_partial_or_unprovable_scan_asserts_no_coverage(config):
    out = build(rows([port(A, 80)], scans=[scan(A, config=config)]))
    assert out.coverage == []
    assert dsts(out) == [(f"ip:{A}", "tcp", 80)]          # the observed edge is still there
    assert not ext.scan_covers_all_ports(config)


def test_partial_scan_hosts_are_counted_in_notes():
    out = build(rows(scans=[scan(A, ports="top-100"), scan(B, ports="1-1000"), scan(C)]))
    assert [c.node_ref for c in out.coverage] == [f"ip:{C}"]
    assert any(n.startswith("external_scan: 2 host(s) latest scan covered fewer") for n in out.notes)


@pytest.mark.parametrize("ports", ["1-65535", "full", "FULL", " 1-65535 ", "1-1024,1025-65535",
                                   "1-100,50-65535", [1, "2-65535"], "1,2-65535"])
def test_full_port_scan_gives_inbound_observed_coverage(ports):
    finished = NOW - 3 * H
    out = build(rows([port(A, 443)], scans=[scan(A, ports=ports, finished=finished)]))
    (c,) = out.coverage
    assert (c.node_ref, c.direction, c.tier, c.source) == (f"ip:{A}", "in", "observed", "external_scan")
    assert c.observed_at == finished                       # the scan's finish time, not now
    assert c.detail["ports"] == "1-65535" and c.detail["proto"] == "tcp"


def test_tool_failure_or_scan_error_asserts_no_coverage():
    for s in (scan(A, failed=True), scan(A, summary={"error": "naabu crashed"}),
              scan(A, summary={"tool_failed": True}), {**scan(A), "error": "boom"}):
        out = build(rows(scans=[s]))
        assert out.coverage == []
        assert any("tool failure" in n for n in out.notes)


def test_stale_scan_private_target_hostname_target_and_out_of_scope_give_no_coverage():
    out = build(rows(scans=[scan(A, finished=NOW - MAX_AGE - dt.timedelta(seconds=1)),
                            scan("10.0.0.5"), scan("example.com"), scan("9.9.9.9")]))
    assert out.coverage == []


def test_internet_node_never_gets_coverage_and_covered_host_without_ports_is_a_node():
    out = build(rows(scans=[scan(A)]))
    assert all(c.node_ref != "internet" for c in out.coverage)
    assert [c.node_ref for c in out.coverage] == [f"ip:{A}"]
    assert f"ip:{A}" in {n.ref for n in out.nodes}         # a scanned, closed host is still known
    assert out.edges == []


def test_coverage_for_expired_scope_host_is_dropped():
    expired = [{"id": 1, "kind": "ipv4_cidr", "value": "93.184.216.0/24", "expires_at": NOW - H}]
    assert build(rows(scans=[scan(A)], scope=expired)).coverage == []


# --------------------------------------------------------------------------- #
# identity (cloud assets, multi-IP, ambiguity)
# --------------------------------------------------------------------------- #

def test_public_ip_of_a_cloud_instance_resolves_to_the_asset_for_edges_and_coverage():
    inst = cloud(ips_pub=[A], ips_priv=["10.0.0.5"])
    out = build(rows([port(A, 443)], scans=[scan(A)], assets=[inst]))
    ref = refs.asset_ref(inst["id"])
    assert dsts(out) == [(ref, "tcp", 443)]
    assert [c.node_ref for c in out.coverage] == [ref]
    # the asset node itself is owned by its connector's builder: not re-emitted (would clobber attrs)
    assert {n.ref for n in out.nodes} == {"internet"}


def test_asset_with_two_public_ips_is_covered_only_when_all_are_fully_scanned():
    inst = cloud(ips_pub=[A, B])
    one = build(rows([port(A, 22)], scans=[scan(A)], assets=[inst]))
    assert one.coverage == []
    assert any("several public addresses" in n for n in one.notes)
    both = build(rows([port(A, 22)], assets=[inst],
                      scans=[scan(A, finished=NOW - 2 * H), scan(B, finished=NOW - 5 * H)]))
    (c,) = both.coverage
    assert c.node_ref == refs.asset_ref(inst["id"])
    assert c.observed_at == NOW - 5 * H                    # oldest scan bounds the claim
    partial_b = build(rows(assets=[inst], scans=[scan(A), scan(B, ports="top-100")]))
    assert partial_b.coverage == []


def test_asset_with_a_public_ip_outside_scope_is_not_covered():
    inst = cloud(ips_pub=[A, "9.9.9.9"])                  # 9.9.9.9 is never scanned/in scope
    assert build(rows(assets=[inst], scans=[scan(A)])).coverage == []


def test_ambiguous_public_ip_reaches_every_candidate_and_covers_none():
    a1, a2 = cloud(ips_pub=[A]), cloud(ips_pub=[A])
    out = build(rows([port(A, 5432)], scans=[scan(A)], assets=[a1, a2]))
    want = sorted([refs.asset_ref(a1["id"]), refs.asset_ref(a2["id"]), f"ip:{A}"])
    assert [e.dst_ref for e in out.edges] == want         # nothing is lost by not guessing
    assert all("ambiguous_identity" in e.evidence["assumptions"] for e in out.edges)
    assert out.coverage == []
    assert any("claimed by more than one asset" in n for n in out.notes)


def test_same_private_ip_in_two_vpcs_is_not_merged():
    a1, a2 = cloud(ips_priv=["10.0.0.5"], ips_pub=[A]), cloud(ips_priv=["10.0.0.5"], ips_pub=[B])
    out = build(rows([port(A, 80), port(B, 80)], assets=[a1, a2]))
    # the shared private address must not make A and B the same node
    assert dsts(out) == sorted([(refs.asset_ref(a1["id"]), "tcp", 80),
                                (refs.asset_ref(a2["id"]), "tcp", 80)])
    m = _ipmap.build_ip_map([a1, a2])
    assert m.resolve("10.0.0.5") == "ip:10.0.0.5" and "10.0.0.5" in m.ambiguous


# --------------------------------------------------------------------------- #
# determinism / shape
# --------------------------------------------------------------------------- #

def test_build_is_deterministic_and_input_order_independent():
    inst = cloud(ips_pub=[B])
    ports_ = [port(A, p, aid=f"id-{p}") for p in (22, 80, 443, 8080)] + \
             [port(B, 3306, source="shodan", aid="s1"), port(V6, 22, aid="v6"),
              port(C, 53, md={"protocol": "udp"}, aid="c53")]
    scans_ = [{**s, "id": f"scan-{i}"} for i, s in enumerate(
        [scan(A), scan(B), scan(V6, ports="top-100"), scan(C)])]
    base = build(rows(ports_, scans_, [inst]))
    assert base.coverage and base.edges
    for seed in range(8):
        rnd = random.Random(seed)
        p2, s2, sc2 = ports_[:], scans_[:], SCOPE[:]
        rnd.shuffle(p2), rnd.shuffle(s2), rnd.shuffle(sc2)
        assert build(rows(p2, s2, [inst], scope=sc2)) == base
    assert base.edges == sorted(base.edges, key=lambda e: (e.dst_ref, e.proto, e.port_lo, e.port_hi))
    assert [c.node_ref for c in base.coverage] == sorted(c.node_ref for c in base.coverage)
    assert [n.ref for n in base.nodes] == sorted(n.ref for n in base.nodes)


def test_naive_now_is_treated_as_utc_and_inputs_are_not_mutated():
    r = rows([port(A, 80)], scans=[scan(A)])
    before = json.dumps([r.ports, r.scans], default=str)
    out = ext.build(r, NOW.replace(tzinfo=None), max_age=MAX_AGE)
    assert len(out.edges) == 1 and len(out.coverage) == 1
    assert json.dumps([r.ports, r.scans], default=str) == before


def test_every_edge_is_a_valid_store_row():
    out = build(rows([port(A, 443), port(V6, 22), port(B, 53, md={"protocol": "udp"})]))
    for e in out.edges:
        assert refs.is_valid_ref(e.src_ref) and refs.is_valid_ref(e.dst_ref)
        assert 1 <= e.port_lo == e.port_hi <= 65535 and e.proto in ("tcp", "udp", "any")
        assert e.last_seen.tzinfo is not None and 0 <= e.confidence <= 100
        json.dumps(e.evidence)                             # JSON-serialisable for the jsonb column


# --------------------------------------------------------------------------- #
# _ipmap
# --------------------------------------------------------------------------- #

def test_ipmap_unique_public_and_private_resolve_to_assets():
    inst, db = cloud(["54.1.2.3"], ["10.0.0.5"]), cloud([], ["10.0.9.9"], rtype="db_instance")
    dev = {"id": str(uuid.uuid4()), "kind": "iot_device", "value": "cam", "metadata": {"ips": ["192.168.1.9"]}}
    m = _ipmap.build_ip_map([inst, db, dev])
    assert m.resolve("54.1.2.3") == m.resolve("10.0.0.5") == refs.asset_ref(inst["id"])
    assert m.resolve("10.0.9.9") == refs.asset_ref(db["id"])
    assert m.resolve("192.168.1.9") == refs.asset_ref(dev["id"])
    assert m.resolve("8.8.8.8") == "ip:8.8.8.8"           # unknown -> bare ip
    assert m.node_kind(refs.asset_ref(inst["id"])) == "cloud_instance"
    assert m.node_kind(refs.asset_ref(db["id"])) == "cloud_db"
    assert m.node_kind(refs.asset_ref(dev["id"])) == "device"
    assert m.node_kind("ip:8.8.8.8") == "ip"
    assert _ipmap.resolve(m, "54.1.2.3") == m.resolve("54.1.2.3")


def test_ipmap_ambiguity_is_dropped_reported_and_never_guessed():
    a1, a2, solo = cloud([], ["10.0.0.5"]), cloud([], ["10.0.0.5"]), cloud(["54.9.9.9"], ["10.0.0.6"])
    m = _ipmap.build_ip_map([a1, a2, solo])
    assert m.resolve("10.0.0.5") == "ip:10.0.0.5"
    assert m.unique.get("10.0.0.5") is None
    assert m.ambiguous["10.0.0.5"] == tuple(sorted([refs.asset_ref(a1["id"]), refs.asset_ref(a2["id"])]))
    assert set(m.resolve_all("10.0.0.5")) == {refs.asset_ref(a1["id"]), refs.asset_ref(a2["id"]),
                                              "ip:10.0.0.5"}
    assert m.resolve("10.0.0.6") == refs.asset_ref(solo["id"])    # unaffected neighbours stay merged
    assert m.resolve_all("10.0.0.6") == (refs.asset_ref(solo["id"]),)
    rep = m.report()
    assert rep and "10.0.0.5" in "\n".join(rep)
    assert _ipmap.build_ip_map([cloud([], ["10.0.0.5"])]).report() == []


def test_ipmap_is_order_independent_and_tolerant_of_junk():
    rs = [cloud(["54.1.1.1"], ["10.0.0.1"]), cloud([], ["10.0.0.1"]), cloud(["2001:db8::5"], [])]
    rs.append({"id": str(uuid.uuid4()), "kind": "cloud_resource", "value": "x",
               "metadata": json.dumps({"public_ips": ["999.1.1.1", "not-an-ip", "10.0.0.0/8", 5, None,
                                                      "[2001:db8::7]", "::ffff:1.2.3.4"]})})
    rs.append({"id": "not-a-uuid", "kind": "cloud_resource", "metadata": {"ips": ["1.1.1.1"]}})
    rs.append({"id": str(uuid.uuid4()), "kind": "ipv4", "value": "1.2.3.4", "metadata": {"ips": ["7.7.7.7"]}})
    rs.append({"id": str(uuid.uuid4()), "kind": "cloud_resource", "metadata": "{not json"})
    rs.append({"id": str(uuid.uuid4()), "kind": "cloud_resource", "metadata": ["list"]})
    base = _ipmap.build_ip_map(rs)
    for seed in range(5):
        shuffled = rs[:]
        random.Random(seed).shuffle(shuffled)
        assert _ipmap.build_ip_map(shuffled) == base
    assert base.resolve("2001:db8::7").startswith("asset:")        # bracketed v6 normalised
    assert base.resolve("1.2.3.4").startswith("asset:")            # v4-mapped v6 unwrapped
    assert base.resolve("7.7.7.7") == "ip:7.7.7.7"                 # plain ipv4 assets carry no identity
    assert base.resolve("1.1.1.1") == "ip:1.1.1.1"                 # bad asset id skipped
    with pytest.raises(refs.RefError):
        base.resolve("nope")
    with pytest.raises(refs.RefError):
        base.resolve_all("10.0.0.0/8")


def test_ipmap_caps_ips_per_asset():
    huge = cloud(public_ips := [f"20.{i // 250}.{i % 250}.1" for i in range(1000)])
    m = _ipmap.build_ip_map([huge])
    assert len(m.ips[refs.asset_ref(huge["id"])]) <= 256 and public_ips


@pytest.mark.parametrize("ip,expect", [("8.8.8.8", True), ("10.0.0.1", False), ("127.0.0.1", False),
                                       ("169.254.169.254", False), ("100.64.0.1", False),
                                       ("192.0.2.1", False), ("fe80::1", False), ("::1", False),
                                       ("2606:4700::1", True), ("nope", False)])
def test_is_public_ip(ip, expect):
    assert _ipmap.is_public_ip(ip) is expect


# --------------------------------------------------------------------------- #
# loader against real Postgres, under tenant contexts (RLS enforced)
# --------------------------------------------------------------------------- #

TENANT_A = tenancy.DEFAULT_TENANT_ID
TENANT_B = "00000000-0000-0000-0000-0000000000b3"
DB_NOW = dt.datetime.now(UTC).replace(microsecond=0)


@contextlib.asynccontextmanager
async def conn_for(pool, tid=TENANT_A):
    """Tenancy is set BEFORE acquire, exactly as production does."""
    with tenancy.tenant_context(tid):
        async with pool.acquire() as con:
            yield con


@pytest.fixture
async def tenant_b(db_pool):
    await tenancy.create_tenant(db_pool, slug="extb", name="Ext B", tenant_id=TENANT_B)
    return TENANT_B


async def _asset(con, kind, value, *, source="port_scan", md=None, last=None, canonical=None):
    return await con.fetchval(
        "INSERT INTO assets (kind, value, canonical, source, metadata, last_seen) "
        "VALUES ($1, $2, $3, $4, $5::jsonb, COALESCE($6, NOW())) RETURNING id",
        kind, value, canonical or value.lower(), source, json.dumps(md or {}), last)


async def _scope(con, value, *, kind="ipv4_cidr", active=True, expires=None):
    await con.execute("INSERT INTO scope_entries (kind, value, added_by, active, expires_at) "
                      "VALUES ($1, $2, 'test', $3, $4)", kind, value, active, expires)


async def _scan(con, target, *, kind="port_scan", status="completed", ports="1-65535",
                finished=None, started=None, summary=None, no_ports_key=False):
    fin = finished if finished is not None else DB_NOW - H
    cfg = {} if no_ports_key else {"ports": ports}
    return await con.fetchval(
        "INSERT INTO scans (kind, target, status, started_at, finished_at, config, result_summary) "
        "VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb) RETURNING id",
        kind, target, status, started or fin - H,
        fin if status in ("completed", "failed") else None, json.dumps(cfg), json.dumps(summary or {}))


async def _load_build(pool, tid=TENANT_A):
    async with conn_for(pool, tid) as con:
        r = await ext.load(con, DB_NOW, max_age=MAX_AGE)
    return r, ext.build(r, DB_NOW, max_age=MAX_AGE)


async def test_loader_end_to_end_ports_scope_scans_and_identity(app_pool):
    async with conn_for(app_pool) as con:
        await _scope(con, "93.184.216.0/24")
        await _scope(con, "10.0.0.0/8")                                    # private scope: ignored hosts
        await _scope(con, "8.8.4.0/24", active=False)                      # inactive
        await _scope(con, "9.9.9.0/24", expires=DB_NOW - H)                # expired
        await _scope(con, "2606:4700::/32", kind="ipv6_cidr")
        host = await _asset(con, "ipv4", A, source="port_scan")
        await _asset(con, "port", f"{A}:443", md={"port": 443, "protocol": "tcp"})
        await _asset(con, "port", f"{A}:22", source="shodan", md={"ip": A, "port": 22})
        await _asset(con, "port", f"{A}:9999", last=DB_NOW - 30 * 24 * H)    # stale
        await _asset(con, "port", "10.1.1.1:22")                           # private
        await _asset(con, "port", f"{C}:22")                               # inactive scope
        await _asset(con, "port", "9.9.9.9:22")                            # expired scope
        await _asset(con, "ipv4", V6, source="port_scan")                  # worker labels v6 as ipv4
        await _asset(con, "port", f"{V6}:443", md={"port": 443, "protocol": "tcp"})
        await _asset(con, "port", f"[{V6}]:8443")                          # bracketed spelling
        await _scan(con, A)
        await _scan(con, V6, ports="top-100")
        inst = await _asset(con, "cloud_resource", "arn:aws:ec2:i-1", source="aws",
                            md={"resource_type": "instance", "public_ips": [B], "private_ips": ["10.0.0.5"]})
        await _asset(con, "port", f"{B}:80")
        await _scan(con, B)
    r, out = await _load_build(app_pool)

    by_dst = {(e.dst_ref, e.port_lo): e for e in out.edges}
    assert set(by_dst) == {
        (f"ip:{A}", 22), (f"ip:{A}", 443), (f"ip:{V6}", 443), (f"ip:{V6}", 8443),
        (refs.asset_ref(inst), 80)}
    assert by_dst[(f"ip:{A}", 22)].evidence["origin"] == "shodan_internetdb"
    assert by_dst[(f"ip:{A}", 22)].confidence == 60
    assert by_dst[(f"ip:{A}", 443)].evidence["host_assets"] == [str(host)]   # LEFT JOIN found the host
    assert {c.node_ref for c in out.coverage} == {f"ip:{A}", refs.asset_ref(inst)}   # V6: partial
    assert all(c.direction == "in" and c.tier == "observed" for c in out.coverage)
    assert any("fewer than all 65535" in n for n in out.notes)
    assert out.source == "external_scan" and out.mode == "window"
    assert len(r.assets) == 1 and r.assets[0]["kind"] == "cloud_resource"      # identity rows only
    assert isinstance(r.ports[0]["metadata"], dict)                          # jsonb decoded


async def test_loader_picks_the_latest_completed_scan_per_target(app_pool):
    async with conn_for(app_pool) as con:
        await _scope(con, "93.184.216.0/24")
        await _scan(con, A, ports="1-65535", finished=DB_NOW - 10 * H)         # older, full
        await _scan(con, A, ports="top-100", finished=DB_NOW - 2 * H)          # newer, partial: wins
        await _scan(con, A, status="running", ports="1-65535")                 # not completed
        await _scan(con, A, status="failed", ports="1-65535", finished=DB_NOW - H)
        await _scan(con, B, ports="top-100", finished=DB_NOW - 10 * H)
        await _scan(con, B, ports="1-65535", finished=DB_NOW - 1 * H)          # newer full wins
        await _scan(con, "93.184.216.36", kind="tls_grade")                    # wrong kind
        await _scan(con, "93.184.216.37", no_ports_key=True)                   # worker default: top-100
    r, out = await _load_build(app_pool)
    assert {s["target"] for s in r.scans} == {A, B, "93.184.216.37"}
    assert [c.node_ref for c in out.coverage] == [f"ip:{B}"]
    assert out.coverage[0].observed_at == DB_NOW - H


async def test_loader_tool_failure_finding_blocks_coverage_but_old_failure_does_not(app_pool):
    async with conn_for(app_pool) as con:
        await _scope(con, "93.184.216.0/24")
        a = await _asset(con, "ipv4", A)
        b = await _asset(con, "ipv4", B)
        for aid, rule in ((a, "tool-unavailable-naabu"), (b, "tool-error-naabu")):
            await con.execute(
                "INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description, last_seen) "
                "VALUES ($1, $2, 'policy', 'info', 't', 'd', $3)", aid, rule,
                DB_NOW - H if aid == a else DB_NOW - 100 * H)           # B's failure predates its scan
        await _scan(con, A, finished=DB_NOW - H / 2, started=DB_NOW - 2 * H)
        await _scan(con, B, finished=DB_NOW - H / 2, started=DB_NOW - 2 * H)
    r, out = await _load_build(app_pool)
    flags = {s["target"]: s["tool_failed"] for s in r.scans}
    assert flags == {A: True, B: False}
    assert [c.node_ref for c in out.coverage] == [f"ip:{B}"]


async def test_loader_sees_only_its_own_tenant(app_pool, tenant_b):
    async with conn_for(app_pool, TENANT_A) as con:
        await _scope(con, "93.184.216.0/24")
        await _asset(con, "port", f"{A}:443")
        await _scan(con, A)
        await _asset(con, "cloud_resource", "arn:a", source="aws",
                     md={"resource_type": "instance", "public_ips": [A]})
    async with conn_for(app_pool, TENANT_B) as con:
        await _scope(con, "8.8.4.0/24")
        await _asset(con, "port", f"{C}:53", md={"port": 53, "protocol": "udp"})
        await _scan(con, C)
    ra, oa = await _load_build(app_pool, TENANT_A)
    rb, ob = await _load_build(app_pool, TENANT_B)
    assert {e.dst_ref for e in oa.edges} == {refs.asset_ref(ra.assets[0]["id"])}
    assert [(e.dst_ref, e.proto) for e in ob.edges] == [(f"ip:{C}", "udp")]
    assert [c.node_ref for c in ob.coverage] == [f"ip:{C}"]
    assert not any(A in e.evidence["host"] for e in ob.edges)
    assert len(rb.assets) == 0 and len(ra.assets) == 1 and len(rb.scope) == 1
    # a tenant with nothing sees nothing (and nothing leaks in via the shared default tenant)
    async with conn_for(app_pool, TENANT_B) as con:
        await con.execute("DELETE FROM scope_entries")
    _, empty = await _load_build(app_pool, TENANT_B)
    assert empty.edges == [] and empty.coverage == []


async def test_loader_scope_cutoffs_are_parameters_not_wall_clock(app_pool):
    """``now`` drives expiry, so a replay with a different now sees a different scope."""
    async with conn_for(app_pool) as con:
        await _scope(con, "93.184.216.0/24", expires=DB_NOW + 2 * H)
        await _asset(con, "port", f"{A}:80", last=DB_NOW - 3 * H)
    async with conn_for(app_pool) as con:
        now_ok = await ext.load(con, DB_NOW, max_age=MAX_AGE)
        later = await ext.load(con, DB_NOW + 3 * H, max_age=MAX_AGE)
    assert len(now_ok.scope) == 1 and later.scope == []
    assert len(ext.build(now_ok, DB_NOW, max_age=MAX_AGE).edges) == 1
    assert ext.build(replace(later, scope=[]), DB_NOW + 3 * H, max_age=MAX_AGE).edges == []


def test_default_max_age_comes_from_settings():
    from app.config import settings
    out = ext.build(rows([port(A, 80)]), NOW)
    assert out.window == dt.timedelta(hours=settings.assurance_external_max_age_h)
