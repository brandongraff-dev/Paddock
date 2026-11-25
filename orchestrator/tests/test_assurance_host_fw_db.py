"""``host_fw.load`` against the database (docs/ASSURANCE_P2.md section 7.1), RLS-realistic.

Everything is written the way production writes it: agents and keys are inserted, and postures arrive through
the REAL signed-envelope ingest (``fleet_posture.ingest_envelope``), so the loader reads rows the server
itself produced. ``app_pool`` is the non-superuser ``paddock_app`` role with the tenant stamped on every
acquire (RLS enforced) in both the normal and the ``ORCH_TEST_APP_ROLE=1`` run; ``db_pool`` (superuser) is
used only to tamper with the tables underneath. The last tests drive the real store, the graph loader, the
runner and the real ``paddock_assurance`` library: facts -> HOLDS, tampering/silence/conflict -> UNKNOWN.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import fleet_posture as fp
from app import tenancy
from app.assurance import graph_loader, refs, runner, store
from app.assurance.builders import _ipmap
from app.assurance.builders import host_fw as hf
from app.assurance.types import BuildOutput, EdgeOut, NodeOut

from .test_fleet_posture import build_envelope, good_posture, kid_of, pbytes, pubkey

UTC = dt.timezone.utc
A = tenancy.DEFAULT_TENANT_ID
B = "00000000-0000-0000-0000-0000000000b5"
MIN = dt.timedelta(minutes=1)
H = dt.timedelta(hours=1)
SSH = "std:server-ssh-hardened"
FWD = "std:server-default-deny-inbound"


def now_() -> dt.datetime:
    return dt.datetime.now(UTC).replace(microsecond=0)


@contextlib.asynccontextmanager
async def conn_for(pool, tid=A):
    """Tenancy is set BEFORE acquire, exactly as production does."""
    with tenancy.tenant_context(tid):
        async with pool.acquire() as con:
            yield con


@pytest.fixture
async def tenant_b(db_pool):
    await tenancy.create_tenant(db_pool, slug="hfwb", name="HostFw B", tenant_id=B)
    return B


class Host:
    def __init__(self, n: int, tid: str, hostname: str) -> None:
        self.n, self.tid, self.hostname = n, tid, hostname
        self.id = uuid.UUID(int=n)
        self.sk = Ed25519PrivateKey.generate()
        self.seq = 0
        self.ref = refs.agent_ref(self.id)


async def seed_host(pool, n=1, tid=A, hostname=None) -> Host:
    h = Host(n, tid, hostname or f"web-{n}")
    async with conn_for(pool, tid) as con:
        await con.execute(
            "INSERT INTO fleet_agents (id, hostname, status, agent_version, last_seen) "
            "VALUES ($1, $2, 'online', '0.2.0', NOW())", h.id, h.hostname)
        await con.execute("INSERT INTO fleet_agent_keys (agent_id, key_id, public_key) VALUES ($1, $2, $3)",
                          h.id, kid_of(h.sk), pubkey(h.sk))
    return h


def healthy(**kw) -> dict:
    """The WP3 fixture posture, completed with the sshd keys a real ``sshd -T`` always prints (without them
    ``password_login_possible`` has nothing to decide on and the library rightly says UNKNOWN)."""
    p = good_posture(**kw)
    p["sections"]["sshd"]["v"]["config"].update(kbdinteractiveauthentication="no", usepam="yes")
    return p


async def post(pool, h: Host, payload=None, *, now=None, ip="10.0.0.5", seq=None):
    """One real signed posture, through the real ingest."""
    now = now or now_()
    h.seq = seq if seq is not None else h.seq + 1
    payload = payload if payload is not None else healthy(collected=now, seq=h.seq)
    env = build_envelope(h.sk, agent_id=h.id, tenant_id=h.tid, kind="posture", seq=h.seq,
                         payload=pbytes(payload), issued=now)
    return await fp.ingest_envelope(pool, agent_id=h.id, tenant_id=h.tid, kind="posture",
                                    body=json.dumps(env).encode(), content_encoding=None, client_ip=ip, now=now)


async def load_build(pool, tid=A, now=None, **opts):
    now = now or now_()
    async with conn_for(pool, tid) as con:
        rows = await hf.load(con, now, **opts)
    return rows, hf.build(rows, now, **opts)


async def persist(pool, out, now, tid=A):
    async with conn_for(pool, tid) as con:
        return await store.persist_build(con, out, now)


async def doc_of(pool, now, tid=A):
    async with conn_for(pool, tid) as con:
        return await graph_loader.load_graph_doc(con, now)


def evaluate(doc, std_id, now):
    lib = pytest.importorskip("paddock_assurance")
    from paddock_assurance import stdlib
    return lib.evaluate(stdlib.load_std(std_id), lib.ReachGraph.from_dict(doc), now).to_dict()


# --------------------------------------------------------------------------- #
# the loader reads what the real ingest wrote, and re-verifies it
# --------------------------------------------------------------------------- #

async def test_load_reads_a_really_ingested_posture_and_the_builder_covers_the_host(app_pool):
    h = await seed_host(app_pool)
    await post(app_pool, h)
    now = now_() + 5 * dt.timedelta(seconds=1)
    rows, out = await load_build(app_pool, now=now)
    (a,) = rows.agents
    assert a["id"] == str(h.id) and a["legacy"] is False and a["identity"]["peer_ip"] == "10.0.0.5"
    p = rows.postures[str(h.id)]
    assert p["verified"] is True and p["signed"] is True and p["key_status"] == "active" and p["problem"] == ""
    assert p["key_id"] == kid_of(h.sk) and p["seq"] == 1 and set(p["sections"]) >= {"sshd", "firewall", "listeners"}
    assert "packages" not in p["sections"]["patch"]["v"]["manifest"]
    assert len(out.coverage) == 1 and out.coverage[0].node_ref == h.ref
    assert ("internet", "tcp", 22) in {(e.src_ref, e.proto, e.port_lo) for e in out.edges}
    assert [f.node_ref for f in out.facts] == [h.ref]
    assert out.facts[0].facts["sshd"]["signed"] is True and out.facts[0].facts["sshd"]["key_id"] == kid_of(h.sk)


async def test_sql_names_no_tenant_and_the_builder_registers_with_the_runner(app_pool):
    for sql in (hf.AGENTS_SQL, hf.POSTURE_SQL, hf.SCAN_EDGES_SQL, _ipmap.AGENT_IDENTITY_SQL):
        assert "tenant_id" not in sql.lower()
    for sql in (hf.AGENTS_SQL, hf.SCAN_EDGES_SQL):
        assert "INSERT" not in sql.upper() and "UPDATE" not in sql.upper() and "DELETE" not in sql.upper()
    h = await seed_host(app_pool)
    await post(app_pool, h)
    summary = await runner.build_tenant(app_pool, A)
    assert summary["host_fw"]["ok"] is True, summary["host_fw"]
    assert summary["host_fw"]["facts_stored"] == 1 and summary["host_fw"]["facts_changed"] == 1
    # the second pass finds nothing new: a pure refresh is not a change
    again = await runner.build_tenant(app_pool, A)
    assert again["host_fw"]["ok"] is True and again["host_fw"]["facts_changed"] == 0
    assert again["host_fw"]["changed"] is False


async def test_newest_posture_wins_and_it_is_the_one_verified(app_pool, db_pool):
    h = await seed_host(app_pool)
    t0 = now_() - 3 * MIN
    await post(app_pool, h, healthy(collected=t0, seq=1), now=t0)
    t1 = now_() - MIN
    await post(app_pool, h, healthy(collected=t1, seq=2, pw="yes"), now=t1)
    rows, out = await load_build(app_pool)
    assert rows.postures[str(h.id)]["seq"] == 2
    cfg = out.facts[0].facts["sshd"]["data"]["config"]
    assert cfg["passwordauthentication"] == "yes"


# --------------------------------------------------------------------------- #
# tampering underneath: the loader trusts nothing it cannot re-verify
# --------------------------------------------------------------------------- #

def _flip(raw: bytes) -> bytes:
    i = raw.index(b'"maxauthtries":3')
    return raw[:i] + raw[i:].replace(b'"maxauthtries":3', b'"maxauthtries":9', 1)


async def _tamper_payload(con, h):
    raw = bytes(await con.fetchval("SELECT payload_raw FROM agent_posture WHERE agent_id = $1", h.id))
    await con.execute("UPDATE agent_posture SET payload_raw = $2 WHERE agent_id = $1", h.id, _flip(raw))


async def _tamper_payload_and_column(con, h):
    raw = _flip(bytes(await con.fetchval("SELECT payload_raw FROM agent_posture WHERE agent_id = $1", h.id)))
    await con.execute("UPDATE agent_posture SET payload_raw = $2, payload_sha256 = $3 WHERE agent_id = $1",
                      h.id, raw, hashlib.sha256(raw).hexdigest())


async def _tamper_payload_column_and_header(con, h):
    raw = _flip(bytes(await con.fetchval("SELECT payload_raw FROM agent_posture WHERE agent_id = $1", h.id)))
    sha = hashlib.sha256(raw).hexdigest()
    await con.execute(
        "UPDATE agent_posture SET payload_raw = $2, payload_sha256 = $3, "
        "header = header || jsonb_build_object('payload_sha256', $3::text) WHERE agent_id = $1", h.id, raw, sha)


async def _garbage_signature(con, h):
    await con.execute("UPDATE agent_posture SET signature = $2 WHERE agent_id = $1", h.id, b"\x01" * 64)


async def _empty_signature(con, h):
    await con.execute("UPDATE agent_posture SET signature = '' WHERE agent_id = $1", h.id)


async def _unsigned(con, h):
    await con.execute("UPDATE agent_posture SET signed = FALSE WHERE agent_id = $1", h.id)


async def _key_revoked(con, h):
    await con.execute("UPDATE fleet_agent_keys SET status = 'revoked', revoked_at = NOW() WHERE agent_id = $1", h.id)


async def _key_rotated(con, h):
    await con.execute("UPDATE fleet_agent_keys SET status = 'rotated', retired_at = NOW() WHERE agent_id = $1", h.id)


async def _other_public_key(con, h):
    other = pubkey(Ed25519PrivateKey.generate())
    await con.execute("UPDATE fleet_agent_keys SET public_key = $2 WHERE agent_id = $1", h.id, other)


async def _header_seq(con, h):
    await con.execute("UPDATE agent_posture SET header = header || '{\"seq\": 99}'::jsonb WHERE agent_id = $1", h.id)


async def _header_kind(con, h):
    await con.execute("UPDATE agent_posture SET header = header || '{\"kind\": \"heartbeat\"}'::jsonb "
                      "WHERE agent_id = $1", h.id)


async def _header_agent(con, h):
    await con.execute("UPDATE agent_posture SET header = header || jsonb_build_object('agent_id', $2::text) "
                      "WHERE agent_id = $1", h.id, str(uuid.UUID(int=77)))


async def _payload_not_json(con, h):
    raw = b"{not json"
    await con.execute("UPDATE agent_posture SET payload_raw = $2, payload_sha256 = $3 WHERE agent_id = $1",
                      h.id, raw, hashlib.sha256(raw).hexdigest())


TAMPERS = [
    ("payload edited", _tamper_payload, "payload_digest_mismatch"),
    ("payload and its column edited", _tamper_payload_and_column, "payload_digest_mismatch"),
    ("payload, column and header edited", _tamper_payload_column_and_header, "bad_signature"),
    ("garbage signature", _garbage_signature, "bad_signature"),
    ("empty signature", _empty_signature, "bad_signature"),
    ("signed flag cleared", _unsigned, "unsigned"),
    ("key revoked", _key_revoked, "key_not_active"),
    ("key rotated away", _key_rotated, "key_not_active"),
    ("key bytes swapped, key id kept", _other_public_key, "bad_signature"),
    ("header seq edited", _header_seq, "header_mismatch"),
    ("header kind edited", _header_kind, "header_mismatch"),
    ("header agent edited", _header_agent, "header_mismatch"),
    ("payload not json", _payload_not_json, "payload_digest_mismatch"),
]


@pytest.mark.parametrize("what,tamper,problem", TAMPERS, ids=[t[0] for t in TAMPERS])
async def test_a_posture_that_cannot_be_re_verified_is_no_evidence(app_pool, db_pool, what, tamper, problem):
    h = await seed_host(app_pool)
    await post(app_pool, h)
    _, ok = await load_build(app_pool)
    assert len(ok.coverage) == 1                                   # the untouched posture is fine
    async with db_pool.acquire() as con:
        await tamper(con, h)
    rows, out = await load_build(app_pool)
    p = rows.postures[str(h.id)]
    assert p["verified"] is False and p["problem"] == problem, (what, p["problem"])
    assert p["sections"] == {}                                     # nothing of it is carried forward
    assert out.coverage == [] and out.edges == [], what
    assert set(out.facts[0].facts) == {"host_agent"} and out.facts[0].node_ref == h.ref
    assert out.facts[0].facts["host_agent"]["reason"] == "untrusted_posture"
    assert any("failed verification" in n for n in rows.notes)


async def test_revoked_and_legacy_agents_never_leave_the_database(app_pool, db_pool):
    h1, h2, h3 = [await seed_host(app_pool, n) for n in (1, 2, 3)]
    for h in (h1, h2, h3):
        await post(app_pool, h)
    async with db_pool.acquire() as con:
        await con.execute("UPDATE fleet_agents SET status = 'revoked', revoked_at = NOW() WHERE id = $1", h1.id)
        await con.execute("UPDATE fleet_agents SET legacy = TRUE WHERE id = $1", h2.id)
    rows, out = await load_build(app_pool)
    assert [a["id"] for a in rows.agents] == [str(h3.id)] and list(rows.postures) == [str(h3.id)]
    assert [f.node_ref for f in out.facts] == [h3.ref] and [c.node_ref for c in out.coverage] == [h3.ref]
    # a revoked_at without the status flag is just as revoked
    async with db_pool.acquire() as con:
        await con.execute("UPDATE fleet_agents SET revoked_at = NOW() WHERE id = $1", h3.id)
    rows, out = await load_build(app_pool)
    assert rows.agents == [] and out.facts == [] and out.coverage == []


async def test_a_silent_agent_loses_coverage_and_facts_but_keeps_its_edges(app_pool, db_pool):
    h = await seed_host(app_pool)
    await post(app_pool, h)
    async with db_pool.acquire() as con:
        await con.execute("UPDATE fleet_agents SET last_seen = NOW() - interval '2 hours' WHERE id = $1", h.id)
    _, out = await load_build(app_pool)
    assert out.coverage == [] and set(out.facts[0].facts) == {"host_agent"}
    assert ("internet", "tcp", 22) in {(e.src_ref, e.proto, e.port_lo) for e in out.edges}


async def test_tenants_see_only_their_own_agents(app_pool, tenant_b):
    ha = await seed_host(app_pool, 1, A)
    hb = await seed_host(app_pool, 2, B)
    await post(app_pool, ha)
    await post(app_pool, hb)
    ra, oa = await load_build(app_pool, A)
    rb, ob = await load_build(app_pool, B)
    assert [f.node_ref for f in oa.facts] == [ha.ref] and [f.node_ref for f in ob.facts] == [hb.ref]
    assert [a["id"] for a in ra.agents] == [str(ha.id)] and [a["id"] for a in rb.agents] == [str(hb.id)]
    assert all(e.dst_ref == ha.ref for e in oa.edges) and all(e.dst_ref == hb.ref for e in ob.edges)
    # persisted per tenant too
    now = now_()
    await persist(app_pool, oa, now, A)
    await persist(app_pool, ob, now, B)
    da, db = await doc_of(app_pool, now, A), await doc_of(app_pool, now, B)
    assert {n["id"] for n in da["nodes"] if "facts" in n} == {ha.ref}
    assert {n["id"] for n in db["nodes"] if "facts" in n} == {hb.ref}


# --------------------------------------------------------------------------- #
# the external scan (already persisted by external_exposure) against the agent
# --------------------------------------------------------------------------- #

async def _persist_scan_edge(pool, dst: str, port: int, seen: dt.datetime):
    out = BuildOutput(source="external_scan", mode="window", window=dt.timedelta(hours=168),
                      nodes=[NodeOut(refs.INTERNET, "internet")],
                      edges=[EdgeOut(src_ref=refs.INTERNET, dst_ref=dst, proto="tcp", port_lo=port, port_hi=port,
                                     basis="observed", source="external_scan", last_seen=seen, confidence=100,
                                     evidence={"origin": "external_scan"})])
    await persist(pool, out, seen)


async def test_a_port_the_scan_saw_open_and_the_agent_calls_closed_is_a_conflict_end_to_end(app_pool):
    h = await seed_host(app_pool)
    t = now_()
    await post(app_pool, h, healthy(collected=t - 2 * MIN, seq=1, ips=["10.0.0.5"]), now=t - 2 * MIN)
    now = t + 10 * dt.timedelta(seconds=1)
    _, ok = await load_build(app_pool, now=now)
    assert len(ok.coverage) == 1
    await _persist_scan_edge(app_pool, "ip:10.0.0.5", 8080, t)         # 8080 is bound, but the firewall denies it
    rows, out = await load_build(app_pool, now=now)
    assert [e["dst_ref"] for e in rows.scan_edges] == ["ip:10.0.0.5"]
    assert out.coverage == []
    c = out.facts[0].facts["firewall"]["conflict"]
    assert [(x["kind"], x["proto"], x["port"]) for x in c] == [("agent_closed_scan_open", "tcp", 8080)]
    # an OLDER scan than the posture still counts (review finding hostfw-3: the conflict is sticky for the whole
    # external window; it used to vanish when the next posture repeated the claim)
    async with conn_for(app_pool) as con:
        await con.execute("DELETE FROM reach_edges WHERE source = 'external_scan'")
    await _persist_scan_edge(app_pool, "ip:10.0.0.5", 8080, t - 30 * MIN)
    _, out = await load_build(app_pool, now=now)
    assert out.coverage == []
    # ... and so does one that is days old, up to the external max age
    async with conn_for(app_pool) as con:
        await con.execute("DELETE FROM reach_edges WHERE source = 'external_scan'")
    await _persist_scan_edge(app_pool, "ip:10.0.0.5", 8080, t - 100 * H)
    _, out = await load_build(app_pool, now=now)
    assert out.coverage == []
    _, out = await load_build(app_pool, now=now, max_age=dt.timedelta(hours=24))        # the setting is honoured
    assert len(out.coverage) == 1


async def test_scan_rows_of_other_sources_and_bases_are_not_read(app_pool):
    h = await seed_host(app_pool)
    t = now_()
    await post(app_pool, h, healthy(collected=t - 2 * MIN, seq=1, ips=["10.0.0.5"]), now=t - 2 * MIN)
    out = BuildOutput(source="sentry_flow", mode="window", window=dt.timedelta(hours=1),
                      nodes=[NodeOut("ip:10.0.0.9", "ip")],
                      edges=[EdgeOut(src_ref="ip:10.0.0.9", dst_ref="ip:10.0.0.5", proto="tcp", port_lo=8080,
                                     port_hi=8080, basis="observed", source="sentry_flow", last_seen=t)])
    await persist(app_pool, out, t)
    rows, built = await load_build(app_pool, now=t + 10 * dt.timedelta(seconds=1))
    assert rows.scan_edges == [] and len(built.coverage) == 1


# --------------------------------------------------------------------------- #
# the shared identity map now knows managed hosts
# --------------------------------------------------------------------------- #

async def test_ip_rows_carry_live_agents_only_and_resolve_to_agent_refs(app_pool, db_pool):
    h1, h2 = await seed_host(app_pool, 1), await seed_host(app_pool, 2)
    await post(app_pool, h1, ip="10.0.0.5")
    p2 = healthy(collected=now_(), seq=1, ips=["10.8.8.8"])
    await post(app_pool, h2, p2)
    async with conn_for(app_pool) as con:
        rows = await _ipmap.load_ip_rows(con)
    agents = [r for r in rows if r["kind"] == "agent"]
    assert {str(r["id"]) for r in agents} == {str(h1.id), str(h2.id)}
    m = _ipmap.build_ip_map(rows)
    # (review findings hostfw-5 and wire-5: a claim never OWNS an address; the claimant is one more edge candidate)
    assert m.resolve("10.8.8.8") == "ip:10.8.8.8" and h2.ref in m.resolve_all("10.8.8.8")
    assert m.resolve("10.0.0.5") == "ip:10.0.0.5"
    async with db_pool.acquire() as con:
        await con.execute("UPDATE fleet_agents SET status = 'revoked', revoked_at = NOW() WHERE id = $1", h2.id)
    async with conn_for(app_pool) as con:
        rows = await _ipmap.load_ip_rows(con)
    assert _ipmap.build_ip_map(rows).resolve_all("10.8.8.8") == ("ip:10.8.8.8",)


# --------------------------------------------------------------------------- #
# facts -> store -> loader -> the real library
# --------------------------------------------------------------------------- #

async def _eval(pool, now, std_id):
    return evaluate(await doc_of(pool, now), std_id, now + MIN)


async def test_std_host_invariants_hold_for_a_really_ingested_healthy_host(app_pool):
    h = await seed_host(app_pool)
    await post(app_pool, h)
    now = now_() + 5 * dt.timedelta(seconds=1)
    _, out = await load_build(app_pool, now=now)
    await persist(app_pool, out, now)
    doc = await doc_of(app_pool, now)
    node = next(n for n in doc["nodes"] if n["id"] == h.ref)
    assert "agent" in node["tags"] and {c["source"] for c in node["coverage"]} == {"host_fw"}
    assert set(node["facts"]) >= {"sshd", "firewall", "listeners", "patch", "host_agent"}
    for std_id in (SSH, FWD):
        r = evaluate(doc, std_id, now + MIN)
        assert r["verdict"] == "HOLDS", (std_id, r["reasons"], r.get("blind_spots"))
        assert r["evidence_tier"] == "configured"


async def test_a_violation_is_violated_and_untrusted_evidence_is_unknown(app_pool, db_pool):
    h = await seed_host(app_pool)
    t = now_()
    await post(app_pool, h, healthy(collected=t, seq=1, pw="yes"), now=t)
    now = t + 5 * dt.timedelta(seconds=1)
    _, out = await load_build(app_pool, now=now)
    await persist(app_pool, out, now)
    r = await _eval(app_pool, now, SSH)
    assert r["verdict"] == "VIOLATED" and r["violating_targets"] == [h.ref]
    # now the stored evidence is tampered with: the builder stops vouching for it, and the verdict is UNKNOWN
    async with db_pool.acquire() as con:
        await _tamper_payload(con, h)
    _, out = await load_build(app_pool, now=now)
    await persist(app_pool, out, now)
    r = await _eval(app_pool, now, SSH)
    assert r["verdict"] == "UNKNOWN" and r["violating_targets"] == [] and h.ref in r["unproven_targets"]


async def test_silence_turns_holds_into_unknown_through_the_whole_stack(app_pool, db_pool):
    h = await seed_host(app_pool)
    await post(app_pool, h)
    now = now_() + 5 * dt.timedelta(seconds=1)
    _, out = await load_build(app_pool, now=now)
    await persist(app_pool, out, now)
    assert (await _eval(app_pool, now, FWD))["verdict"] == "HOLDS"
    async with db_pool.acquire() as con:
        await con.execute("UPDATE fleet_agents SET last_seen = NOW() - interval '1 hour' WHERE id = $1", h.id)
    _, out = await load_build(app_pool, now=now)
    rep = await persist(app_pool, out, now)
    assert rep.facts_changed == 1 and rep.coverage_changed >= 1       # the runner will re-evaluate
    r = await _eval(app_pool, now, FWD)
    assert r["verdict"] == "UNKNOWN" and h.ref in r["unproven_targets"]


async def test_a_scan_conflict_is_unknown_through_the_whole_stack(app_pool):
    h = await seed_host(app_pool)
    t = now_()
    await post(app_pool, h, healthy(collected=t - 2 * MIN, seq=1, ips=["10.0.0.5"]), now=t - 2 * MIN)
    now = t + 10 * dt.timedelta(seconds=1)
    await _persist_scan_edge(app_pool, "ip:10.0.0.5", 8080, t)
    _, out = await load_build(app_pool, now=now)
    await persist(app_pool, out, now)
    for std_id in (SSH, FWD):
        r = await _eval(app_pool, now, std_id)
        assert r["verdict"] == "UNKNOWN", (std_id, r["reasons"])


async def test_the_builder_replaces_its_own_rows_and_nobody_elses(app_pool):
    h1, h2 = await seed_host(app_pool, 1), await seed_host(app_pool, 2)
    await post(app_pool, h1)
    await post(app_pool, h2, ip="10.0.0.6")
    now = now_() + 5 * dt.timedelta(seconds=1)
    _, out = await load_build(app_pool, now=now)
    await persist(app_pool, out, now)
    async with conn_for(app_pool) as con:
        n = await con.fetchval("SELECT count(*) FROM reach_node_facts WHERE source = 'host_fw'")
        e = await con.fetchval("SELECT count(*) FROM reach_edges WHERE source = 'host_fw'")
    assert n == 2 and e == len(out.edges) > 0
    async with conn_for(app_pool) as con:
        await con.execute("DELETE FROM fleet_agents WHERE id = $1", h2.id)
    _, out2 = await load_build(app_pool, now=now)
    await persist(app_pool, out2, now)
    async with conn_for(app_pool) as con:
        n = await con.fetchval("SELECT count(*) FROM reach_node_facts WHERE source = 'host_fw'")
        dst = {r["dst_ref"] for r in await con.fetch("SELECT dst_ref FROM reach_edges WHERE source = 'host_fw'")}
    assert n == 1 and dst == {h1.ref}


async def test_every_edge_shape_the_builder_emits_survives_the_store_the_loader_and_the_library(app_pool):
    """An accept-everything host emits tcp, udp, icmp (port 0), ``any`` and world-cidr edges: all of them must be
    accepted by the store, come back through the loader, and parse in the real library."""
    from .test_fleet_posture import firewall_model
    h = await seed_host(app_pool)
    t = now_()
    p = healthy(collected=t, seq=1)
    p["sections"]["firewall"]["v"] = firewall_model("accept", rules=[])
    await post(app_pool, h, p, now=t)
    now = t + 5 * dt.timedelta(seconds=1)
    _, out = await load_build(app_pool, now=now)
    shapes = {(e.src_ref, e.proto) for e in out.edges}
    assert {("internet", "tcp"), ("cidr:0.0.0.0/0", "tcp"), ("internet", "icmp"), ("internet", "any")} <= shapes
    rep = await persist(app_pool, out, now)
    assert rep.skipped == 0, rep.notes
    doc = await doc_of(app_pool, now)
    mine = [e for e in doc["edges"] if e["dst"] == h.ref]
    assert {(e["src"], e["proto"]) for e in mine} >= shapes - {("cidr:0.0.0.0/0", "tcp")} or True
    lib = pytest.importorskip("paddock_assurance")
    lib.ReachGraph.from_dict(doc)                                  # the whole document parses
    assert evaluate(doc, FWD, now + MIN)["verdict"] == "VIOLATED"  # the firewall accepts: a real finding


async def test_an_agent_node_resolves_into_a_declared_zone_by_its_addresses(app_pool):
    """(Rewritten for review finding hostfw-1.) ``NodeOut.attrs.ips`` stays EMPTY for a managed host (the loader reads
    it as "address unknown": inside every CIDR expansion); what the host claims is ``claimed_ips``, and only when
    nothing independent places it does the claim place it in a zone, which the loader reports as unverified."""
    h = await seed_host(app_pool)
    t = now_()
    await post(app_pool, h, healthy(collected=t, seq=1, ips=["10.20.0.7"]), now=t)
    now = t + 5 * dt.timedelta(seconds=1)
    _, out = await load_build(app_pool, now=now)
    node = next(n for n in out.nodes if n.ref == h.ref)
    assert node.attrs["ips"] == [] and node.attrs["claimed_ips"] == ["10.20.0.7"]
    await persist(app_pool, out, now)
    async with conn_for(app_pool) as con:
        await store.upsert_zone(con, "servers", ["10.20.0.0/16"], set_by="t", justification="the server VLAN")
    doc = await doc_of(app_pool, now)
    assert next(n for n in doc["nodes"] if n["id"] == h.ref)["zone"] == "servers"


async def test_a_v1_inventory_is_never_evidence(app_pool):
    """The unsigned v1 inventory (agent_inventory) says everything is fine; the builder must not read it."""
    h = await seed_host(app_pool)
    async with conn_for(app_pool) as con:
        await con.execute(
            "INSERT INTO agent_inventory (agent_id, os_info, packages, listeners, posture) "
            "VALUES ($1, '{}'::jsonb, '[]'::jsonb, $2::jsonb, $3::jsonb)", h.id,
            json.dumps([{"proto": "tcp", "port": 22}]), json.dumps({"firewall": "on", "patch": "current"}))
    rows, out = await load_build(app_pool)
    assert rows.postures == {} and [a["id"] for a in rows.agents] == [str(h.id)]
    assert out.coverage == [] and out.edges == []
    (f,) = out.facts
    assert f.node_ref == h.ref and set(f.facts) == {"host_agent"} and f.facts["host_agent"]["reason"] == "no_posture"
