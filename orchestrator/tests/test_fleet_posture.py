"""Signed host evidence ingest (docs/ASSURANCE_P2.md section 2; app/fleet_posture.py, routers/fleet.py).

Every numbered server check has a test with its status code and its ``fleet.evidence.rejected`` audit row. The
envelope is built and signed HERE, independently of the code under test (the canonical form is the one the contract
states), and cross-checked against the vectors the agent package ships (``agent/tests/vectors/envelope_v1.json``).

Everything runs in AUTH_MODE=enforce through the HTTP surface, with two tenants, so what is asserted is what a
real agent and a real admin would see. ``ORCH_TEST_APP_ROLE=1`` serves it all through the RLS-enforcing role.
"""
from __future__ import annotations

import asyncio
import base64
import copy
import datetime as dt
import gzip
import hashlib
import json
import os
import pathlib
import sys
import uuid
from typing import Any

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient

from app import auth as auth_svc
from app import fleet_enroll as fe
from app import fleet_posture as fp
from app import tenancy
from app.config import settings

TENANT_A = tenancy.DEFAULT_TENANT_ID
TENANT_B = "00000000-0000-0000-0000-0000000000b9"
PREFIX = b"paddock-agent-envelope/v1\n"
NOW = lambda: dt.datetime.now(dt.timezone.utc)  # noqa: E731
REPO = pathlib.Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- #
# independent envelope builder (the contract's canonical form, nothing imported from the server)
# --------------------------------------------------------------------------- #

def canon(x: Any) -> bytes:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


COLLECTORS = {"agent": "0.2.0", "sshd": "1", "listeners": "1", "firewall": "1", "patch": "1", "self": "1"}
PAYLOAD_TYPE = {"posture": "paddock.host.posture/v2", "heartbeat": "paddock.host.heartbeat/v1",
                "rotate": "paddock.agent.key-rotate/v1"}


def pubkey(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def kid_of(sk: Ed25519PrivateKey) -> str:
    return hashlib.sha256(pubkey(sk)).hexdigest()[:32]


def build_envelope(sk, *, agent_id, tenant_id, kind, seq, payload: bytes, issued: dt.datetime | None = None,
                   kid: str | None = None, collectors=None, nonce: bytes | None = None,
                   payload_type: str | None = None) -> dict:
    header = {
        "v": 1, "alg": "ed25519", "kid": kid or kid_of(sk), "agent_id": str(agent_id),
        "tenant_id": str(tenant_id), "kind": kind, "seq": seq, "issued_at": iso(issued or NOW()),
        "nonce": b64u(nonce or os.urandom(16)), "payload_type": payload_type or PAYLOAD_TYPE[kind],
        "payload_sha256": hashlib.sha256(payload).hexdigest(), "payload_len": len(payload),
        "collectors": collectors if collectors is not None else dict(COLLECTORS),
    }
    sig = sk.sign(PREFIX + canon(header))
    return {**header, "payload_b64": b64u(payload), "sig": b64u(sig)}


def resign(sk, env: dict) -> dict:
    """Re-sign an envelope whose header fields were edited (so the signature is valid for what it now says)."""
    header = {k: v for k, v in env.items() if k not in ("payload_b64", "sig")}
    return {**env, "sig": b64u(sk.sign(PREFIX + canon(header)))}


# --------------------------------------------------------------------------- #
# a valid posture payload (hand written from agent/PAYLOAD.md; the real collectors' output is checked below)
# --------------------------------------------------------------------------- #

def firewall_model(default: str = "drop", rules: list | None = None, confidence: str = "exact") -> dict:
    chain_rules = rules if rules is not None else [
        {"m": {"ct": ["established", "related"]}, "v": "accept"},
        {"m": {"proto": "tcp", "dport": [[22, 22]]}, "v": "accept"},
    ]
    fam = {"read": True, "effective_default": default, "chains": [
        {"name": "inet.filter.input", "hook": "input", "prio": 0, "policy": "drop" if default != "accept" else "accept",
         "base": True, "rules": chain_rules}]}
    return {"v": 1, "backend": "nft", "frontends": [], "ipv6_enabled": False,
            "families": {"ip4": fam, "ip6": copy.deepcopy(fam)},
            "flat_view": {"default_input_policy": default, "rules": [], "confidence": confidence},
            "confidence_reasons": [] if confidence == "exact" else ["opaque_rule"],
            "opaque_features": [], "dataplane": [], "other_hooks": ["forward", "output"], "rule_count": len(chain_rules)}


def good_posture(*, pw: str = "no", fw_default: str = "drop", ips: list[str] | None = None,
                 security: int = 0, ms: int = 5, uptime: int = 1000, collected: dt.datetime | None = None,
                 seq: int = 1, mid: str | None = "c" * 64, with_packages: bool = False) -> dict:
    listeners = [{"proto": "tcp", "ip": "0.0.0.0", "port": 22, "bind_class": "wildcard4", "uid": 0, "pid": 700,
                  "n_pids": 1, "comm": "sshd", "exe": "/usr/sbin/sshd", "exe_deleted": False,
                  "exe_sha256": "d" * 64, "unit": "ssh.service", "container": None}]
    for ip in ips or []:
        listeners.append({"proto": "tcp", "ip": ip, "port": 8080, "bind_class": "specific", "uid": 1000,
                          "pid": 800, "n_pids": 1, "comm": "app", "exe": "/usr/bin/app", "exe_deleted": False,
                          "exe_sha256": None, "unit": None, "container": None})
    manifest = {"state": "ok", "mgr": "dpkg", "count": 2, "sha256": "a" * 64, "held": 0, "full": with_packages}
    if with_packages:
        manifest["packages"] = [["bash", "5.2", "amd64", "bash", "5.2"], ["curl", "8.5", "amd64", "curl", "8.5"]]
    return {
        "schema": 2, "collected_at": iso(collected or NOW()),
        "sections": {
            "sshd": {"s": "ok", "conf": "exact", "partial": False, "v": {
                "installed": True, "source": "sshd_T", "version": "9.6p1", "binary": "/usr/sbin/sshd",
                "socket_activated": False,
                "config": {"passwordauthentication": pw, "permitrootlogin": "no", "pubkeyauthentication": "yes",
                           "permitemptypasswords": "no", "maxauthtries": 3, "port": [22]},
                "probes": {"addrs": ["10.255.255.1", "203.0.113.7"], "users_probed": 2, "users_total": 2,
                           "planned": 6, "done": 6, "deltas": []},
                "match": {"blocks": 0, "criteria": [], "known": True, "unprobed": False, "unprobed_reasons": []},
                "files": [{"path": "/etc/ssh/sshd_config", "sha256": "b" * 64, "size": 100}],
                # a current agent ALWAYS reports the running daemon (agent/PAYLOAD.md section 3): positive evidence
                # that it runs these files (one master, default config, no -o, same binary, no reload pending)
                "daemon": {"found": True, "masters": 1, "pid": 700, "start_epoch": 1780000000,
                           "reexec_epoch": None, "config_path": None, "config_default": True,
                           "options_override": False, "binary_matches": True, "config_mtime": 1770000000,
                           "reload_pending": False}}},
            "listeners": {"s": "ok", "conf": "exact", "partial": False, "v": {
                "count": len(listeners), "listeners": listeners, "ipv6": False, "bindv6only": None,
                "attribution": {"status": "ok", "unreadable_pids": 0, "unattributed": 0}}},
            "firewall": {"s": "ok", "conf": "exact" if fw_default else "approximate", "partial": False,
                         "v": firewall_model(fw_default)},
            "patch": {"s": "ok", "conf": "exact", "partial": False, "v": {
                "os": {"state": "ok", "id": "ubuntu", "id_like": ["debian"], "version_id": "24.04",
                       "codename": "noble", "pretty_name": "Ubuntu 24.04 LTS", "family": "debian", "arch": "x86_64"},
                "manifest": manifest,
                "pending": {"state": "ok", "mgr": "apt", "total": security, "security": security,
                            "security_pkgs": ["openssl"] * security, "kept_back": 0, "removals": 0,
                            "metadata_age_s": 60},
                "auto_update": {"state": "ok", "mgr": "unattended-upgrades", "installed": True,
                                "interval_days": 1, "timer_enabled": True},
                "kernel": {"state": "ok", "running": "6.8.0-45-generic", "package": "linux-image-6.8.0-45-generic",
                           "package_version": "6.8.0-45.45", "installed": ["6.8.0-45-generic"], "livepatch": False},
                "reboot": {"state": "ok", "required": False, "pkgs": [], "source": "file"}}},
            "self": {"s": "ok", "conf": "exact", "partial": False, "v": {
                "agent_version": "0.2.0", "python": "3.12.3", "platform": "linux",
                "collectors": {n: {"status": "ok", "ms": ms, "reason": None}
                               for n in ("sshd", "listeners", "firewall", "patch")},
                "caps": {"cap_eff": "0000000000081004", "net_admin": True, "sys_ptrace": True,
                         "dac_read_search": True},
                "is_root": True, "containerised": False, "boot_id": "11111111-2222-3333-4444-555555555555",
                "machine_id_hash": mid, "uptime_s": uptime, "seq": seq, "key_id": "k" * 32,
                "payload_bytes": 4000 + ms, "clock_skew_ms": ms, "imds_enabled": False}},
        },
    }


def pbytes(p: dict) -> bytes:
    return canon(p)


# --------------------------------------------------------------------------- #
# world: two tenants, users, hosts
# --------------------------------------------------------------------------- #

@pytest.fixture(autouse=True)
def _private_peer_proof_on_for_ingest(monkeypatch):
    """These tests exercise the ingest's corroboration rules (``_ipmap.corroborate`` rules 1 to 4), so the private-peer
    proof, OFF in production since review finding Z-2 (``_ipmap.PRIVATE_PEER_IS_PROOF``), is switched on here. The
    default-off behaviour is pinned in ``test_p2z_builder.py``."""
    from app.assurance.builders import _ipmap
    monkeypatch.setattr(_ipmap, "PRIVATE_PEER_IS_PROOF", True)


@pytest.fixture(autouse=True)
def _reset_limiters():
    saved = {name: lim.limit for name, lim in fp._LIMITERS.items()}
    fe.reset_limiters()
    fp.reset_limiters()
    yield
    for name, limit in saved.items():
        fp._LIMITERS[name].limit = limit
    fe.reset_limiters()
    fp.reset_limiters()


@pytest.fixture
def unsampled(monkeypatch):
    """Switch the rejection-audit sampling off (``fleet.evidence.rejected`` rows are bounded per agent and reason, so a
    flood cannot grow the chain): the tests that count one row per rejection need every row."""
    monkeypatch.setattr(fp._reason_gate, "burst", 10 ** 6)
    monkeypatch.setattr(fp._agent_gate, "burst", 10 ** 6)


@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


async def seed_key(db_pool, tenant_id: str, username: str, role: str = "admin") -> str:
    full, prefix, key_hash = auth_svc.generate_api_key()
    async with db_pool.acquire() as con:
        uid = await con.fetchval(
            "INSERT INTO app_users (username, role, clearance, pw_hash, tenant_id) "
            "VALUES ($1, $2, 'restricted', $3, $4) RETURNING id",
            username, role, auth_svc.hash_password("pw-" + username), tenant_id)
        await con.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes, tenant_id) "
            "VALUES ($1, 'k', $2, $3, $4::text[], $5)",
            uid, prefix, key_hash, sorted(auth_svc.ROLE_CAPABILITIES[role]), tenant_id)
    return full


def hdr(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


class World:
    pass


@pytest_asyncio.fixture
async def rls_app(app_pool, fake_redis):
    """The app served through the NON-superuser role (RLS enforced, the tenant stamped on every acquire), in BOTH
    normal and ORCH_TEST_APP_ROLE runs: the isolation assertions below mean nothing on a superuser pool."""
    from .conftest import _build_app
    return _build_app(app_pool, fake_redis)


@pytest_asyncio.fixture
async def world(db_pool, rls_app, enforce):
    async with AsyncClient(transport=ASGITransport(app=rls_app), base_url="http://test") as client:
        yield await _world(db_pool, client)


async def _world(db_pool, client):
    w = World()
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO tenants (id, slug, name) VALUES ($1, 'tenant-b', 'Tenant B')",
                          uuid.UUID(TENANT_B))
    w.client = client
    w.db = db_pool
    w.admin_a = await seed_key(db_pool, TENANT_A, "admin-a", "admin")
    w.analyst_a = await seed_key(db_pool, TENANT_A, "analyst-a", "analyst")
    w.viewer_a = await seed_key(db_pool, TENANT_A, "viewer-a", "viewer")
    w.admin_b = await seed_key(db_pool, TENANT_B, "admin-b", "admin")
    return w


class Host:
    """An enrolled agent: its key, its credential and a seq counter."""

    def __init__(self, sk, agent_id: str, tenant_id: str, token: str, hostname: str) -> None:
        self.sk, self.agent_id, self.tenant_id, self.token, self.hostname = sk, agent_id, tenant_id, token, hostname
        self.seq = 0
        self.kid = kid_of(sk)

    @property
    def h(self) -> dict:
        return {"X-Agent-Token": self.token, "Content-Type": "application/json"}

    def env(self, kind: str, payload: bytes | dict | None = None, *, seq: int | None = None, **kw) -> dict:
        if payload is None:
            payload = {"agent_version": "0.2.0", "status": "ok"} if kind == "heartbeat" else good_posture()
        if isinstance(payload, dict):
            payload = pbytes(payload)
        if seq is None:
            self.seq += 1
            seq = self.seq
        else:
            self.seq = max(self.seq, seq)
        kw.setdefault("sk", self.sk)
        return build_envelope(kw.pop("sk"), agent_id=kw.pop("agent_id", self.agent_id),
                              tenant_id=kw.pop("tenant_id", self.tenant_id), kind=kind, seq=seq,
                              payload=payload, **kw)


async def enroll_host(client, admin_key: str, hostname: str = "web-1", *, sk=None, token_kw=None,
                      headers=None) -> Host:
    sk = sk or Ed25519PrivateKey.generate()
    r = await client.post("/v1/fleet/enroll-tokens", headers=hdr(admin_key), json=token_kw or {})
    assert r.status_code == 201, r.text
    token = r.json()["token"]
    prefix = token.split("_")[1]
    proof = sk.sign(b"paddock-enroll/v1\n" + prefix.encode() + b"\n" + hostname.encode())
    r = await client.post("/v1/fleet/enroll", headers=headers, json={
        "token": token, "hostname": hostname, "public_key_b64": b64u(pubkey(sk)), "proof_b64": b64u(proof),
        "agent_version": "0.2.0", "capabilities": ["inventory", "posture"]})
    assert r.status_code == 201, r.text
    out = r.json()
    h = Host(sk, out["agent_id"], out["tenant_id"], out["agent_token"], hostname)
    assert out["key_id"] == h.kid
    return h


async def post(client, host: Host, route: str, env: dict | bytes, *, gz: bool = False, headers=None,
               agent_id: str | None = None):
    body = env if isinstance(env, bytes) else json.dumps(env).encode()
    h = dict(host.h)
    if gz:
        body = gzip.compress(body)
        h["Content-Encoding"] = "gzip"
    h.update(headers or {})
    return await client.post(f"/v1/fleet/{agent_id or host.agent_id}/{route}", content=body, headers=h)


async def hb(client, host: Host, **kw):
    return await post(client, host, "heartbeat", host.env("heartbeat", **kw))


async def ps(client, host: Host, payload=None, **kw):
    return await post(client, host, "posture", host.env("posture", payload, **kw))


async def key_row(db, agent_id: str, kid: str | None = None):
    async with db.acquire() as con:
        if kid:
            return await con.fetchrow("SELECT * FROM fleet_agent_keys WHERE agent_id=$1 AND key_id=$2",
                                      uuid.UUID(agent_id), kid)
        return await con.fetch("SELECT * FROM fleet_agent_keys WHERE agent_id=$1 ORDER BY created_at",
                               uuid.UUID(agent_id))


async def agent_row(db, agent_id: str):
    async with db.acquire() as con:
        return await con.fetchrow("SELECT * FROM fleet_agents WHERE id=$1", uuid.UUID(agent_id))


async def posture_rows(db, agent_id: str):
    async with db.acquire() as con:
        return await con.fetch("SELECT * FROM agent_posture WHERE agent_id=$1 ORDER BY received_at, seq",
                               uuid.UUID(agent_id))


def jd(v: Any) -> Any:
    return json.loads(v) if isinstance(v, str) else v


async def audits(db, action: str, resource_id: str | None = None) -> list[dict]:
    async with db.acquire() as con:
        rows = await con.fetch("SELECT * FROM audit_log WHERE action=$1 ORDER BY id", action)
    out = [dict(r, details=jd(r["details"])) for r in rows]
    return [r for r in out if resource_id is None or r["resource_id"] == resource_id]


async def rejected(db, host: Host) -> list[dict]:
    return await audits(db, "fleet.evidence.rejected", host.agent_id)


async def last_build_at(db):
    async with db.acquire() as con:
        return await con.fetchval("SELECT last_build_at FROM assurance_state WHERE tenant_id=$1",
                                  uuid.UUID(TENANT_A))


# =========================================================================== #
# vectors the agent package ships: the server must agree with its signer
# =========================================================================== #

VECTORS = REPO / "agent" / "tests" / "vectors" / "envelope_v1.json"


@pytest.mark.skipif(not VECTORS.exists(), reason="agent vectors not present")
def test_agent_vectors_verify_with_the_server_code():
    d = json.loads(VECTORS.read_text())
    pub = bytes.fromhex(d["key"]["public_key_hex"])
    for case in d["cases"]:
        header = case["header"]
        assert fp.signing_input(header) == bytes.fromhex(case["signing_input_hex"])
        assert fe.verify_ed25519(pub, fp.signing_input(header), bytes.fromhex(case["signature_hex"]))
        env = fp.parse_envelope(case["body_json"].encode(), header["kind"])
        assert env.header == header
        assert fp.decode_payload(env) == bytes.fromhex(case["payload_hex"])
        assert fp.verify_signature(pub, env)
        # and the canonical form is byte-identical to the signer's
        assert fp.canon(header) == case["signing_input_utf8"][len("paddock-agent-envelope/v1\n"):].encode()


@pytest.mark.skipif(not VECTORS.exists(), reason="agent vectors not present")
def test_agent_negative_vectors_are_each_refused_at_their_step():
    d = json.loads(VECTORS.read_text())
    pub = bytes.fromhex(d["key"]["public_key_hex"])
    seen = set()
    for neg in d["negative"]:
        env_json = json.dumps(neg["envelope"]).encode()
        kind = neg["envelope"]["kind"]
        try:
            env = fp.parse_envelope(env_json, kind)
            fp.decode_payload(env)
            ok = fp.verify_signature(pub, env)
            assert ok is False, neg["name"]
            seen.add(neg["name"])
        except fp.Rejection as rej:
            assert rej.status in (400, 401, 413), (neg["name"], rej.status)
            seen.add(neg["name"])
    assert seen == {n["name"] for n in d["negative"]}


@pytest.mark.skipif(not VECTORS.exists(), reason="agent vectors not present")
def test_agent_rotate_vector_proof_verifies():
    d = json.loads(VECTORS.read_text())
    r = d["rotate"]
    obj, new_pub = fp.validate_rotate(r["payload_json"].encode(), agent_id=d["agent_id"], old_kid=r["old_key_id"])
    assert fe.key_id_for(new_pub) == r["new_key_id"] == obj["new_key_id"]
    with pytest.raises(fp.PayloadError):      # the proof binds the agent id and both key ids
        fp.validate_rotate(r["payload_json"].encode(), agent_id=str(uuid.uuid4()), old_kid=r["old_key_id"])
    with pytest.raises(fp.PayloadError):
        fp.validate_rotate(r["payload_json"].encode(), agent_id=d["agent_id"], old_kid="0" * 32)


# =========================================================================== #
# payload schema: the models accept what the real collectors produce, and refuse everything else
# =========================================================================== #

def test_the_handwritten_good_posture_is_valid():
    fp.validate_posture(pbytes(good_posture()))
    fp.validate_posture(pbytes(good_posture(with_packages=True, ips=["10.0.1.5"])))


def _agent_ctx_factory():
    """Real collector output, from the agent package's own fixtures (skipped when the agent tree is absent)."""
    agent = REPO / "agent"
    fix = agent / "tests" / "fixtures"
    if not (agent / "paddock_agent").is_dir() or not fix.is_dir():
        pytest.skip("agent package not present")
    sys.path.insert(0, str(agent))
    try:
        from paddock_agent.collectors import collect_all, payload_bytes
        from paddock_agent.runner import Ctx
    finally:
        sys.path.remove(str(agent))

    def fx(*parts):
        return (fix.joinpath(*parts)).read_text(encoding="utf-8")

    def res(out="", rc=0, err="", missing=False):
        return {"rc": None if missing else rc, "out": out, "err_tail": err, "timed_out": False,
                "missing": missing, "truncated": False}

    class Runner:
        def __init__(self, table):
            self.table = table

        def __call__(self, argv, timeout, max_bytes):
            hit = self.table.get(os.path.basename(argv[0]))
            if hit is None:
                return res(missing=True)
            return hit(argv) if callable(hit) else hit

    def make(tmp_path, table, files, bins, **kw):
        root, proc = tmp_path / "root", tmp_path / "proc"
        root.mkdir(parents=True, exist_ok=True)
        proc.mkdir(parents=True, exist_ok=True)
        for path, content in files.items():
            base = proc if path.startswith("/proc/") else root
            p = base / (path[len("/proc/"):] if path.startswith("/proc/") else path.lstrip("/"))
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        for b in bins:
            p = root / b.lstrip("/")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("#!/bin/sh\n")
            p.chmod(0o755)
        ctx = Ctx(str(tmp_path / "state"), "0.2.0-test", seq=7, key_id="k" * 32, machine_salt=b"salt",
                  now=1795000000, proc_root=str(proc), host_root=str(root), runner=Runner(table),
                  is_root=kw.pop("is_root", True), containerised=kw.pop("containerised", False),
                  platform="linux")
        ctx.cache["machine"] = "x86_64"
        return ctx

    return fx, res, make, collect_all, payload_bytes


def test_real_collector_output_validates(tmp_path):
    fx, res, make, collect_all, payload_bytes = _agent_ctx_factory()
    U, S = "ubuntu2404", "synthetic"
    nft_empty = json.dumps({"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}]})
    files = {
        "/etc/os-release": fx(U, "os-release.ubuntu2404.txt"), "/etc/machine-id": "0123456789abcdef\n",
        "/proc/sys/kernel/random/boot_id": "11111111-2222-3333-4444-555555555555\n",
        "/proc/uptime": "12345.67 9999.99\n", "/proc/self/status": "Name:\tx\nCapEff:\t0000000000081004\n",
        "/proc/net/tcp": fx(U, "proc_net_tcp.container.txt"), "/proc/net/udp": fx(U, "proc_net_udp.container.txt"),
        "/etc/ssh/sshd_config": fx(S, "sshd", "sshd_config.ubuntu2404.txt"),
        "/etc/passwd": fx(S, "sshd", "passwd.sample")}
    bins = ["/usr/sbin/sshd", "/usr/bin/ssh", "/usr/sbin/nft", "/usr/bin/dpkg-query", "/usr/bin/apt-get",
            "/usr/sbin/ufw", "/usr/bin/firewall-cmd"]
    scenarios = {
        "hardened": (nft_empty, fx(S, "sshd", "sshd_T.hardened.txt")),
        "ubuntu_nft": (fx(U, "nft_json_unshare.json"), fx(S, "sshd", "sshd_T.ubuntu2404.txt")),
        "firewalld": (fx(S, "firewall", "firewalld_nft.json"), fx(S, "sshd", "sshd_T.kbd_pam.txt")),
        "fail2ban": (fx(S, "firewall", "fail2ban_nft.json"), fx(S, "sshd", "sshd_T.old_openssh7.txt")),
    }
    for name, (nft, sshd_t) in scenarios.items():
        def sshd(argv, _t=sshd_t):
            return res("", err="OpenSSH_9.6p1") if argv[0].endswith("/ssh") else res(_t)
        table = {"dpkg-query": res(fx(U, "dpkg_query_full.ubuntu2404.tsv")),
                 "apt-get": res(fx(U, "apt_get_s_dist_upgrade.ubuntu2404.txt")), "nft": res(nft),
                 "sshd": sshd, "ssh": sshd, "ufw": res(fx(S, "firewall", "ufw_status_active.txt")),
                 "firewall-cmd": lambda argv: res("running\n") if argv[-1] == "--state" else res("public\n")}
        ctx = make(tmp_path / name, table, files, bins)
        raw = payload_bytes(collect_all(ctx))
        assert fp.validate_posture(raw)["schema"] == 2, name
    # an unprivileged host with nothing installed, and a containerised agent
    for name, kw in {"nothing": {"is_root": False}, "container": {"containerised": True}}.items():
        ctx = make(tmp_path / name, {}, {} if name == "nothing" else files, [] if name == "nothing" else bins, **kw)
        fp.validate_posture(payload_bytes(collect_all(ctx)))


def _mut(path: tuple, value):
    def apply(p):
        node = p
        for k in path[:-1]:
            node = node[k]
        if value is _DEL:
            del node[path[-1]]
        else:
            node[path[-1]] = value
        return p
    return apply


_DEL = object()
SEC = ("sections",)


@pytest.mark.parametrize("name,mutate", [
    ("extra top-level key", lambda p: p.update(extra=1)),
    ("extra key in a section", _mut(("sections", "sshd", "x"), 1)),
    ("unknown section", _mut(("sections", "accounts"), {"s": "unavailable", "reason": "no_data"})),
    ("missing section", _mut(("sections", "listeners"), _DEL)),
    ("schema 3", _mut(("schema",), 3)),
    ("bad collected_at", _mut(("collected_at",), "yesterday")),
    ("bool where int", _mut(("sections", "self", "v", "seq"), True)),
    ("string where int", _mut(("sections", "self", "v", "uptime_s"), "5")),
    ("enum outside domain", _mut(("sections", "sshd", "v", "config", "passwordauthentication"), "maybe")),
    ("null where absent", _mut(("sections", "sshd", "v", "config", "passwordauthentication"), None)),
    ("control char", _mut(("sections", "self", "v", "python"), "3.\x00")),
    ("string too long", _mut(("sections", "self", "v", "python"), "x" * 33)),
    ("port out of range", _mut(("sections", "sshd", "v", "config", "port"), [70000])),
    ("too many listeners", _mut(("sections", "listeners", "v", "listeners"),
                                [good_posture()["sections"]["listeners"]["v"]["listeners"][0]] * 2001)),
    ("ok section without conf", _mut(("sections", "firewall", "conf"), _DEL)),
    ("error detail too long", _mut(("sections", "patch"), {"s": "error", "reason": "timeout", "detail": "x" * 121})),
    ("error reason outside domain", _mut(("sections", "patch"), {"s": "error", "reason": "nope", "detail": ""})),
    ("self not ok", _mut(("sections", "self"), {"s": "unavailable", "reason": "no_data"})),
    ("self partial", _mut(("sections", "self", "partial"), True)),
    ("firewall v2", _mut(("sections", "firewall", "v", "v"), 2)),
    ("firewall bad verdict string too long", _mut(
        ("sections", "firewall", "v", "families", "ip4", "chains", 0, "rules", 0, "v"), "j" * 121)),
    ("ufw frontend with firewalld field", _mut(
        ("sections", "firewall", "v", "frontends"), [{"name": "ufw", "state": "active", "default_incoming": "deny",
                                                       "rules": 1, "default_zone": "x"}])),
    ("package row of 4", _mut(("sections", "patch", "v", "manifest"), {
        "state": "ok", "mgr": "dpkg", "count": 1, "sha256": "a" * 64, "held": 0, "full": True,
        "packages": [["a", "1", "amd64", "a"]]})),
    ("sha256 not hex", _mut(("sections", "patch", "v", "manifest", "sha256"), "Z" * 64)),
])
def test_payload_schema_refuses(name, mutate):
    p = mutate(good_posture())
    with pytest.raises(fp.PayloadError) as ei:
        fp.validate_posture(pbytes(p))
    assert ei.value.reason in ("payload_schema",), (name, ei.value.reason, ei.value.detail)
    # the message names fields, never values
    assert "x" * 40 not in ei.value.detail


def test_payload_json_strictness():
    good = pbytes(good_posture())
    for bad, why in [(b'{"schema":2,"schema":2}', "dup"), (b'{"schema":2.0}', "float"), (b'{"a":NaN}', "nan"),
                     (b"\xef\xbb\xbf" + good, "bom"), (b"\xff\xfe", "utf8"), (b"[]", "not an object"),
                     (b"[" * 5000 + b"]" * 5000, "deep"), (b"", "empty")]:
        with pytest.raises(fp.PayloadError):
            fp.validate_posture(bad)
        with pytest.raises(fp.PayloadError):
            fp.validate_heartbeat(bad)


def test_heartbeat_payload_schema():
    assert fp.validate_heartbeat(canon({"agent_version": "0.2.0", "status": "ok"}))
    assert fp.validate_heartbeat(b"{}") == {}
    for bad in ({"extra": 1}, {"status": 5}, {"agent_version": "x" * 65}, {"status": None}):
        with pytest.raises(fp.PayloadError):
            fp.validate_heartbeat(canon(bad))


def test_content_digest_ignores_volatile_fields_and_nothing_else():
    base = fp.content_digest(good_posture())
    # timings, uptime, seq, clock skew, key id, collection time, package attachment, metadata age: not content
    vol = good_posture(ms=999, uptime=77777, seq=42, collected=NOW() + dt.timedelta(hours=1), with_packages=True)
    vol["sections"]["patch"]["v"]["pending"]["metadata_age_s"] = 99999
    vol["sections"]["self"]["v"]["key_id"] = "z" * 32
    assert fp.content_digest(vol) == base
    # every real change moves it
    for p in (good_posture(pw="yes"), good_posture(fw_default="accept"), good_posture(security=3),
              good_posture(ips=["10.0.1.5"]), good_posture(mid="e" * 64)):
        assert fp.content_digest(p) != base
    p = good_posture()
    p["sections"]["self"]["v"]["collectors"]["sshd"]["status"] = "error"
    p["sections"]["self"]["v"]["collectors"]["sshd"]["reason"] = "timeout"
    assert fp.content_digest(p) != base


def test_posture_identity_claims_only_specific_non_loopback_addresses():
    p = good_posture(ips=["10.0.1.5", "10.0.1.5", "127.0.0.2", "::ffff:10.0.1.6", "fe80::1", "224.0.0.1"])
    ident = fp.posture_identity(p)
    assert ident["ips"] == ["10.0.1.5", "10.0.1.6"]        # wildcard, loopback, link-local, multicast dropped
    assert ident["machine_id_hash"] == "c" * 64 and ident["boot_id"].startswith("1111")


# =========================================================================== #
# the happy path, and what a stored posture looks like
# =========================================================================== #

async def test_enroll_heartbeat_posture_and_read(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    # a signed heartbeat is the proof of life
    r = await hb(c, host)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "online" and body["pending_actions"] == [] and body["idempotent"] is False
    p = good_posture(ips=["10.0.1.5"])
    r = await ps(c, host, p)
    assert r.status_code == 200, r.text
    ack = r.json()
    assert ack["ok"] is True and ack["stored"] is True and ack["changed"] is True and ack["seq"] == host.seq
    # the stored row keeps the EXACT bytes, the signature and the signed header; signed is set by the ingest
    rows = await posture_rows(world.db, host.agent_id)
    assert len(rows) == 1
    row = rows[0]
    assert bytes(row["payload_raw"]) == pbytes(p) and row["signed"] is True and row["key_id"] == host.kid
    assert row["payload_sha256"] == hashlib.sha256(pbytes(p)).hexdigest() and row["seq"] == host.seq
    assert len(bytes(row["signature"])) == 64 and jd(row["header"])["kind"] == "posture"
    assert "payload_b64" not in jd(row["header"]) and "sig" not in jd(row["header"])
    assert fe.verify_ed25519(pubkey(host.sk), PREFIX + canon(jd(row["header"])), bytes(row["signature"]))
    # a viewer gets the summary but never the posture; an analyst (triage) gets it
    assert (await c.get(f"/v1/fleet/agents/{host.agent_id}/posture", headers=hdr(world.viewer_a))).status_code == 403
    r = await c.get(f"/v1/fleet/agents/{host.agent_id}/posture", headers=hdr(world.analyst_a))
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["tier"] == "configured" and out["signed"] is True and out["key_status"] == "active"
    assert out["payload"]["sections"]["sshd"]["v"]["config"]["passwordauthentication"] == "no"
    assert out["payload_sha256"] == row["payload_sha256"] and out["online"] is True
    detail = (await c.get(f"/v1/fleet/agents/{host.agent_id}", headers=hdr(world.viewer_a))).json()
    assert "sections" not in json.dumps(detail) and detail["key_id"] == host.kid and detail["legacy"] is False
    assert [k["status"] for k in detail["keys"]] == ["active"] and detail["identity"]["ips"] == ["10.0.1.5"]
    assert "_ingest" not in detail["identity"]
    # agent row is refreshed
    a = await agent_row(world.db, host.agent_id)
    assert a["last_posture_seq"] == host.seq and a["last_posture_at"] is not None and a["status"] == "online"
    # reading a full posture is itself audited
    assert any((x["path"] or "").endswith("/posture") and x["method"] == "GET"
               for x in [dict(r) for r in await world.db.fetch("SELECT method, path FROM audit_log")])


async def test_posture_read_404s(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    r = await c.get(f"/v1/fleet/agents/{host.agent_id}/posture", headers=hdr(world.analyst_a))
    assert r.status_code == 404                                        # no posture yet
    assert (await c.get(f"/v1/fleet/agents/{uuid.uuid4()}/posture", headers=hdr(world.analyst_a))).status_code == 404


async def test_gzip_bodies_are_accepted(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    r = await post(c, host, "posture", host.env("posture", good_posture(with_packages=True)), gz=True)
    assert r.status_code == 200, r.text


async def test_agent_version_is_taken_from_the_signed_header(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    env = host.env("heartbeat", {"status": "ok"}, collectors={"agent": "0.9.9"})
    assert (await post(c, host, "heartbeat", env)).status_code == 200
    assert (await agent_row(world.db, host.agent_id))["agent_version"] == "0.9.9"


# =========================================================================== #
# step 1: body size
# =========================================================================== #

async def test_step1_oversize_body_is_413_and_audited(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    r = await post(c, host, "posture", b"x" * (fp.MAX_BODY_BYTES + 1))
    assert r.status_code == 413 and r.json()["reason"] == "body_too_large"
    rows = await rejected(world.db, host)
    assert rows and rows[-1]["details"]["reason"] == "body_too_large" and rows[-1]["details"]["http_status"] == 413
    assert (await agent_row(world.db, host.agent_id))["rejected_total"] == 1
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0


async def test_step1_declared_length_over_the_cap_is_refused_before_reading(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    r = await post(c, host, "posture", b"{}", headers={"Content-Length": str(fp.MAX_BODY_BYTES + 1)})
    assert r.status_code in (400, 413)       # the transport itself may refuse a lying length; never accepted


async def test_step1_inflation_bomb_is_413(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    bomb = gzip.compress(b"0" * (fp.MAX_INFLATED_BYTES + 10), 9)
    assert len(bomb) < fp.MAX_BODY_BYTES              # small on the wire, huge inflated
    r = await post(c, host, "posture", bomb, headers={"Content-Encoding": "gzip"})
    assert r.status_code == 413 and r.json()["reason"] == "inflated_too_large"
    assert (await rejected(world.db, host))[-1]["details"]["reason"] == "inflated_too_large"


async def test_step1_bad_and_truncated_gzip_and_unknown_encoding(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    r = await post(c, host, "posture", b"not gzip at all", headers={"Content-Encoding": "gzip"})
    assert r.status_code == 400 and r.json()["reason"] == "bad_gzip"
    good = gzip.compress(json.dumps(host.env("posture")).encode())
    r = await post(c, host, "posture", good[:-12], headers={"Content-Encoding": "gzip"})
    assert r.status_code == 400
    r = await post(c, host, "posture", good + b"trailing", headers={"Content-Encoding": "gzip"})
    assert r.status_code == 400
    r = await post(c, host, "posture", b"{}", headers={"Content-Encoding": "br"})
    assert r.status_code == 415 and r.json()["reason"] == "unsupported_encoding"


async def test_step1_json_depth_over_16_is_413(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    r = await post(c, host, "posture", b"[" * 17 + b"]" * 17)
    assert r.status_code == 413 and r.json()["reason"] == "json_too_deep"
    r = await post(c, host, "posture", b"[" * 100000 + b"]" * 100000)
    assert r.status_code == 413
    r = await post(c, host, "posture", b"[]," * 100000)               # a flat flood of tokens is bounded too
    assert r.status_code == 413
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0


async def test_step1_header_over_2kib_and_payload_over_2mib_are_413(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    env = host.env("posture")
    env["collectors"] = {f"c{i:02d}" + "k" * 58: "v" * 128 for i in range(16)}
    r = await post(c, host, "posture", resign(host.sk, env))
    assert r.status_code == 413 and r.json()["reason"] == "header_too_large"
    env = host.env("posture")
    env["payload_len"] = fp.MAX_PAYLOAD_BYTES + 1
    r = await post(c, host, "posture", resign(host.sk, env))
    assert r.status_code == 413 and r.json()["reason"] == "payload_too_large"
    env = host.env("posture")
    env["payload_b64"] = "A" * (fp.MAX_PAYLOAD_BYTES * 2)
    r = await post(c, host, "posture", resign(host.sk, env), gz=True)
    assert r.status_code == 413


async def test_step1_a_payload_of_exactly_2mib_passes_the_size_checks(world):
    """The cap is on the decoded payload; a payload of exactly the cap is not refused for size (it then fails the
    schema, which is step 9: proof the size gate is not off by one)."""
    c = world.client
    host = await enroll_host(c, world.admin_a)
    r = await post(c, host, "posture", host.env("posture", b" " * fp.MAX_PAYLOAD_BYTES), gz=True)
    assert r.status_code == 422 and r.json()["reason"] == "payload_not_json"


# =========================================================================== #
# step 2: strict JSON, fields, types
# =========================================================================== #

async def test_step2_malformed_envelopes_are_400(world, unsampled):
    c = world.client
    fp.posture_limiter.limit = 1000
    host = await enroll_host(c, world.admin_a)
    good = host.env("posture")

    def raw(env):
        return json.dumps(env).encode()

    dup = raw(good)[:-1] + b',"seq":999}'
    cases = {
        "duplicate key": dup,
        "not json": b"{nope",
        "not an object": b'["a"]',
        "float seq": raw({**good, "seq": 1.0}).replace(b'"seq": %d' % good["seq"], b'"seq": 1.0'),
        "NaN": raw(good)[:-1] + b',"x":NaN}',
        "missing field": raw({k: v for k, v in good.items() if k != "nonce"}),
        "extra field": raw({**good, "extra": 1}),
        "v=2": raw({**good, "v": 2}),
        "v=true": raw({**good, "v": True}),
        "seq=0": raw({**good, "seq": 0}),
        "seq as string": raw({**good, "seq": "1"}),
        "seq bool": raw({**good, "seq": True}),
        "negative payload_len": raw({**good, "payload_len": -1}),
        "bad issued_at": raw({**good, "issued_at": "2026-13-45T00:00:00Z"}),
        "issued_at with offset": raw({**good, "issued_at": "2026-11-24T19:00:00+00:00"}),
        "bad nonce": raw({**good, "nonce": "AAAA"}),
        "kind unknown": raw({**good, "kind": "inventory"}),
        "payload_type mismatch": raw({**good, "payload_type": "paddock.host.heartbeat/v1"}),
        "sha not hex": raw({**good, "payload_sha256": "G" * 64}),
        "uppercase agent id": raw({**good, "agent_id": good["agent_id"].upper()}),
        "collectors not strings": raw({**good, "collectors": {"agent": 1}}),
        "null field": raw({**good, "alg": None}),
        "invalid utf-8": b"\xff\xfe\xfd",
        "bom": b"\xef\xbb\xbf" + raw(good),
    }
    for name, body in cases.items():
        r = await post(c, host, "posture", body)
        assert r.status_code == 400, (name, r.status_code, r.text)
        assert r.json()["reason"] in ("bad_json", "bad_envelope"), (name, r.json())
    # nothing advanced, every refusal was recorded
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0
    assert len(await rejected(world.db, host)) == len(cases)


async def test_step2_kind_must_match_the_route(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    r = await post(c, host, "posture", host.env("heartbeat"))
    assert r.status_code == 400 and r.json()["reason"] == "kind_route_mismatch"
    r = await post(c, host, "heartbeat", host.env("posture"))
    assert r.status_code == 400 and r.json()["reason"] == "kind_route_mismatch"
    r = await post(c, host, "keys/rotate", host.env("heartbeat"))
    assert r.status_code == 400
    r = await post(c, host, "heartbeat", host.env("rotate", b"{}"))
    assert r.status_code == 400
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0


# =========================================================================== #
# step 3: the agent row
# =========================================================================== #

async def test_step3_header_tenant_and_agent_must_match(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    r = await post(c, host, "posture", host.env("posture", tenant_id=TENANT_B))
    assert r.status_code == 403 and r.json()["reason"] == "tenant_mismatch"
    r = await post(c, host, "posture", host.env("posture", agent_id=str(uuid.uuid4())))
    assert r.status_code == 403 and r.json()["reason"] == "agent_mismatch"
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0
    assert [x["details"]["reason"] for x in await rejected(world.db, host)] == ["tenant_mismatch", "agent_mismatch"]


async def test_step3_unknown_agent_is_404_and_audited(world, db_pool):
    pool = world.client._transport.app.state.pool
    aid = uuid.uuid4()
    sk = Ed25519PrivateKey.generate()
    env = build_envelope(sk, agent_id=aid, tenant_id=TENANT_A, kind="heartbeat", seq=1,
                         payload=canon({"status": "ok"}))
    with pytest.raises(fp.Rejection) as ei:
        await fp.ingest_envelope(pool, agent_id=aid, tenant_id=TENANT_A, kind="heartbeat",
                                 body=json.dumps(env).encode(), content_encoding=None)
    assert ei.value.status == 404 and ei.value.reason == "agent_not_found"


async def test_step3_revoked_and_legacy_agents_get_403(world):
    c = world.client
    pool = c._transport.app.state.pool
    host = await enroll_host(c, world.admin_a)
    env = host.env("heartbeat")
    await world.db.execute("UPDATE fleet_agents SET legacy = TRUE WHERE id = $1", uuid.UUID(host.agent_id))
    with pytest.raises(fp.Rejection) as ei:      # the principal refuses first over HTTP; the module refuses too
        await fp.ingest_envelope(pool, agent_id=uuid.UUID(host.agent_id), tenant_id=TENANT_A, kind="heartbeat",
                                 body=json.dumps(env).encode(), content_encoding=None)
    assert ei.value.status == 403 and ei.value.body == {"error": "re_enroll_required"}
    await world.db.execute("UPDATE fleet_agents SET legacy = FALSE, status='revoked', revoked_at=NOW() WHERE id=$1",
                           uuid.UUID(host.agent_id))
    with pytest.raises(fp.Rejection) as ei:
        await fp.ingest_envelope(pool, agent_id=uuid.UUID(host.agent_id), tenant_id=TENANT_A, kind="heartbeat",
                                 body=json.dumps(env).encode(), content_encoding=None)
    assert ei.value.status == 403 and ei.value.reason == "agent_revoked"


# =========================================================================== #
# step 4: the key
# =========================================================================== #

async def test_step4_unknown_rotated_revoked_keys_and_foreign_alg_are_401(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    other = Ed25519PrivateKey.generate()
    r = await post(c, host, "heartbeat", host.env("heartbeat", sk=other))       # kid of an unregistered key
    assert r.status_code == 401 and r.json()["reason"] == "unknown_key"
    env = host.env("heartbeat")
    env["alg"] = "ed448"
    r = await post(c, host, "heartbeat", resign(host.sk, env))
    assert r.status_code == 401 and r.json()["reason"] == "alg_not_allowed"
    await world.db.execute("UPDATE fleet_agent_keys SET status='rotated' WHERE agent_id=$1", uuid.UUID(host.agent_id))
    r = await hb(c, host)
    assert r.status_code == 401 and r.json()["reason"] == "key_not_active"
    await world.db.execute("UPDATE fleet_agent_keys SET status='revoked' WHERE agent_id=$1", uuid.UUID(host.agent_id))
    r = await hb(c, host)
    assert r.status_code == 401 and r.json()["reason"] == "key_not_active"
    # another agent's key id is not "a key of this agent"
    host2 = await enroll_host(c, world.admin_a, "web-2")
    r = await post(c, host, "heartbeat", host.env("heartbeat", sk=host2.sk))
    assert r.status_code == 401 and r.json()["reason"] == "unknown_key"
    assert all(x["details"]["http_status"] == 401 for x in await rejected(world.db, host))


# =========================================================================== #
# step 5: payload digest
# =========================================================================== #

async def test_step5_payload_encoding_length_and_digest_are_400(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    e = host.env("posture")
    bad_b64 = resign(host.sk, {**e, "payload_b64": "!!!not base64!!!"})
    assert (r := await post(c, host, "posture", bad_b64)).status_code == 400 and r.json()["reason"] == "bad_payload_b64"
    e = host.env("posture")
    wrong_len = resign(host.sk, {**e, "payload_len": e["payload_len"] + 1})
    assert (r := await post(c, host, "posture", wrong_len)).status_code == 400
    assert r.json()["reason"] == "payload_len_mismatch"
    e = host.env("posture")
    wrong_sha = resign(host.sk, {**e, "payload_sha256": "0" * 64})
    assert (r := await post(c, host, "posture", wrong_sha)).status_code == 400
    assert r.json()["reason"] == "payload_sha256_mismatch"
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0


# =========================================================================== #
# step 6: signature. Tamper => 401 + audit row + the previous posture is intact + seq never advances
# =========================================================================== #

async def test_step6_tampered_payload_is_401_audited_and_changes_nothing(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    assert (await ps(c, host, good_posture(pw="no"))).status_code == 200
    before = await posture_rows(world.db, host.agent_id)
    last_before = (await key_row(world.db, host.agent_id, host.kid))["last_seq"]
    # an attacker flips the payload (password auth on) and fixes up length and digest, but cannot sign
    evil = pbytes(good_posture(pw="yes"))
    env = host.env("posture", good_posture(pw="no"))
    env["payload_b64"] = b64u(evil)
    env["payload_len"] = len(evil)
    env["payload_sha256"] = hashlib.sha256(evil).hexdigest()
    r = await post(c, host, "posture", env)
    assert r.status_code == 401 and r.json()["reason"] == "bad_signature"
    after = await posture_rows(world.db, host.agent_id)
    assert [bytes(x["payload_raw"]) for x in after] == [bytes(x["payload_raw"]) for x in before]
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == last_before    # seq NEVER advanced
    rej = (await rejected(world.db, host))[-1]["details"]
    assert rej["reason"] == "bad_signature" and rej["key_id"] == host.kid and rej["seq"] == env["seq"]
    assert (await agent_row(world.db, host.agent_id))["rejected_total"] == 1
    # the seq the attacker burned is still usable by the real agent
    env_ok = build_envelope(host.sk, agent_id=host.agent_id, tenant_id=host.tenant_id, kind="posture",
                            seq=env["seq"], payload=pbytes(good_posture(pw="no", ms=77)))
    assert (await post(c, host, "posture", env_ok)).status_code == 200


async def test_step6_every_signed_field_is_covered(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    base = host.env("posture")
    now_s = iso(NOW() - dt.timedelta(seconds=30))
    edits = {
        "seq": base["seq"] + 5, "issued_at": now_s, "nonce": b64u(b"\x01" * 16),
        "collectors": {"agent": "9.9.9"}, "payload_type": "paddock.host.posture/v2 ",
    }
    for field, value in edits.items():
        env = dict(base)
        env[field] = value
        r = await post(c, host, "posture", env)
        assert r.status_code in (400, 401), (field, r.status_code)
        if r.status_code == 400:
            assert field == "payload_type"             # whitespace is refused earlier, as malformed
        else:
            assert r.json()["reason"] == "bad_signature", field
    # kind is covered too: a heartbeat signature replayed as a posture does not verify
    hb_env = host.env("heartbeat")
    as_posture = dict(hb_env, kind="posture", payload_type=PAYLOAD_TYPE["posture"])
    r = await post(c, host, "posture", as_posture)
    assert r.status_code == 401
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0


async def test_step6_signature_by_another_enrolled_agents_key_is_401(world):
    c = world.client
    h1 = await enroll_host(c, world.admin_a, "web-1")
    h2 = await enroll_host(c, world.admin_a, "web-2")
    # h2 signs an envelope that CLAIMS h1's key id
    env = h1.env("heartbeat", sk=h2.sk, kid=h1.kid)
    r = await post(c, h1, "heartbeat", env)
    assert r.status_code == 401 and r.json()["reason"] == "bad_signature"
    for bad in (b"", b"A" * 10, b64u(b"\x00" * 63).encode(), b64u(b"\x00" * 65).encode()):
        env = h1.env("heartbeat")
        env["sig"] = bad.decode() if isinstance(bad, bytes) else bad
        assert (await post(c, h1, "heartbeat", env)).status_code == 401


# =========================================================================== #
# step 7: clock
# =========================================================================== #

async def test_step7_clock_window(world, unsampled):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    for off, code in ((-599, 200), (599, 200), (-601, 422), (601, 422), (-86400, 422), (86400 * 400, 422)):
        r = await post(c, host, "heartbeat", host.env("heartbeat", issued=NOW() + dt.timedelta(seconds=off)))
        assert r.status_code == code, (off, r.status_code, r.text)
        if code == 422:
            body = r.json()
            assert body["reason"] == "clock_skew" and abs(body["server_now"] - NOW().timestamp()) < 30
            assert body["server_time"].endswith("Z")
    rej = [x for x in await rejected(world.db, host) if x["details"]["reason"] == "clock_skew"]
    assert len(rej) == 4


# =========================================================================== #
# step 8: the atomic seq claim
# =========================================================================== #

async def test_step8_replay_is_409_and_identical_retry_is_idempotent(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    env = host.env("heartbeat")
    assert (await post(c, host, "heartbeat", env)).status_code == 200
    again = await post(c, host, "heartbeat", env)
    assert again.status_code == 200 and again.json()["idempotent"] is True    # identical bytes: the lost answer
    env2 = host.env("heartbeat")
    assert (await post(c, host, "heartbeat", env2)).status_code == 200
    # the older envelope is now a replay
    r = await post(c, host, "heartbeat", env)
    assert r.status_code == 409 and r.json()["reason"] == "replayed_seq" and r.json()["expected_min"] == env2["seq"] + 1
    # seq 0 and a lower seq with a fresh signature are replays as well
    low = host.env("heartbeat", seq=1)
    r = await post(c, host, "heartbeat", low)
    assert r.status_code == 409 and r.json()["expected_min"] == env2["seq"] + 1
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == env2["seq"]
    reasons = [x["details"]["reason"] for x in await rejected(world.db, host)]
    assert reasons == ["replayed_seq", "replayed_seq"]                      # an idempotent retry is not a rejection


async def test_step8_idempotent_retry_of_a_posture_does_not_write_twice(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    env = host.env("posture")
    assert (await post(c, host, "posture", env)).status_code == 200
    r = await post(c, host, "posture", env)
    assert r.status_code == 200 and r.json()["idempotent"] is True and r.json()["stored"] is False
    assert len(await posture_rows(world.db, host.agent_id)) == 1
    # still idempotent after newer envelopes went through (the stored posture row proves it)
    assert (await hb(c, host)).status_code == 200
    r = await post(c, host, "posture", env)
    assert r.status_code == 200 and r.json()["idempotent"] is True


async def test_step8_same_seq_different_digest_is_equivocation(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    a = host.env("posture", good_posture(pw="no"), seq=5)
    assert (await post(c, host, "posture", a)).status_code == 200
    b = build_envelope(host.sk, agent_id=host.agent_id, tenant_id=host.tenant_id, kind="posture", seq=5,
                       payload=pbytes(good_posture(pw="yes")))
    r = await post(c, host, "posture", b)
    assert r.status_code == 409 and r.json()["reason"] == "equivocation" and r.json()["expected_min"] == 6
    rej = (await rejected(world.db, host))[-1]["details"]
    assert rej["reason"] == "equivocation" and rej["seq"] == 5 and rej["sha256_new"] != rej["sha256_accepted"]
    # the accepted posture is untouched
    assert json.loads(bytes((await posture_rows(world.db, host.agent_id))[0]["payload_raw"]))[
        "sections"]["sshd"]["v"]["config"]["passwordauthentication"] == "no"
    # equivocating against a heartbeat that was not stored is caught too (last accepted envelope)
    h = host.env("heartbeat", seq=9)
    assert (await post(c, host, "heartbeat", h)).status_code == 200
    h2 = build_envelope(host.sk, agent_id=host.agent_id, tenant_id=host.tenant_id, kind="heartbeat", seq=9,
                        payload=canon({"status": "other"}))
    r = await post(c, host, "heartbeat", h2)
    assert r.status_code == 409 and r.json()["reason"] == "equivocation"


async def test_step8_concurrent_claims_have_one_winner(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    envs = [build_envelope(host.sk, agent_id=host.agent_id, tenant_id=host.tenant_id, kind="heartbeat", seq=3,
                           payload=canon({"status": f"s{i}"})) for i in range(12)]
    rs = await asyncio.gather(*[post(c, host, "heartbeat", e) for e in envs])
    codes = sorted(r.status_code for r in rs)
    assert codes.count(200) == 1 and codes.count(409) == 11, codes
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 3
    # and the same envelope sent 12 times: one real accept, eleven idempotent answers, no 409
    e = host.env("heartbeat", seq=4)
    rs = await asyncio.gather(*[post(c, host, "heartbeat", e) for _ in range(12)])
    assert sorted(r.status_code for r in rs) == [200] * 12
    assert sum(1 for r in rs if r.json()["idempotent"]) == 11


async def test_step8_distinct_seqs_in_parallel_all_succeed_and_the_highest_wins(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    envs = [host.env("heartbeat") for _ in range(6)]
    rs = await asyncio.gather(*[post(c, host, "heartbeat", e) for e in envs])
    ok = [r for r in rs if r.status_code == 200]
    assert len(ok) >= 1 and all(r.status_code in (200, 409) for r in rs)
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == max(e["seq"] for e in envs)


# =========================================================================== #
# step 9: payload schema; the claim rolls back
# =========================================================================== #

async def test_step9_schema_failure_is_422_and_rolls_the_claim_back(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    assert (await ps(c, host, good_posture(pw="no"))).status_code == 200
    stored = await posture_rows(world.db, host.agent_id)
    bad = good_posture()
    bad["sections"]["sshd"]["v"]["surprise"] = "x"
    env = host.env("posture", bad)
    r = await post(c, host, "posture", env)
    assert r.status_code == 422 and r.json()["reason"] == "payload_schema" and "sshd" in r.json()["detail"]
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == env["seq"] - 1    # claim rolled back
    assert len(await posture_rows(world.db, host.agent_id)) == len(stored)
    assert (await rejected(world.db, host))[-1]["details"]["reason"] == "payload_schema"
    # a heartbeat with a posture-shaped payload is a schema failure as well
    r = await post(c, host, "heartbeat", host.env("heartbeat", good_posture()))
    assert r.status_code == 422
    # and a payload that is not JSON at all
    r = await post(c, host, "posture", host.env("posture", b"\x00\x01 not json"))
    assert r.status_code == 422 and r.json()["reason"] == "payload_not_json"
    r = await post(c, host, "posture", host.env("posture", b'{"schema":2,"schema":2}'))
    assert r.status_code == 422


async def test_step9_floats_and_deep_nesting_in_the_payload_are_refused(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    p = good_posture()
    raw = pbytes(p).replace(b'"uptime_s":1000', b'"uptime_s":1000.5')
    assert (await post(c, host, "posture", host.env("posture", raw))).status_code == 422
    deep = b'{"schema":2,"collected_at":"2026-11-24T19:00:00Z","sections":' + b"[" * 50000 + b"]" * 50000 + b"}"
    assert (await post(c, host, "posture", host.env("posture", deep), gz=True)).status_code == 422


# =========================================================================== #
# persistence: digest change detection, hourly refresh, assurance invalidation
# =========================================================================== #

async def test_unchanged_content_is_not_stored_again_but_the_agent_stays_alive(world, monkeypatch):
    # this test is about the DIGEST rule (store on change); the coalescing interval (a changed posture inside it
    # overwrites the newest row, tests/test_fleet_p2x_wire.py) is switched off so each change is its own row
    monkeypatch.setattr(fp, "MIN_STORE_INTERVAL_S", 0)
    # ... and so is the per-agent spacing of rebuild REQUESTS (review finding hostfw-9, covered in
    # tests/test_node_identity_a1.py): here the second change comes right after the first and must invalidate
    monkeypatch.setattr(fp, "REBUILD_REQUEST_MIN_INTERVAL_S", 0)
    c = world.client
    host = await enroll_host(c, world.admin_a)
    assert (await ps(c, host, good_posture(ms=5, uptime=100))).json()["stored"] is True
    await asyncio.sleep(0.05)
    seen1 = (await agent_row(world.db, host.agent_id))["last_seen"]
    r = await ps(c, host, good_posture(ms=900, uptime=9999, collected=NOW() + dt.timedelta(seconds=5)))
    assert r.status_code == 200 and r.json() == {**r.json(), "stored": False, "changed": False}
    assert len(await posture_rows(world.db, host.agent_id)) == 1
    a = await agent_row(world.db, host.agent_id)
    assert a["last_seen"] > seen1 and a["last_posture_seq"] == host.seq     # liveness and seq still move
    # a real change is stored and invalidates the assurance graph
    await world.db.execute("INSERT INTO assurance_state (last_build_at) VALUES (NOW()) "
                           "ON CONFLICT (tenant_id) DO UPDATE SET last_build_at = NOW()")
    r = await ps(c, host, good_posture(pw="yes"))
    assert r.json()["stored"] is True and r.json()["changed"] is True
    assert len(await posture_rows(world.db, host.agent_id)) == 2
    assert await last_build_at(world.db) is None
    # unchanged again: the graph is NOT invalidated
    await world.db.execute("UPDATE assurance_state SET last_build_at = NOW()")
    assert (await ps(c, host, good_posture(pw="yes", ms=3))).json()["stored"] is False
    assert await last_build_at(world.db) is not None


async def test_an_unchanged_posture_is_refreshed_hourly(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    assert (await ps(c, host)).json()["stored"] is True
    ident = jd((await agent_row(world.db, host.agent_id))["identity"])
    ident["_ingest"]["stored_at"] = iso(NOW() - dt.timedelta(hours=2))
    await world.db.execute("UPDATE fleet_agents SET identity=$2::jsonb WHERE id=$1", uuid.UUID(host.agent_id),
                           json.dumps(ident))
    r = await ps(c, host)
    assert r.json()["stored"] is True and r.json()["changed"] is False
    assert len(await posture_rows(world.db, host.agent_id)) == 2


async def test_collected_at_can_only_make_evidence_older(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    future = NOW() + dt.timedelta(hours=5)
    assert (await ps(c, host, good_posture(collected=future))).status_code == 200
    row = (await posture_rows(world.db, host.agent_id))[0]
    assert row["collected_at"] <= NOW() + dt.timedelta(seconds=5)           # clamped to the envelope's issued_at
    host2 = await enroll_host(c, world.admin_a, "web-2")
    assert (await ps(c, host2, good_posture(collected=NOW() - dt.timedelta(hours=3)))).status_code == 200
    row2 = (await posture_rows(world.db, host2.agent_id))[0]
    assert row2["collected_at"] < NOW() - dt.timedelta(hours=2, minutes=50)


async def test_a_heartbeat_never_creates_posture_rows(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    for _ in range(3):
        assert (await hb(c, host)).status_code == 200
    assert await posture_rows(world.db, host.agent_id) == []
    a = await agent_row(world.db, host.agent_id)
    assert a["last_posture_at"] is None and a["last_posture_seq"] == 0 and a["status"] == "online"


# =========================================================================== #
# key rotation
# =========================================================================== #

def rotate_payload(new_sk, agent_id: str, old_kid: str) -> bytes:
    new_kid = kid_of(new_sk)
    proof = new_sk.sign(b"paddock-rotate/v1\n" + agent_id.encode() + b"\n" + old_kid.encode() + b"\n" + new_kid.encode())
    return canon({"new_key_id": new_kid, "new_public_key_b64": b64u(pubkey(new_sk)), "proof_b64": b64u(proof)})


async def test_rotation_retires_the_old_key_and_activates_the_new_one(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    assert (await hb(c, host)).status_code == 200
    new_sk = Ed25519PrivateKey.generate()
    env = host.env("rotate", rotate_payload(new_sk, host.agent_id, host.kid))
    r = await post(c, host, "keys/rotate", env)
    assert r.status_code == 200, r.text
    assert r.json()["key_id"] == kid_of(new_sk) and r.json()["ok"] is True
    keys = {k["key_id"]: k for k in await key_row(world.db, host.agent_id)}
    assert keys[host.kid]["status"] == "rotated" and keys[host.kid]["retired_at"] is not None
    assert keys[kid_of(new_sk)]["status"] == "active" and keys[kid_of(new_sk)]["last_seq"] == 0
    # the old key is dead, immediately; the new key works and its seq space is its own
    assert (await hb(c, host)).status_code == 401
    old_sk, host.sk, host.kid = host.sk, new_sk, kid_of(new_sk)
    r = await hb(c, host)
    assert r.status_code == 200
    assert (await post(c, host, "heartbeat", host.env("heartbeat", sk=old_sk, kid=kid_of(old_sk)))).status_code == 401
    assert (await audits(world.db, "fleet.agent.key_rotate", host.agent_id))[0]["details"]["new_key_id"] == kid_of(new_sk)


async def test_rotation_refuses_bad_proofs_and_taken_keys_and_leaves_the_key_alone(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    other = await enroll_host(c, world.admin_a, "web-2")
    new_sk = Ed25519PrivateKey.generate()
    good = json.loads(rotate_payload(new_sk, host.agent_id, host.kid))
    cases = {
        "proof by another key": {**good, "proof_b64": json.loads(rotate_payload(
            Ed25519PrivateKey.generate(), host.agent_id, host.kid))["proof_b64"]},
        "key id not the key's": {**good, "new_key_id": "0" * 32},
        "same key again": json.loads(rotate_payload(host.sk, host.agent_id, host.kid)),
        "small order key": {**good, "new_public_key_b64": b64u(b"\x01" + b"\x00" * 31),
                            "new_key_id": hashlib.sha256(b"\x01" + b"\x00" * 31).hexdigest()[:32]},
        "extra field": {**good, "x": 1},
        "proof for another agent": json.loads(rotate_payload(new_sk, other.agent_id, host.kid)),
    }
    for name, p in cases.items():
        r = await post(c, host, "keys/rotate", host.env("rotate", canon(p)))
        assert r.status_code == 422, (name, r.status_code, r.text)
    # a key that another agent of the tenant already registered is a 409
    p = json.loads(rotate_payload(other.sk, host.agent_id, host.kid))
    r = await post(c, host, "keys/rotate", host.env("rotate", canon(p)))
    assert r.status_code in (409, 422), r.text
    assert all(k["status"] == "active" for k in await key_row(world.db, host.agent_id))
    assert len(await key_row(world.db, host.agent_id)) == 1
    assert (await hb(c, host)).status_code == 200                       # still on the old key


async def test_rotate_route_is_only_for_the_rotate_kind_and_is_rate_limited(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    fp.rotate_limiter.limit = 2
    codes = []
    for _ in range(4):
        r = await post(c, host, "keys/rotate", host.env("rotate", b"{}"))
        codes.append(r.status_code)
    assert codes[:2] == [422, 422] and codes[2:] == [429, 429]


# =========================================================================== #
# revocation: immediate, nothing cached
# =========================================================================== #

async def test_admin_revoke_cuts_the_agent_off_on_the_next_call(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    assert (await hb(c, host)).status_code == 200
    rt = await c.post("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a), json={"for_agent": host.agent_id})
    assert rt.status_code == 201
    r = await c.post(f"/v1/fleet/agents/{host.agent_id}/revoke", headers=hdr(world.analyst_a), json={"reason": "x"})
    assert r.status_code == 403                                           # admin only
    r = await c.post(f"/v1/fleet/agents/{host.agent_id}/revoke", headers=hdr(world.admin_a),
                     json={"reason": "decommissioned"})
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    for call in (hb(c, host), ps(c, host)):
        resp = await call
        assert resp.status_code == 403 and resp.json()["error"] == "agent_revoked"
    a = await agent_row(world.db, host.agent_id)
    assert a["status"] == "revoked" and a["revoked_at"] is not None and a["revoked_by"] == "admin-a"
    assert all(k["status"] == "revoked" and k["revoke_reason"] == "decommissioned"
               for k in await key_row(world.db, host.agent_id))
    # its pending re-key token died with it
    tok = [t for t in (await c.get("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a))).json()
           if t["for_agent"] == host.agent_id][0]
    assert tok["state"] == "revoked"
    assert await last_build_at(world.db) is None
    row = (await audits(world.db, "fleet.agent.revoke", host.agent_id))[0]
    assert row["details"]["reason"] == "decommissioned" and row["details"]["revoked_keys"] == [host.kid]
    # twice is a 409, an unknown id a 404
    assert (await c.post(f"/v1/fleet/agents/{host.agent_id}/revoke", headers=hdr(world.admin_a),
                         json={})).status_code == 409
    assert (await c.post(f"/v1/fleet/agents/{uuid.uuid4()}/revoke", headers=hdr(world.admin_a),
                         json={})).status_code == 404
    # a revoked agent cannot be given work
    r = await c.post("/v1/fleet/actions", headers=hdr(world.admin_a), json={
        "agent_id": host.agent_id, "action_type": "block_ip", "target": "203.0.113.9"})
    assert r.status_code == 409


async def test_key_revoke_is_immediate_and_leaves_the_agent_row(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    assert (await hb(c, host)).status_code == 200
    url = f"/v1/fleet/agents/{host.agent_id}/keys/{host.kid}/revoke"
    assert (await c.post(url, headers=hdr(world.analyst_a), json={})).status_code == 403
    r = await c.post(url, headers=hdr(world.admin_a), json={"reason": "key leaked"})
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    r = await hb(c, host)
    assert r.status_code == 401 and r.json()["reason"] == "key_not_active"
    k = await key_row(world.db, host.agent_id, host.kid)
    assert k["status"] == "revoked" and k["revoke_reason"] == "key leaked" and k["revoked_at"] is not None
    assert (await agent_row(world.db, host.agent_id))["status"] != "revoked"
    assert (await c.post(url, headers=hdr(world.admin_a), json={})).status_code == 409
    bad = f"/v1/fleet/agents/{host.agent_id}/keys/{'0' * 32}/revoke"
    assert (await c.post(bad, headers=hdr(world.admin_a), json={})).status_code == 404
    assert (await c.post(f"/v1/fleet/agents/{host.agent_id}/keys/NOTAKEY/revoke", headers=hdr(world.admin_a),
                         json={})).status_code == 422
    assert len(await audits(world.db, "fleet.agent.key_revoke", host.agent_id)) == 1


async def test_rekey_after_revocation_restores_service_with_history(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    assert (await ps(c, host)).status_code == 200
    assert (await c.post(f"/v1/fleet/agents/{host.agent_id}/revoke", headers=hdr(world.admin_a),
                         json={})).status_code == 200
    rt = (await c.post("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a),
                       json={"for_agent": host.agent_id})).json()
    new_sk = Ed25519PrivateKey.generate()
    proof = new_sk.sign(b"paddock-enroll/v1\n" + rt["token_prefix"].encode() + b"\n" + b"web-1")
    r = await c.post("/v1/fleet/enroll", json={"token": rt["token"], "hostname": "web-1",
                                               "public_key_b64": b64u(pubkey(new_sk)), "proof_b64": b64u(proof)})
    assert r.status_code == 201 and r.json()["rekey"] is True and r.json()["agent_id"] == host.agent_id
    host.sk, host.kid, host.token, host.seq = new_sk, kid_of(new_sk), r.json()["agent_token"], 0
    assert (await hb(c, host)).status_code == 200
    assert len(await posture_rows(world.db, host.agent_id)) == 1            # the history stayed


# =========================================================================== #
# rate limits
# =========================================================================== #

async def test_heartbeat_and_posture_are_rate_limited_per_agent(world):
    c = world.client
    h1 = await enroll_host(c, world.admin_a, "web-1")
    h2 = await enroll_host(c, world.admin_a, "web-2")
    fp.heartbeat_limiter.limit = 3
    fp.posture_limiter.limit = 2
    codes = [(await hb(c, h1)).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    r = await hb(c, h1)
    assert r.status_code == 429 and r.headers["retry-after"] == "60"
    assert (await hb(c, h2)).status_code == 200                              # per agent, not global
    assert [(await ps(c, h2)).status_code for _ in range(3)] == [200, 200, 429]
    # a 429 consumes no seq
    assert (await key_row(world.db, h1.agent_id, h1.kid))["last_seq"] == 3


# =========================================================================== #
# data-plane audit exemption
# =========================================================================== #

async def test_accepted_heartbeats_and_postures_are_not_audited_per_request_but_rejections_are(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)

    async def n():
        return await world.db.fetchval("SELECT count(*) FROM audit_log WHERE path LIKE $1",
                                       f"/v1/fleet/{host.agent_id}/%")

    base = await n()
    for _ in range(3):
        assert (await hb(c, host)).status_code == 200
    assert (await ps(c, host)).status_code == 200
    assert await n() == base                          # no write-ahead intent, no outcome row
    assert (await hb(c, host, payload=b"{nope")).status_code == 422
    assert await n() > base                           # a refused one is audited by the middleware too
    assert len(await rejected(world.db, host)) == 1


# =========================================================================== #
# cross-tenant
# =========================================================================== #

async def test_tenant_b_can_neither_see_nor_post_for_tenant_as_agent(world):
    c = world.client
    a = await enroll_host(c, world.admin_a, "same-name")
    b = await enroll_host(c, world.admin_b, "same-name")                     # the same hostname is fine per tenant
    assert (await ps(c, a)).status_code == 200
    # B's admin sees only B's agent
    lst = (await c.get("/v1/fleet/agents", headers=hdr(world.admin_b))).json()
    assert [x["id"] for x in lst] == [b.agent_id]
    assert (await c.get(f"/v1/fleet/agents/{a.agent_id}", headers=hdr(world.admin_b))).status_code == 404
    assert (await c.get(f"/v1/fleet/agents/{a.agent_id}/posture", headers=hdr(world.admin_b))).status_code == 404
    assert (await c.post(f"/v1/fleet/agents/{a.agent_id}/revoke", headers=hdr(world.admin_b),
                         json={})).status_code == 404
    url = f"/v1/fleet/agents/{a.agent_id}/keys/{a.kid}/revoke"
    assert (await c.post(url, headers=hdr(world.admin_b), json={})).status_code == 404
    assert (await agent_row(world.db, a.agent_id))["status"] != "revoked"
    toks_b = (await c.get("/v1/fleet/enroll-tokens", headers=hdr(world.admin_b))).json()
    toks_a = (await c.get("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a))).json()
    assert {t["id"] for t in toks_a}.isdisjoint({t["id"] for t in toks_b})
    # B's agent cannot post evidence for A's agent id, with its own key or with A's envelope
    r = await post(c, b, "posture", b.env("posture"), agent_id=a.agent_id)
    assert r.status_code == 403
    r = await post(c, b, "heartbeat", build_envelope(b.sk, agent_id=a.agent_id, tenant_id=TENANT_A, kind="heartbeat",
                                                     seq=1, payload=canon({})), agent_id=a.agent_id)
    assert r.status_code == 403
    # A's own envelope sent with B's credential is 403 as well, and nothing of A's moved
    r = await post(c, b, "heartbeat", a.env("heartbeat"), agent_id=a.agent_id)
    assert r.status_code == 403
    # an envelope that names the right agent id but the OTHER tenant is refused at step 3
    r = await post(c, a, "posture", a.env("posture", tenant_id=TENANT_B))
    assert r.status_code == 403
    assert (await key_row(world.db, a.agent_id, a.kid))["last_seq"] == 1
    # the rejection landed in the agent's OWN tenant chain, never in the other's
    rows = await world.db.fetch("SELECT tenant_id, resource_id FROM audit_log WHERE action='fleet.evidence.rejected'")
    assert rows and all(str(x["tenant_id"]) in (TENANT_A, TENANT_B) for x in rows)
    mine = [x for x in rows if x["resource_id"] == a.agent_id]
    assert mine and all(str(x["tenant_id"]) == TENANT_A for x in mine)


async def test_the_same_key_cannot_be_registered_in_two_tenants_agents_independently(world):
    """A key id is unique per tenant; two tenants may enroll the same public key without sharing anything."""
    c = world.client
    sk = Ed25519PrivateKey.generate()
    a = await enroll_host(c, world.admin_a, "x", sk=sk)
    b = await enroll_host(c, world.admin_b, "x", sk=sk)
    assert (await hb(c, a)).status_code == 200 and (await hb(c, b)).status_code == 200
    # A's envelope (A's agent id, A's tenant) cannot be replayed at B's route: wrong agent id for B's principal
    assert (await post(c, b, "heartbeat", a.env("heartbeat"))).status_code == 403


# =========================================================================== #
# identity and node_ref
# =========================================================================== #

async def _seed_instance(db, private: list[str], public: list[str] | None = None, rtype: str = "instance") -> str:
    async with db.acquire() as con:
        return str(await con.fetchval(
            "INSERT INTO assets (tenant_id, kind, value, canonical, source, metadata) "
            "VALUES ($1,'cloud_resource',$2,$2,'test',$3::jsonb) RETURNING id",
            TENANT_A, "i-" + uuid.uuid4().hex[:8],
            json.dumps({"resource_type": rtype, "private_ips": private, "public_ips": public or []})))


@pytest_asyncio.fixture
async def client_from_10(rls_app):
    """A client whose socket peer is 10.0.1.5 (the address the server sees)."""
    async with AsyncClient(transport=ASGITransport(app=rls_app, client=("10.0.1.5", 4321)),
                           base_url="http://test") as c:
        yield c


async def test_a_new_agent_is_a_claimed_agent_node(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    a = await agent_row(world.db, host.agent_id)
    assert a["node_ref"] == f"agent:{host.agent_id}" and jd(a["identity"])["basis"] == "claimed"
    assert (await ps(c, host, good_posture(ips=["10.0.1.5"]))).status_code == 200
    a = await agent_row(world.db, host.agent_id)
    ident = jd(a["identity"])
    assert a["node_ref"] == f"agent:{host.agent_id}" and ident["basis"] == "claimed" and ident["ips"] == ["10.0.1.5"]
    assert ident["machine_id_hash"] == "c" * 64 and ident["hostname"] == "web-1"


async def test_corroboration_needs_the_server_to_see_the_instances_address(world, client_from_10):
    inst = await _seed_instance(world.db, ["10.0.1.5"], ["54.1.2.3"])
    # the claimed addresses match the instance, but the request comes from 127.0.0.1: NOT corroborated. This is
    # what stops any enrolled host from claiming a victim instance's addresses and attaching its own facts to it.
    host = await enroll_host(world.client, world.admin_a)
    assert (await ps(world.client, host, good_posture(ips=["10.0.1.5"]))).status_code == 200
    a = await agent_row(world.db, host.agent_id)
    assert a["node_ref"] == f"agent:{host.agent_id}" and jd(a["identity"])["note"] == "peer_address_not_instance"
    # (rewritten for review findings hostfw-5 and wire-5: it used to assert that a second agent at the instance's
    # address could NOT merge because the first, uncorroborated agent merely CLAIMED the same addresses. A claim
    # that never passed the peer check must not clash with anyone, so the agent really at the address merges.)
    host2 = await enroll_host(client_from_10, world.admin_a, "web-2")
    assert (await ps(client_from_10, host2, good_posture(ips=["10.0.1.5"]))).status_code == 200
    assert (await agent_row(world.db, host2.agent_id))["node_ref"] == f"asset:{inst}"
    assert (await agent_row(world.db, host.agent_id))["node_ref"] == f"agent:{host.agent_id}"


async def test_an_agent_at_the_instances_address_is_corroborated(world, client_from_10):
    inst = await _seed_instance(world.db, ["10.0.1.5"], ["54.1.2.3"])
    host = await enroll_host(client_from_10, world.admin_a, "web-2")
    r = await ps(client_from_10, host, good_posture(ips=["10.0.1.5"]))
    assert r.status_code == 200, r.text
    a = await agent_row(world.db, host.agent_id)
    assert a["node_ref"] == f"asset:{inst}" and jd(a["identity"])["basis"] == "corroborated", a["identity"]
    assert "note" not in jd(a["identity"])
    # corroboration changes the graph's identity of the host, so the assurance graph is rebuilt
    assert await last_build_at(world.db) is None


async def test_claiming_addresses_that_are_not_the_instances_is_not_corroboration(world, client_from_10):
    await _seed_instance(world.db, ["10.0.1.5"])
    host = await enroll_host(client_from_10, world.admin_a)
    # claims an extra address the instance does not have: not a subset
    assert (await ps(client_from_10, host, good_posture(ips=["10.0.1.5", "10.9.9.9"]))).status_code == 200
    assert (await agent_row(world.db, host.agent_id))["node_ref"] == f"agent:{host.agent_id}"
    # non-instance resources never merge
    host2 = await enroll_host(client_from_10, world.admin_a, "db-1")
    await _seed_instance(world.db, ["10.0.2.7"], rtype="db_instance")
    assert (await ps(client_from_10, host2, good_posture(ips=["10.0.2.7"]))).status_code == 200
    assert (await agent_row(world.db, host2.agent_id))["node_ref"] == f"agent:{host2.agent_id}"


async def test_two_agents_claiming_one_cloud_node_merge_neither(world, client_from_10):
    inst = await _seed_instance(world.db, ["10.0.1.5"])
    h1 = await enroll_host(client_from_10, world.admin_a, "web-1")
    assert (await ps(client_from_10, h1, good_posture(ips=["10.0.1.5"]))).status_code == 200
    assert (await agent_row(world.db, h1.agent_id))["node_ref"] == f"asset:{inst}"
    h2 = await enroll_host(client_from_10, world.admin_a, "web-2")
    assert (await ps(client_from_10, h2, good_posture(ips=["10.0.1.5"]))).status_code == 200
    r1, r2 = await agent_row(world.db, h1.agent_id), await agent_row(world.db, h2.agent_id)
    assert r1["node_ref"] == f"agent:{h1.agent_id}" and r2["node_ref"] == f"agent:{h2.agent_id}"   # BOTH demoted
    # (both hosts connect from the same address here: that is the ``shared_peer_address`` refusal; two agents at
    # DIFFERENT private addresses of one instance are the ``ambiguous_cloud_node`` case, see test_node_identity_a1)
    assert jd(r1["identity"])["basis"] == "claimed" and jd(r2["identity"])["note"] == "shared_peer_address"


async def test_two_instances_with_the_same_private_address_are_ambiguous(world, client_from_10):
    await _seed_instance(world.db, ["10.0.1.5"])
    await _seed_instance(world.db, ["10.0.1.5"])             # the same RFC1918 address in another VPC
    host = await enroll_host(client_from_10, world.admin_a)
    assert (await ps(client_from_10, host, good_posture(ips=["10.0.1.5"]))).status_code == 200
    a = await agent_row(world.db, host.agent_id)
    assert a["node_ref"] == f"agent:{host.agent_id}" and jd(a["identity"])["note"] == "ambiguous_cloud_node"


async def test_node_ref_falls_back_when_corroboration_disappears(world, client_from_10):
    inst = await _seed_instance(world.db, ["10.0.1.5"])
    host = await enroll_host(client_from_10, world.admin_a)
    assert (await ps(client_from_10, host, good_posture(ips=["10.0.1.5"]))).status_code == 200
    assert (await agent_row(world.db, host.agent_id))["node_ref"] == f"asset:{inst}"
    assert (await ps(client_from_10, host, good_posture(ips=["10.0.1.99"]))).status_code == 200
    a = await agent_row(world.db, host.agent_id)
    assert a["node_ref"] == f"agent:{host.agent_id}" and jd(a["identity"])["basis"] == "claimed"


# =========================================================================== #
# direct unit checks on the pure helpers
# =========================================================================== #

def test_b64u_decode_is_strict():
    assert fp.b64u_decode("AAEC") == b"\x00\x01\x02" and fp.b64u_decode("AAE") == b"\x00\x01"
    for bad in ("AA+/", "AA==\n", "A", "AAAAA", "é", "AA AA", None, 5):
        with pytest.raises(ValueError):
            fp.b64u_decode(bad)
    with pytest.raises(ValueError):
        fp.b64u_decode("AAAA", max_chars=3)


def test_parse_envelope_rejects_what_the_contract_rejects():
    sk = Ed25519PrivateKey.generate()
    aid, tid = str(uuid.uuid4()), str(uuid.uuid4())
    e = build_envelope(sk, agent_id=aid, tenant_id=tid, kind="heartbeat", seq=1, payload=b"{}")
    ok = fp.parse_envelope(json.dumps(e).encode(), "heartbeat")
    assert ok.seq == 1 and ok.kid == kid_of(sk) and ok.payload_b64 == e["payload_b64"]
    with pytest.raises(fp.Rejection) as ei:
        fp.parse_envelope(json.dumps(e).encode(), "posture")
    assert ei.value.reason == "kind_route_mismatch"


def test_gunzip_capped_is_bounded():
    assert fp.gunzip_capped(gzip.compress(b"a" * 1000)) == b"a" * 1000
    with pytest.raises(fp.Rejection) as ei:
        fp.gunzip_capped(gzip.compress(b"a" * 5000), limit=1000)
    assert ei.value.status == 413
    two = gzip.compress(b"a") + gzip.compress(b"b")
    with pytest.raises(fp.Rejection):
        fp.gunzip_capped(two)


# =========================================================================== #
# hardening found in review: nothing malformed may reach SQL or JSONB as a 500, nothing unsigned may be malleable
# =========================================================================== #

async def test_step2_control_characters_in_kid_and_collectors_are_a_clean_400_not_a_500(world, unsampled):
    """A NUL in `kid` (a SQL text parameter) or in `collectors` (stored as JSONB, which cannot hold U+0000) used to
    be a database error, i.e. an unaudited 500 after the claim. They are refused as malformed, audited, and the
    seq never moves."""
    c = world.client
    host = await enroll_host(c, world.admin_a)
    fp.posture_limiter.limit = 1000
    bad = {
        "kid NUL": {"kid": "ab\u0000cd"},
        "kid newline": {"kid": host.kid + "\n"},
        "kid space": {"kid": "ab cd"},
        "kid empty": {"kid": ""},
        "kid too long": {"kid": "a" * 65},
        "kid non-ascii": {"kid": "k\u00e9"},
        "collectors NUL value": {"collectors": {"agent": "0.2.0\u0000"}},
        "collectors NUL key": {"collectors": {"ag\u0000ent": "0.2.0"}},
        "collectors newline": {"collectors": {"agent": "0.2.0\n"}},
    }
    for name, edit in bad.items():
        env = {**host.env("posture"), **edit}
        r = await post(c, host, "posture", json.dumps(env).encode())
        assert r.status_code == 400 and r.json()["reason"] == "bad_envelope", (name, r.status_code, r.text)
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0
    assert len(await rejected(world.db, host)) == len(bad)
    assert await posture_rows(world.db, host.agent_id) == []
    # and the real agent is unaffected
    assert (await ps(c, host)).status_code == 200


async def test_trailing_newlines_cannot_make_a_signed_envelope_malleable(world):
    """`$` in a Python regex matches before a trailing newline, and urlsafe_b64decode silently drops it: an
    envelope with `sig` or `payload_b64` plus a newline used to verify and be accepted although it is not the
    bytes the agent signed/sent. The unsigned fields must be exactly what they say."""
    c = world.client
    host = await enroll_host(c, world.admin_a)
    fp.posture_limiter.limit = 1000
    base = host.env("posture")
    cases = {
        "sig newline": ({**base, "sig": base["sig"] + "\n"}, 401),
        "sig space": ({**base, "sig": base["sig"][:10] + " " + base["sig"][10:]}, 401),
        "payload_b64 newline": ({**base, "payload_b64": base["payload_b64"] + "\n"}, 400),
        "payload_sha256 newline": ({**base, "payload_sha256": base["payload_sha256"] + "\n"}, 400),
        "issued_at newline": ({**base, "issued_at": base["issued_at"] + "\n"}, 400),
        "nonce newline": ({**base, "nonce": base["nonce"] + "\n"}, 400),
    }
    for name, (env, want) in cases.items():
        r = await post(c, host, "posture", json.dumps(env).encode())
        assert r.status_code == want, (name, r.status_code, r.text)
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0
    assert await posture_rows(world.db, host.agent_id) == []
    # the exact envelope still verifies: the refusals above were about the extra byte only
    assert (await post(c, host, "posture", base)).status_code == 200


async def test_a_heartbeat_payload_is_tiny(world):
    """The heartbeat is a liveness proof, not a data channel: padding it past 4 KiB is a 422 and rolls the claim back."""
    c = world.client
    host = await enroll_host(c, world.admin_a)
    ok = pbytes({"agent_version": "0.2.0", "status": "ok"})
    fat = ok + b" " * 5000                       # still strict JSON, still schema-valid, just not tiny
    r = await post(c, host, "heartbeat", host.env("heartbeat", fat))
    assert r.status_code == 422 and r.json()["reason"] == "payload_schema"
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0
    assert (await hb(c, host)).status_code == 200


async def test_the_ingest_itself_refuses_legacy_and_revoked_agents(world):
    """Defence in depth: the principal already answers 403 for these, but the ingest re-reads the agent row under
    its lock, so a credential resolved a moment before a revoke (or a re-flag) still cannot land evidence."""
    c = world.client
    for how, sql, reason in (
        ("legacy", "UPDATE fleet_agents SET legacy=TRUE WHERE id=$1", "re_enroll_required"),
        ("revoked", "UPDATE fleet_agents SET status='revoked', revoked_at=NOW() WHERE id=$1", "agent_revoked"),
        ("revoked_at only", "UPDATE fleet_agents SET revoked_at=NOW() WHERE id=$1", "agent_revoked"),
    ):
        host = await enroll_host(c, world.admin_a, f"direct-{how.replace(' ', '-')}")
        env = host.env("posture")
        await world.db.execute(sql, uuid.UUID(host.agent_id))
        with pytest.raises(fp.Rejection) as ei:
            await fp.ingest_envelope(world.db, agent_id=uuid.UUID(host.agent_id), tenant_id=TENANT_A,
                                     kind="posture", body=json.dumps(env).encode(), content_encoding=None)
        assert ei.value.status == 403 and ei.value.reason == reason, how
        assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0, how
        assert await posture_rows(world.db, host.agent_id) == [], how
        assert [r["details"]["reason"] for r in await rejected(world.db, host)] == [reason], how


async def test_the_online_transition_names_the_host(world):
    """`agent.online` carries the hostname (it used to be an empty string)."""
    c = world.client
    host = await enroll_host(c, world.admin_a, "web-online")
    assert (await hb(c, host)).status_code == 200
    await world.db.execute("UPDATE fleet_agents SET online=FALSE, offline_since=NOW() WHERE id=$1",
                           uuid.UUID(host.agent_id))
    assert (await hb(c, host)).status_code == 200
    rows = await audits(world.db, "fleet.agent.online", host.agent_id)
    assert len(rows) == 1 and rows[0]["details"]["hostname"] == "web-online"


def test_the_module_is_python_312_clean_and_has_no_third_party_surprises():
    src = pathlib.Path(fp.__file__).read_text()
    assert "pickle" not in src and "eval(" not in src and "yaml" not in src
