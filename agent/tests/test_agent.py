"""The agent core against a fake orchestrator that enforces contract section 2 in order."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import types

import pytest

from paddock_agent import __version__, envelope, signing
from paddock_agent.actions import Action
from paddock_agent.agent import (
    EXIT_OK,
    EXIT_RE_ENROLL,
    MAX_AUTH_FAILURES,
    Agent,
    AgentError,
)
from paddock_agent.client import FleetClient, FleetClientError
from paddock_agent.config import AgentConfig
from paddock_agent.state import State, StateError
from tests.fake_fleet import FakeFleet


class Clock:
    """One mutable timeline for wall clock, monotonic clock and sleeping."""

    def __init__(self, t=1_790_000_000.0):
        self.t = t
        self.slept = []

    def time(self):
        return self.t

    def mono(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


SERVER_IP = "192.0.2.10"


def fake_resolver(host, port, *args, **kwargs):
    """The fake server's name resolves to a documentation address (the self-lockout guard resolves it)."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (SERVER_IP, port))]


def collect_stub(ctx):
    return {"schema": 2, "collected_at": envelope.issued_at_iso(1_790_000_000),
            "sections": {"self": {"s": "ok", "conf": "exact", "partial": False,
                                  "v": {"seq": ctx.seq, "key_id": ctx.key_id}}}}


class Rig:
    def __init__(self, tmp_path, *, dry_run=False, enforcer=None, collect=collect_stub, fleet=None, **cfg):
        self.clock = Clock()
        self.fleet = fleet or FakeFleet(now=self.clock.time)
        self.fleet.now = self.clock.time
        self.ctxs = []
        self.cfg = AgentConfig(server="https://paddock.test", state_dir=str(tmp_path / "state"),
                               quarantine_dir=str(tmp_path / "q"), dry_run=dry_run, heartbeat_interval_s=30,
                               posture_interval_s=300, inventory_interval_s=0, platform_name="linux", **cfg)
        os.makedirs(self.cfg.state_dir, mode=0o700, exist_ok=True)
        os.chmod(self.cfg.state_dir, 0o700)
        self.client = FleetClient("https://paddock.test", transport=self.fleet.transport)

        def ctx_factory(seq, key_id):
            ctx = types.SimpleNamespace(seq=seq, key_id=key_id, known_manifest_sha="unset",
                                        force_full_manifest="unset")
            self.ctxs.append(ctx)
            return ctx

        self.agent = Agent(self.cfg, client=self.client, enforcer=enforcer, collect_fn=collect,
                           encode_fn=envelope.canon, ctx_factory=ctx_factory, clock=self.clock.time,
                           monotonic=self.clock.mono, rand=lambda: 0.5, resolver=fake_resolver)

    @property
    def state(self):
        return self.agent.state

    def enroll(self):
        return self.agent.enroll(self.fleet.token, hostname="web-01.example")

    def fresh_agent(self, **kw):
        """A new process over the same state dir (what a restart looks like)."""
        a = Agent(self.cfg, client=FleetClient("https://paddock.test", transport=self.fleet.transport),
                  collect_fn=collect_stub, encode_fn=envelope.canon,
                  ctx_factory=lambda seq, key_id: types.SimpleNamespace(
                      seq=seq, key_id=key_id, known_manifest_sha=None, force_full_manifest=False),
                  clock=self.clock.time, monotonic=self.clock.mono, rand=lambda: 0.5,
                  resolver=fake_resolver, **kw)
        return a


@pytest.fixture
def rig(tmp_path):
    r = Rig(tmp_path)
    r.enroll()
    return r


# --------------------------------------------------------------------------- #
# enrollment
# --------------------------------------------------------------------------- #

def test_enroll_registers_a_fresh_key_with_proof_and_stores_secrets_privately(tmp_path):
    r = Rig(tmp_path)
    creds = r.enroll()
    f = r.fleet
    assert creds.agent_id == f.agent_id and creds.tenant_id == f.tenant_id and creds.hostname == "web-01.example"
    kid = f.active_key()
    assert creds.key_id == kid == r.agent.key_id
    assert signing.key_id(signing.public_key(r.state.load_key())) == kid
    for path in (r.state.cred_path, r.state.key_path):
        assert os.stat(path).st_mode & 0o777 == 0o600
    assert r.state.load_pending_key() is None
    # the one-time token is on no disk file anywhere
    for root, _d, files in os.walk(r.cfg.state_dir):
        for name in files:
            assert f.token.encode() not in open(os.path.join(root, name), "rb").read()


def test_enroll_request_carries_no_agent_header_and_the_proof_verifies(tmp_path):
    r = Rig(tmp_path)
    seen = {}
    real = r.fleet.handle

    def spy(method, path, headers, body):
        if path.endswith("/enroll"):
            seen["headers"], seen["body"] = headers, json.loads(body)
        return real(method, path, headers, body)

    r.fleet.handle = spy
    r.enroll()
    assert "X-Agent-Token" not in seen["headers"]
    assert set(seen["body"]) == {"token", "hostname", "public_key_b64", "proof_b64", "agent_version",
                                 "capabilities"}
    assert seen["body"]["agent_version"] == __version__ and seen["body"]["hostname"] == "web-01.example"


def test_enroll_refuses_a_malformed_token_before_any_network_call(tmp_path):
    r = Rig(tmp_path)
    for bad in ("", "not-a-token", "fat_0123456789ab_" + "x" * 30):
        with pytest.raises(AgentError):
            r.agent.enroll(bad, hostname="web-01")
    assert r.fleet.requests == []


def test_enroll_refuses_unusable_hostnames(tmp_path):
    r = Rig(tmp_path)
    for bad in ("has space", "semi;colon", "x" * 300, "café"):
        with pytest.raises(AgentError):
            r.agent.enroll(r.fleet.token, hostname=bad)
    assert r.fleet.requests == []


def test_failed_enroll_leaves_no_key_and_no_credentials(tmp_path):
    r = Rig(tmp_path)
    r.fleet.token_used = True                      # the server will answer 401
    with pytest.raises(FleetClientError) as e:
        r.agent.enroll(r.fleet.token, hostname="web-01")
    assert e.value.status == 401
    assert r.state.load_credentials() is None and r.state.load_key() is None
    assert r.state.load_pending_key() is None and r.agent.creds is None


def test_enroll_network_failure_discards_the_pending_key(tmp_path):
    r = Rig(tmp_path)
    r.fleet.fail.append(ConnectionRefusedError("down"))
    with pytest.raises(FleetClientError):
        r.agent.enroll(r.fleet.token, hostname="web-01")
    assert r.state.load_pending_key() is None and r.state.load_credentials() is None


def test_enroll_reply_without_a_tenant_is_refused_and_nothing_is_kept(tmp_path):
    r = Rig(tmp_path)
    r.fleet.omit_tenant = True
    with pytest.raises(AgentError, match="tenant_id"):
        r.enroll()
    assert r.state.load_credentials() is None and r.state.load_key() is None


def test_enroll_reply_with_a_different_key_id_is_refused(tmp_path):
    r = Rig(tmp_path)
    real = r.fleet._enroll

    def lie(body):
        status, h, out = real(body)
        out["key_id"] = "0" * 32
        return status, h, out

    r.fleet._enroll = lie
    with pytest.raises(AgentError, match="different key"):
        r.enroll()
    assert r.state.load_credentials() is None


def test_already_enrolled_needs_force_and_force_makes_a_new_key_keeping_the_counter(rig):
    old_kid = rig.agent.key_id
    rig.agent.heartbeat()
    seq_before = rig.state.current_seq()
    with pytest.raises(AgentError, match="already enrolled"):
        rig.agent.enroll(rig.fleet.new_token(), hostname="web-01.example")
    rig.agent.enroll(rig.fleet.token, hostname="web-01.example", force=True)
    assert rig.agent.key_id != old_kid and rig.fleet.active_key() == rig.agent.key_id
    assert rig.state.current_seq() == seq_before                   # monotonic across re-enrollment
    rig.agent.heartbeat()                                           # new key works


def test_wiped_state_means_not_enrolled_until_a_fresh_token_is_used(rig, tmp_path):
    import shutil
    shutil.rmtree(rig.cfg.state_dir)
    fresh = rig.fresh_agent()
    with pytest.raises(AgentError, match="not enrolled"):
        fresh.run(max_iterations=1, sleep=lambda s: None)
    with pytest.raises(AgentError):
        fresh.heartbeat()
    old_kid = rig.fleet.active_key()
    fresh.enroll(rig.fleet.new_token(), hostname="web-01.example", force=True)
    assert fresh.key_id != old_kid and rig.fleet.keys[old_kid]["status"] == "revoked"
    fresh.heartbeat()


# --------------------------------------------------------------------------- #
# signed heartbeat and posture
# --------------------------------------------------------------------------- #

def test_heartbeat_is_a_verifiable_signed_envelope_with_write_ahead_seq(rig):
    rig.agent.heartbeat()
    rig.agent.heartbeat()
    kinds = [k for k, _ in rig.fleet.accepted]
    assert kinds == ["heartbeat", "heartbeat"]
    e1, e2 = rig.fleet.accepted[0][1], rig.fleet.accepted[1][1]
    assert (e1["seq"], e2["seq"]) == (1, 2) and e1["nonce"] != e2["nonce"]
    assert e1["tenant_id"] == rig.fleet.tenant_id and e1["agent_id"] == rig.fleet.agent_id
    assert e1["kid"] == rig.agent.key_id and e1["payload_type"] == envelope.PAYLOAD_TYPE_HEARTBEAT
    assert envelope.verify_envelope(e1, rig.fleet.keys[e1["kid"]]["pub"])
    assert json.loads(envelope.b64u_decode(e1["payload_b64"])) == {"agent_version": __version__, "status": "ok"}
    # heartbeats carry the agent token header and the seq as idempotency key
    hb = [q for q in rig.fleet.requests if q[1].endswith("/heartbeat")][0]
    assert hb[2]["X-Agent-Token"] == rig.fleet.agent_token and hb[2]["Idempotency-Key"] == "1"


def test_posture_signs_the_exact_collector_bytes_and_tells_the_collectors_its_seq(rig):
    rig.agent.send_posture()
    kind, env = rig.fleet.accepted[0]
    assert kind == "posture" and env["payload_type"] == envelope.PAYLOAD_TYPE_POSTURE
    payload = envelope.b64u_decode(env["payload_b64"])
    ctx = rig.ctxs[-1]
    assert ctx.seq == env["seq"] and ctx.key_id == env["kid"]
    assert payload == envelope.canon(collect_stub(ctx))                       # exact bytes, no re-serialising
    assert env["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert env["collectors"]["agent"] == __version__
    assert {"sshd", "listeners", "firewall", "patch", "self"} <= set(env["collectors"])
    assert envelope.verify_envelope(env, rig.fleet.keys[env["kid"]]["pub"])


def test_a_collector_crash_sends_nothing_and_does_not_stop_the_loop(tmp_path):
    def boom(ctx):
        raise RuntimeError("collector bug")
    r = Rig(tmp_path, collect=boom)
    r.enroll()
    assert r.agent.step() == "ok"                                    # logged; the heartbeat is unaffected
    assert [k for k, _ in r.fleet.accepted] == ["heartbeat"]         # no posture was invented
    assert r.agent.stats["posture_errors"] == 1
    # a permanently broken collector must not drag the heartbeat cadence into backoff (silence = offline)
    r.clock.slept.clear()
    r.agent.run(max_iterations=12, sleep=r.clock.sleep)
    assert all(27 <= d <= 33 for d in r.clock.slept)
    assert [k for k, _ in r.fleet.accepted].count("heartbeat") == 13
    assert "posture" not in [k for k, _ in r.fleet.accepted]


def test_an_oversize_payload_is_never_signed(tmp_path):
    r = Rig(tmp_path, collect=lambda ctx: {"schema": 2, "collected_at": "x", "sections": {"x": "A" * (3 << 20)}})
    r.enroll()
    assert r.agent.step() == "ok"
    assert [k for k, _ in r.fleet.accepted] == ["heartbeat"]


def test_manifest_digest_is_acknowledged_only_after_the_server_accepted_the_posture(tmp_path):
    sha = "a" * 64

    def with_manifest(ctx):
        d = collect_stub(ctx)
        d["sections"]["patch"] = {"s": "ok", "v": {"manifest": {"state": "ok", "sha256": sha, "full": True}}}
        return d

    r = Rig(tmp_path, collect=with_manifest)
    r.enroll()
    r.fleet.fail.append(503)
    with pytest.raises(FleetClientError):
        r.agent.send_posture()
    assert r.agent._known_manifest is None                 # not acknowledged: the server may not have it
    r.agent.send_posture()
    assert r.agent._known_manifest == sha
    r.agent.send_posture()
    assert r.ctxs[-1].known_manifest_sha == sha


def test_machine_salt_is_tenant_scoped_and_never_the_raw_id(rig):
    assert rig.agent._machine_salt() == ("paddock-machine/v1:%s" % rig.fleet.tenant_id).encode()


# --------------------------------------------------------------------------- #
# the loop survives the network
# --------------------------------------------------------------------------- #

def test_run_survives_connection_errors_backs_off_and_recovers(rig):
    clock = rig.clock
    rig.fleet.fail.extend([ConnectionRefusedError("refused")] * 4)
    code = rig.agent.run(max_iterations=8, sleep=clock.sleep)         # must not raise
    assert code == EXIT_OK
    delays = clock.slept
    assert len(delays) == 7
    failing, recovered = delays[:4], delays[4:]
    assert all(5 <= d <= 300 for d in failing)
    assert failing[3] > failing[0]                                    # exponential growth
    assert all(27 <= d <= 33 for d in recovered)                      # back to the heartbeat cadence
    assert [k for k, _ in rig.fleet.accepted].count("heartbeat") >= 3
    assert "posture" in [k for k, _ in rig.fleet.accepted]            # and the posture got through


def test_backoff_never_exceeds_300_seconds_over_a_long_outage(rig):
    rig.fleet.fail.extend([TimeoutError("t")] * 60)
    rig.agent.run(max_iterations=40, sleep=rig.clock.sleep)
    assert max(rig.clock.slept) <= 300.0 and rig.clock.slept[-1] >= 150.0


def test_every_failure_class_is_survived_by_the_loop(rig):
    rig.fleet.fail.extend([503, ConnectionResetError("x"), 502, OSError("x"), 500])
    assert rig.agent.run(max_iterations=7, sleep=rig.clock.sleep) == EXIT_OK


def test_a_failed_posture_is_requeued_and_resent_byte_identical_before_anything_newer(rig):
    rig.agent.heartbeat()
    # heartbeat ok; now the posture POST hits a 503
    real = rig.fleet.handle
    state = {"n": 0}

    def flaky(method, path, headers, body):
        if path.endswith("/posture") and state["n"] == 0:
            state["n"] = 1
            return 503, {}, {"detail": "busy"}
        return real(method, path, headers, body)

    rig.fleet.handle = flaky
    with pytest.raises(FleetClientError):
        rig.agent.send_posture()
    assert len(rig.state.outbox) == 1
    queued = rig.state.outbox.read(rig.state.outbox.files()[0])["envelope"]
    assert rig.agent.flush_outbox() == "ok" and len(rig.state.outbox) == 0
    sent = [e for k, e in rig.fleet.accepted if k == "posture"][0]
    assert sent == queued                                              # the SAME bytes, same seq, same sig
    rig.agent.heartbeat()
    seqs = [e["seq"] for _k, e in rig.fleet.accepted]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


def test_a_lost_reply_is_retried_idempotently(rig):
    rig.agent.heartbeat()
    rig.agent.send_posture()                       # accepted by the server...
    seq = rig.state.current_seq()
    env = [e for k, e in rig.fleet.accepted if k == "posture"][0]
    # ...but pretend the reply was lost: the same bytes come again and the server says 200 idempotent
    out = rig.client.post_posture(env)
    assert out.get("idempotent") is True
    assert rig.state.current_seq() == seq


def test_stale_queued_postures_are_dropped_not_sent(rig):
    rig.state.outbox.put({"kind": "posture", "envelope": {"seq": 5}, "seq": 5, "issued": int(rig.clock.time()) - 481})
    before = len(rig.fleet.requests)
    assert rig.agent.flush_outbox() == "ok"
    assert len(rig.state.outbox) == 0 and len(rig.fleet.requests) == before and rig.agent.stats["expired"] == 1


def test_409_fast_forwards_the_counter_and_does_not_resend(rig):
    for _ in range(3):
        rig.agent.heartbeat()
    os.unlink(rig.state.seq_path)                              # the counter state was lost
    with pytest.raises(FleetClientError) as e:
        rig.agent.heartbeat()
    assert e.value.status == 409 and e.value.verdict == "drop"
    rig.agent.heartbeat()                                      # continues past the server's last_seq
    assert rig.fleet.accepted[-1][1]["seq"] == 4
    assert len(rig.state.outbox) == 0


def test_422_clock_error_is_dropped_and_reported(rig):
    rig.clock.t += 5000                                        # the SERVER moves on; the agent clock is stale
    agent_time = rig.clock.t - 5000
    rig.agent._clock = lambda: agent_time
    with pytest.raises(FleetClientError) as e:
        rig.agent.heartbeat()
    assert e.value.status == 422 and e.value.verdict == "drop"
    assert len(rig.state.outbox) == 0


def test_a_tampered_envelope_is_rejected_by_the_server_and_changes_nothing(rig):
    rig.agent.heartbeat()
    env = rig.fleet.accepted[0][1]
    bad = dict(env, seq=99, payload_b64=envelope.b64u(b'{"agent_version":"x","status":"evil"}'))
    with pytest.raises(FleetClientError) as e:
        rig.client.heartbeat(bad)
    assert e.value.status in (400, 401)
    assert len(rig.fleet.accepted) == 1


def test_an_unknown_agent_id_404_is_retried_and_never_terminal(rig):
    """Rewritten for P2 review agent-2/pkg-11: ten bare 404s used to end the daemon with exit 7 (and systemd
    does not restart exit 7), so one ingress mistake silenced the fleet. Only the server's explicit
    structured verdict (agent_revoked / re_enroll_required) is terminal now."""
    rig.fleet.fail.extend([404] * (MAX_AUTH_FAILURES + 2))
    assert rig.agent.run(max_iterations=MAX_AUTH_FAILURES + 3, sleep=rig.clock.sleep) == EXIT_OK
    assert rig.fleet.accepted                                  # and the next answer from the server is used


def test_reenroll_required_ends_the_loop_with_exit_7_immediately(rig):
    rig.fleet.require_reenroll = True
    assert rig.agent.run(max_iterations=5, sleep=rig.clock.sleep) == EXIT_RE_ENROLL
    assert rig.clock.slept == []                               # no hot retry, no backoff dance


def test_repeated_auth_failures_never_end_the_loop_and_a_success_resets_the_count(rig):
    """Rewritten for P2 review agent-2/pkg-11 (it used to expect exit 7 after ten 403s)."""
    rig.fleet.fail.extend([401] * (MAX_AUTH_FAILURES - 1))
    assert rig.agent.run(max_iterations=MAX_AUTH_FAILURES - 1, sleep=rig.clock.sleep) == EXIT_OK
    assert rig.agent._auth_failures == MAX_AUTH_FAILURES - 1
    rig.agent.heartbeat()                                      # one success resets the streak
    assert rig.agent._auth_failures == 0
    rig.fleet.fail.extend([403] * (MAX_AUTH_FAILURES + 5))
    assert rig.agent.run(max_iterations=MAX_AUTH_FAILURES + 5, sleep=rig.clock.sleep) == EXIT_OK
    assert rig.agent._auth_failures == MAX_AUTH_FAILURES + 5   # counted (and logged loudly), never terminal


def test_posture_cadence_is_slower_than_heartbeat_cadence(rig):
    rig.agent.run(max_iterations=25, sleep=rig.clock.sleep)    # ~25 ticks of ~30 s = 750 s
    kinds = [k for k, _ in rig.fleet.accepted]
    assert kinds.count("heartbeat") == 25
    assert kinds.count("posture") == 3                         # t=0, 300, 600


def test_stop_ends_the_loop_cleanly(rig):
    done = {}

    def go():
        done["code"] = rig.agent.run()
    rig.agent.cfg.heartbeat_interval_s = 5
    t = threading.Thread(target=go, daemon=True)
    t.start()
    for _ in range(200):
        if rig.fleet.accepted:
            break
        threading.Event().wait(0.01)
    rig.agent.stop()
    t.join(timeout=5)
    assert not t.is_alive() and done["code"] == EXIT_OK


def test_unexpected_exceptions_in_a_tick_never_kill_the_daemon(rig, monkeypatch):
    monkeypatch.setattr(rig.agent, "heartbeat", lambda: (_ for _ in ()).throw(ZeroDivisionError("bug")))
    assert rig.agent.run(max_iterations=3, sleep=rig.clock.sleep) == EXIT_OK


def test_unsigned_inventory_failures_do_not_affect_the_signed_path(tmp_path):
    r = Rig(tmp_path)
    r.cfg.inventory_interval_s = 60
    r.enroll()
    real = r.fleet.handle
    r.fleet.handle = lambda m, p, h, b: (500, {}, {}) if p.endswith("/inventory") else real(m, p, h, b)
    assert r.agent.step() == "ok"
    assert "posture" in [k for k, _ in r.fleet.accepted]


# --------------------------------------------------------------------------- #
# end to end over a real socket with the real signer, no stubs on the client side
# --------------------------------------------------------------------------- #

def test_end_to_end_over_real_http(tmp_path):
    fleet = FakeFleet()
    httpd, url = fleet.serve()
    try:
        cfg = AgentConfig(server=url, state_dir=str(tmp_path / "s"), quarantine_dir=str(tmp_path / "q"),
                          dry_run=True, heartbeat_interval_s=5, posture_interval_s=60, inventory_interval_s=0,
                          platform_name="linux")
        agent = Agent(cfg, collect_fn=collect_stub, encode_fn=envelope.canon,
                      ctx_factory=lambda seq, key_id: types.SimpleNamespace(
                          seq=seq, key_id=key_id, known_manifest_sha=None, force_full_manifest=False))
        agent.enroll(fleet.token, hostname=socket.gethostname() if "_" not in socket.gethostname() else "h1")
        assert agent.run(max_iterations=2, sleep=lambda s: None) == EXIT_OK
        assert [k for k, _ in fleet.accepted] == ["heartbeat", "posture", "heartbeat"]
        assert fleet.rejected == []
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.skipif(os.environ.get("PADDOCK_SKIP_REAL_COLLECTORS") == "1", reason="disabled")
def test_real_collectors_produce_a_payload_the_server_accepts(tmp_path):
    pytest.importorskip("paddock_agent.collectors")
    from paddock_agent.runner import Ctx
    r = Rig(tmp_path)
    r.enroll()
    r.agent._collect_fn = None
    r.agent._encode_fn = None
    r.agent._ctx_factory = lambda seq, key_id: Ctx(r.cfg.state_dir, __version__, seq=seq, key_id=key_id,
                                                   collector_budget_s=20, total_budget_s=40)
    r.agent.send_posture()
    env = [e for k, e in r.fleet.accepted if k == "posture"][0]
    payload = json.loads(envelope.b64u_decode(env["payload_b64"]))
    assert payload["schema"] == 2 and set(payload["sections"]) == {"sshd", "listeners", "firewall", "patch", "self"}
    assert envelope.verify_envelope(env, r.fleet.keys[env["kid"]]["pub"])


# --------------------------------------------------------------------------- #
# key rotation
# --------------------------------------------------------------------------- #

def test_rotation_hands_over_to_a_new_key_signed_by_the_old_one(rig):
    rig.agent.heartbeat()
    old = rig.agent.key_id
    new = rig.agent.rotate_key()
    assert new != old and rig.agent.key_id == new == rig.fleet.active_key()
    assert rig.fleet.keys[old]["status"] == "rotated"
    kind, env = rig.fleet.accepted[-1]
    assert kind == "rotate" and env["kid"] == old                       # signed by the CURRENT key
    assert rig.state.load_pending_key() is None
    assert rig.state.load_credentials().key_id == new
    rig.agent.heartbeat()                                               # the new key signs from now on
    assert rig.fleet.accepted[-1][1]["kid"] == new
    seqs = [e["seq"] for _k, e in rig.fleet.accepted]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)         # one counter across both keys


def test_old_key_stops_working_after_rotation(rig):
    old_seed = rig.state.load_key()
    rig.agent.rotate_key()
    env = envelope.build_envelope(old_seed, agent_id=rig.fleet.agent_id, tenant_id=rig.fleet.tenant_id,
                                  kind="heartbeat", seq=500, issued_at=int(rig.clock.time()),
                                  payload=b"{}", payload_type=envelope.PAYLOAD_TYPE_HEARTBEAT,
                                  collectors={"agent": "0"})
    with pytest.raises(FleetClientError) as e:
        rig.client.heartbeat(env)
    assert e.value.status == 401


def test_rotation_discards_queued_envelopes_signed_by_the_retired_key(rig):
    rig.state.outbox.put({"kind": "posture", "envelope": {"seq": 1}, "seq": 1, "issued": int(rig.clock.time())})
    rig.state.outbox.put({"kind": "result", "action_id": "x", "status": "applied", "output": {}})
    rig.agent.rotate_key()
    kinds = [rig.state.outbox.read(f)["kind"] for f in rig.state.outbox.files()]
    assert kinds == ["result"]


def test_a_refused_rotation_keeps_the_old_key_and_drops_the_pending_one(rig):
    old = rig.agent.key_id
    rig.fleet.fail.append(400)
    with pytest.raises(FleetClientError):
        rig.agent.rotate_key()
    assert rig.agent.key_id == old and rig.state.load_pending_key() is None
    rig.agent.heartbeat()


def test_rotation_with_a_lost_reply_is_settled_by_probing_the_server(rig):
    """Server activated the new key, the agent never heard: pending stays on disk, the next tick adopts it."""
    old = rig.agent.key_id
    real = rig.fleet.handle

    def drop_reply(method, path, headers, body):
        out = real(method, path, headers, body)
        if path.endswith("/keys/rotate"):
            raise ConnectionResetError("reply lost")
        return out

    rig.fleet.handle = drop_reply
    with pytest.raises(FleetClientError):
        rig.agent.rotate_key()
    rig.fleet.handle = real
    assert rig.state.load_pending_key() is not None and rig.agent.key_id == old
    restarted = rig.fresh_agent()
    assert restarted.resolve_pending_key() == "ok"
    assert restarted.key_id == rig.fleet.active_key() != old and rig.state.load_pending_key() is None
    restarted.heartbeat()


def test_rotation_with_a_lost_request_discards_the_pending_key(rig):
    old = rig.agent.key_id
    real = rig.fleet.handle

    def drop_request(method, path, headers, body):
        if path.endswith("/keys/rotate"):
            raise ConnectionResetError("never arrived")
        return real(method, path, headers, body)

    rig.fleet.handle = drop_request
    with pytest.raises(FleetClientError):
        rig.agent.rotate_key()
    rig.fleet.handle = real
    assert rig.state.load_pending_key() is not None
    restarted = rig.fresh_agent()
    assert restarted.resolve_pending_key() == "ok"          # the server answers 401: it never saw that key
    assert rig.state.load_pending_key() is None and restarted.key_id == old
    restarted.heartbeat()


def test_pending_resolution_waits_while_the_server_is_unreachable(rig):
    rig.state.save_pending_key(signing.generate_seed())
    rig.fleet.fail.append(ConnectionRefusedError("down"))
    assert rig.fresh_agent().resolve_pending_key() == "retry"
    assert rig.state.load_pending_key() is not None


def test_enrollment_that_crashed_before_promoting_the_key_is_completed_on_restart(rig):
    seed = signing.generate_seed()
    import shutil
    shutil.copy(rig.state.key_path, rig.state.key_path + ".bak")
    os.unlink(rig.state.key_path)                              # only a pending key exists, creds exist
    rig.state.save_pending_key(seed)
    a = rig.fresh_agent()
    assert a.resolve_pending_key() == "ok" and a.state.load_key() == seed and a.state.load_pending_key() is None


# --------------------------------------------------------------------------- #
# actions: gated, idempotent, reported
# --------------------------------------------------------------------------- #

def _server_action(**kw):
    base = {"id": "33333333-3333-4333-8333-333333333333", "action_type": "block_ip", "target": "203.0.113.10",
            "status": "approved", "dry_run": False}
    base.update(kw)
    return base


def test_approved_real_action_is_applied_and_its_result_with_revert_is_reported(tmp_path, enforcer):
    r = Rig(tmp_path, enforcer=enforcer)
    r.enroll()
    r.fleet.pending_actions = [_server_action()]
    r.agent.heartbeat()
    assert enforcer.state == {"block_ip:203.0.113.10"}
    aid, body = r.fleet.results[0]
    assert aid == _server_action()["id"] and body["status"] == "applied" and body["revert"]["key"]


def test_dry_run_agent_never_mutates_and_never_reports(tmp_path, enforcer):
    r = Rig(tmp_path, enforcer=enforcer, dry_run=True)
    r.enroll()
    r.fleet.pending_actions = [_server_action(), _server_action(id="44444444-4444-4444-8444-444444444444",
                                                                   action_type="block_ip", target="2001:db8::1")]
    r.agent.heartbeat()
    assert enforcer.state == set() and r.fleet.results == []


def test_an_action_the_server_offers_again_is_not_applied_twice(tmp_path, enforcer):
    r = Rig(tmp_path, enforcer=enforcer)
    r.enroll()
    real = r.fleet.handle
    r.fleet.handle = lambda m, p, h, b: (_ for _ in ()).throw(ConnectionResetError("lost")) \
        if "/actions/" in p else real(m, p, h, b)
    r.fleet.pending_actions = [_server_action()]
    r.agent.heartbeat()                                        # applied; the result POST was lost
    assert [c for c in enforcer.calls if c[0] == "apply"] == [("apply", "block_ip:203.0.113.10")]
    assert len(r.state.outbox) == 1                           # queued durably
    r.fleet.handle = real
    r.fleet.pending_actions = [_server_action()]              # the server never saw the result: offers it again
    r.agent.heartbeat()
    assert [c for c in enforcer.calls if c[0] == "apply"] == [("apply", "block_ip:203.0.113.10")]   # still ONE
    assert [res[0] for res in r.fleet.results] == [_server_action()["id"]]                          # result delivered
    r.agent.flush_outbox()
    assert len(r.state.outbox) == 0


def test_queued_results_survive_a_restart_and_are_delivered(tmp_path, enforcer):
    r = Rig(tmp_path, enforcer=enforcer)
    r.enroll()
    real = r.fleet.handle
    r.fleet.handle = lambda m, p, h, b: (503, {}, {}) if "/actions/" in p else real(m, p, h, b)
    r.fleet.pending_actions = [_server_action()]
    r.agent.heartbeat()
    r.fleet.handle = real
    restarted = r.fresh_agent(enforcer=enforcer)
    assert restarted.flush_outbox() == "ok"
    assert len(r.fleet.results) == 1 and len(restarted.state.outbox) == 0


def test_non_host_local_approved_action_is_reported_failed_not_retried_forever(tmp_path, enforcer):
    r = Rig(tmp_path, enforcer=enforcer)
    r.enroll()
    r.fleet.pending_actions = [_server_action(action_type="quarantine_file", target="scp://evil/x")]
    r.agent.heartbeat()
    assert enforcer.state == set() and r.fleet.results[0][1]["status"] == "failed"
    assert r.fleet.results[0][1]["output"]["error"] == "not_host_local"


def test_unapproved_or_unknown_actions_are_neither_applied_nor_reported(tmp_path, enforcer):
    r = Rig(tmp_path, enforcer=enforcer)
    r.enroll()
    r.fleet.pending_actions = [_server_action(status="proposed"),
                               _server_action(id="55555555-5555-4555-8555-555555555555", action_type="scan_network"),
                               "garbage", {"id": 1}]
    r.agent.heartbeat()
    assert enforcer.state == set() and r.fleet.results == []


def test_a_server_revert_with_a_hostile_plan_is_reported_failed_and_runs_nothing(tmp_path):
    from paddock_agent.platform_block import LinuxEnforcer
    calls = []

    def runner(cmd):
        calls.append(cmd)
        from paddock_agent.platform_block import CompletedLike
        return CompletedLike(0)

    r = Rig(tmp_path, enforcer=LinuxEnforcer(runner=runner, quarantine_dir=str(tmp_path / "q"),
                                             hosts_path=str(tmp_path / "hosts")))
    r.enroll()
    r.fleet.pending_actions = [{"id": "66666666-6666-4666-8666-666666666666", "action_type": "revert",
                                "target": "x", "status": "approved", "dry_run": False, "revert_of": "a",
                                "result": {"revert": {"mechanism": "iptables", "commands": [["rm", "-rf", "/"]]}}}]
    r.agent.heartbeat()
    assert calls == []
    status = r.fleet.results[0][1]
    assert status["status"] == "failed" and status["output"]["error"] == "revert_plan_rejected"


def test_actions_are_capped_per_heartbeat(tmp_path, enforcer):
    r = Rig(tmp_path, enforcer=enforcer, dry_run=True)
    r.enroll()
    r.fleet.pending_actions = [_server_action(id=str(__import__("uuid").uuid4())) for _ in range(500)]
    r.agent.heartbeat()
    assert len([c for c in enforcer.calls if c[0] == "simulate"]) == 50


def test_state_errors_are_a_retry_not_a_crash(rig, monkeypatch):
    monkeypatch.setattr(State, "next_seq", lambda self: (_ for _ in ()).throw(StateError("disk full")))
    assert rig.agent.step() == "retry"
    assert rig.fleet.accepted == []                          # write-ahead failed => nothing was sent
