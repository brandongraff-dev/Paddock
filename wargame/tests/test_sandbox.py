"""Isolation-guard and backend tests for the Proving Ground sandbox.

These are PURE: no DB, no Docker, no network. They exercise the ONE INVARIANT
from both sides -- the happy path (a real internal replica verifies and runs)
and, more importantly, the refusal paths: every way a buggy or malicious backend
could try to hand the guard something that is NOT an isolated replica must raise
``IsolationError`` *and* trigger teardown.
"""
from __future__ import annotations

import dataclasses

import pytest

from app.sandbox.backend import DockerBackend, FakeBackend
from app.sandbox.guard import IsolationGuard
from app.sandbox.types import (
    ExecResult,
    IsolationError,
    NetworkMode,
    Replica,
    SandboxSpec,
    is_sandbox_internal_host,
)


def mk_spec(component: str = "redis", **kw) -> SandboxSpec:
    kw.setdefault("image", "library/redis:6.0")
    return SandboxSpec(component=component, **kw)


# --------------------------------------------------------------------------- #
# FakeBackend
# --------------------------------------------------------------------------- #

async def test_fake_build_exec_destroy_roundtrip():
    be = FakeBackend(
        scripted={("redis", ("redis-cli", "PING")): ExecResult(0, "PONG")}
    )
    replica = await be.build(mk_spec("redis", port=6379))

    assert replica.backend == "fake"
    assert replica.network_mode is NetworkMode.INTERNAL
    assert replica.verified is False
    assert replica.network.startswith("wg-")
    assert replica.internal_port == 6379
    assert is_sandbox_internal_host(replica.internal_host)
    assert await be.network_is_isolated(replica) is True

    # Scripted exec is returned; it is stamped with where it ran.
    res = await be.exec_in(replica, ("redis-cli", "PING"))
    assert res.exit_code == 0 and res.stdout == "PONG"
    assert res.replica_id == replica.replica_id

    # Unmatched exec falls back to the default (exit 0, empty).
    default = await be.exec_in(replica, ("whoami",))
    assert default.exit_code == 0 and default.stdout == ""

    await be.destroy(replica)
    # Gone from the registry: exec now refuses.
    with pytest.raises(IsolationError):
        await be.exec_in(replica, ("redis-cli", "PING"))


async def test_fake_ids_are_deterministic():
    a = FakeBackend()
    b = FakeBackend()
    ra1 = await a.build(mk_spec("nginx"))
    ra2 = await a.build(mk_spec("nginx"))
    rb1 = await b.build(mk_spec("nginx"))
    rb2 = await b.build(mk_spec("nginx"))
    # Two fresh backends produce the same id sequence (counter, not random).
    assert (ra1.replica_id, ra1.internal_host) == (rb1.replica_id, rb1.internal_host)
    assert (ra2.replica_id, ra2.internal_host) == (rb2.replica_id, rb2.internal_host)
    assert ra1.replica_id != ra2.replica_id


async def test_fake_sidecars_share_network_and_are_destroyed():
    be = FakeBackend()
    spec = mk_spec("app", sidecars=(mk_spec("attacker-toolbox", image="toolbox:1"),))
    replica = await be.build(spec)
    # The sidecar joined the SAME internal network.
    assert len(be._sidecars[replica.replica_id]) == 1
    sidecar_id = be._sidecars[replica.replica_id][0]
    assert be._replicas[sidecar_id].network == replica.network
    await be.destroy(replica)
    assert sidecar_id not in be._replicas


async def test_fake_handler_callable_and_longest_prefix_wins():
    be = FakeBackend(scripted={
        ("redis", ()): ExecResult(0, "general"),  # component redis, any argv
        ("redis", ("redis-cli", "INFO")): lambda r, argv: ExecResult(0, "specific"),
    })
    replica = await be.build(mk_spec("redis"))
    assert (await be.exec_in(replica, ("redis-cli",))).stdout == "general"
    assert (await be.exec_in(replica, ("redis-cli", "INFO"))).stdout == "specific"


# --------------------------------------------------------------------------- #
# IsolationGuard -- happy path
# --------------------------------------------------------------------------- #

async def test_guard_build_marks_verified():
    guard = IsolationGuard(FakeBackend(), max_ttl_sec=300)
    replica = await guard.build(mk_spec("redis"))
    assert replica.verified is True
    assert replica.network_mode is NetworkMode.INTERNAL


async def test_guard_exec_on_verified_replica():
    be = FakeBackend(scripted={("redis", ("id",)): ExecResult(0, "uid=0")})
    guard = IsolationGuard(be)
    replica = await guard.build(mk_spec("redis"))
    res = await guard.exec_in(replica, ("id",))
    assert res.ok and res.stdout == "uid=0"


async def test_guard_exec_clamps_timeout():
    captured = {}

    class RecordingBackend(FakeBackend):
        async def exec_in(self, replica, argv, *, timeout_sec=30):
            captured["timeout"] = timeout_sec
            return await super().exec_in(replica, argv, timeout_sec=timeout_sec)

    guard = IsolationGuard(RecordingBackend(), max_exec_timeout_sec=60)
    replica = await guard.build(mk_spec("redis"))
    await guard.exec_in(replica, ("id",), timeout_sec=99999)
    assert captured["timeout"] == 60  # clamped down to the cap


# --------------------------------------------------------------------------- #
# IsolationGuard -- REFUSALS (a backend that lies / a bad spec)
# --------------------------------------------------------------------------- #

class BadBackend:
    """A backend that returns a specific isolation violation, to prove the guard
    refuses it AND tears it down. Records every destroy() it receives."""

    name = "bad"

    def __init__(self, replica: Replica, *, isolated: bool = True):
        self._replica = replica
        self._isolated = isolated
        self.destroyed: list[str] = []

    async def build(self, spec):
        return self._replica

    async def exec_in(self, replica, argv, *, timeout_sec=30):  # pragma: no cover
        return ExecResult(0)

    async def network_is_isolated(self, replica):
        return self._isolated

    async def destroy(self, replica):
        self.destroyed.append(replica.replica_id)


def _replica(**kw) -> Replica:
    base = dict(
        replica_id="bad-1",
        component="redis",
        network_mode=NetworkMode.INTERNAL,
        internal_host="redis-000001",
        internal_port=6379,
        image="library/redis:6.0",
        backend="bad",
        network="wg-000001",
    )
    base.update(kw)
    return Replica(**base)


@pytest.mark.parametrize(
    "kwargs, isolated, label",
    [
        (dict(network_mode=NetworkMode.OPEN), True, "network_mode=OPEN"),
        (dict(internal_host="10.0.0.5"), True, "routable IPv4 internal_host"),
        (dict(internal_host="169.254.169.254"), True, "IMDS internal_host"),
        (dict(internal_host="evil.com"), True, "external hostname"),
        (dict(internal_host="localhost"), True, "localhost"),
        (dict(internal_host="host.docker.internal"), True, "docker host alias"),
        (dict(), False, "network_is_isolated() == False"),
    ],
)
async def test_guard_refuses_and_tears_down(kwargs, isolated, label):
    bad = BadBackend(_replica(**kwargs), isolated=isolated)
    guard = IsolationGuard(bad)
    with pytest.raises(IsolationError):
        await guard.build(mk_spec("redis"))
    # The invariant: a refused build is also a destroyed build.
    assert bad.destroyed == ["bad-1"], f"destroy not attempted for: {label}"


async def test_guard_refuses_network_is_isolated_raising():
    class ExplodingBackend(BadBackend):
        async def network_is_isolated(self, replica):
            raise RuntimeError("inspect failed")

    bad = ExplodingBackend(_replica())
    guard = IsolationGuard(bad)
    with pytest.raises(IsolationError):
        await guard.build(mk_spec("redis"))
    assert bad.destroyed == ["bad-1"]  # verification error still tears down


async def test_guard_refuses_ttl_over_cap():
    guard = IsolationGuard(FakeBackend(), max_ttl_sec=60)
    with pytest.raises(IsolationError):
        await guard.build(mk_spec("redis", ttl_sec=300))


async def test_guard_refuses_bad_sidecar_ttl():
    guard = IsolationGuard(FakeBackend(), max_ttl_sec=300)
    spec = mk_spec("app", sidecars=(mk_spec("side", ttl_sec=99999),))
    with pytest.raises(IsolationError):
        await guard.build(spec)


async def test_guard_exec_refuses_unverified_replica():
    be = FakeBackend()
    guard = IsolationGuard(be)
    raw = await be.build(mk_spec("redis"))  # built directly, NOT via the guard
    assert raw.verified is False
    with pytest.raises(IsolationError):
        await guard.exec_in(raw, ("id",))


async def test_guard_exec_refuses_open_mode_even_if_flag_set():
    # A replica flagged verified but somehow on OPEN must still be refused.
    guard = IsolationGuard(FakeBackend())
    forged = _replica(network_mode=NetworkMode.OPEN, verified=True)
    with pytest.raises(IsolationError):
        await guard.exec_in(forged, ("id",))


# --------------------------------------------------------------------------- #
# assert_replica_target -- defense in depth
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "host",
    ["10.0.0.5", "169.254.169.254", "127.0.0.1", "localhost", "evil.com",
     "host.docker.internal", "metadata.google.internal", "", "  "],
)
def test_assert_replica_target_refuses_live_hosts(host):
    guard = IsolationGuard(FakeBackend())
    with pytest.raises(IsolationError):
        guard.assert_replica_target(host)


@pytest.mark.parametrize("host", ["redis-000001", "app-abc123", "jenkins-deadbeef"])
def test_assert_replica_target_accepts_sandbox_alias(host):
    guard = IsolationGuard(FakeBackend())
    assert is_sandbox_internal_host(host)
    guard.assert_replica_target(host)  # does not raise


# --------------------------------------------------------------------------- #
# session() -- always destroys
# --------------------------------------------------------------------------- #

async def test_session_destroys_on_success():
    be = FakeBackend()
    guard = IsolationGuard(be)
    async with guard.session(mk_spec("redis")) as replica:
        assert replica.verified is True
        assert replica.replica_id in be._replicas
    assert replica.replica_id not in be._replicas  # torn down


async def test_session_destroys_on_exception():
    be = FakeBackend()
    guard = IsolationGuard(be)
    captured_id = {}
    with pytest.raises(ValueError):
        async with guard.session(mk_spec("redis")) as replica:
            captured_id["id"] = replica.replica_id
            assert replica.replica_id in be._replicas
            raise ValueError("scenario blew up")
    assert captured_id["id"] not in be._replicas  # destroyed despite the raise


async def test_destroy_never_raises():
    class CrashOnDestroy(FakeBackend):
        async def destroy(self, replica):
            raise RuntimeError("teardown exploded")

    guard = IsolationGuard(CrashOnDestroy())
    replica = await guard.build(mk_spec("redis"))
    # Guard-mediated destroy swallows the backend error.
    await guard.destroy(replica)


# --------------------------------------------------------------------------- #
# DockerBackend -- importable & fails closed with docker absent
# --------------------------------------------------------------------------- #

async def test_docker_backend_build_fails_closed_without_docker():
    # Point the resolver at a binary that does not exist -> no docker available.
    be = DockerBackend(docker_bin="/nonexistent/path/to/docker")
    assert be._docker_available() is False
    with pytest.raises(IsolationError):
        await be.build(mk_spec("redis"))


async def test_docker_backend_build_fails_closed_when_unavailable_monkeypatched(monkeypatch):
    be = DockerBackend()
    monkeypatch.setattr(be, "_resolve_docker", lambda: None)
    with pytest.raises(IsolationError):
        await be.build(mk_spec("redis"))
    # network_is_isolated and exec_in also fail closed, not silently true.
    r = _replica(backend="docker")
    with pytest.raises(IsolationError):
        await be.network_is_isolated(r)
    with pytest.raises(IsolationError):
        await be.exec_in(r, ("id",))


async def test_docker_backend_destroy_is_safe_without_docker():
    be = DockerBackend(docker_bin="/nonexistent/path/to/docker")
    # Must not raise even though docker is absent.
    await be.destroy(_replica(backend="docker"))


async def test_guard_over_docker_backend_refuses_without_docker():
    guard = IsolationGuard(DockerBackend(docker_bin="/nonexistent/docker"))
    with pytest.raises(IsolationError):
        await guard.build(mk_spec("redis"))
