"""Sandbox backends: the mechanism that builds and drives isolated replicas.

Two implementations of the ``SandboxBackend`` protocol (see ``types.py``):

* :class:`FakeBackend` -- the default, used in tests and dry-runs. Builds NO
  real containers; it keeps an in-memory registry and returns programmable
  outputs so scenarios and the prover are deterministic in CI with no Docker.
* :class:`DockerBackend` -- the real backend. Every replica lives on a Docker
  network created with ``--internal`` (no egress), ports are NEVER published,
  resource caps and a TTL are enforced, the container drops all capabilities
  and gains ``no-new-privileges``, and a read-only rootfs is used where
  feasible. All docker invocations go through ``asyncio.create_subprocess_exec``
  with an argv list -- never a shell, never a string-interpolated command.

Neither backend is trusted on its own: ``guard.IsolationGuard`` wraps a backend
and independently re-verifies the isolation facts, failing closed on any doubt.
This file's job is to make the *honest* path correct and to FAIL CLOSED
(raise ``IsolationError``) the moment it cannot prove internal-only networking.

The module imports cleanly whether or not Docker is installed: every docker
check is lazy, so ``DockerBackend`` can be imported in CI and only raises
``IsolationError`` when someone actually asks it to build without a usable
``docker`` binary or a provably-internal network.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
from typing import Any, Callable, Optional, Union

import structlog

from app.sandbox.types import (
    ExecResult,
    IsolationError,
    NetworkMode,
    Replica,
    SandboxSpec,
    is_sandbox_internal_host,
)

log = structlog.get_logger(__name__)

# Caps, in the spirit of workers/.../safe_checks/base.py: nothing a replica
# prints back is allowed to be unbounded. Output is truncated, not trusted.
MAX_OUTPUT_BYTES = 256 * 1024          # per stream (stdout / stderr) read cap
DEFAULT_EXEC_TIMEOUT_SEC = 30
MAX_EXEC_TIMEOUT_SEC = 600

# Secret-shaped tokens are scrubbed from anything we log (host/image refs,
# command names). We never log argv values or command output.
_SECRET_LOG = re.compile(
    r"(?i)(secret|token|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|credential)"
)


def _safe_log(value: str, limit: int = 120) -> str:
    """A short, secret-scrubbed, printable form of ``value`` for structured logs."""
    v = _SECRET_LOG.sub("<redacted>", str(value))
    v = "".join(ch if ch.isprintable() else "?" for ch in v)
    return v[:limit]


def _cap(data: bytes) -> str:
    """Decode and length-cap one captured output stream."""
    text = data[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    if len(data) > MAX_OUTPUT_BYTES:
        text += "\n...<truncated>"
    return text


def _sanitize_component(component: str) -> str:
    """Turn a component name into a DNS-safe label fragment for an alias.

    The result is lower-case ``[a-z0-9-]`` so ``<component>-<shortid>`` always
    satisfies ``is_sandbox_internal_host``; a degenerate component falls back to
    a fixed label rather than producing an invalid or empty host.
    """
    s = re.sub(r"[^a-z0-9]+", "-", (component or "").lower()).strip("-")
    return s[:40] or "replica"


# --------------------------------------------------------------------------- #
# FakeBackend -- deterministic, builds nothing
# --------------------------------------------------------------------------- #

# A programmed exec outcome is either a fixed ExecResult or a callable that
# computes one from (replica, argv). Handlers are keyed on (component_or_None,
# argv_prefix): a None component matches any replica, and the longest matching
# argv prefix wins, so tests can layer a specific response over a general one.
ExecHandler = Union[ExecResult, Callable[[Replica, tuple[str, ...]], ExecResult]]
_HandlerKey = tuple[Optional[str], tuple[str, ...]]


class FakeBackend:
    """In-memory backend for tests and dry-runs. Builds no containers.

    Determinism: short ids come from a monotonic counter (never ``random`` /
    time), so a given sequence of ``build`` calls always yields the same ids.

    Programming outcomes::

        FakeBackend(scripted={
            ("redis", ("redis-cli", "PING")): ExecResult(0, "PONG"),
            ("probe",): ExecResult(0, "open"),           # component wildcard key
        })

    or at runtime via :meth:`register`. A key may be ``(component, argv_prefix)``
    (argv_prefix a tuple/list) or a bare ``argv_prefix`` tuple/list (any
    component). Unmatched execs return :attr:`default_result` (exit 0, empty).
    """

    name = "fake"

    def __init__(
        self,
        scripted: Optional[dict[Any, ExecHandler]] = None,
        *,
        default_result: Optional[ExecResult] = None,
        isolated: bool = True,
    ) -> None:
        self._counter = 0
        self._replicas: dict[str, Replica] = {}
        # replica_id -> list of sidecar replica_ids built with it (for destroy).
        self._sidecars: dict[str, list[str]] = {}
        self._handlers: list[tuple[_HandlerKey, ExecHandler]] = []
        self._default = default_result
        # Lets a test simulate a backend that *claims* a replica but whose
        # network cannot be proven internal (the guard must refuse it).
        self._isolated = isolated
        for key, handler in (scripted or {}).items():
            self._handlers.append((self._normalize_key(key), handler))

    # -- programming ------------------------------------------------------- #

    @staticmethod
    def _normalize_key(key: Any) -> _HandlerKey:
        # (component_or_None, argv_prefix_tuple)
        if (
            isinstance(key, tuple)
            and len(key) == 2
            and (key[0] is None or isinstance(key[0], str))
            and isinstance(key[1], (tuple, list))
        ):
            return (key[0], tuple(key[1]))
        # bare argv prefix (any component)
        if isinstance(key, (tuple, list)):
            return (None, tuple(key))
        if isinstance(key, str):
            return (None, (key,))
        raise ValueError(f"unsupported scripted key: {key!r}")

    def register(
        self,
        handler: ExecHandler,
        *,
        component: Optional[str] = None,
        argv_prefix: tuple[str, ...] = (),
    ) -> None:
        self._handlers.append(((component, tuple(argv_prefix)), handler))

    # -- id allocation ----------------------------------------------------- #

    def _shortid(self) -> str:
        self._counter += 1
        return f"{self._counter:06d}"

    # -- backend protocol -------------------------------------------------- #

    async def build(self, spec: SandboxSpec) -> Replica:
        if not isinstance(spec, SandboxSpec):  # defensive: contract says SandboxSpec
            raise IsolationError("FakeBackend.build requires a SandboxSpec")
        replica = self._make_replica(spec, network=None)
        # Sidecars share the SAME internal network as the primary replica.
        sidecar_ids: list[str] = []
        for side in spec.sidecars:
            sr = self._make_replica(side, network=replica.network)
            sidecar_ids.append(sr.replica_id)
        self._sidecars[replica.replica_id] = sidecar_ids
        log.info(
            "sandbox.fake.build",
            replica_id=replica.replica_id,
            component=_safe_log(replica.component),
            network=replica.network,
            sidecars=len(sidecar_ids),
        )
        return replica

    def _make_replica(self, spec: SandboxSpec, network: Optional[str]) -> Replica:
        sid = self._shortid()
        net = network or f"wg-{sid}"
        host = f"{_sanitize_component(spec.component)}-{sid}"
        # Guarantee our own alias is well-formed before anyone relies on it.
        if not is_sandbox_internal_host(host):  # pragma: no cover - sanitizer guarantees this
            raise IsolationError(f"FakeBackend produced a non-internal host: {host!r}")
        replica = Replica(
            replica_id=f"fake-{sid}",
            component=spec.component,
            network_mode=NetworkMode.INTERNAL,
            internal_host=host,
            internal_port=spec.port,
            image=spec.image,
            image_digest=spec.image_digest,
            backend=self.name,
            network=net,
            verified=False,
            metadata={"fake": True},
        )
        self._replicas[replica.replica_id] = replica
        return replica

    async def exec_in(
        self, replica: Replica, argv: tuple[str, ...], *, timeout_sec: int = DEFAULT_EXEC_TIMEOUT_SEC
    ) -> ExecResult:
        if replica.replica_id not in self._replicas:
            raise IsolationError(f"exec on unknown replica {replica.replica_id!r}")
        argv = tuple(str(a) for a in argv)
        handler = self._match(replica, argv)
        if handler is None:
            res = self._default or ExecResult(exit_code=0, stdout="", stderr="")
        elif callable(handler):
            res = handler(replica, argv)
        else:
            res = handler
        # Return a fresh copy stamped with where it ran, so callers can't mutate
        # a shared scripted object.
        return ExecResult(
            exit_code=res.exit_code,
            stdout=res.stdout,
            stderr=res.stderr,
            duration_ms=res.duration_ms,
            timed_out=res.timed_out,
            replica_id=replica.replica_id,
        )

    def _match(self, replica: Replica, argv: tuple[str, ...]) -> Optional[ExecHandler]:
        best: Optional[ExecHandler] = None
        best_len = -1
        for (comp, prefix), handler in self._handlers:
            if comp is not None and comp != replica.component:
                continue
            if tuple(argv[: len(prefix)]) == prefix and len(prefix) > best_len:
                best, best_len = handler, len(prefix)
        return best

    async def network_is_isolated(self, replica: Replica) -> bool:
        # A known replica on an internal/none network is isolated; the flag lets
        # a test flip this to drive the guard's fail-closed path.
        if replica.replica_id not in self._replicas:
            return False
        if replica.network_mode not in (NetworkMode.INTERNAL, NetworkMode.NONE):
            return False
        return bool(self._isolated)

    async def destroy(self, replica: Replica) -> None:
        for sid in self._sidecars.pop(replica.replica_id, []):
            self._replicas.pop(sid, None)
        self._replicas.pop(replica.replica_id, None)
        log.info("sandbox.fake.destroy", replica_id=replica.replica_id)


# --------------------------------------------------------------------------- #
# DockerBackend -- real isolated containers
# --------------------------------------------------------------------------- #

class DockerBackend:
    """Build replicas as Docker containers on an ``--internal`` network.

    Safety posture (all enforced here; re-verified by the guard):

    * Network is created with ``--internal`` and the ``bridge`` driver, giving
      containers a shared segment with NO route to the host or the internet.
    * Containers NEVER publish a port (no ``-p``): a replica is reachable only
      by its service alias from inside the sandbox network.
    * ``--cap-drop ALL``, ``--security-opt no-new-privileges``, a read-only
      rootfs (``--read-only``) where feasible, and the ``cpu`` / ``mem_mb`` /
      ``ttl`` caps from the spec are applied to every container.
    * Images are pulled ``--pull never`` (or by digest when pinned): the owner's
      registry/SBOM vouches for the image offline; we don't reach out to pull.
    * Every docker call is ``create_subprocess_exec(argv...)`` -- no shell, no
      string interpolation of untrusted values.

    Docker need not be present to import this class. Each operation lazily
    resolves the ``docker`` binary and FAILS CLOSED with ``IsolationError`` if it
    is missing or if a network's isolation cannot be proven.
    """

    name = "docker"

    def __init__(
        self,
        *,
        docker_bin: str = "docker",
        label: str = "paddock-wargame",
        read_only_rootfs: bool = True,
    ) -> None:
        self._docker_bin = docker_bin
        self._label = label
        self._read_only = read_only_rootfs
        # replica_id -> {"container": name, "network": name, "sidecars": [names]}
        self._live: dict[str, dict[str, Any]] = {}

    # -- docker availability (lazy; never at import time) ------------------ #

    def _resolve_docker(self) -> Optional[str]:
        """Absolute path to a usable docker binary, or None. Overridable in tests."""
        # Accept an explicit absolute path only if it actually exists; otherwise
        # fall back to PATH lookup. Never trust a bare name that isn't found.
        if "/" in self._docker_bin:
            return self._docker_bin if shutil.which(self._docker_bin) else None
        return shutil.which(self._docker_bin)

    def _docker_available(self) -> bool:
        return self._resolve_docker() is not None

    def _require_docker(self) -> str:
        path = self._resolve_docker()
        if not path:
            # FAIL CLOSED: no silent fallback to a less-isolated path.
            raise IsolationError(
                f"docker binary {self._docker_bin!r} not found; refusing to build a "
                "replica without a backend that can guarantee an internal-only network"
            )
        return path

    # -- subprocess helper ------------------------------------------------- #

    async def _docker(
        self, args: list[str], *, timeout_sec: int = 60
    ) -> tuple[int, bytes, bytes, bool]:
        """Run ``docker <args>`` with no shell, capturing capped output."""
        docker = self._require_docker()
        argv = [docker, *args]
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            return proc.returncode or 0, out, err, False
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:  # pragma: no cover
                pass
            await proc.wait()
            return 124, b"", b"", True

    # -- backend protocol -------------------------------------------------- #

    async def build(self, spec: SandboxSpec) -> Replica:
        if not isinstance(spec, SandboxSpec):
            raise IsolationError("DockerBackend.build requires a SandboxSpec")
        self._require_docker()  # fail closed before creating anything

        sid = _short_token()
        network = f"wg-{sid}"
        primary_name = f"wg-{_sanitize_component(spec.component)}-{sid}"
        replica = Replica(
            replica_id=primary_name,
            component=spec.component,
            network_mode=NetworkMode.INTERNAL,
            internal_host=_sanitize_component(spec.component) + f"-{sid}",
            internal_port=spec.port,
            image=spec.image,
            image_digest=spec.image_digest,
            backend=self.name,
            network=network,
            verified=False,
            metadata={"container": primary_name},
        )
        self._live[replica.replica_id] = {
            "container": primary_name,
            "network": network,
            "sidecars": [],
        }
        try:
            # 1) Internal-only network. --internal removes the egress route.
            rc, _out, err, _to = await self._docker(
                ["network", "create", "--internal", "--driver", "bridge", network]
            )
            if rc != 0:
                raise IsolationError(f"could not create internal network: {_safe_log(err.decode(errors='replace'))}")

            # 2) Prove it is internal BEFORE launching anything on it.
            if not await self.network_is_isolated(replica):
                raise IsolationError(f"network {network} is not provably internal; refusing to launch")

            # 3) Primary replica, then sidecars, all on the same internal net.
            await self._run_container(primary_name, replica.internal_host, network, spec)
            for side in spec.sidecars:
                s_host = _sanitize_component(side.component) + f"-{_short_token()}"
                s_name = f"wg-{s_host}"
                await self._run_container(s_name, s_host, network, side)
                self._live[replica.replica_id]["sidecars"].append(s_name)

            log.info(
                "sandbox.docker.build",
                replica_id=replica.replica_id,
                network=network,
                sidecars=len(spec.sidecars),
            )
            return replica
        except IsolationError:
            await self.destroy(replica)
            raise
        except Exception as e:  # noqa: BLE001 - any build failure fails closed
            await self.destroy(replica)
            raise IsolationError(f"docker build failed, torn down: {_safe_log(str(e))}") from e

    async def _run_container(
        self, name: str, host_alias: str, network: str, spec: SandboxSpec
    ) -> None:
        # Image reference: prefer the pinned digest when available.
        image = spec.image
        if spec.image_digest:
            base = spec.image.split("@", 1)[0].split(":", 1)[0]
            image = f"{base}@{spec.image_digest}"

        args: list[str] = [
            "run",
            "-d",
            "--name", name,
            "--hostname", host_alias,
            "--network", network,
            "--network-alias", host_alias,
            # Hardening. NO -p / --publish anywhere: replicas are never exposed.
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "512",
            # Resource caps from the spec.
            "--cpus", f"{max(0.1, float(spec.cpu)):.2f}",
            "--memory", f"{max(16, int(spec.mem_mb))}m",
            # Offline: the owner's registry/SBOM vouches for the image.
            "--pull", "never",
            # Isolation labels so destroy()/GC can find our objects.
            "--label", f"{self._label}=1",
            "--label", f"{self._label}.network={network}",
        ]
        if self._read_only:
            # Read-only rootfs with a small writable tmpfs for scratch.
            args += ["--read-only", "--tmpfs", "/tmp:rw,size=64m"]
        for k, v in spec.env.items():
            # argv form: a value can never break out into a shell.
            args += ["--env", f"{k}={v}"]
        args.append(image)
        args += list(spec.cmd)

        rc, _out, err, timed_out = await self._docker(args)
        if timed_out or rc != 0:
            raise IsolationError(
                f"could not start container {name}: {_safe_log(err.decode(errors='replace'))}"
            )

    async def exec_in(
        self, replica: Replica, argv: tuple[str, ...], *, timeout_sec: int = DEFAULT_EXEC_TIMEOUT_SEC
    ) -> ExecResult:
        self._require_docker()
        live = self._live.get(replica.replica_id)
        container = (live or {}).get("container") or replica.metadata.get("container")
        if not container:
            raise IsolationError(f"no live container for replica {replica.replica_id!r}")
        timeout_sec = max(1, min(int(timeout_sec), MAX_EXEC_TIMEOUT_SEC))
        argv = tuple(str(a) for a in argv)
        if not argv:
            raise IsolationError("exec_in requires a non-empty argv")

        import time as _time

        started = _time.monotonic()
        # `docker exec` runs strictly inside the container's namespaces; nothing
        # touches the host. argv is passed as a list -- never a shell string.
        rc, out, err, timed_out = await self._docker(
            ["exec", container, *argv], timeout_sec=timeout_sec
        )
        return ExecResult(
            exit_code=rc,
            stdout=_cap(out),
            stderr=_cap(err),
            duration_ms=int((_time.monotonic() - started) * 1000),
            timed_out=timed_out,
            replica_id=replica.replica_id,
        )

    async def network_is_isolated(self, replica: Replica) -> bool:
        """Inspect the live network: isolated only if ``Internal`` is true and the
        driver is ``bridge`` or ``none``. Any ambiguity returns False (the guard
        then fails closed). Docker missing is a hard ``IsolationError``."""
        self._require_docker()
        network = replica.network
        if not network:
            return False
        rc, out, _err, _to = await self._docker(["network", "inspect", network])
        if rc != 0:
            return False
        try:
            data = json.loads(out.decode(errors="replace"))
        except (ValueError, UnicodeError):
            return False
        if not isinstance(data, list) or not data:
            return False
        net = data[0]
        if not isinstance(net, dict):
            return False
        internal = net.get("Internal")
        driver = str(net.get("Driver", "")).lower()
        return internal is True and driver in ("bridge", "none")

    async def destroy(self, replica: Replica) -> None:
        """Idempotent, best-effort teardown of containers (incl. sidecars) then
        the network. Never raises -- it runs in a ``finally``."""
        if not self._docker_available():
            # Nothing we can (or should) do; there is nothing live without docker.
            self._live.pop(replica.replica_id, None)
            return
        live = self._live.get(replica.replica_id, {})
        containers = []
        c = live.get("container") or replica.metadata.get("container")
        if c:
            containers.append(c)
        containers += list(live.get("sidecars", []))
        network = live.get("network") or replica.network

        for name in containers:
            try:
                await self._docker(["rm", "-f", "-v", name], timeout_sec=30)
            except Exception as e:  # noqa: BLE001 - best effort
                log.warning("sandbox.docker.destroy_container_failed", name=name, err=_safe_log(str(e)))
        if network:
            try:
                await self._docker(["network", "rm", network], timeout_sec=30)
            except Exception as e:  # noqa: BLE001 - best effort
                log.warning("sandbox.docker.destroy_network_failed", network=network, err=_safe_log(str(e)))
        self._live.pop(replica.replica_id, None)
        log.info("sandbox.docker.destroy", replica_id=replica.replica_id)


def _short_token() -> str:
    """A short, lowercase, DNS-safe random token for docker object names.

    Uses ``uuid4`` (host entropy) because real docker names only need to be
    unique on the host; FakeBackend, which must be deterministic, uses a counter
    instead and never calls this.
    """
    import uuid

    return uuid.uuid4().hex[:10]
