"""The isolation guard: the one piece of code that enforces THE INVARIANT.

    A scenario only ever runs against an isolated REPLICA the customer owns, on
    an internal-only network with NO route to any live or out-of-scope system.
    There is no "run against production" path.

``IsolationGuard`` wraps a ``SandboxBackend`` and refuses to let anything --
a scenario, a buggy backend, or a malformed spec -- reach anything but a
freshly-built, egress-less replica. It is deliberately paranoid and FAILS
CLOSED: on any doubt it raises ``IsolationError`` and tears down.

Why re-verify what the backend already promised? Because the backend is the
thing most likely to have the bug. The guard treats a backend's return value as
a *claim* to be checked, not a fact. It independently requires, for every
replica it hands back:

1. ``network_mode`` is ``INTERNAL`` or ``NONE`` (never ``OPEN``);
2. ``internal_host`` passes ``is_sandbox_internal_host`` (a sandbox alias, not a
   routable address, IMDS endpoint, ``localhost``, etc.);
3. ``backend.network_is_isolated(replica)`` returns ``True`` (the live network
   really has no route out).

Only then is the replica stamped ``verified=True`` and allowed to run commands.
Every refusal carries a reason string and a structured audit log line, in the
spirit of ``workers/.../safe_checks/base.py``.
"""
from __future__ import annotations

import dataclasses
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import structlog

from app.sandbox.types import (
    ExecResult,
    IsolationError,
    NetworkMode,
    Replica,
    SandboxBackend,
    SandboxSpec,
    is_sandbox_internal_host,
)

log = structlog.get_logger(__name__)

# Network modes a verified replica may ever run a command on. OPEN is never here.
_RUNNABLE_MODES = frozenset({NetworkMode.INTERNAL, NetworkMode.NONE})


def _is_replica_alias(host: str) -> bool:
    """Stricter, guard-owned check for a replica service alias.

    ``is_sandbox_internal_host`` (the contract) is the syntactic floor: it
    rejects empty / IPv4 / IMDS / ``localhost`` / docker-host shapes. The guard
    adds one more rule and fails closed on top of it: a replica is reached by a
    single DNS label on its internal network (``<component>-<shortid>``), so a
    *dotted* host -- which is what a public FQDN like ``evil.com`` or a metadata
    endpoint looks like -- is refused. Our backends only ever mint single-label
    aliases, so this never rejects a legitimate replica.
    """
    if not is_sandbox_internal_host(host):
        return False
    return "." not in host.strip()

# Fallback caps if the caller passes nothing. The guard always clamps DOWN to
# these; it never widens what the caller asked for.
_DEFAULT_MAX_TTL_SEC = 300
_DEFAULT_MAX_EXEC_TIMEOUT_SEC = 600
_MIN_EXEC_TIMEOUT_SEC = 1


class IsolationGuard:
    """Mediates every sandbox operation and enforces the one invariant.

    Parameters
    ----------
    backend:
        The ``SandboxBackend`` that does the mechanics. Treated as untrusted:
        its outputs are re-verified.
    max_ttl_sec:
        Hard cap on a spec's replica lifetime (``settings().max_replica_ttl_sec``).
    max_exec_timeout_sec:
        Hard cap on any single ``exec_in`` timeout (``settings().max_run_sec``).
    """

    def __init__(
        self,
        backend: SandboxBackend,
        *,
        max_ttl_sec: int = _DEFAULT_MAX_TTL_SEC,
        max_exec_timeout_sec: int = _DEFAULT_MAX_EXEC_TIMEOUT_SEC,
    ) -> None:
        if backend is None:
            raise IsolationError("IsolationGuard requires a backend")
        self.backend = backend
        self.max_ttl_sec = max(1, int(max_ttl_sec))
        self.max_exec_timeout_sec = max(_MIN_EXEC_TIMEOUT_SEC, int(max_exec_timeout_sec))

    # -- spec validation --------------------------------------------------- #

    def _validate_spec(self, spec: SandboxSpec, *, depth: int = 0) -> None:
        """Reject a spec that could not possibly yield a safe replica.

        Raises ``IsolationError`` (the spec never half-builds). Sidecars are
        validated recursively; a deep nest is itself suspicious and refused.
        """
        if not isinstance(spec, SandboxSpec):
            raise IsolationError("build() requires a SandboxSpec")
        if depth > 8:
            raise IsolationError("sidecar nesting too deep; refusing to build")
        # TTL must be a positive, finite number within the operator's cap.
        ttl = spec.ttl_sec
        if not isinstance(ttl, int) or ttl <= 0:
            raise IsolationError(f"spec ttl_sec must be a positive int, got {ttl!r}")
        if ttl > self.max_ttl_sec:
            raise IsolationError(
                f"spec ttl_sec={ttl} exceeds max_replica_ttl_sec={self.max_ttl_sec}"
            )
        # Resource caps must be sane; a non-positive cap is a malformed spec.
        if not (isinstance(spec.cpu, (int, float)) and spec.cpu > 0):
            raise IsolationError(f"spec cpu must be positive, got {spec.cpu!r}")
        if not (isinstance(spec.mem_mb, int) and spec.mem_mb > 0):
            raise IsolationError(f"spec mem_mb must be a positive int, got {spec.mem_mb!r}")
        for side in spec.sidecars:
            self._validate_spec(side, depth=depth + 1)

    # -- build + verify ---------------------------------------------------- #

    async def build(self, spec: SandboxSpec) -> Replica:
        """Build a replica and return it ONLY if its isolation is proven.

        On success returns a copy of the backend's ``Replica`` with
        ``verified=True``. On any failure it attempts ``backend.destroy`` and
        raises ``IsolationError`` -- never a partially-trusted replica.
        """
        self._validate_spec(spec)

        # Backend build failures propagate as IsolationError; there is no replica
        # to tear down yet.
        try:
            replica = await self.backend.build(spec)
        except IsolationError:
            raise
        except Exception as e:  # noqa: BLE001 - a backend crash fails the build closed
            log.warning("sandbox.guard.build_backend_error", err=str(e)[:200])
            raise IsolationError(f"backend.build failed: {e}") from e

        reason: Optional[str] = None
        try:
            if not isinstance(replica, Replica):
                reason = "backend returned a non-Replica object"
            elif replica.network_mode not in _RUNNABLE_MODES:
                reason = f"network_mode={getattr(replica.network_mode, 'value', replica.network_mode)!r} is not internal/none"
            elif not _is_replica_alias(replica.internal_host):
                reason = f"internal_host={replica.internal_host!r} is not a sandbox-internal alias"
            else:
                isolated = await self.backend.network_is_isolated(replica)
                if isolated is not True:
                    reason = f"backend.network_is_isolated returned {isolated!r}; network not provably egress-less"
        except Exception as e:  # noqa: BLE001 - a verification error is itself a refusal
            reason = f"verification raised {type(e).__name__}: {str(e)[:160]}"

        if reason is not None:
            await self._safe_destroy(replica)
            log.warning(
                "sandbox.guard.refused_build",
                reason=reason,
                component=getattr(replica, "component", None),
                backend=self.backend.name,
            )
            raise IsolationError(f"isolation not proven, replica torn down: {reason}")

        verified = dataclasses.replace(replica, verified=True)
        log.info(
            "sandbox.guard.verified",
            replica_id=verified.replica_id,
            component=verified.component,
            network_mode=verified.network_mode.value,
            network=verified.network,
            backend=self.backend.name,
        )
        return verified

    # -- exec -------------------------------------------------------------- #

    async def exec_in(
        self, replica: Replica, argv: tuple[str, ...], *, timeout_sec: int = 30
    ) -> ExecResult:
        """Run ``argv`` inside a VERIFIED replica's network. Refuses otherwise."""
        if not isinstance(replica, Replica):
            raise IsolationError("exec_in requires a Replica")
        if not replica.verified:
            log.warning("sandbox.guard.refused_exec", reason="unverified replica",
                        replica_id=getattr(replica, "replica_id", None))
            raise IsolationError(
                f"refusing exec on unverified replica {replica.replica_id!r}; "
                "it did not pass the isolation guard"
            )
        if replica.network_mode not in _RUNNABLE_MODES:
            log.warning("sandbox.guard.refused_exec", reason="non-runnable network mode",
                        replica_id=replica.replica_id)
            raise IsolationError(
                f"refusing exec on replica {replica.replica_id!r} with "
                f"network_mode={replica.network_mode.value!r}"
            )
        if not argv:
            raise IsolationError("exec_in requires a non-empty argv")
        # Clamp the timeout DOWN into a sane window; never widen it.
        clamped = max(_MIN_EXEC_TIMEOUT_SEC, min(int(timeout_sec), self.max_exec_timeout_sec))
        return await self.backend.exec_in(replica, tuple(argv), timeout_sec=clamped)

    # -- defense-in-depth target check ------------------------------------- #

    def assert_replica_target(self, host: str) -> None:
        """Raise ``IsolationError`` unless ``host`` is a sandbox-internal alias.

        Defense in depth: the prover routes probes through the replica, but any
        code that forms a target string can call this to prove it is pointed at a
        replica alias and not a live/routable address (IMDS, ``localhost``, an IP,
        an external hostname).
        """
        if not _is_replica_alias(host):
            log.warning("sandbox.guard.refused_target", host=str(host)[:120])
            raise IsolationError(
                f"target {host!r} is not a sandbox-internal replica alias; refusing "
                "to treat it as a sandbox target"
            )

    # -- teardown ---------------------------------------------------------- #

    async def destroy(self, replica: Replica) -> None:
        """Best-effort, idempotent teardown. Never raises."""
        await self._safe_destroy(replica)

    async def _safe_destroy(self, replica: Optional[Replica]) -> None:
        if replica is None:
            return
        try:
            await self.backend.destroy(replica)
        except Exception as e:  # noqa: BLE001 - teardown must never raise
            log.warning(
                "sandbox.guard.destroy_failed",
                replica_id=getattr(replica, "replica_id", None),
                err=str(e)[:200],
            )

    # -- session helper ---------------------------------------------------- #

    @asynccontextmanager
    async def session(self, spec: SandboxSpec) -> AsyncIterator[Replica]:
        """Build a VERIFIED replica and guarantee teardown.

        Usage::

            async with guard.session(spec) as replica:
                await guard.exec_in(replica, ("id",))

        The replica is always destroyed on exit, including when the body raises.
        """
        replica = await self.build(spec)
        try:
            yield replica
        finally:
            await self._safe_destroy(replica)
