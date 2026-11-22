"""Core data contracts for the Proving Ground sandbox.

This module is intentionally I/O-free and dependency-free so it can be imported
by the isolation guard, the backends, the scenarios and the prover without
pulling in docker, asyncpg or httpx. It defines WHAT a sandbox run operates on;
``guard.py`` enforces the one invariant and ``backend.py`` implements the
mechanics.

THE ONE INVARIANT (enforced in ``guard.py``, recorded on every run):

    A scenario only ever runs against an isolated REPLICA the customer owns,
    on an internal-only network with NO route to any live or out-of-scope
    system. There is no "run against production" path anywhere in this service.

Everything here supports that: a ``SandboxSpec`` can only describe a replica to
*build* (an image + config), never a live target address; a ``Replica`` carries
the isolation facts that held; and ``ExecResult`` is the captured output of a
command run *inside* the replica's network namespace.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable


class IsolationError(RuntimeError):
    """Raised when a sandbox operation would, or did, breach isolation.

    Any path that could touch a non-replica target, open egress, or run against
    an address instead of a built replica raises this. It is never caught and
    swallowed inside the service: it fails the run closed and is audited.
    """


class NetworkMode(str, Enum):
    """How a replica's network is confined. Only INTERNAL is ever allowed to
    run a scenario; the others exist so the guard can name what it refused."""

    #: Docker ``--internal`` network (or equivalent): containers can talk to
    #: each other but the bridge has no route to the host or the internet.
    INTERNAL = "internal"
    #: No network at all (``--network none``): used for pure-local checks.
    NONE = "none"
    #: Anything else (bridge/host/a real CIDR). The guard REFUSES these.
    OPEN = "open"


# A replica id is an opaque token the backend assigns. Replica endpoints are
# only ever hostnames *inside* the sandbox network (service aliases), never a
# routable address. This pattern is what the guard checks endpoints against.
_SANDBOX_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")

# Hostnames that would indicate a real/outside target slipped in. The guard
# rejects a replica whose endpoint resolves to, or is literally, any of these
# shapes. (Belt-and-suspenders: the INTERNAL network already has no route out.)
_FORBIDDEN_HOST_TOKENS = (
    "localhost",
    "metadata.google",      # cloud metadata endpoints
    "169.254.169.254",      # link-local / IMDS
    "host.docker.internal",
)


@dataclass(frozen=True)
class SandboxSpec:
    """What to BUILD. Describes a replica, never a live address.

    ``image`` is a container image reference the owner's registry/SBOM vouches
    for; ``image_digest`` pins it. ``config``/``env``/``cmd`` reproduce the
    component's real configuration (from the technology asset / IaC) so the
    replica matches production *shape* without being production.
    """

    #: Logical component this replicates, e.g. "nginx", "jenkins", "redis".
    component: str
    #: Container image reference, e.g. "library/redis:6.0" or a private digest.
    image: str
    #: Pinned digest ("sha256:...") when known; the backend prefers it.
    image_digest: Optional[str] = None
    #: Version label for the proof record.
    version: Optional[str] = None
    #: Environment variables reproducing the component's config.
    env: dict[str, str] = field(default_factory=dict)
    #: Command override, if the scenario needs one.
    cmd: tuple[str, ...] = ()
    #: Internal port the replica listens on (reached only inside the sandbox net).
    port: Optional[int] = None
    #: Free-form config the scenario reproduces (mounted files, flags...).
    config: dict[str, Any] = field(default_factory=dict)
    #: Resource caps the backend enforces.
    cpu: float = 1.0
    mem_mb: int = 512
    #: Hard wall-clock cap for the whole replica lifetime (seconds).
    ttl_sec: int = 300
    #: Sidecar replicas this scenario also needs (e.g. an attacker toolbox
    #: image), each a SandboxSpec joined to the same internal network.
    sidecars: tuple["SandboxSpec", ...] = ()

    def __post_init__(self) -> None:
        if not self.component or not self.image:
            raise IsolationError("SandboxSpec requires a component and an image")
        # A spec must name an image to build, never an address to reach. Reject
        # anything that looks like a URL/host:port target sneaking in via image.
        if "://" in self.image or self.image.strip().startswith(("http", "tcp")):
            raise IsolationError(f"image must be a registry reference, not a URL: {self.image!r}")


@dataclass(frozen=True)
class Replica:
    """A built, running, isolated replica. Endpoints are sandbox-internal only."""

    replica_id: str
    component: str
    network_mode: NetworkMode
    #: Service alias reachable ONLY inside the sandbox network.
    internal_host: str
    internal_port: Optional[int]
    image: str
    image_digest: Optional[str] = None
    backend: str = "unknown"
    #: Network name the backend created (internal-only).
    network: str = ""
    #: True once the guard has verified this replica's isolation facts.
    verified: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def isolation_record(self) -> dict[str, Any]:
        """The isolation facts persisted on ``wargame_runs.isolation``."""
        return {
            "backend": self.backend,
            "network_mode": self.network_mode.value,
            "egress": "none",
            "network": self.network,
            "replica_id": self.replica_id,
            "image": self.image,
            "image_digest": self.image_digest,
            "verified": self.verified,
        }


@dataclass
class ExecResult:
    """Captured output of a command run INSIDE the sandbox network."""

    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False
    #: Where it ran (replica id), for the proof record.
    replica_id: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def is_sandbox_internal_host(host: str) -> bool:
    """True only for a plausible sandbox-internal service alias.

    A replica is reached by a SINGLE-LABEL network alias (``redis-ab12cd``), so
    any dotted host is rejected: that excludes every FQDN (``evil.com``,
    ``metadata.google.internal``) and every IP literal in one rule, which is
    exactly what we want — a routable target can never masquerade as a replica.
    Empty, dangerous-token and non-label hosts are rejected too. This is the
    syntactic half of the guard's endpoint check; the other half is that the
    network itself is INTERNAL/NONE, which the guard verifies with the backend.
    """
    h = (host or "").strip().lower()
    if not h or not _SANDBOX_HOST_RE.match(h):
        return False
    # Single DNS label only: no dots. Rejects FQDNs and IPv4/IPv6 literals.
    if "." in h or ":" in h:
        return False
    if any(tok in h for tok in _FORBIDDEN_HOST_TOKENS):
        return False
    return True


@runtime_checkable
class SandboxBackend(Protocol):
    """A mechanism that can build and drive isolated replicas.

    Implementations (``FakeBackend`` for tests, ``DockerBackend`` for real runs)
    MUST create replicas on an internal-only (or no) network and never publish a
    port or grant egress. The guard wraps a backend and refuses to proceed if
    these facts don't hold, so a backend bug fails closed rather than leaking.
    """

    name: str

    async def build(self, spec: SandboxSpec) -> Replica:
        """Create and start an isolated replica (and its sidecars). Raises
        ``IsolationError`` if it cannot guarantee internal-only networking."""
        ...

    async def exec_in(
        self, replica: Replica, argv: tuple[str, ...], *, timeout_sec: int = 30
    ) -> ExecResult:
        """Run ``argv`` inside the sandbox network (in the replica or a sidecar
        toolbox) and capture output. Never runs on the host."""
        ...

    async def network_is_isolated(self, replica: Replica) -> bool:
        """Confirm, by asking the backend about the live replica, that its
        network has no route out (used by the guard as defence in depth)."""
        ...

    async def destroy(self, replica: Replica) -> None:
        """Tear down the replica, its sidecars and its network. Best-effort,
        idempotent; always attempted in a ``finally``."""
        ...
