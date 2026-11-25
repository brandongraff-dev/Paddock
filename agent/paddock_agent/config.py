"""Agent runtime configuration, read from the environment.

Secrets (the key, the ``fat_`` credential) live in the state directory (see :mod:`state`), never in the
environment. The **enrollment token is never a command-line argument**: it is read from the
``PADDOCK_ENROLL_TOKEN`` variable or from stdin (see ``cli.py``), because argv is visible to every local
user in ``ps`` and ``/proc``.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from .state import DEFAULT_STATE_DIR

MIN_HEARTBEAT_S = 5
MIN_POSTURE_S = 60
DEFAULT_DEADMAN_MIN = 10

log = logging.getLogger("paddock-agent.config")
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if v else default


def _env_bool(name: str, default: bool) -> bool:
    """A boolean switch. Only an explicit true/false word changes ``default``; anything else is logged and
    keeps ``default``. Every safety switch here defaults to its SAFE value (dry-run on, IMDS off), so a typo
    (``y``, ``enabled``, ``ture``) can never turn enforcement or an optional egress on."""
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    word = v.strip().lower()
    if word in _TRUE:
        return True
    if word in _FALSE:
        return False
    log.error("%s=%r is not a recognised value (use true/false, 1/0, yes/no, on/off); keeping the safe "
              "default %s", name, v, "on" if default else "off")
    return default


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    try:
        value = int(os.environ.get(name) or default)
    except ValueError:
        value = default
    return max(minimum, value)


def _state_dir() -> str:
    return _env("PADDOCK_STATE_DIR", DEFAULT_STATE_DIR) or DEFAULT_STATE_DIR


@dataclass
class AgentConfig:
    # Empty means "use the server recorded at enrollment". There is no silent localhost default.
    server: str = field(default_factory=lambda: _env("PADDOCK_SERVER", "") or "")
    state_dir: str = field(default_factory=_state_dir)
    quarantine_dir: str = field(
        default_factory=lambda: _env("PADDOCK_QUARANTINE_DIR", os.path.join(_state_dir(), "quarantine"))
        or "")
    # SAFETY: dry-run is TRUE by default. A real apply requires BOTH the server
    # to have approved the action for real (dry_run=false) AND this flag off.
    dry_run: bool = field(default_factory=lambda: _env_bool("PADDOCK_DRY_RUN", True))
    heartbeat_interval_s: int = field(
        default_factory=lambda: _env_int("PADDOCK_HEARTBEAT_SEC", 30, MIN_HEARTBEAT_S))
    posture_interval_s: int = field(
        default_factory=lambda: _env_int("PADDOCK_POSTURE_SEC", 300, MIN_POSTURE_S))
    # The v1 inventory is unsigned and only feeds the Fleet page; 0 turns it off.
    inventory_interval_s: int = field(default_factory=lambda: _env_int("PADDOCK_INVENTORY_SEC", 3600))
    timeout_s: int = field(default_factory=lambda: _env_int("PADDOCK_HTTP_TIMEOUT", 20, 1))
    outbox_max_bytes: int = field(
        default_factory=lambda: _env_int("PADDOCK_OUTBOX_MAX_MB", 64, 1) * 1024 * 1024)
    # Dead-man timer: a network block (block_ip / firewall_rule) the server never heard about again within this
    # many minutes of applying it is removed, so a block that cut the agent off from its server cannot strand
    # the host (the revert would have to arrive over the channel just cut). A block confirmed by any later
    # successful round trip stays. 0 disables it.
    deadman_minutes: int = field(
        default_factory=lambda: _env_int("PADDOCK_NETBLOCK_DEADMAN_MIN", DEFAULT_DEADMAN_MIN, 0))
    # The cloud metadata (IMDS) request is OFF by default (docs/ASSURANCE_P2.md E6).
    enable_imds: bool = field(default_factory=lambda: _env_bool("PADDOCK_ENABLE_IMDS", False))
    ca_file: Optional[str] = field(default_factory=lambda: _env("PADDOCK_CA_FILE"))
    # platform override (mostly for tests); defaults to the running OS.
    platform_name: Optional[str] = field(default_factory=lambda: _env("PADDOCK_PLATFORM"))

    def with_server(self, server: Optional[str]) -> "AgentConfig":
        if server:
            self.server = server.rstrip("/")
        return self
