"""Agent runtime configuration.

Pulled from environment + an optional on-disk credential file. The credential
file is written at enrollment time and holds the agent id + the minted agent
token (its only copy; the server stores only a hash).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    return v if v else default


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name) or default)
    except ValueError:
        return default


DEFAULT_CRED_PATH = os.environ.get(
    "PASM_AGENT_CRED", str(Path.home() / ".config" / "palantir-agent" / "credentials.json")
)
DEFAULT_QUARANTINE_DIR = os.environ.get(
    "PASM_QUARANTINE_DIR", "/var/lib/palantir-agent/quarantine"
)


@dataclass
class AgentConfig:
    server: str = field(default_factory=lambda: _env("PASM_SERVER", "http://localhost:8080") or "")
    cred_path: str = field(default_factory=lambda: DEFAULT_CRED_PATH)
    quarantine_dir: str = field(default_factory=lambda: DEFAULT_QUARANTINE_DIR)
    # SAFETY: dry-run is TRUE by default. A real apply requires BOTH the server
    # to have approved the action for real (dry_run=false) AND this flag off.
    dry_run: bool = field(default_factory=lambda: _env_bool("PASM_DRY_RUN", True))
    heartbeat_interval_s: int = field(default_factory=lambda: _env_int("PASM_HEARTBEAT_SEC", 30))
    inventory_interval_s: int = field(default_factory=lambda: _env_int("PASM_INVENTORY_SEC", 300))
    timeout_s: int = field(default_factory=lambda: _env_int("PASM_HTTP_TIMEOUT", 20))
    # platform override (mostly for tests); defaults to the running OS.
    platform_name: str | None = field(default_factory=lambda: _env("PASM_PLATFORM"))

    def with_server(self, server: str | None) -> "AgentConfig":
        if server:
            self.server = server.rstrip("/")
        return self


@dataclass
class Credentials:
    agent_id: str
    agent_token: str
    server: str
    hostname: str

    def to_json(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_token": self.agent_token,
            "server": self.server,
            "hostname": self.hostname,
        }


def load_credentials(path: str) -> Credentials | None:
    p = Path(path)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    try:
        return Credentials(
            agent_id=data["agent_id"],
            agent_token=data["agent_token"],
            server=data.get("server", ""),
            hostname=data.get("hostname", ""),
        )
    except KeyError:
        return None


def save_credentials(path: str, creds: Credentials) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(creds.to_json(), indent=2))
    # The token is a secret; keep it readable only by the owner.
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
