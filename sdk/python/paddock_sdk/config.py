"""``paddockctl`` configuration profiles.

Stored as JSON at ``$PADDOCK_CONFIG`` or ``~/.config/paddock/paddockctl.json``
(created 0600, because it can hold an API key or JWT)::

    {
      "current": "prod",
      "profiles": {
        "prod": {"url": "https://paddock.internal", "api_key": "pak_..."},
        "lab":  {"url": "http://localhost:8080", "token": "eyJ..."}
      }
    }

Environment variables override the profile: ``PADDOCK_URL``,
``PADDOCK_API_KEY``, ``PADDOCK_TOKEN``, ``PADDOCK_PROFILE``.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._core import DEFAULT_URL


def config_path() -> Path:
    env = os.environ.get("PADDOCK_CONFIG")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "paddock" / "paddockctl.json"


@dataclass
class Profile:
    name: str
    url: str = DEFAULT_URL
    api_key: str | None = None
    token: str | None = None
    verify_tls: bool = True

    def redacted(self) -> dict[str, Any]:
        def mask(v: str | None) -> str | None:
            if not v:
                return None
            return v[:8] + "..." if len(v) > 12 else "***"

        return {"name": self.name, "url": self.url, "api_key": mask(self.api_key),
                "token": mask(self.token), "verify_tls": self.verify_tls}


@dataclass
class Config:
    current: str = "default"
    profiles: dict[str, dict[str, Any]] = field(default_factory=dict)
    path: Path = field(default_factory=config_path)

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        p = path or config_path()
        if not p.exists():
            return cls(path=p)
        data = json.loads(p.read_text(encoding="utf-8") or "{}")
        return cls(current=data.get("current", "default"), profiles=data.get("profiles", {}), path=p)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"current": self.current, "profiles": self.profiles}, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    def profile(self, name: str | None = None) -> Profile:
        name = name or os.environ.get("PADDOCK_PROFILE") or self.current
        raw = dict(self.profiles.get(name, {}))
        prof = Profile(name=name, url=raw.get("url", DEFAULT_URL), api_key=raw.get("api_key"),
                       token=raw.get("token"), verify_tls=raw.get("verify_tls", True))
        if os.environ.get("PADDOCK_URL"):
            prof.url = os.environ["PADDOCK_URL"]
        if os.environ.get("PADDOCK_API_KEY"):
            prof.api_key, prof.token = os.environ["PADDOCK_API_KEY"], None
        elif os.environ.get("PADDOCK_TOKEN"):
            prof.token, prof.api_key = os.environ["PADDOCK_TOKEN"], None
        return prof

    def set_profile(self, prof: Profile, *, make_current: bool = True) -> None:
        self.profiles[prof.name] = {k: v for k, v in {
            "url": prof.url, "api_key": prof.api_key, "token": prof.token,
            "verify_tls": prof.verify_tls,
        }.items() if v is not None}
        if make_current:
            self.current = prof.name
