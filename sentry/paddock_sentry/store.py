"""The sensor's credential file.

Written once by ``paddock-sentry enroll`` and read by ``run``. It holds the
per-sensor credential (the server keeps only its hash), so it is created
atomically with mode 0600 and refused on read if it is group/world accessible.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SYSTEM_PATH = "/var/lib/paddock-sentry/credentials.json"


def default_path() -> str:
    env = os.environ.get("PADDOCK_SENTRY_CRED")
    if env:
        return env
    if os.path.isdir(os.path.dirname(SYSTEM_PATH)):
        return SYSTEM_PATH
    return str(Path.home() / ".config" / "paddock-sentry" / "credentials.json")


class CredentialError(RuntimeError):
    pass


@dataclass
class Credentials:
    server: str
    sensor_id: str
    credential: str
    name: str = ""
    site: str = ""
    enrolled_at: str = ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def save(path: str | os.PathLike[str], creds: Credentials) -> None:
    """Write atomically, 0600 from the first byte (no world-readable window)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".cred-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(creds.to_json(), fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load(path: str | os.PathLike[str]) -> Credentials | None:
    p = Path(path)
    if not p.is_file():
        return None
    mode = stat.S_IMODE(p.stat().st_mode)
    if mode & 0o077:
        raise CredentialError(
            f"{p} is accessible by other users (mode {mode:04o}); run: chmod 600 {p}")
    try:
        data = json.loads(p.read_text())
        return Credentials(
            server=str(data["server"]), sensor_id=str(data["sensor_id"]),
            credential=str(data["credential"]), name=str(data.get("name", "")),
            site=str(data.get("site", "")), enrolled_at=str(data.get("enrolled_at", "")),
        )
    except (OSError, ValueError, KeyError) as exc:
        raise CredentialError(f"{p} is not a valid credential file: {exc}") from exc
