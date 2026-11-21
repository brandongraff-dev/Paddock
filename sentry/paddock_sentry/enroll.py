"""``paddock-sentry enroll``: exchange a one-time token for a sensor credential.

    paddock-sentry enroll https://paddock.example:8101 pet_xxxxxxxx_...

The only connection made is to the server you name. The server answers with a
per-sensor credential, shown exactly once; it is written to the credential
file with mode 0600 and never printed.
"""
from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from . import __version__, netif, store


class EnrollError(RuntimeError):
    pass


def normalize_server(server: str, *, allow_http: bool = False) -> str:
    s = server.strip().rstrip("/")
    if "://" not in s:
        s = "https://" + s
    parts = urlsplit(s)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise EnrollError(f"{server!r} is not a valid server URL (expected https://host:port)")
    if parts.scheme == "http" and not allow_http and not _is_local(parts.hostname):
        raise EnrollError(
            "refusing to send an enrollment token over plain http. Put the ingest port behind "
            "TLS (https://), or pass --allow-http if this is a trusted lab network.")
    return s


def _is_local(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback


def enroll(server: str, token: str, *, name: str | None = None, cred_path: str | None = None,
           force: bool = False, allow_http: bool = False, timeout: float = 20.0) -> store.Credentials:
    server = normalize_server(server, allow_http=allow_http)
    path = cred_path or store.default_path()
    if not force:
        try:
            existing = store.load(path)
        except store.CredentialError:
            existing = None
        if existing is not None:
            raise EnrollError(
                f"this sensor is already enrolled as {existing.name or existing.sensor_id} "
                f"(site {existing.site or '?'}). Revoke it in the dashboard and re-run with --force "
                "to enroll again.")
    body: dict[str, Any] = {
        "token": token.strip(),
        "hostname": netif.hostname(),
        "version": __version__,
        "interfaces": netif.interface_report(),
    }
    if name:
        body["name"] = name
    data = json.dumps(body).encode()
    req = urllib.request.Request(server + "/enroll", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", f"paddock-sentry/{__version__} (+passive sensor)")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - the operator's server
            out = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise EnrollError(_explain(exc)) from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise EnrollError(
            f"could not reach {server}: {getattr(exc, 'reason', exc)}. Check the address, that this "
            "device has network access, and that the Paddock sensor-ingest port is reachable.") from exc
    except ValueError as exc:
        raise EnrollError(f"{server} did not answer like a Paddock server: {exc}") from exc
    try:
        creds = store.Credentials(
            server=server, sensor_id=str(out["sensor_id"]), credential=str(out["credential"]),
            name=str(out.get("name", "")), site=str(out.get("site", "")),
            enrolled_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
    except KeyError as exc:
        raise EnrollError(f"unexpected enrollment response (missing {exc})") from exc
    store.save(path, creds)
    return creds


def _explain(exc: urllib.error.HTTPError) -> str:
    try:
        detail = json.loads(exc.read().decode()).get("detail") or ""
    except (ValueError, OSError, AttributeError):
        detail = ""
    if exc.code == 401:
        return ("the server rejected the enrollment token: it is wrong, already used, revoked or "
                "expired (tokens are single-use and short-lived). Create a new one in the "
                "dashboard: Sensors > Add sensor.")
    if exc.code == 429:
        return "too many enrollment attempts from this address; wait a minute and try again."
    if exc.code == 404:
        return ("the server has no sensor enrollment endpoint: is this the Paddock sensor-ingest "
                "address (port 8101) and a current version?")
    return f"enrollment failed (HTTP {exc.code}){': ' + str(detail) if detail else ''}"
