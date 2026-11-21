"""Best-effort public-registry metadata (last-release date, yanked versions).

Read-only GETs against public package-registry metadata endpoints (npm, PyPI).
Used by the ``abandoned`` and ``yanked`` detectors. Every call degrades
gracefully: on any network/parse error it returns ``None`` so the scan still
completes offline. No registry is ever written to.
"""
from __future__ import annotations

import logging
from typing import Any

import aiohttp

log = logging.getLogger("sca.registry")

NPM_URL = "https://registry.npmjs.org/{name}"
PYPI_URL = "https://pypi.org/pypi/{name}/json"


async def _get_json(session: aiohttp.ClientSession, url: str) -> dict[str, Any] | None:
    try:
        async with session.get(url) as resp:
            if resp.status != 200:
                return None
            return await resp.json()
    except Exception as exc:  # network off, DNS, timeout, bad json -> skip
        log.debug("registry fetch failed %s: %s", url, exc)
        return None


async def metadata(
    session: aiohttp.ClientSession, ecosystem: str, name: str
) -> dict[str, Any] | None:
    """Return {'last_release': iso-or-None, 'yanked_versions': set} or None."""
    if ecosystem == "npm":
        return await _npm_metadata(session, name)
    if ecosystem == "PyPI":
        return await _pypi_metadata(session, name)
    return None


async def _npm_metadata(session: aiohttp.ClientSession, name: str) -> dict[str, Any] | None:
    data = await _get_json(session, NPM_URL.format(name=name))
    if not isinstance(data, dict):
        return None
    times = data.get("time") or {}
    last = None
    if isinstance(times, dict):
        # 'modified' is the newest publish timestamp
        last = times.get("modified")
        if not last:
            stamps = [v for k, v in times.items() if k not in ("created",)]
            last = max(stamps) if stamps else None
    return {"last_release": last, "yanked_versions": set()}


async def _pypi_metadata(session: aiohttp.ClientSession, name: str) -> dict[str, Any] | None:
    data = await _get_json(session, PYPI_URL.format(name=name))
    if not isinstance(data, dict):
        return None
    releases = data.get("releases") or {}
    last = None
    yanked: set[str] = set()
    if isinstance(releases, dict):
        for ver, files in releases.items():
            if not isinstance(files, list):
                continue
            all_yanked = files and all(
                isinstance(f, dict) and f.get("yanked") for f in files
            )
            if all_yanked:
                yanked.add(ver)
            for f in files:
                if isinstance(f, dict) and f.get("upload_time_iso_8601"):
                    t = f["upload_time_iso_8601"]
                    if last is None or t > last:
                        last = t
    return {"last_release": last, "yanked_versions": yanked}
