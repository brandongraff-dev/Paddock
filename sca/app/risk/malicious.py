"""Malicious-package / yanked-release detector (DEFENSIVE).

Two signals, both read-only:
  * ``malicious_version`` -- an OSV advisory with a ``MAL-`` id matched the
    component (OSV's malware feed). We report that the owner is pulling a
    package flagged as malicious; we never reproduce or describe the payload.
  * ``yanked`` -- a registry marked the exact installed version as yanked /
    withdrawn (passed in via ``yanked`` metadata, best-effort, offline-safe).

Input is the OSV scan map from :mod:`app.osv` keyed ``"eco|name|version"``.
"""
from __future__ import annotations

from typing import Any

RISK_TYPE_MAL = "malicious_version"
RISK_TYPE_YANKED = "yanked"


def _key(c: dict[str, Any]) -> str:
    return f"{c.get('ecosystem')}|{c.get('name')}|{c.get('version')}"


def detect(
    components: list[dict[str, Any]],
    osv_results: dict[str, list[dict[str, Any]]] | None = None,
    *,
    yanked_keys: set[str] | None = None,
) -> list[dict[str, Any]]:
    osv_results = osv_results or {}
    yanked_keys = yanked_keys or set()
    out: list[dict[str, Any]] = []
    for c in components:
        key = _key(c)
        # malicious: any matched OSV vuln flagged malicious
        mal_ids = [
            v.get("osv_id")
            for v in osv_results.get(key, [])
            if v.get("malicious")
        ]
        if mal_ids:
            out.append({
                "risk_type": RISK_TYPE_MAL,
                "severity": "critical",
                "summary": (
                    f"'{c.get('name')}'@{c.get('version')} ({c.get('ecosystem')}) matches "
                    f"an OSV malicious-package advisory ({', '.join(x for x in mal_ids if x)})"
                ),
                "detail": {
                    "ecosystem": c.get("ecosystem"),
                    "osv_ids": [x for x in mal_ids if x],
                    "action": "Remove this package immediately, rotate anything it could "
                              "have accessed during install, and audit the build host.",
                },
                "ecosystem": c.get("ecosystem"),
                "name": c.get("name"),
                "version": c.get("version"),
            })
        if key in yanked_keys:
            out.append({
                "risk_type": RISK_TYPE_YANKED,
                "severity": "medium",
                "summary": (
                    f"'{c.get('name')}'@{c.get('version')} ({c.get('ecosystem')}) was yanked / "
                    "withdrawn by the registry"
                ),
                "detail": {
                    "ecosystem": c.get("ecosystem"),
                    "note": "The maintainer pulled this exact version; move to a current "
                            "release.",
                },
                "ecosystem": c.get("ecosystem"),
                "name": c.get("name"),
                "version": c.get("version"),
            })
    return out
