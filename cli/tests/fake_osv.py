"""An in-process fake of api.osv.dev for tests (no network).

Advisories are modelled on real OSV records (same ids / fixed versions for the
well-known ones) and evaluated with the CLI's own version comparison, so the
"nearest non-vulnerable version" logic runs against realistic range data.
"""
from __future__ import annotations

from typing import Any

from paddock_cli import versions as V

# (id, aliases, ecosystem, package, [(introduced, fixed|None)], severity label, cvss vector|None, summary)
ADVISORIES: list[dict[str, Any]] = [
    {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "eco": "npm", "pkg": "lodash",
     "ranges": [("0", "4.17.21")], "sev": "HIGH", "cvss": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
     "summary": "Command Injection in lodash"},
    {"id": "GHSA-p6mc-m468-83gw", "aliases": ["CVE-2020-8203"], "eco": "npm", "pkg": "lodash",
     "ranges": [("0", "4.17.19")], "sev": "HIGH", "cvss": None,
     "summary": "Prototype Pollution in lodash"},
    {"id": "GHSA-x84v-xcm2-53pg", "aliases": ["CVE-2018-18074"], "eco": "PyPI", "pkg": "requests",
     "ranges": [("0", "2.20.0")], "sev": "HIGH", "cvss": None,
     "summary": "Insufficiently Protected Credentials in requests"},
    {"id": "GHSA-j8r2-6x86-q33q", "aliases": ["CVE-2023-32681"], "eco": "PyPI", "pkg": "requests",
     "ranges": [("2.3.0", "2.31.0")], "sev": "MODERATE", "cvss": None,
     "summary": "Unintended leak of Proxy-Authorization header in requests"},
    {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"], "eco": "Maven",
     "pkg": "org.apache.logging.log4j:log4j-core", "ranges": [("2.0-beta9", "2.15.0")],
     "sev": "CRITICAL", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
     "summary": "Remote code injection in Log4j"},
    {"id": "GHSA-7rjr-3q55-vv33", "aliases": ["CVE-2021-45046"], "eco": "Maven",
     "pkg": "org.apache.logging.log4j:log4j-core", "ranges": [("2.0-beta9", "2.16.0")],
     "sev": "CRITICAL", "cvss": None, "summary": "Incomplete fix for Apache Log4j vulnerability"},
    {"id": "GHSA-h395-qcrw-5vmq", "aliases": ["CVE-2020-28483"], "eco": "Go",
     "pkg": "github.com/gin-gonic/gin", "ranges": [("0", "v1.7.0")], "sev": "HIGH", "cvss": None,
     "summary": "Gin Web Framework does not properly sanitize forwarded client IP"},
    # synthetic: affects only the version that fixes the advisory above, so the CLI must hop twice
    {"id": "GHSA-demo-0001-gin", "aliases": [], "eco": "Go", "pkg": "github.com/gin-gonic/gin",
     "ranges": [("v1.7.0", "v1.7.7")], "sev": "MODERATE", "cvss": None,
     "summary": "Synthetic follow-up advisory (test data)"},
    {"id": "MAL-2024-0001", "aliases": [], "eco": "npm", "pkg": "evil-demo-pkg",
     "ranges": [("0", None)], "sev": "CRITICAL", "cvss": None,
     "summary": "Malicious code in evil-demo-pkg (test data)"},
]


def _affects(adv: dict[str, Any], version: str) -> bool:
    for intro, fixed in adv["ranges"]:
        if V.compare(version, intro if intro != "0" else "0") >= 0 and (
                fixed is None or V.compare(version, fixed) < 0):
            return True
    return False


def _record(adv: dict[str, Any]) -> dict[str, Any]:
    events: list[dict[str, str]] = []
    for intro, fixed in adv["ranges"]:
        events.append({"introduced": intro})
        if fixed:
            events.append({"fixed": fixed})
    rec: dict[str, Any] = {
        "id": adv["id"], "aliases": adv["aliases"], "summary": adv["summary"],
        "details": adv["summary"] + ".",
        "database_specific": {"severity": adv["sev"]},
        "affected": [{"package": {"ecosystem": adv["eco"], "name": adv["pkg"]},
                      "ranges": [{"type": "ECOSYSTEM", "events": events}]}],
        "references": [{"type": "ADVISORY", "url": f"https://osv.dev/vulnerability/{adv['id']}"}],
    }
    if adv["cvss"]:
        rec["severity"] = [{"type": "CVSS_V3", "score": adv["cvss"]}]
    return rec


class FakeOsv:
    """Callable transport: ``FakeOsv()(method, url, body)``."""

    def __init__(self, advisories: list[dict[str, Any]] | None = None) -> None:
        self.advisories = ADVISORIES if advisories is None else advisories
        self.calls: list[tuple[str, str]] = []
        self.fail = False

    def ids_for(self, eco: str, name: str, version: str) -> list[str]:
        return [a["id"] for a in self.advisories
                if a["eco"] == eco and a["pkg"].lower() == name.lower() and _affects(a, version)]

    def __call__(self, method: str, url: str, body: Any = None) -> Any:
        self.calls.append((method, url))
        if self.fail:
            raise OSError("network down")
        if url.endswith("/v1/querybatch"):
            return {"results": [
                {"vulns": [{"id": i, "modified": "2024-01-01T00:00:00Z"} for i in self.ids_for(
                    q["package"]["ecosystem"], q["package"]["name"], q.get("version", ""))]}
                for q in body["queries"]]}
        if "/v1/vulns/" in url:
            vid = url.rsplit("/", 1)[-1]
            for a in self.advisories:
                if a["id"] == vid:
                    return _record(a)
            return None
        raise OSError(f"unexpected url {url}")
