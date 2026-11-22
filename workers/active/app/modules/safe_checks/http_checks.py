"""HTTP-based safe checks (GET/HEAD only).

exposed_file      a sensitive path is still served          (exposed_file rules)
admin_panel       an admin/login panel is still reachable   (nuclei panel rules)
directory_listing an auto-index is still served             (nuclei dir-listing rules)
version_disclosure / default_page   banner / stock page still shown
security_headers  a missing/weak response header is still missing/weak

Every check answers one question about the SAME thing the original finding
claimed, using the same decision rule the detector used, so "not_reproducible"
means "the detector would no longer fire", not "we looked differently".
A check never decides ``not_reproducible`` from an error, a rate limit or a
403 it cannot tell apart from a WAF block: those are ``inconclusive``.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from app.modules import exposed_file as exposed_file_mod
from app.modules import header_check as header_check_mod

from .base import (
    SUSPECT_BLOCK,
    TRANSIENT,
    CheckEnv,
    CheckResult,
    Fetch,
    FindingCtx,
    SafeFetcher,
    blocked_by_server,
    confirmed,
    excerpt,
    inconclusive,
    not_reproducible,
    sha_prefix,
)

_SNIFF = 8192


def _classify_fetch_problem(check_id: str, f: Fetch) -> CheckResult | None:
    """Errors and transient statuses are never proof of a fix."""
    if f.error:
        return inconclusive(check_id, f"could not reach the target: {f.error}", url=f.url)
    if f.status in TRANSIENT:
        return inconclusive(check_id, f"target answered {f.status} (transient/rate limit)",
                            url=f.url, status=f.status)
    return None


# --------------------------------------------------------------------------- #
# exposed_file
# --------------------------------------------------------------------------- #

_EXPOSED = {t.rule_id: t for t in exposed_file_mod.PATHS}
# Archives have no text marker; require the magic number instead of "HTML or not".
_MAGIC = {"exposed-backup-archive": (b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"7z\xbc\xaf")}


def _match_exposed_file(f: FindingCtx) -> bool:
    return f.rule_source == "exposed_file" and f.rule_id in _EXPOSED


async def _run_exposed_file(f: FindingCtx, env: CheckEnv) -> CheckResult:
    cid = "exposed_file"
    entry = _EXPOSED[f.rule_id]
    url = f.evidence_url()
    if url is None:
        base = f.base_url()
        if base is None:
            return inconclusive(cid, "finding has no URL or host to re-check")
        url = urljoin(base, entry.path.lstrip("/"))
    fetcher = SafeFetcher(env, cid)
    r = await fetcher.get(url, max_bytes=_SNIFF)
    if (bad := _classify_fetch_problem(cid, r)) is not None:
        return bad
    ev = {"url": url, "status": r.status, "content_type": r.headers.get("content-type")}
    if r.status == 200:
        head = r.body[:_SNIFF]
        magic = _MAGIC.get(f.rule_id)
        if magic is not None:
            hit = head.startswith(magic)
        elif entry.pattern is None:
            hit = "html" not in (r.headers.get("content-type") or "").lower()
        else:
            hit = bool(entry.pattern.search(head))
        if hit:
            return confirmed(cid, f"{entry.path} is still served (HTTP 200, expected content present)",
                             **ev, bytes_read=len(r.body), sha256_16=sha_prefix(head),
                             excerpt=excerpt(head))
        return not_reproducible(cid, f"{entry.path} answers 200 but no longer matches the exposed "
                                     "content signature", **ev)
    if r.status in SUSPECT_BLOCK:
        why = await blocked_by_server(fetcher, f"{urlsplit(url).scheme}://{urlsplit(url).netloc}/", r.status)
        if why:
            return inconclusive(cid, why, **ev)
    return not_reproducible(cid, f"{entry.path} now answers HTTP {r.status}", **ev)


# --------------------------------------------------------------------------- #
# admin panel
# --------------------------------------------------------------------------- #

_PANEL_RULE = re.compile(
    r"(?i)(^|[-_/:])(exposed-admin|admin-panel|login-panel|exposed-panel|admin|panel|panels|login)([-_/:]|$)")
_PANEL_MARKERS = [
    ("password-input", re.compile(r"(?i)<input[^>]+type=[\"']?password")),
    ("login-title", re.compile(r"(?i)<title>[^<]*(admin|log ?in|sign ?in|dashboard|console|manager)[^<]*</title>")),
    ("login-form-field", re.compile(r"(?i)name=[\"']?(username|user|login|j_username)[\"']?")),
]
_TITLE = re.compile(r"(?is)<title>(.*?)</title>")


def _match_admin_panel(f: FindingCtx) -> bool:
    if f.rule_source not in ("nuclei", "policy", "manual"):
        return False
    tags = [str(t).lower() for t in (f.metadata.get("tags") or [])]
    return bool(_PANEL_RULE.search(f.rule_id) or "panel" in tags) and f.evidence_url() is not None


async def _run_admin_panel(f: FindingCtx, env: CheckEnv) -> CheckResult:
    cid = "admin_panel"
    url = f.evidence_url()
    assert url
    fetcher = SafeFetcher(env, cid)
    r = await fetcher.get(url, max_bytes=_SNIFF * 2)
    if (bad := _classify_fetch_problem(cid, r)) is not None:
        return bad
    ev = {"url": url, "final_url": r.url, "status": r.status}
    orig_host = (urlsplit(url).hostname or "").lower()
    if (urlsplit(r.url).hostname or "").lower() != orig_host:
        return not_reproducible(cid, f"{url} now redirects to another host ({urlsplit(r.url).hostname})", **ev)
    if r.status == 401 and "www-authenticate" in r.headers:
        scheme = r.headers["www-authenticate"].split(" ", 1)[0]
        return confirmed(cid, "panel is still reachable and prompts for authentication",
                         **ev, auth_scheme=scheme)
    if r.status == 200:
        body = r.text()
        markers = [name for name, rx in _PANEL_MARKERS if rx.search(body)]
        matcher = f.evidence.get("matcher_name")
        if isinstance(matcher, str) and len(matcher) >= 3 and matcher.lower() in body.lower():
            markers.append("detector-matcher")
        if markers:
            t = _TITLE.search(body)
            return confirmed(cid, "panel is still reachable and shows a login/admin interface",
                             **ev, markers=markers, title=excerpt(t.group(1), 100) if t else None)
        return not_reproducible(cid, "page answers 200 but shows no login/admin interface", **ev)
    if r.status in SUSPECT_BLOCK:
        why = await blocked_by_server(fetcher, f"{urlsplit(url).scheme}://{urlsplit(url).netloc}/", r.status)
        if why:
            return inconclusive(cid, why, **ev)
    return not_reproducible(cid, f"panel URL now answers HTTP {r.status}", **ev)


# --------------------------------------------------------------------------- #
# directory listing
# --------------------------------------------------------------------------- #

_DIRLIST_RULE = re.compile(r"(?i)dir(ectory)?[-_]?(listing|index)|index-of|autoindex|open-directory")
_DIRLIST_BODY = re.compile(
    r"(?is)<title>\s*Index of\s*/|<h1>\s*Index of\s|Directory listing for\s|<title>\s*Directory Listing"
    r"|\[To Parent Directory\]|<a href=\"\.\./\">\.\./</a>|Parent Directory</a>")


def _match_dir_listing(f: FindingCtx) -> bool:
    return bool(_DIRLIST_RULE.search(f.rule_id)) and f.evidence_url() is not None


async def _run_dir_listing(f: FindingCtx, env: CheckEnv) -> CheckResult:
    cid = "directory_listing"
    url = f.evidence_url()
    assert url
    fetcher = SafeFetcher(env, cid)
    r = await fetcher.get(url, max_bytes=_SNIFF)
    if (bad := _classify_fetch_problem(cid, r)) is not None:
        return bad
    ev = {"url": url, "status": r.status}
    if r.status == 200 and _DIRLIST_BODY.search(r.text()):
        t = _TITLE.search(r.text())
        return confirmed(cid, "directory auto-index is still served", **ev,
                         title=excerpt(t.group(1), 100) if t else None, bytes_read=len(r.body))
    if r.status in SUSPECT_BLOCK:
        why = await blocked_by_server(fetcher, f"{urlsplit(url).scheme}://{urlsplit(url).netloc}/", r.status)
        if why:
            return inconclusive(cid, why, **ev)
    return not_reproducible(cid, "no directory listing is served at this URL any more", **ev)


# --------------------------------------------------------------------------- #
# default page / version disclosure
# --------------------------------------------------------------------------- #

_VERSION_RULE = re.compile(
    r"(?i)(server|x-powered-by|version|banner)[-_]?(header|disclos|detect|leak)|"
    r"(apache|nginx|iis|tomcat|php|openssl)[-_]?(version|detect)|tech-detect-version|"
    r"x-aspnet-version|server-version")
_DEFAULT_RULE = re.compile(
    r"(?i)default[-_](page|welcome|apache|nginx|iis|tomcat|index)|welcome[-_]page|"
    r"(apache|nginx|iis|tomcat)[-_]default|it-works|test-page")
_VERSIONISH = re.compile(r"\d+\.\d+|/\d")
_VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
_DEFAULT_PAGES = [
    ("nginx", re.compile(r"(?i)<title>Welcome to nginx!?</title>")),
    ("apache-debian", re.compile(r"(?i)Apache2 (Ubuntu|Debian) Default Page")),
    ("apache-rhel", re.compile(r"(?i)Test Page for the (Apache|HTTP Server)")),
    ("apache-it-works", re.compile(r"(?i)<h1>It works!</h1>")),
    ("iis", re.compile(r"(?i)<title>IIS Windows Server</title>|Internet Information Services")),
    ("tomcat", re.compile(r"(?i)Apache Tomcat/[\d.]+.*(successfully installed|congratulations)|<title>Apache Tomcat")),
    ("lighttpd", re.compile(r"(?i)<title>Placeholder page</title>")),
    ("caddy", re.compile(r"(?i)<title>Caddy works!</title>")),
]


def _match_version_disclosure(f: FindingCtx) -> bool:
    return bool(_VERSION_RULE.search(f.rule_id)) and not _DEFAULT_RULE.search(f.rule_id) \
        and f.base_url() is not None


def _match_default_page(f: FindingCtx) -> bool:
    return bool(_DEFAULT_RULE.search(f.rule_id)) and f.base_url() is not None


async def _run_version_disclosure(f: FindingCtx, env: CheckEnv) -> CheckResult:
    cid = "version_disclosure"
    url = f.evidence_url() or f.base_url()
    assert url
    r = await SafeFetcher(env, cid).get(url, max_bytes=1024)
    if (bad := _classify_fetch_problem(cid, r)) is not None:
        return bad
    leaks = {h: r.headers[h][:100] for h in _VERSION_HEADERS
             if h in r.headers and _VERSIONISH.search(r.headers[h])}
    ev = {"url": url, "status": r.status}
    if leaks:
        return confirmed(cid, "response headers still disclose software versions", **ev, headers=leaks)
    return not_reproducible(cid, "no version information in the Server / X-Powered-By headers", **ev,
                            headers={h: r.headers.get(h, "")[:60] for h in _VERSION_HEADERS if h in r.headers})


async def _run_default_page(f: FindingCtx, env: CheckEnv) -> CheckResult:
    cid = "default_page"
    url = f.evidence_url() or f.base_url()
    assert url
    r = await SafeFetcher(env, cid).get(url, max_bytes=_SNIFF)
    if (bad := _classify_fetch_problem(cid, r)) is not None:
        return bad
    ev = {"url": url, "status": r.status}
    if r.status == 200:
        body = r.text()
        for name, rx in _DEFAULT_PAGES:
            if rx.search(body):
                return confirmed(cid, f"the stock {name} default page is still served", **ev, page=name)
    return not_reproducible(cid, "the default welcome page is no longer served", **ev)


# --------------------------------------------------------------------------- #
# security headers
# --------------------------------------------------------------------------- #

_HEADER_RULE_IDS = {row[0] for row in header_check_mod._HEADER_RULES.values()}


def _match_security_headers(f: FindingCtx) -> bool:
    return f.rule_source == "header_check" and f.rule_id in _HEADER_RULE_IDS \
        and (f.evidence_url() or f.base_url()) is not None


async def _run_security_headers(f: FindingCtx, env: CheckEnv) -> CheckResult:
    cid = "security_headers"
    url = f.evidence_url() or f.base_url()
    assert url
    r = await SafeFetcher(env, cid).get(url, max_bytes=512)
    if (bad := _classify_fetch_problem(cid, r)) is not None:
        return bad
    produced = header_check_mod.analyze_headers(
        final_url=r.url, headers=r.headers, status_code=r.status)
    cookie = f.evidence.get("cookie")
    still = [p for p in produced if p["rule_id"] == f.rule_id
             and (not cookie or p["evidence"].get("cookie") == cookie)]
    present = {h: r.headers[h][:120] for h in (
        "strict-transport-security", "content-security-policy", "x-content-type-options",
        "x-frame-options", "referrer-policy", "permissions-policy") if h in r.headers}
    ev = {"url": r.url, "status": r.status, "headers_present": present}
    if cookie:
        ev["cookie"] = cookie
    if still:
        return confirmed(cid, f"{f.rule_id}: the response still lacks the protection", **ev)
    return not_reproducible(cid, f"{f.rule_id}: the response now carries the protection", **ev)


# --------------------------------------------------------------------------- #
# exports
# --------------------------------------------------------------------------- #

# (id, title, description, matcher, runner, methods)
HTTP_CHECKS = [
    ("exposed_file", "Exposed sensitive file", "GET the path; require the same content signature.",
     _match_exposed_file, _run_exposed_file, ("GET",)),
    ("admin_panel", "Admin panel exposed", "GET the panel URL; look for a login/admin interface.",
     _match_admin_panel, _run_admin_panel, ("GET",)),
    ("directory_listing", "Directory listing", "GET the URL; look for an auto-index page.",
     _match_dir_listing, _run_dir_listing, ("GET",)),
    ("default_page", "Default page", "GET the site; match known stock welcome pages.",
     _match_default_page, _run_default_page, ("GET",)),
    ("version_disclosure", "Version disclosure", "GET the site; inspect Server/X-Powered-By.",
     _match_version_disclosure, _run_version_disclosure, ("GET",)),
    ("security_headers", "Security headers", "GET the URL; re-run the header analyzer.",
     _match_security_headers, _run_security_headers, ("GET",)),
]
