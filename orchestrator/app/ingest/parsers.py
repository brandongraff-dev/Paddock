"""Format parsers: scanner output -> :class:`IFinding` / components.

Pure functions, no I/O. Each ``parse_*`` takes the decoded document (or an
iterator of records for the line-oriented formats), the caller's
:class:`Hints`, and appends to a :class:`ParseResult`. A record that cannot be
understood is reported via ``res.error`` and skipped; only a payload that is
unusable as a whole raises :class:`IngestError`.

Findings reuse existing ``rule_source`` values (``sast``, ``sca``, ``nuclei``,
``policy``, ``secret_scan``, ``cve_match``, ``manual``) so the DB CHECK and the
SDKs stay unchanged; the producing tool lives in ``metadata.ingest.tool``.
Rule ids embed the package / location so the existing
``(asset_id, rule_id, rule_source)`` upsert key is stable across re-ingests
and distinct per location, and CVE ids stay visible to the lifecycle
fingerprint (cross-engine dedupe against Paddock's own scanners).
"""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Optional

from .. import standards
from .common import (
    IFinding,
    IngestError,
    ParseResult,
    as_list,
    clean,
    clean_refs,
    cves_in,
    cvss_severity,
    get,
    host_asset,
    norm_severity,
    safe_path,
    slug,
    strip_url_credentials,
    to_cvss,
)

FORMATS = ("sarif", "cyclonedx", "spdx", "ocsf", "trivy", "grype", "semgrep", "nuclei", "zap", "csv")

_CWE_RE = re.compile(r"\bCWE[-_ ]?(\d{1,5})\b", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]{0,2000}>")


@dataclass
class Hints:
    """Caller-supplied context. ``project``/``asset`` override what the file says."""

    project: Optional[str] = None          # repo / project name
    asset: Optional[str] = None            # force every finding onto this asset
    asset_kind: Optional[str] = None
    fallback: str = "ingest"               # used when neither file nor caller names an asset
    max_findings: int = 50_000
    max_components: int = standards.MAX_IMPORT_COMPONENTS


def _add(res: ParseResult, h: Hints, f: IFinding) -> None:
    if len(res.findings) >= h.max_findings:
        raise IngestError(f"too many findings (max {h.max_findings})", 413)
    res.findings.append(f)


def _cwe(*vals: Any) -> Optional[str]:
    for v in vals:
        for s in (v if isinstance(v, list) else [v]):
            if isinstance(s, bool):
                continue
            if isinstance(s, int) and 0 < s < 100000:
                return f"CWE-{s}"
            if isinstance(s, str):
                m = _CWE_RE.search(s)
                if m:
                    return f"CWE-{int(m.group(1))}"
                if s.strip().isnumeric() and 0 < int(s) < 100000:
                    return f"CWE-{int(s)}"
    return None


def _forced_asset(h: Hints, default_kind: str) -> Optional[tuple[str, str]]:
    if not h.asset:
        return None
    v = clean(h.asset, 512)
    if not v:
        return None
    kind = h.asset_kind
    if not kind:
        ha = host_asset(v)
        kind = ha[0] if ha and default_kind in ("endpoint", "subdomain", "domain", "ipv4", "ipv6") else default_kind
    return kind, (strip_url_credentials(v) if "://" in v else v)


def _repo_asset(h: Hints, derived: Optional[str] = None) -> tuple[str, str]:
    forced = _forced_asset(h, "repository")
    if forced:
        return forced
    name = clean(h.project or derived or h.fallback, 300)
    return "repository", name or "ingest"


def _tag_strip(s: Any, limit: int = 4000) -> str:
    return clean(_TAG_RE.sub(" ", clean(s, 20000)), limit)


def _meta(h: Hints, tool: str, fmt: str, **extra: Any) -> dict[str, Any]:
    return {"ingest": {"format": fmt, "tool": clean(tool, 80), **extra}}


# --------------------------------------------------------------------------- #
# SARIF 2.1.0
# --------------------------------------------------------------------------- #

def parse_sarif(doc: dict[str, Any], h: Hints, res: ParseResult) -> None:
    runs = doc.get("runs")
    if not isinstance(runs, list):
        raise IngestError("SARIF document has no 'runs' array")
    for ri, run in enumerate(runs):
        if not isinstance(run, dict):
            res.error(f"runs[{ri}]", "run is not an object")
            continue
        driver = get(run, "tool", "driver", default={}) or {}
        tool = clean(driver.get("name") or "sarif", 80)
        res.tool = res.tool or tool
        rules: dict[str, dict[str, Any]] = {}
        rule_list = list(as_list(driver.get("rules")))
        for ext in as_list(get(run, "tool", "extensions", default=[])):
            if isinstance(ext, dict):
                rule_list += as_list(ext.get("rules"))
        for r in rule_list:
            if isinstance(r, dict) and isinstance(r.get("id"), str):
                rules[r["id"]] = r
        vcs = next((v for v in as_list(run.get("versionControlProvenance")) if isinstance(v, dict)), {})
        repo_uri = strip_url_credentials(vcs["repositoryUri"]) if isinstance(vcs.get("repositoryUri"), str) else ""
        derived = re.sub(r"(\.git)?/?$", "", re.sub(r"^https?://[^/]+/", "", repo_uri)) if repo_uri else None
        kind, asset = _repo_asset(h, derived)
        for i, r in enumerate(as_list(run.get("results"))):
            where = f"runs[{ri}].results[{i}]"
            if not isinstance(r, dict):
                res.error(where, "result is not an object")
                continue
            if as_list(r.get("suppressions")):
                res.skipped += 1                      # already suppressed in the source tool
                continue
            rid = r.get("ruleId") or get(r, "rule", "id")
            if not isinstance(rid, str) or not rid.strip():
                res.error(where, "result has no ruleId")
                continue
            rid = clean(rid, 200)
            rule = rules.get(rid, {})
            msg = clean(get(r, "message", "text") or get(r, "message", "markdown") or "", 4000)
            title = clean(get(rule, "shortDescription", "text") or rule.get("name") or msg.split("\n")[0] or rid, 300)
            props = {**(rule.get("properties") or {}), **(r.get("properties") or {})}
            sec = props.get("security-severity")
            if sec is not None and to_cvss(sec) is not None:
                sev, score = cvss_severity(float(sec)), to_cvss(sec)
            else:
                sev, score = norm_severity(r.get("level") or get(rule, "defaultConfiguration", "level"), "medium"), None
            loc = next((x for x in as_list(r.get("locations")) if isinstance(x, dict)), {})
            art = get(loc, "physicalLocation", "artifactLocation", default={}) or {}
            path = safe_path(art.get("uri") or "")
            region = get(loc, "physicalLocation", "region", default={}) or {}
            line = region.get("startLine") if isinstance(region.get("startLine"), int) else None
            end = region.get("endLine") if isinstance(region.get("endLine"), int) else None
            cwe = _cwe(props.get("cwe"), props.get("tags"), rule.get("relationships"), rid)
            ev: dict[str, Any] = {"rule": rid}
            if path:
                ev["file"] = path
            if line:
                ev["start_line"] = line
            if end:
                ev["end_line"] = end
            if cwe:
                ev["cwe"] = cwe
            loc_key = f"@{path}:{line}" if path else ""
            rule_id = f"sarif:{rid}{loc_key}"[:256]
            cves = cves_in(rid, msg)
            if cves:
                rule_id = f"{cves[0]}{loc_key}"[:256]
                ev["cve_ids"] = cves
            fp = get(r, "partialFingerprints", default={})
            _add(res, h, IFinding(
                asset_kind=kind, asset_value=asset, rule_id=rule_id, rule_source="sast",
                severity=sev, title=title or rid, description=msg or title,
                remediation=clean(get(rule, "help", "text") or "", 4000) or None,
                cvss=score, references=clean_refs(rule.get("helpUri")),
                evidence=ev,
                metadata=_meta(h, tool, "sarif", rule=rid,
                               **({"fingerprint": clean(next(iter(fp.values())), 80)}
                                  if isinstance(fp, dict) and fp else {})),
            ))


# --------------------------------------------------------------------------- #
# Trivy
# --------------------------------------------------------------------------- #

def _trivy_asset(doc: dict[str, Any], h: Hints) -> tuple[str, str]:
    forced = _forced_asset(h, "repository")
    if forced:
        return forced
    name = clean(doc.get("ArtifactName") or "", 300)
    atype = str(doc.get("ArtifactType") or "").lower()
    if atype in ("container_image", "vm", "oci_image") and name:
        return "cloud_resource", name
    if name and name not in (".", "/") and atype in ("repository",):
        return "repository", re.sub(r"(\.git)?/?$", "", re.sub(r"^https?://[^/]+/", "", name))
    return "repository", clean(h.project or h.fallback, 300)


def parse_trivy(doc: dict[str, Any], h: Hints, res: ParseResult) -> None:
    res.tool = "trivy"
    kind, asset = _trivy_asset(doc, h)
    res.project_hint = asset
    for ti, tr in enumerate(as_list(doc.get("Results"))):
        if not isinstance(tr, dict):
            res.error(f"Results[{ti}]", "result is not an object")
            continue
        target = clean(tr.get("Target") or "", 400)
        cls = clean(tr.get("Class") or "", 40)
        for vi, v in enumerate(as_list(tr.get("Vulnerabilities"))):
            where = f"Results[{ti}].Vulnerabilities[{vi}]"
            if not isinstance(v, dict) or not v.get("VulnerabilityID"):
                res.error(where, "vulnerability has no VulnerabilityID")
                continue
            vid = clean(v["VulnerabilityID"], 100)
            pkg, ver = clean(v.get("PkgName"), 200), clean(v.get("InstalledVersion"), 100)
            score = None
            cv = v.get("CVSS")
            if isinstance(cv, dict):
                for src in ("nvd", "redhat", "ghsa"):
                    s = to_cvss(get(cv, src, "V3Score"))
                    if s is not None:
                        score = s
                        break
            sev = norm_severity(v.get("Severity"), "medium")
            fixed = clean(v.get("FixedVersion") or "", 200)
            rid = f"{vid}:{pkg}@{ver}"[:256] if pkg else vid
            _add(res, h, IFinding(
                asset_kind=kind, asset_value=asset, rule_id=rid, rule_source="sca", severity=sev,
                title=clean(v.get("Title") or f"{vid} in {pkg}", 300),
                description=clean(v.get("Description") or "", 4000),
                remediation=(f"Upgrade {pkg} to {fixed}" if fixed and pkg else None),
                cvss=score, references=clean_refs(([v["PrimaryURL"]] if v.get("PrimaryURL") else [])
                                                  + as_list(v.get("References"))),
                evidence={"package": pkg, "installed_version": ver, "fixed_version": fixed or None,
                          "target": target, "cve_ids": cves_in(vid)},
                metadata=_meta(h, "trivy", "trivy", class_=cls),
            ))
            if pkg and ver:
                _component(res, h, ecosystem=_trivy_eco(tr.get("Type")), name=pkg, version=ver,
                           purl=get(v, "PkgIdentifier", "PURL"), vid=vid, severity=sev, cvss=score,
                           summary=v.get("Title"))
        for mi, m in enumerate(as_list(tr.get("Misconfigurations"))):
            where = f"Results[{ti}].Misconfigurations[{mi}]"
            if not isinstance(m, dict) or not (m.get("ID") or m.get("AVDID")):
                res.error(where, "misconfiguration has no ID")
                continue
            if str(m.get("Status") or "FAIL").upper() == "PASS":
                res.skipped += 1
                continue
            mid = clean(m.get("ID") or m.get("AVDID"), 100)
            cm = m.get("CauseMetadata") if isinstance(m.get("CauseMetadata"), dict) else {}
            _add(res, h, IFinding(
                asset_kind=kind, asset_value=asset, rule_id=f"trivy:{mid}@{safe_path(target)}"[:256],
                rule_source="policy", severity=norm_severity(m.get("Severity"), "medium"),
                title=clean(m.get("Title") or mid, 300),
                description=clean(m.get("Description") or m.get("Message") or "", 4000),
                remediation=clean(m.get("Resolution") or "", 2000) or None,
                references=clean_refs(([m["PrimaryURL"]] if m.get("PrimaryURL") else []) + as_list(m.get("References"))),
                evidence={"file": safe_path(target), "start_line": cm.get("StartLine"),
                          "resource": clean(cm.get("Resource") or "", 200) or None},
                metadata=_meta(h, "trivy", "trivy", check=mid),
            ))
        for si, s in enumerate(as_list(tr.get("Secrets"))):
            where = f"Results[{ti}].Secrets[{si}]"
            if not isinstance(s, dict) or not s.get("RuleID"):
                res.error(where, "secret has no RuleID")
                continue
            line = s.get("StartLine") if isinstance(s.get("StartLine"), int) else None
            _add(res, h, IFinding(                        # the matched secret itself is never stored
                asset_kind=kind, asset_value=asset,
                rule_id=f"trivy-secret:{clean(s['RuleID'], 80)}@{safe_path(target)}:{line or 0}"[:256],
                rule_source="secret_scan", severity=norm_severity(s.get("Severity"), "high"),
                title=clean(s.get("Title") or f"Secret: {s['RuleID']}", 300),
                description=f"{clean(s.get('Category') or 'secret', 80)} detected in {safe_path(target)}",
                evidence={"file": safe_path(target), "start_line": line, "category": clean(s.get("Category"), 80)},
                metadata=_meta(h, "trivy", "trivy"),
            ))
    if not res.findings and "Results" not in doc:
        raise IngestError("Trivy document has no 'Results'")


def _trivy_eco(t: Any) -> str:
    t = str(t or "").lower()
    return {"npm": "npm", "yarn": "npm", "pnpm": "npm", "node-pkg": "npm", "pip": "PyPI", "pipenv": "PyPI",
            "poetry": "PyPI", "python-pkg": "PyPI", "gomod": "Go", "gobinary": "Go", "cargo": "crates.io",
            "rust-binary": "crates.io", "jar": "Maven", "pom": "Maven", "gradle": "Maven",
            "bundler": "RubyGems", "gemspec": "RubyGems", "composer": "Packagist", "nuget": "NuGet",
            "debian": "Debian", "ubuntu": "Debian", "alpine": "Alpine"}.get(t, t[:64] or "generic")


def _component(res: ParseResult, h: Hints, *, ecosystem: str, name: str, version: str, purl: Any,
               vid: str, severity: str, cvss: Optional[float], summary: Any) -> None:
    if len(res.components) >= h.max_components:
        return
    key = (ecosystem, name[:512], version[:256])
    res.components.append({
        "ecosystem": ecosystem[:64], "name": name[:512], "version": version[:256],
        "purl": clean(purl, 1024) if isinstance(purl, str) and purl.startswith("pkg:")
        else standards.purl_for(ecosystem, name, version),
        "direct": True, "depth": 0, "paths": [], "metadata": {"imported_from": "ingest"}})
    res.component_vulns.append({
        "key": key, "osv_id": vid[:128], "cve_id": vid if vid.upper().startswith("CVE-") else None,
        "severity": severity, "cvss": cvss, "summary": clean(summary, 2000) or None, "reachability": None})


# --------------------------------------------------------------------------- #
# Grype
# --------------------------------------------------------------------------- #

def parse_grype(doc: dict[str, Any], h: Hints, res: ParseResult) -> None:
    res.tool = "grype"
    forced = _forced_asset(h, "repository")
    src = doc.get("source") if isinstance(doc.get("source"), dict) else {}
    stype = str(src.get("type") or "").lower()
    target = src.get("target")
    if forced:
        kind, asset = forced
    elif stype == "image" and isinstance(target, dict):
        kind, asset = "cloud_resource", clean(target.get("userInput") or target.get("imageID") or h.fallback, 300)
    elif stype == "image" and isinstance(target, str) and target:
        kind, asset = "cloud_resource", clean(target, 300)
    else:
        kind, asset = "repository", clean(h.project or h.fallback, 300)
    res.project_hint = asset
    matches = doc.get("matches")
    if not isinstance(matches, list):
        raise IngestError("Grype document has no 'matches' array")
    for i, m in enumerate(matches):
        where = f"matches[{i}]"
        if not isinstance(m, dict) or not isinstance(m.get("vulnerability"), dict) or not isinstance(m.get("artifact"), dict):
            res.error(where, "match needs 'vulnerability' and 'artifact' objects")
            continue
        v, a = m["vulnerability"], m["artifact"]
        vid = clean(v.get("id"), 100)
        pkg, ver = clean(a.get("name"), 200), clean(a.get("version"), 100)
        if not vid or not pkg:
            res.error(where, "match has no vulnerability id or artifact name")
            continue
        scores = [to_cvss(get(c, "metrics", "baseScore")) for c in as_list(v.get("cvss")) if isinstance(c, dict)]
        scores = [s for s in scores if s is not None]
        score = max(scores) if scores else None
        sev = norm_severity(v.get("severity"), "medium")
        fix = v.get("fix") if isinstance(v.get("fix"), dict) else {}
        fixed = ", ".join(clean(x, 60) for x in as_list(fix.get("versions"))[:5])
        related = [clean(r.get("id"), 60) for r in as_list(m.get("relatedVulnerabilities")) if isinstance(r, dict)]
        _add(res, h, IFinding(
            asset_kind=kind, asset_value=asset, rule_id=f"{vid}:{pkg}@{ver}"[:256], rule_source="sca",
            severity=sev, title=f"{vid} in {pkg} {ver}".strip()[:300],
            description=clean(v.get("description") or "", 4000),
            remediation=f"Upgrade {pkg} to {fixed}" if fixed else None, cvss=score,
            references=clean_refs(([v["dataSource"]] if v.get("dataSource") else []) + as_list(v.get("urls"))),
            evidence={"package": pkg, "installed_version": ver, "fixed_version": fixed or None,
                      "package_type": clean(a.get("type"), 40), "cve_ids": cves_in(vid, related)},
            metadata=_meta(h, "grype", "grype"),
        ))
        _component(res, h, ecosystem=_trivy_eco(a.get("type")), name=pkg, version=ver or "unknown",
                   purl=a.get("purl"), vid=vid, severity=sev, cvss=score, summary=v.get("description"))


# --------------------------------------------------------------------------- #
# Semgrep
# --------------------------------------------------------------------------- #

def parse_semgrep(doc: dict[str, Any], h: Hints, res: ParseResult) -> None:
    res.tool = "semgrep"
    results = doc.get("results")
    if not isinstance(results, list):
        raise IngestError("Semgrep document has no 'results' array")
    kind, asset = _repo_asset(h)
    for i, r in enumerate(results):
        where = f"results[{i}]"
        if not isinstance(r, dict) or not r.get("check_id") or not r.get("path"):
            res.error(where, "result needs check_id and path")
            continue
        extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        md = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        check = clean(r["check_id"], 200)
        path = safe_path(r["path"])
        line = get(r, "start", "line")
        line = line if isinstance(line, int) else None
        end = get(r, "end", "line")
        sev = norm_severity(extra.get("severity"), "medium")
        if str(extra.get("severity") or "").upper() == "INFO":
            sev = "low"
        cwe = _cwe(md.get("cwe"))
        ev: dict[str, Any] = {"rule": check, "file": path, "start_line": line,
                              "end_line": end if isinstance(end, int) else None}
        if cwe:
            ev["cwe"] = cwe
        msg = clean(extra.get("message") or check, 4000)
        _add(res, h, IFinding(
            asset_kind=kind, asset_value=asset, rule_id=f"semgrep:{check}@{path}:{line or 0}"[:256],
            rule_source="sast", severity=sev, title=clean(msg.split("\n")[0], 300) or check,
            description=msg, remediation=clean(extra.get("fix") or "", 2000) or None,
            references=clean_refs(md.get("references") or md.get("source")),
            evidence={k: v for k, v in ev.items() if v is not None},
            metadata=_meta(h, "semgrep", "semgrep", confidence=clean(md.get("confidence"), 20) or None),
        ))


# --------------------------------------------------------------------------- #
# Nuclei (JSONL or JSON array)
# --------------------------------------------------------------------------- #

def parse_nuclei(items: Iterable[Any], h: Hints, res: ParseResult) -> None:
    res.tool = "nuclei"
    for i, it in enumerate(items):
        where = f"line {i + 1}"
        if not isinstance(it, dict) or not it.get("template-id"):
            res.error(where, "record needs a template-id")
            continue
        info = it.get("info") if isinstance(it.get("info"), dict) else {}
        matched = clean(it.get("matched-at") or it.get("url") or it.get("host") or "", 600)
        forced = _forced_asset(h, "endpoint")
        ha = host_asset(it.get("host") or matched)
        if forced:
            kind, asset = forced
        elif ha:
            kind, asset = ha
        else:
            res.error(where, "record has no usable host")
            continue
        tid = clean(it["template-id"], 120)
        path = ""
        if "://" in matched:
            from urllib.parse import urlsplit
            try:
                path = urlsplit(matched).path or ""
            except ValueError:
                path = ""
        matcher = clean(it.get("matcher-name") or "", 60)
        rid = f"nuclei:{tid}" + (f":{matcher}" if matcher else "") + (f"@{clean(path, 100)}" if len(path) > 1 else "")
        cls = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        cves = cves_in(cls.get("cve-id"), tid)
        score = to_cvss(cls.get("cvss-score"))
        refs = clean_refs(info.get("reference"))
        ev = {"template": tid, "matched_at": strip_url_credentials(matched) if "://" in matched else matched[:300],
              "type": clean(it.get("type"), 20), "cve_ids": cves,
              "extracted": [clean(x, 200) for x in as_list(it.get("extracted-results"))[:10]],
              "ip": clean(it.get("ip"), 64) or None}       # request / response / curl-command are dropped on purpose
        cwe = _cwe(cls.get("cwe-id"))
        if cwe:
            ev["cwe"] = cwe
        _add(res, h, IFinding(
            asset_kind=kind, asset_value=asset, rule_id=rid[:256], rule_source="nuclei",
            severity=norm_severity(info.get("severity"), "info"),
            title=clean(info.get("name") or tid, 300), description=clean(info.get("description") or "", 4000),
            remediation=clean(info.get("remediation") or "", 2000) or None, cvss=score, references=refs,
            evidence={k: v for k, v in ev.items() if v not in (None, "", [])},
            metadata=_meta(h, "nuclei", "nuclei", tags=clean(",".join(map(str, as_list(info.get("tags")))), 200)),
        ))


# --------------------------------------------------------------------------- #
# OWASP ZAP (JSON report)
# --------------------------------------------------------------------------- #

def parse_zap(doc: dict[str, Any], h: Hints, res: ParseResult) -> None:
    res.tool = "zap"
    sites = doc.get("site")
    if isinstance(sites, dict):
        sites = [sites]
    if not isinstance(sites, list):
        raise IngestError("ZAP report has no 'site' array")
    risk = {"0": "info", "1": "low", "2": "medium", "3": "high"}
    for si, site in enumerate(sites):
        if not isinstance(site, dict):
            res.error(f"site[{si}]", "site is not an object")
            continue
        name = clean(site.get("@name") or site.get("name") or "", 600)
        forced = _forced_asset(h, "endpoint")
        ha = host_asset(name or site.get("@host"))
        if forced:
            kind, asset = forced
        elif ha:
            kind, asset = ha
        else:
            res.error(f"site[{si}]", "site has no usable @name/@host")
            continue
        for ai, al in enumerate(as_list(site.get("alerts"))):
            where = f"site[{si}].alerts[{ai}]"
            if not isinstance(al, dict):
                res.error(where, "alert is not an object")
                continue
            pid = clean(al.get("pluginid") or al.get("alertRef") or "", 40)
            title = clean(al.get("alert") or al.get("name") or "", 300)
            if not (pid or title):
                res.error(where, "alert has no pluginid or name")
                continue
            code = str(al.get("riskcode") if al.get("riskcode") is not None else "").strip()
            sev = risk.get(code) or norm_severity(str(al.get("riskdesc") or "").split(" ")[0], "medium")
            insts = [x for x in as_list(al.get("instances")) if isinstance(x, dict)]
            uris = []
            for x in insts[:20]:
                u = strip_url_credentials(str(x.get("uri") or ""))
                if u:
                    uris.append({"uri": u, "method": clean(x.get("method"), 10), "param": clean(x.get("param"), 80)})
            cwe = _cwe(al.get("cweid"))
            cnt = str(al.get("count") or "")
            ev: dict[str, Any] = {"instances": uris, "instance_count": int(cnt) if cnt.isdigit() else len(insts)}
            if cwe:
                ev["cwe"] = cwe
            _add(res, h, IFinding(
                asset_kind=kind, asset_value=asset, rule_id=f"zap:{pid or slug(title, 60)}",
                rule_source="manual", severity=sev, title=title or f"ZAP alert {pid}",
                description=_tag_strip(al.get("desc")), remediation=_tag_strip(al.get("solution"), 2000) or None,
                references=clean_refs(re.findall(r"https?://[^\s<\"']+", str(al.get("reference") or ""))),
                evidence=ev,
                metadata=_meta(h, "zap", "zap", confidence=clean(al.get("confidence"), 20) or None),
            ))


# --------------------------------------------------------------------------- #
# OCSF 1.x (Vulnerability Finding 2002 / Detection Finding 2004 / Security Finding 2001)
# --------------------------------------------------------------------------- #

_OCSF_SEV = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "critical"}


def parse_ocsf(items: Iterable[Any], h: Hints, res: ParseResult) -> None:
    res.tool = "ocsf"
    for i, e in enumerate(items):
        where = f"event {i + 1}"
        if not isinstance(e, dict) or not isinstance(e.get("class_uid"), int):
            res.error(where, "event needs an integer class_uid")
            continue
        if e["class_uid"] not in (2001, 2002, 2004, 2005, 2003, 2006):
            res.skipped += 1                              # not a finding class
            continue
        fi = e.get("finding_info") if isinstance(e.get("finding_info"), dict) else {}
        vulns = [v for v in as_list(e.get("vulnerabilities")) if isinstance(v, dict)]
        title = clean(fi.get("title") or get(vulns[0] if vulns else {}, "title") or e.get("message") or "", 300)
        if not title:
            res.error(where, "event has no finding_info.title")
            continue
        sid = e.get("severity_id")
        sev = _OCSF_SEV.get(sid) if isinstance(sid, int) else None
        sev = sev or norm_severity(e.get("severity"), "medium")
        forced = _forced_asset(h, "endpoint")
        res0 = next((r for r in as_list(e.get("resources")) if isinstance(r, dict)), {})
        dev = e.get("device") if isinstance(e.get("device"), dict) else {}
        cand = [dev.get("hostname"), dev.get("ip"), dev.get("name")]
        cand += [c for c in (res0.get("name"), res0.get("uid")) if isinstance(c, str) and ("." in c or ":" in c)]
        ha = next((x for x in (host_asset(c) for c in cand) if x), None)
        if forced:
            kind, asset = forced
        elif ha:
            kind, asset = ha
        elif res0.get("name"):
            kind, asset = "cloud_resource", clean(res0["name"], 300)
        else:
            kind, asset = "repository", clean(h.project or h.fallback, 300)
        cve = next((clean(get(v, "cve", "uid"), 40) for v in vulns if get(v, "cve", "uid")), None)
        uid = clean(fi.get("uid") or cve or slug(title, 80), 200)
        pkg = next((p for v in vulns for p in as_list(v.get("affected_packages")) if isinstance(p, dict)), {})
        score = next((to_cvss(c.get("base_score")) for v in vulns for c in as_list(get(v, "cve", "cvss"))
                      if isinstance(c, dict) and to_cvss(c.get("base_score")) is not None), None)
        rid = f"{cve}:{clean(pkg.get('name'), 120)}@{clean(pkg.get('version'), 60)}" if cve and pkg.get("name") else f"ocsf:{uid}"
        ev = {"class_uid": e["class_uid"], "uid": uid, "cve_ids": cves_in(cve),
              "package": clean(pkg.get("name"), 200) or None, "installed_version": clean(pkg.get("version"), 100) or None}
        _add(res, h, IFinding(
            asset_kind=kind, asset_value=asset, rule_id=rid[:256],
            rule_source="cve_match" if cve else "manual", severity=sev, title=title,
            description=clean(fi.get("desc") or get(vulns[0] if vulns else {}, "desc") or "", 4000),
            remediation=clean(get(e, "remediation", "desc"), 2000) or None, cvss=score,
            references=clean_refs(get(vulns[0] if vulns else {}, "references")),
            evidence={k: v for k, v in ev.items() if v not in (None, "", [])},
            metadata=_meta(h, clean(get(e, "metadata", "product", "name") or "ocsf", 80), "ocsf"),
        ))


# --------------------------------------------------------------------------- #
# CSV (documented columns)
# --------------------------------------------------------------------------- #

CSV_COLUMNS: dict[str, str] = {
    "asset": "REQUIRED. Host, IP, URL, repository or resource the finding is on.",
    "title": "REQUIRED. Short summary.",
    "severity": "REQUIRED. critical|high|medium|low|info (also: moderate, warning, error, 0-10 CVSS).",
    "rule_id": "Stable id of the check; defaults to a slug of the title.",
    "description": "Longer explanation.",
    "cve": "CVE id(s), separated by space, comma or semicolon.",
    "cvss": "CVSS base score 0-10.",
    "cwe": "CWE id, e.g. CWE-79.",
    "remediation": "How to fix it.",
    "references": "URL(s), separated by space or semicolon.",
    "asset_kind": "domain|subdomain|ipv4|ipv6|endpoint|repository|cloud_resource|... (default: guessed).",
    "file": "File path (repository-relative).",
    "line": "Line number.",
    "component": "Package / component name.",
    "version": "Installed version of the component.",
    "tags": "Free-form tags.",
}
_CSV_ALIASES = {
    "host": "asset", "hostname": "asset", "target": "asset", "ip": "asset", "url": "asset", "resource": "asset",
    "name": "title", "summary": "title", "risk": "severity", "priority": "severity",
    "id": "rule_id", "plugin_id": "rule_id", "check_id": "rule_id", "rule": "rule_id",
    "desc": "description", "details": "description", "cve_id": "cve", "cvss_score": "cvss",
    "solution": "remediation", "fix": "remediation", "recommendation": "remediation", "reference": "references",
    "package": "component", "package_version": "version", "path": "file",
}
_CSV_MAX_COLS = 64
_CSV_KINDS = {"domain", "subdomain", "ipv4", "ipv6", "endpoint", "repository", "cloud_resource",
              "cloud_account", "service", "technology", "certificate", "port", "org"}


def csv_looks_like(text: str) -> bool:
    head = text.split("\n", 1)[0].lower()
    cols = {_CSV_ALIASES.get(c.strip().strip('"').strip().replace(" ", "_"), c.strip().strip('"').strip().replace(" ", "_"))
            for c in head.split(",")}
    return {"asset", "title", "severity"} <= cols


def parse_csv(text: str, h: Hints, res: ParseResult) -> None:
    res.tool = "csv"
    csv.field_size_limit(65536)
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except StopIteration:
        raise IngestError("CSV is empty") from None
    except csv.Error as exc:
        raise IngestError(f"CSV header is malformed: {exc}") from None
    if len(header) > _CSV_MAX_COLS:
        raise IngestError(f"CSV has too many columns (max {_CSV_MAX_COLS})")
    cols = []
    for c in header:
        k = clean(c, 60).lower().replace(" ", "_").replace("-", "_").lstrip("﻿")
        cols.append(_CSV_ALIASES.get(k, k))
    missing = [c for c in ("asset", "title", "severity") if c not in cols]
    if missing:
        raise IngestError(f"CSV is missing required column(s): {', '.join(missing)} "
                          f"(documented columns: {', '.join(CSV_COLUMNS)})")
    n = 1
    while True:
        try:
            row = next(reader)
        except StopIteration:
            break
        except csv.Error as exc:
            res.error(f"row {n + 1}", f"malformed CSV: {exc}")
            if res.skipped > 1000:
                raise IngestError("too many malformed CSV rows") from None
            n += 1
            continue
        n += 1
        if not any(c.strip() for c in row):
            continue
        rec = {cols[i]: v for i, v in enumerate(row[:len(cols)]) if cols[i] not in ("",)}
        where = f"row {n}"
        title = clean(rec.get("title"), 300)
        raw_asset = clean(rec.get("asset"), 512)
        if not title or not raw_asset:
            res.error(where, "row needs asset and title")
            continue
        sev_raw = clean(rec.get("severity"), 20)
        if sev_raw.strip().lower() not in ("critical", "high", "medium", "low", "info", "informational", "moderate",
                                           "warning", "error", "none", "unknown", "note", "minor", "major", "severe") \
                and not re.fullmatch(r"\d+(\.\d+)?", sev_raw.strip()):
            res.error(where, f"unrecognised severity {sev_raw[:30]!r}")
            continue
        forced = _forced_asset(h, "repository")
        ak = clean(rec.get("asset_kind"), 30).lower()
        ha = host_asset(raw_asset)
        if forced:
            kind, asset = forced
        elif ak:
            if ak not in _CSV_KINDS:
                res.error(where, f"unknown asset_kind {ak[:30]!r}")
                continue
            kind, asset = ak, (strip_url_credentials(raw_asset) if "://" in raw_asset else raw_asset)
        elif ha:
            kind, asset = ha
        else:
            kind, asset = "repository", raw_asset
        cves = cves_in(rec.get("cve") or "", rec.get("rule_id") or "")
        cwe = _cwe(rec.get("cwe"))
        ev: dict[str, Any] = {}
        if rec.get("file"):
            ev["file"] = safe_path(rec["file"])
        if str(rec.get("line") or "").strip().isdigit():
            ev["start_line"] = int(rec["line"])
        if cwe:
            ev["cwe"] = cwe
        if cves:
            ev["cve_ids"] = cves
        if rec.get("component"):
            ev["package"] = clean(rec["component"], 200)
            ev["installed_version"] = clean(rec.get("version"), 100)
        rid = clean(rec.get("rule_id"), 200) or (cves[0] if cves else f"csv:{slug(title, 100)}")
        if cves and rec.get("component"):
            rid = f"{cves[0]}:{ev['package']}@{ev.get('installed_version', '')}"
        elif ev.get("file"):
            rid = f"{rid}@{ev['file']}:{ev.get('start_line', 0)}"
        _add(res, h, IFinding(
            asset_kind=kind, asset_value=asset, rule_id=rid[:256],
            rule_source="cve_match" if cves else "manual", severity=norm_severity(sev_raw, "medium"),
            title=title, description=clean(rec.get("description"), 4000),
            remediation=clean(rec.get("remediation"), 2000) or None, cvss=to_cvss(rec.get("cvss")),
            references=clean_refs(re.split(r"[\s;]+", rec.get("references") or "")), evidence=ev,
            metadata=_meta(h, "csv", "csv", tags=clean(rec.get("tags"), 200) or None),
        ))


# --------------------------------------------------------------------------- #
# SBOMs reuse app.standards
# --------------------------------------------------------------------------- #

def parse_sbom_doc(doc: dict[str, Any], h: Hints, res: ParseResult) -> None:
    try:
        out = standards.parse_sbom(doc)
    except standards.ImportError_ as exc:
        raise IngestError(str(exc)) from None
    res.sbom = out
    res.tool = out["format"]
    res.project_hint = out.get("name")
    if len(out["components"]) > h.max_components:
        raise IngestError(f"too many components (max {h.max_components})", 413)


def iter_objects(items: Iterable[Any]) -> Iterator[Any]:
    yield from items
