"""Interoperability formats: SARIF 2.1.0, CycloneDX 1.5 (SBOM + VEX), SPDX 2.3,
OpenVEX 0.2.0 -- builders and the SBOM import parser.

Pure functions over plain dicts (DB rows already coerced); the HTTP surface is
``app/routers/exports.py``. Nothing here performs I/O.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import quote, unquote

from . import __version__

TOOL_NAME = "Paddock"
TOOL_URI = "https://github.com/brandongraff-dev/Paddock"

# --------------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------------- #

_SEV_ORDER = ("info", "low", "medium", "high", "critical")
_SEV_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0}
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

# Paddock (OSV) ecosystem <-> purl type.
_ECO_TO_PURL = {
    "npm": "npm", "PyPI": "pypi", "Go": "golang", "crates.io": "cargo", "Maven": "maven",
    "RubyGems": "gem", "NuGet": "nuget", "Packagist": "composer", "Hex": "hex", "Pub": "pub",
    "Debian": "deb", "Alpine": "apk",
}
_PURL_TO_ECO = {v: k for k, v in _ECO_TO_PURL.items()}

# lockfile basename (lower-case) -> ecosystem; mirrors sca/app/parsers/registry.py
LOCKFILE_ECOSYSTEM: dict[str, str] = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm", "requirements.txt": "PyPI", "poetry.lock": "PyPI",
    "pipfile.lock": "PyPI", "cargo.lock": "crates.io", "pom.xml": "Maven",
    "gemfile.lock": "RubyGems", "go.sum": "Go", "go.mod": "Go",
}
# Fallback SARIF location for a dependency when no manifest was recorded.
_DEFAULT_MANIFEST = {
    "npm": "package-lock.json", "PyPI": "requirements.txt", "Go": "go.mod",
    "crates.io": "Cargo.lock", "Maven": "pom.xml", "RubyGems": "Gemfile.lock",
}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(dt: Optional[datetime] = None) -> str:
    dt = (dt or now_utc()).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def sev_rank(sev: Optional[str]) -> int:
    try:
        return _SEV_ORDER.index((sev or "").lower())
    except ValueError:
        return -1


def purl_for(ecosystem: Optional[str], name: Optional[str], version: Optional[str]) -> Optional[str]:
    """Package URL for a component (mirrors the SCA service's builder)."""
    if not name or not version:
        return None
    ptype = _ECO_TO_PURL.get(ecosystem or "")
    if not ptype:
        return None
    v = quote(str(version), safe=".-_+~")
    if ptype == "maven" and ":" in name:
        group, _, artifact = name.partition(":")
        return f"pkg:maven/{quote(group, safe='.-_')}/{quote(artifact, safe='.-_')}@{v}"
    if ptype == "npm" and name.startswith("@") and "/" in name:
        scope, _, base = name.partition("/")
        return f"pkg:npm/{quote(scope, safe='')}/{quote(base, safe='.-_')}@{v}"
    if ptype == "golang":
        return f"pkg:golang/{quote(name, safe='/.-_~')}@{v}"
    if ptype == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    return f"pkg:{ptype}/{quote(name, safe='.-_')}@{v}"


def parse_purl(purl: str) -> Optional[dict[str, Any]]:
    """Minimal purl parser -> {type, namespace, name, version}."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    rest = purl[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in rest:
        return None
    ptype, _, path = rest.partition("/")
    version = None
    if "@" in path:
        path, _, version = path.rpartition("@")
        version = unquote(version)
    parts = [unquote(p) for p in path.split("/") if p]
    if not parts:
        return None
    return {"type": ptype.lower(), "namespace": "/".join(parts[:-1]) or None,
            "name": parts[-1], "version": version}


def purl_to_component(purl: str) -> Optional[dict[str, Any]]:
    p = parse_purl(purl)
    if not p:
        return None
    eco = _PURL_TO_ECO.get(p["type"], p["type"])
    ns, name = p["namespace"], p["name"]
    if ns:
        if p["type"] == "maven":
            name = f"{ns}:{name}"
        else:
            name = f"{ns}/{name}"
    return {"ecosystem": eco, "name": name, "version": p["version"]}


def _ref_for(c: Mapping[str, Any]) -> str:
    return str(c.get("purl") or purl_for(c.get("ecosystem"), c.get("name"), c.get("version"))
               or f"paddock:component:{c.get('id')}")


def _spdx_id(prefix: str, raw: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9.\-]+", "-", raw).strip("-")[:120] or "x"
    return f"SPDXRef-{prefix}-{safe}"


def _parent_edges(components: list[Mapping[str, Any]]) -> dict[str, set[str]]:
    """parent bom-ref -> child bom-refs, from each component's ``paths``
    (immediate parents as ``name@version`` or ``name`` node keys)."""
    by_key: dict[str, list[str]] = {}
    for c in components:
        ref = _ref_for(c)
        eco = c.get("ecosystem")
        by_key.setdefault(f"{eco}|{c.get('name')}@{c.get('version')}", []).append(ref)
        by_key.setdefault(f"{eco}|{c.get('name')}", []).append(ref)
    edges: dict[str, set[str]] = {}
    for c in components:
        child = _ref_for(c)
        for p in c.get("paths") or []:
            if isinstance(p, list):
                p = p[-1] if p else None
            if not isinstance(p, str) or not p:
                continue
            key = f"{c.get('ecosystem')}|{p}"
            parents = by_key.get(key)
            if parents is None and "@" in p[1:]:
                parents = by_key.get(f"{c.get('ecosystem')}|{p[:p.rindex('@')]}")
            for parent in parents or []:
                if parent != child:
                    edges.setdefault(parent, set()).add(child)
    return edges


# --------------------------------------------------------------------------- #
# CycloneDX 1.5
# --------------------------------------------------------------------------- #

def _cdx_component(c: Mapping[str, Any]) -> dict[str, Any]:
    name = str(c.get("name") or "")
    comp: dict[str, Any] = {"type": "library", "bom-ref": _ref_for(c)}
    if c.get("ecosystem") == "Maven" and ":" in name:
        group, _, name = name.partition(":")
        comp["group"] = group
    comp["name"] = name
    if c.get("version"):
        comp["version"] = str(c["version"])
    purl = c.get("purl") or purl_for(c.get("ecosystem"), c.get("name"), c.get("version"))
    if purl:
        comp["purl"] = purl
    comp["scope"] = "required"
    props = [{"name": "paddock:ecosystem", "value": str(c.get("ecosystem") or "")},
             {"name": "paddock:direct", "value": "true" if c.get("direct") else "false"},
             {"name": "paddock:depth", "value": str(int(c.get("depth") or 0))}]
    comp["properties"] = props
    return comp


def _cdx_metadata(project: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    root_ref = f"paddock:project:{project.get('id')}"
    md = {
        "timestamp": iso_z(),
        "tools": {"components": [{"type": "application", "name": TOOL_NAME,
                                  "version": __version__, "externalReferences": [
                                      {"type": "website", "url": TOOL_URI}]}]},
        "component": {"type": "application", "bom-ref": root_ref,
                      "name": str(project.get("name") or "project")},
    }
    if project.get("source_ref"):
        md["component"]["externalReferences"] = [{"type": "vcs", "url": str(project["source_ref"])}] \
            if re.match(r"^[a-z][a-z0-9+.-]*://", str(project["source_ref"])) else []
        if not md["component"]["externalReferences"]:
            del md["component"]["externalReferences"]
    return md, root_ref


def cyclonedx_sbom(project: Mapping[str, Any], components: list[Mapping[str, Any]]) -> dict[str, Any]:
    md, root_ref = _cdx_metadata(project)
    comps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for c in components:
        cc = _cdx_component(c)
        if cc["bom-ref"] in seen:
            continue
        seen.add(cc["bom-ref"])
        comps.append(cc)
    edges = _parent_edges(list(components))
    direct = [_ref_for(c) for c in components if c.get("direct")]
    deps = [{"ref": root_ref, "dependsOn": sorted(set(direct) & seen)}]
    for ref in sorted(seen):
        deps.append({"ref": ref, "dependsOn": sorted(edges.get(ref, set()) & seen)})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": md,
        "components": comps,
        "dependencies": deps,
    }


# --------------------------------------------------------------------------- #
# VEX (CycloneDX 1.5 vulnerabilities + OpenVEX 0.2.0)
# --------------------------------------------------------------------------- #

def vex_status(reachability: Optional[str]) -> dict[str, Any]:
    """Map a reachability grade to CycloneDX analysis + OpenVEX status."""
    r = (reachability or "unknown").lower()
    if r == "unreachable":
        return {"cdx_state": "not_affected", "cdx_justification": "code_not_reachable",
                "openvex_status": "not_affected",
                "openvex_justification": "vulnerable_code_not_in_execute_path"}
    if r == "reachable":
        return {"cdx_state": "exploitable", "openvex_status": "affected"}
    return {"cdx_state": "in_triage", "openvex_status": "under_investigation"}


def _vuln_detail(v: Mapping[str, Any]) -> str:
    r = (v.get("reachability") or "unknown").lower()
    sym = v.get("reachable_symbol")
    if r == "reachable":
        return ("Paddock reachability analysis found a call path from first-party code to the "
                f"vulnerable symbol{f' {sym}' if sym else ''}.")
    if r == "unreachable":
        return ("Paddock reachability analysis found no call path from first-party code to the "
                f"vulnerable code{f' ({sym})' if sym else ''}.")
    if r == "potential":
        return "Paddock reachability analysis found a possible but unconfirmed call path."
    return "Reachability has not been determined."


def _osv_url(osv_id: str) -> str:
    return f"https://osv.dev/vulnerability/{quote(osv_id, safe='-_.:')}"


def cyclonedx_vex(project: Mapping[str, Any], rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    """CycloneDX 1.5 BOM carrying the affected components and one
    ``vulnerabilities[]`` entry per (vulnerability, component) with an
    ``analysis`` state derived from reachability. Self-contained: every
    ``affects.ref`` resolves to a component in the same document."""
    md, _root = _cdx_metadata(project)
    comps: dict[str, dict[str, Any]] = {}
    vulns: list[dict[str, Any]] = []
    for v in rows:
        comp = {"id": v.get("component_id"), "ecosystem": v.get("ecosystem"), "name": v.get("name"),
                "version": v.get("version"), "purl": v.get("purl"), "direct": v.get("direct"),
                "depth": v.get("depth")}
        cref = _ref_for(comp)
        comps.setdefault(cref, _cdx_component(comp))
        vid = str(v.get("cve_id") or v.get("osv_id"))
        st = vex_status(v.get("reachability"))
        entry: dict[str, Any] = {
            "bom-ref": f"paddock:vuln:{v.get('id') or hashlib.sha1((vid + cref).encode()).hexdigest()}",
            "id": vid,
            "source": ({"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vid}"}
                       if vid.upper().startswith("CVE-") else
                       {"name": "OSV", "url": _osv_url(vid)}),
        }
        if v.get("osv_id") and v.get("osv_id") != vid:
            entry["references"] = [{"id": str(v["osv_id"]),
                                    "source": {"name": "OSV", "url": _osv_url(str(v["osv_id"]))}}]
        rating: dict[str, Any] = {"severity": (v.get("severity") or "unknown")}
        if v.get("cvss") is not None:
            rating["score"] = float(v["cvss"])
            rating["method"] = "CVSSv3"
        entry["ratings"] = [rating]
        if v.get("summary"):
            entry["description"] = str(v["summary"])
        if v.get("fixed_version"):
            entry["recommendation"] = f"Upgrade {v.get('name')} to {v['fixed_version']} or later."
        analysis: dict[str, Any] = {"state": st["cdx_state"], "detail": _vuln_detail(v)}
        if st.get("cdx_justification"):
            analysis["justification"] = st["cdx_justification"]
        if st["cdx_state"] == "exploitable":
            analysis["response"] = ["update"] if v.get("fixed_version") else ["workaround_available"]
        entry["analysis"] = analysis
        entry["affects"] = [{"ref": cref, "versions": [
            {"version": str(v.get("version")), "status": "unaffected"
             if st["cdx_state"] == "not_affected" else "affected"}]}]
        props = [{"name": "paddock:reachability", "value": str(v.get("reachability") or "unknown")}]
        if v.get("reachable_symbol"):
            props.append({"name": "paddock:reachable_symbol", "value": str(v["reachable_symbol"])})
        entry["properties"] = props
        vulns.append(entry)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": md,
        "components": list(comps.values()),
        "vulnerabilities": vulns,
    }


def openvex(project: Mapping[str, Any], rows: list[Mapping[str, Any]], *,
            author: str = "Paddock") -> dict[str, Any]:
    statements: list[dict[str, Any]] = []
    ts = iso_z()
    for v in rows:
        comp = {"id": v.get("component_id"), "ecosystem": v.get("ecosystem"), "name": v.get("name"),
                "version": v.get("version"), "purl": v.get("purl")}
        vid = str(v.get("cve_id") or v.get("osv_id"))
        st = vex_status(v.get("reachability"))
        vuln: dict[str, Any] = {"name": vid}
        aliases = [a for a in (v.get("osv_id"), v.get("cve_id")) if a and a != vid]
        if aliases:
            vuln["aliases"] = aliases
        if vid.upper().startswith("CVE-"):
            vuln["@id"] = f"https://nvd.nist.gov/vuln/detail/{vid}"
        stmt: dict[str, Any] = {
            "vulnerability": vuln,
            "timestamp": ts,
            "products": [{"@id": _ref_for(comp)}],
            "status": st["openvex_status"],
            "status_notes": _vuln_detail(v),
        }
        if st["openvex_status"] == "not_affected":
            stmt["justification"] = st["openvex_justification"]
            stmt["impact_statement"] = _vuln_detail(v)
        elif st["openvex_status"] == "affected":
            stmt["action_statement"] = (
                f"Upgrade {v.get('name')} to {v['fixed_version']} or later."
                if v.get("fixed_version") else
                "No fixed version is known; apply the advisory's workaround.")
        statements.append(stmt)
    doc_id = uuid.uuid4()
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://openvex.dev/docs/paddock/{doc_id}",
        "author": author,
        "role": "Document Creator",
        "timestamp": ts,
        "version": 1,
        "tooling": f"{TOOL_NAME} {__version__}",
        "statements": statements,
    }


# --------------------------------------------------------------------------- #
# SPDX 2.3
# --------------------------------------------------------------------------- #

def spdx_sbom(project: Mapping[str, Any], components: list[Mapping[str, Any]]) -> dict[str, Any]:
    name = str(project.get("name") or "project")
    root_id = _spdx_id("Project", name)
    packages: list[dict[str, Any]] = [{
        "SPDXID": root_id,
        "name": name,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "primaryPackagePurpose": "APPLICATION",
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }]
    rels: list[dict[str, Any]] = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                                   "relatedSpdxElement": root_id}]
    ids: dict[str, str] = {}
    used: set[str] = {root_id}
    for c in components:
        ref = _ref_for(c)
        if ref in ids:
            continue
        sid = _spdx_id("Package", f"{c.get('ecosystem')}-{c.get('name')}-{c.get('version')}")
        n = 2
        base = sid
        while sid in used:
            sid = f"{base}-{n}"
            n += 1
        used.add(sid)
        ids[ref] = sid
        pkg: dict[str, Any] = {
            "SPDXID": sid,
            "name": str(c.get("name") or ""),
            "versionInfo": str(c.get("version") or ""),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "primaryPackagePurpose": "LIBRARY",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        purl = c.get("purl") or purl_for(c.get("ecosystem"), c.get("name"), c.get("version"))
        if purl:
            pkg["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                    "referenceLocator": purl}]
        packages.append(pkg)
    edges = _parent_edges(list(components))
    for c in components:
        if c.get("direct"):
            rid = ids.get(_ref_for(c))
            if rid:
                rels.append({"spdxElementId": root_id, "relationshipType": "DEPENDS_ON",
                             "relatedSpdxElement": rid})
    for parent, children in sorted(edges.items()):
        pid = ids.get(parent)
        for child in sorted(children):
            cid = ids.get(child)
            if pid and cid:
                rels.append({"spdxElementId": pid, "relationshipType": "DEPENDS_ON",
                             "relatedSpdxElement": cid})
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name} SBOM",
        "documentNamespace": f"https://spdx.org/spdxdocs/paddock/{quote(name, safe='')}-{uuid.uuid4()}",
        "creationInfo": {"created": iso_z(), "creators": [f"Tool: {TOOL_NAME}-{__version__}"]},
        "packages": packages,
        "relationships": rels,
    }


# --------------------------------------------------------------------------- #
# SARIF 2.1.0
# --------------------------------------------------------------------------- #

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def security_severity(sev: Optional[str], cvss: Optional[float] = None) -> str:
    if cvss is not None:
        return f"{float(cvss):.1f}"
    return f"{_SEV_SCORE.get((sev or '').lower(), 5.5):.1f}"


def sarif_level(sev: Optional[str]) -> str:
    return _SARIF_LEVEL.get((sev or "").lower(), "warning")


def normalize_uri(path: str, strip_prefix: Optional[str] = None) -> tuple[str, bool]:
    """(uri, relative?) -- repo-relative when we can make it so."""
    p = str(path or "").replace("\\", "/")
    if strip_prefix:
        sp = strip_prefix.replace("\\", "/").rstrip("/") + "/"
        if p.startswith(sp):
            p = p[len(sp):]
    while p.startswith("./"):
        p = p[2:]
    if p.startswith("/"):
        return "file://" + quote(p, safe="/._-~"), False
    return quote(p, safe="/._-~"), True


def _cwe_num(cwe: Optional[str]) -> Optional[str]:
    m = re.search(r"(\d{1,5})", str(cwe or ""))
    return m.group(1) if m else None


def sarif_log(hits: Iterable[Mapping[str, Any]], *, automation_id: str,
              strip_prefix: Optional[str] = None) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from normalized "hits".

    A hit: ``rule_id, rule_name, title, message, severity, cvss, file,
    start_line, end_line, cwe, dataflow, help, help_uri, fingerprint,
    finding_id, suppressed (status or None), kind ('sast'|'sca'), tags,
    properties``.
    """
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    taxa: list[dict[str, Any]] = []
    taxa_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for h in hits:
        rid = str(h["rule_id"])
        cwe = _cwe_num(h.get("cwe"))
        if cwe and cwe not in taxa_index:
            taxa_index[cwe] = len(taxa)
            taxa.append({"id": cwe, "name": f"CWE-{cwe}",
                         "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe}.html"})
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            tags = ["security", *(h.get("tags") or [])]
            if cwe:
                tags.append(f"external/cwe/cwe-{cwe}")
            rule: dict[str, Any] = {
                "id": rid,
                "name": re.sub(r"[^A-Za-z0-9]+", "", str(h.get("rule_name") or rid).title())[:100] or "Rule",
                "shortDescription": {"text": str(h.get("title") or rid)[:1000]},
                "fullDescription": {"text": str(h.get("description") or h.get("message") or rid)[:4000]},
                "defaultConfiguration": {"level": sarif_level(h.get("severity"))},
                "help": {"text": str(h.get("help") or h.get("description") or h.get("message") or rid)[:4000]},
                "properties": {
                    "tags": list(dict.fromkeys(tags)),
                    "security-severity": security_severity(h.get("severity"), h.get("cvss")),
                    "precision": "high" if h.get("kind") == "sca" else "medium",
                    "problem.severity": {"error": "error", "warning": "warning"}.get(
                        sarif_level(h.get("severity")), "recommendation"),
                },
            }
            if h.get("help_uri"):
                rule["helpUri"] = str(h["help_uri"])
            if cwe:
                rule["relationships"] = [{"target": {"id": cwe, "index": taxa_index[cwe],
                                                     "toolComponent": {"name": "CWE", "index": 0}},
                                          "kinds": ["superset"]}]
            rules.append(rule)

        uri, relative = normalize_uri(str(h.get("file") or ""), strip_prefix)
        art: dict[str, Any] = {"uri": uri}
        if relative:
            art["uriBaseId"] = "%SRCROOT%"
        phys: dict[str, Any] = {"artifactLocation": art}
        sl = h.get("start_line")
        if isinstance(sl, int) and sl >= 1:
            region: dict[str, Any] = {"startLine": sl}
            el = h.get("end_line")
            if isinstance(el, int) and el >= sl:
                region["endLine"] = el
            phys["region"] = region
        level = h.get("level") or sarif_level(h.get("severity"))
        res: dict[str, Any] = {
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": level,
            "message": {"text": str(h.get("message") or h.get("title") or rid)[:4000]},
            "locations": [{"physicalLocation": phys}],
            "partialFingerprints": {"paddock/v1": str(h.get("fingerprint") or hashlib.sha256(
                f"{rid}|{uri}|{sl}".encode()).hexdigest())},
            "properties": {"severity": h.get("severity"),
                           **({"paddockFindingId": str(h["finding_id"])} if h.get("finding_id") else {}),
                           **(h.get("properties") or {})},
        }
        if cwe:
            res["taxa"] = [{"id": cwe, "index": taxa_index[cwe],
                            "toolComponent": {"name": "CWE", "index": 0}}]
        flow = _code_flow(h.get("dataflow"), art)
        if flow:
            res["codeFlows"] = [flow]
        if h.get("suppressed"):
            res["suppressions"] = [{"kind": "external", "status": "accepted",
                                    "justification": f"Paddock status: {h['suppressed']}"}]
        results.append(res)

    run: dict[str, Any] = {
        "tool": {"driver": {
            "name": TOOL_NAME,
            "informationUri": TOOL_URI,
            "semanticVersion": __version__,
            "version": __version__,
            "rules": rules,
        }},
        "automationDetails": {"id": automation_id},
        "columnKind": "unicodeCodePoints",
        "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "The repository root."}}},
        "invocations": [{"executionSuccessful": True, "endTimeUtc": iso_z()}],
        "results": results,
    }
    if taxa:
        run["tool"]["driver"]["supportedTaxonomies"] = [{"name": "CWE", "index": 0}]
        run["taxonomies"] = [{
            "name": "CWE",
            "organization": "MITRE",
            "version": "4.14",
            "informationUri": "https://cwe.mitre.org/data/published/cwe_v4.14.pdf",
            "shortDescription": {"text": "The MITRE Common Weakness Enumeration"},
            "taxa": taxa,
        }]
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def _code_flow(dataflow: Any, art: Mapping[str, Any]) -> Optional[dict[str, Any]]:
    if not isinstance(dataflow, list):
        return None
    locs: list[dict[str, Any]] = []
    for step in dataflow[:50]:
        if not isinstance(step, Mapping):
            continue
        line = step.get("line") or step.get("start_line")
        loc: dict[str, Any] = {"physicalLocation": {"artifactLocation": dict(art)}}
        if isinstance(line, int) and line >= 1:
            loc["physicalLocation"]["region"] = {"startLine": line}
        label = step.get("label") or step.get("code") or step.get("step")
        if label:
            loc["message"] = {"text": str(label)[:500]}
        locs.append({"location": loc})
    if len(locs) < 1:
        return None
    return {"threadFlows": [{"locations": locs}]}


def sca_manifest_for(ecosystem: Optional[str], manifests: Mapping[str, list[str]]) -> str:
    paths = manifests.get(ecosystem or "") or []
    if paths:
        return sorted(paths, key=lambda p: (p.count("/"), p))[0]
    return _DEFAULT_MANIFEST.get(ecosystem or "", "SBOM")


# --------------------------------------------------------------------------- #
# SBOM import (CycloneDX / SPDX JSON) -> components
# --------------------------------------------------------------------------- #

class ImportError_(ValueError):
    """The uploaded document is not a usable CycloneDX/SPDX JSON SBOM."""


MAX_IMPORT_COMPONENTS = 50_000
_MAX_NEST = 32


def detect_format(doc: Mapping[str, Any]) -> str:
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if str(doc.get("spdxVersion") or "").startswith("SPDX-2."):
        return "spdx"
    raise ImportError_("not a CycloneDX (bomFormat) or SPDX 2.x (spdxVersion) JSON document")


def _component_record(name: Any, version: Any, purl: Any, group: Any = None,
                      ecosystem_hint: Optional[str] = None) -> Optional[dict[str, Any]]:
    rec: Optional[dict[str, Any]] = None
    if isinstance(purl, str):
        rec = purl_to_component(purl)
        if rec and not rec.get("version") and version:
            rec["version"] = str(version)
    if rec is None:
        if not name or not version:
            return None
        nm = str(name)
        if group:
            nm = f"{group}:{nm}" if ecosystem_hint == "Maven" else f"{group}/{nm}"
        rec = {"ecosystem": ecosystem_hint or "generic", "name": nm, "version": str(version)}
    if not rec.get("name") or not rec.get("version"):
        return None
    rec["name"] = str(rec["name"])[:512]
    rec["version"] = str(rec["version"])[:256]
    rec["ecosystem"] = str(rec["ecosystem"])[:64]
    rec["purl"] = (str(purl)[:1024] if isinstance(purl, str) and purl.startswith("pkg:")
                   else purl_for(rec["ecosystem"], rec["name"], rec["version"]))
    return rec


def _depths(roots: set[str], edges: Mapping[str, set[str]]) -> dict[str, int]:
    depth: dict[str, int] = {}
    frontier = sorted(roots)
    for r in frontier:
        depth[r] = 0
    while frontier:
        nxt = []
        for cur in frontier:
            for ch in sorted(edges.get(cur, ())):
                if ch not in depth:
                    depth[ch] = depth[cur] + 1
                    nxt.append(ch)
        frontier = nxt
    return depth


def parse_cyclonedx(doc: Mapping[str, Any]) -> dict[str, Any]:
    root = (doc.get("metadata") or {}).get("component") or {}
    root_ref = root.get("bom-ref") if isinstance(root, Mapping) else None
    flat: list[Mapping[str, Any]] = []

    def walk(items: Any, level: int) -> None:
        if level > _MAX_NEST or not isinstance(items, list):
            return
        for c in items:
            if not isinstance(c, Mapping):
                continue
            flat.append(c)
            if len(flat) > MAX_IMPORT_COMPONENTS:
                raise ImportError_(f"too many components (max {MAX_IMPORT_COMPONENTS})")
            walk(c.get("components"), level + 1)

    walk(doc.get("components"), 0)
    edges: dict[str, set[str]] = {}
    for d in doc.get("dependencies") or []:
        if isinstance(d, Mapping) and isinstance(d.get("ref"), str):
            edges.setdefault(d["ref"], set()).update(
                x for x in (d.get("dependsOn") or []) if isinstance(x, str))
    roots = set(edges.get(root_ref, set())) if root_ref else set()
    depth = _depths(roots, edges) if roots else {}
    parents: dict[str, set[str]] = {}
    for p, chs in edges.items():
        for ch in chs:
            parents.setdefault(ch, set()).add(p)

    comps: list[dict[str, Any]] = []
    ref_to_key: dict[str, tuple[str, str, str]] = {}
    for c in flat:
        if c.get("type") not in (None, "library", "framework", "application", "container",
                                 "operating-system", "device", "firmware", "file"):
            continue
        if root_ref and c.get("bom-ref") == root_ref:
            continue
        rec = _component_record(c.get("name"), c.get("version"), c.get("purl"), c.get("group"))
        if rec is None:
            continue
        ref = c.get("bom-ref") if isinstance(c.get("bom-ref"), str) else None
        if roots:
            rec["direct"] = ref in roots
            rec["depth"] = min(depth.get(ref, 1), 32000) if ref else 1
        else:
            rec["direct"], rec["depth"] = True, 0
        rec["paths"] = []
        rec["metadata"] = {"imported_from": "cyclonedx", **({"bom_ref": ref[:512]} if ref else {})}
        if ref:
            ref_to_key[ref] = (rec["ecosystem"], rec["name"], rec["version"])
            rec["_ref"] = ref
        comps.append(rec)
    for rec in comps:
        ref = rec.pop("_ref", None)
        if ref:
            rec["paths"] = sorted(f"{ref_to_key[p][1]}@{ref_to_key[p][2]}"
                                  for p in parents.get(ref, ()) if p in ref_to_key)[:16]

    vulns: list[dict[str, Any]] = []
    for v in doc.get("vulnerabilities") or []:
        if not isinstance(v, Mapping) or not isinstance(v.get("id"), str):
            continue
        vid = v["id"][:128]
        ratings = [r for r in (v.get("ratings") or []) if isinstance(r, Mapping)]
        sevs = [str(r.get("severity") or "").lower() for r in ratings]
        sevs = [x for x in sevs if x in _SEV_SCORE]
        sev = max(sevs, key=sev_rank) if sevs else "medium"
        scores = [float(r["score"]) for r in ratings
                  if isinstance(r.get("score"), (int, float)) and 0 <= r["score"] <= 10]
        score = max(scores) if scores else None
        analysis = v.get("analysis") if isinstance(v.get("analysis"), Mapping) else {}
        reach = ("unreachable" if analysis.get("state") == "not_affected"
                 and analysis.get("justification") == "code_not_reachable" else None)
        for a in v.get("affects") or []:
            ref = a.get("ref") if isinstance(a, Mapping) else None
            if isinstance(ref, str) and ref in ref_to_key:
                vulns.append({"key": ref_to_key[ref], "osv_id": vid,
                              "cve_id": vid if vid.upper().startswith("CVE-") else None,
                              "severity": sev, "cvss": score,
                              "summary": str(v.get("description") or v.get("detail") or "")[:2000] or None,
                              "reachability": reach})
    name = root.get("name") if isinstance(root, Mapping) else None
    return {"format": "cyclonedx", "name": str(name) if name else None, "components": comps,
            "vulns": vulns}


def parse_spdx(doc: Mapping[str, Any]) -> dict[str, Any]:
    pkgs = [p for p in (doc.get("packages") or []) if isinstance(p, Mapping)]
    if len(pkgs) > MAX_IMPORT_COMPONENTS:
        raise ImportError_(f"too many packages (max {MAX_IMPORT_COMPONENTS})")
    rels = [r for r in (doc.get("relationships") or []) if isinstance(r, Mapping)]
    described = {r.get("relatedSpdxElement") for r in rels
                 if r.get("spdxElementId") == "SPDXRef-DOCUMENT" and r.get("relationshipType") == "DESCRIBES"}
    described |= {x for x in (doc.get("documentDescribes") or []) if isinstance(x, str)}
    edges: dict[str, set[str]] = {}
    for r in rels:
        a, b, t = r.get("spdxElementId"), r.get("relatedSpdxElement"), r.get("relationshipType")
        if not (isinstance(a, str) and isinstance(b, str)):
            continue
        if t in ("DEPENDS_ON", "CONTAINS"):
            edges.setdefault(a, set()).add(b)
        elif t in ("DEPENDENCY_OF", "CONTAINED_BY"):
            edges.setdefault(b, set()).add(a)
    roots: set[str] = set()
    for d in described:
        roots |= edges.get(d, set())
    depth = _depths(roots, edges) if roots else {}
    parents: dict[str, set[str]] = {}
    for p, chs in edges.items():
        for ch in chs:
            parents.setdefault(ch, set()).add(p)
    comps: list[dict[str, Any]] = []
    id_to_key: dict[str, tuple[str, str, str]] = {}
    root_name = None
    for p in pkgs:
        sid = p.get("SPDXID")
        if sid in described:
            root_name = root_name or p.get("name")
            continue
        purl = next((r.get("referenceLocator") for r in (p.get("externalRefs") or [])
                     if isinstance(r, Mapping) and r.get("referenceType") == "purl"), None)
        rec = _component_record(p.get("name"), p.get("versionInfo"), purl)
        if rec is None:
            continue
        if roots:
            rec["direct"] = sid in roots
            rec["depth"] = depth.get(sid, 1)
        else:
            rec["direct"], rec["depth"] = True, 0
        rec["metadata"] = {"imported_from": "spdx", **({"spdx_id": str(sid)[:256]} if sid else {})}
        if isinstance(sid, str):
            id_to_key[sid] = (rec["ecosystem"], rec["name"], rec["version"])
            rec["_sid"] = sid
        comps.append(rec)
    for rec in comps:
        sid = rec.pop("_sid", None)
        rec["paths"] = sorted(f"{id_to_key[p][1]}@{id_to_key[p][2]}"
                              for p in parents.get(sid, ()) if p in id_to_key)[:16] if sid else []
    name = root_name or doc.get("name")
    return {"format": "spdx", "name": str(name) if name else None, "components": comps, "vulns": []}


def parse_sbom(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, Mapping):
        raise ImportError_("SBOM must be a JSON object")
    fmt = detect_format(doc)
    out = parse_cyclonedx(doc) if fmt == "cyclonedx" else parse_spdx(doc)
    # de-duplicate on the sbom_components natural key
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    for c in out["components"]:
        k = (c["ecosystem"], c["name"], c["version"])
        if k in seen:
            prev = seen[k]
            prev["direct"] = prev["direct"] or c["direct"]
            prev["depth"] = min(prev["depth"], c["depth"])
        else:
            seen[k] = c
    out["components"] = list(seen.values())
    return out
