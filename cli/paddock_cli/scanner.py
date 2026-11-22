"""`paddock scan`: run the engines over a repo and normalise what they return.

* dependencies  -> sca parsers + OSV (``osvclient``) + sca ``risk.typosquat``
* code / secrets -> codeanalysis ``sast.run_sast`` (Semgrep if asked, else the bundled taint
                    scanner) plus the CLI's repo-wide secret patterns
* config        -> the nginx checks in ``configcheck``
"""
from __future__ import annotations

import os
import posixpath
import re
from pathlib import Path
from typing import Any, Callable

from . import configcheck, engines, secrets_scan, walk
from .model import Finding, ScanResult, fingerprint, rank
from .osvclient import OsvClient, OsvResult, key_of, nearest_fix

ALL_CATEGORIES = ("deps", "secrets", "code", "config")
SOURCE_EXT = {".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go"}



def _dep_why(summary: str | None, direct: bool, malicious: bool = False) -> str:
    if malicious:
        return ("This package is flagged as malware. Installing it can run attacker code on "
                "developer machines and in CI, where your deploy credentials live.")
    if direct:
        return ("This ships in your build and the flaw is public, so attackers can find "
                "vulnerable apps by version alone, without knowing anything about your code.")
    return ("A package you depend on indirectly ships this public flaw; you inherit it even though "
            "you never chose the package, and attackers can find it by version alone.")


def _clean(text: str | None, limit: int = 220) -> str:
    t = re.sub(r"\s+", " ", text or "").strip()
    return t if len(t) <= limit else t[: limit - 1].rstrip() + "…"


def _find_line(text: str, name: str, version: str) -> int | None:
    needle_n = name.split(":")[-1]  # maven group:artifact -> artifact
    first = None
    for i, line in enumerate(text.splitlines(), 1):
        if needle_n in line:
            if version and version in line:
                return i
            first = first or i
    return first


def gomod_requires(go_mod: str) -> list[tuple[str, str, bool]]:
    """(module, version, direct) for every ``require`` in a go.mod (replace/exclude ignored)."""
    out: list[tuple[str, str, bool]] = []
    block: str | None = None
    for raw in go_mod.splitlines():
        indirect = "// indirect" in raw
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if block:
            if line.startswith(")"):
                block = None
            elif block == "require":
                parts = line.split()
                if len(parts) >= 2 and re.match(r"v\d", parts[1]):
                    out.append((parts[0], parts[1], not indirect))
            continue
        m = re.match(r"^(require|replace|exclude|retract)\s*\($", line)
        if m:
            block = m.group(1)
        elif line.startswith("require "):
            parts = line[len("require "):].split()
            if len(parts) >= 2 and re.match(r"v\d", parts[1]):
                out.append((parts[0], parts[1], not indirect))
    return out


def _go_filter(components: list[dict[str, Any]], go_mod: str | None) -> list[dict[str, Any]]:
    """go.sum keeps every version ever downloaded; go.mod says which one is built."""
    if not go_mod:
        return components
    wanted: dict[str, str] = {}
    from . import versions as V
    for name, ver, _direct in gomod_requires(go_mod):
        if name not in wanted or V.compare(ver, wanted[name]) > 0:
            wanted[name] = ver
    return [c for c in components if c["name"] not in wanted or c["version"] == wanted[c["name"]]]


def collect_components(root: Path, rels: list[str]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Parse every supported manifest. Each component gets ``source_file``."""
    parsers = engines.sca_parsers()
    comps: list[dict[str, Any]] = []
    texts: dict[str, str] = {}
    by_dir_gomod: dict[str, str] = {}
    for rel in rels:
        if posixpath.basename(rel).lower() == "go.mod":
            t = walk.read_text(root / rel, walk.MAX_LOCK_BYTES)
            if t is not None:
                by_dir_gomod[posixpath.dirname(rel)] = t
    for rel in rels:
        if not parsers.is_supported(rel) or posixpath.basename(rel).lower() == "go.mod":
            continue
        text = walk.read_text(root / rel, walk.MAX_LOCK_BYTES)
        if text is None:
            continue
        texts[rel] = text
        if posixpath.basename(rel).lower() == "go.sum":
            gm = by_dir_gomod.get(posixpath.dirname(rel))
            found = _go_filter(parsers.parse_files({rel: text, **(
                {posixpath.join(posixpath.dirname(rel), "go.mod"): gm} if gm else {})}), gm)
        else:
            found = parsers.parse_one(rel, text)
        for c in found:
            c = dict(c)
            c["source_file"] = rel
            comps.append(c)
    for d, gm in by_dir_gomod.items():
        sumf = posixpath.join(d, "go.sum")
        src = sumf if sumf in texts else posixpath.join(d, "go.mod")
        have = {(c["name"], c["version"]) for c in comps if c["source_file"] == src}
        for name, ver, direct in gomod_requires(gm):
            if (name, ver) not in have:
                comps.append({"ecosystem": "Go", "name": name, "version": ver, "direct": direct,
                              "depth": 0 if direct else 1, "paths": [], "source_file": src})
        texts.setdefault(src, gm)
    return comps, texts


def _dependency_findings(comps: list[dict[str, Any]], texts: dict[str, str],
                         osv_res: OsvResult) -> list[Finding]:
    osv = engines.sca_osv()
    out: list[Finding] = []
    seen: set[str] = set()
    for c in comps:
        eco, name, ver = c["ecosystem"], c["name"], c.get("version") or ""
        raw = osv_res.vulns.get(key_of(eco, name, ver))
        if not raw:
            continue
        mapped = [(r, osv.map_vuln(r, eco, name)) for r in raw]
        bad = [(r, m) for r, m in mapped if m["malicious"]]
        vuln = [(r, m) for r, m in mapped if not m["malicious"]]
        rel = c["source_file"]
        line = _find_line(texts.get(rel, ""), name, ver)
        direct = bool(c.get("direct"))
        if bad:
            ids = [m["osv_id"] for _, m in bad]
            fid = fingerprint("malicious", eco, name, ver, rel)
            if fid not in seen:
                seen.add(fid)
                out.append(Finding(
                    id=fid, kind="malicious", severity="critical",
                    title=f"{name} {ver} is flagged as malicious",
                    message=f"{name}@{ver} ({eco}) matches OSV malware advisory {', '.join(ids)}",
                    why=_dep_why(None, direct, malicious=True), file=rel, line=line,
                    rule_id="risk:malicious_version",
                    fix=f"remove {name}, then rotate any credentials present where it was installed",
                    refs=[f"https://osv.dev/vulnerability/{i}" for i in ids][:5],
                    data={"ecosystem": eco, "package": name, "version": ver, "osv_ids": ids,
                          "direct": direct}))
        if not vuln:
            continue
        fid = fingerprint("dependency", eco, name, ver, rel)
        if fid in seen:
            continue
        seen.add(fid)
        records = [r for r, _ in vuln]
        maps = [m for _, m in vuln]
        sev = max((m["severity"] for m in maps), key=rank)
        ids = [m["osv_id"] for m in maps if m["osv_id"]]
        cves = [m["cve_id"] for m in maps if m["cve_id"]]
        top = max(maps, key=lambda m: (rank(m["severity"]), m["cvss"] or 0))
        target, complete = nearest_fix(ver, records, eco, name)
        refs: list[str] = []
        for m in maps:
            refs.extend(m["refs"])
        n = len(maps)
        out.append(Finding(
            id=fid, kind="dependency", severity=sev,
            title=f"{name} {ver}: {n} known vulnerabilit{'y' if n == 1 else 'ies'}",
            message="; ".join(f"{(m['cve_id'] or m['osv_id'])}: {_clean(m['summary'], 110)}"
                              for m in maps[:3]) + (f"; +{n - 3} more" if n > 3 else ""),
            why=_dep_why(None, direct), file=rel, line=line,
            rule_id=f"sca:{eco}:{name}",
            fix=(f"upgrade to {target}" + ("" if complete else " (partial: some advisories have no fix)")
                 if target else "no fixed version published; replace or pin around it"),
            refs=list(dict.fromkeys(refs))[:8], cvss=max((m["cvss"] for m in maps if m["cvss"]),
                                                          default=None),
            data={"ecosystem": eco, "package": name, "version": ver, "direct": direct,
                  "depth": c.get("depth"), "osv_ids": list(dict.fromkeys(ids)),
                  "cve_ids": list(dict.fromkeys(cves)), "fixed_version": target,
                  "fix_complete": complete,
                  "advisories": [{"id": m["osv_id"], "cve": m["cve_id"], "severity": m["severity"],
                                  "summary": _clean(m["summary"], 160),
                                  "fixed": m["fixed_version"]} for m in maps]}))
    return out


def _same_namespace(a: str, b: str) -> bool:
    def ns(n: str) -> str:
        i = max(n.rfind("/"), n.rfind(":"))
        return n[:i] if i > 0 else ""
    return bool(ns(a)) and ns(a) == ns(b)


def _typosquat_findings(comps: list[dict[str, Any]], texts: dict[str, str]) -> list[Finding]:
    risk = engines.sca_risk()
    out: list[Finding] = []
    seen: set[str] = set()
    for c in comps:
        for r in risk.typosquat.detect([c]):
            rel = c["source_file"]
            fid = fingerprint("typosquat", c["ecosystem"], c["name"], rel)
            if fid in seen:
                continue
            seen.add(fid)
            resembles = r["detail"]["resembles"]
            if _same_namespace(c["name"], resembles):
                continue  # golang.org/x/text vs golang.org/x/net, @scope/a vs @scope/b: siblings
            out.append(Finding(
                id=fid, kind="typosquat", severity=r["severity"],
                title=f"{c['name']} looks like {resembles}",
                message=r["summary"],
                why="Look-alike package names are a common way malware reaches a build: one "
                    "mistyped install and attacker code runs with your credentials.",
                file=rel, line=_find_line(texts.get(rel, ""), c["name"], c.get("version", "")),
                rule_id="risk:typosquat",
                fix=f"confirm you meant '{c['name']}', not '{resembles}'; remove it if not",
                data={"ecosystem": c["ecosystem"], "package": c["name"],
                      "version": c.get("version"), "resembles": resembles}))
    return out


def _code_findings(sources: dict[str, str], semgrep: bool, root: Path,
                   secret_locs: set[tuple[str, int]]) -> tuple[list[Finding], list[str]]:
    sast = engines.sast()
    norm = engines.sast_normalize()
    res = sast.run_sast(sources, enable_semgrep=semgrep)
    notes = [f"SAST engine: {res['engine']}"]
    out: list[Finding] = []
    seen: set[str] = set()
    for hit in norm.dedupe(res.get("hits", [])):
        item = norm.build_sast_finding(hit, {"name": root.name})
        rel, line = hit.get("file") or "", hit.get("start_line")
        sev = norm.normalize_severity(hit.get("severity"))
        cls = hit.get("rule_class") or "code_weakness"
        if cls == "hardcoded_secret":
            if (rel, line) in secret_locs:
                continue
            text = sources.get(rel, "")
            src_line = text.splitlines()[line - 1] if line and line <= len(text.splitlines()) else ""
            value = _literal_in(src_line)
            fid = fingerprint("secret", rel, secrets_scan.value_hash(value) if value else line)
            if fid in seen:
                continue
            seen.add(fid)
            out.append(Finding(
                id=fid, kind="secret", severity=sev, title=f"Hard-coded credential in {rel}",
                message=hit.get("message") or "hard-coded credential", why=_secret_why(),
                file=rel, line=line, rule_id="secret:hardcoded-credential",
                fix="move it to an environment variable and rotate it",
                cwe=hit.get("cwe"), data={"rule": "sast-hardcoded", "redacted":
                                          secrets_scan.redact(value) if value else None}))
            continue
        fid = fingerprint("code", hit.get("rule"), rel, line)
        if fid in seen:
            continue
        seen.add(fid)
        out.append(Finding(
            id=fid, kind="code", severity=sev,
            title=item["title"], message=hit.get("message") or item["description"],
            why=item["impact"], file=rel, line=line, end_line=hit.get("end_line"),
            rule_id=item["rule_id"], fix=item["remediation"], cwe=hit.get("cwe"),
            refs=item.get("references") or [],
            data={"rule_class": cls, "engine": hit.get("engine"), "source": hit.get("source"),
                  "sink": hit.get("sink"), "dataflow": hit.get("dataflow") or [],
                  "language": hit.get("language")}))
    return out, notes


def _literal_in(line: str) -> str | None:
    m = re.search(r"""["'`]([^"'`\s]{6,})["'`]""", line)
    return m.group(1) if m else None


def _secret_why() -> str:
    return ("Anyone who can read the repo (or a leaked copy of it) can use this credential. "
            "It also stays in git history after you delete it, so it must be rotated.")


def scan(root: str | Path, *, offline: bool = False, only: set[str] | None = None,
         excludes: list[str] | None = None, osv: OsvClient | None = None,
         semgrep: bool = False, use_git: bool = True,
         log: Callable[[str], None] | None = None) -> ScanResult:
    root = Path(root).resolve()
    only = only or set(ALL_CATEGORIES)
    say = log or (lambda _m: None)
    result = ScanResult(root=str(root))
    rels = walk.list_files(root, excludes, use_git=use_git)
    result.stats["files"] = len(rels)

    comps: list[dict[str, Any]] = []
    texts: dict[str, str] = {}
    if "deps" in only:
        comps, texts = collect_components(root, rels)
        result.components = comps
        result.stats["manifests"] = len(texts)
        pk = {(c["ecosystem"], c["name"], c["version"]) for c in comps if c.get("version")}
        result.stats["packages"] = len(pk)
        if pk:
            say(f"checking {len(pk)} packages against OSV" + (" (offline cache)" if offline else ""))
            client = osv or OsvClient(offline=offline)
            res = client.query(sorted(pk))
            result.notes.extend(res.notes)
            result.stats["osv_unchecked"] = len(res.unchecked)
            result.stats["osv_unchecked_keys"] = sorted(res.unchecked)
            result.findings += _dependency_findings(comps, texts, res)
        result.findings += _typosquat_findings(comps, texts)

    secret_locs: set[tuple[str, int]] = set()
    sources: dict[str, str] = {}
    conf_texts: dict[str, str] = {}
    if {"secrets", "code", "config"} & only:
        for rel in rels:
            ext = os.path.splitext(rel)[1].lower()
            is_src = ext in SOURCE_EXT
            is_conf = "config" in only and (rel.lower().endswith(".conf") or
                                            posixpath.basename(rel).lower() == "default")
            text = walk.read_text(root / rel)
            if text is None:
                continue
            if is_src:
                sources[rel] = text
            if is_conf:
                conf_texts[rel] = text
            if "secrets" in only:
                for h in secrets_scan.scan_text(rel, text):
                    secret_locs.add((h.file, h.line))
                    result.findings.append(_secret_finding(h))
        result.stats["source_files"] = len(sources)

    if sources and {"code", "secrets"} & only:
        say(f"analysing {len(sources)} source files")
        found, notes = _code_findings(sources, semgrep, root, secret_locs)
        result.notes.extend(notes)
        want = {"secret": "secrets", "code": "code"}
        result.findings += [f for f in found if want[f.kind] in only]

    for rel, text in conf_texts.items():
        for h in configcheck.check_nginx(rel, text):
            result.findings.append(Finding(
                id=fingerprint("config", h.rule, rel), kind="config", severity=h.severity,
                title={"nginx-weak-tls": "Weak TLS protocols enabled",
                       "nginx-no-hsts": "HSTS header missing"}[h.rule] + f" in {rel}",
                message=h.message, why=h.why, file=rel, line=h.line, rule_id=f"config:{h.rule}",
                fix="pin ssl_protocols to TLSv1.2 TLSv1.3" if h.fix_class == "config_fix"
                else "add the Strict-Transport-Security header",
                data={"rule": h.rule, "fix_class": h.fix_class, "header": h.fix_header}))

    result.findings.sort(key=lambda f: (-rank(f.severity), f.kind, f.file, f.line or 0))
    return result


def _secret_finding(h: secrets_scan.SecretHit) -> Finding:
    return Finding(
        id=fingerprint("secret", h.file, h.value_hash), kind="secret", severity=h.severity,
        title=f"{h.label} in {h.file}",
        message=f"{h.label} committed in source ({h.preview})", why=_secret_why(),
        file=h.file, line=h.line, rule_id=f"secret:{h.rule}",
        fix="load it from an environment variable or secret manager, then rotate it",
        data={"rule": h.rule, "redacted": h.preview, "var_name": h.var_name,
              "value_hash": h.value_hash})
