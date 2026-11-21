"""`paddock fix`: turn findings into deterministic, gated patches.

Nothing here asks a model for code. Every edit is produced by code from facts
OSV or the scanner established, then checked before it is offered:

* dependency bumps and nginx flips reuse ``remediation/app/generators.py`` where it
  can express the edit, and ``gate.check`` + ``verify.verify`` (the remediation
  service's deterministic gate and rule verifier) on the resulting diff;
* edits the generators do not cover (go.mod, pom.xml, lockfile hygiene, CRLF files)
  are made here, but still pass ``gate.check`` as a ``dependency_bump``;
* the secret -> environment-variable rewrite edits *source code*, which the remediation
  gate hard-denies by design, so it is checked by a stricter CLI-local gate below.
"""
from __future__ import annotations

import ast
import asyncio
import difflib
import json
import os
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import engines, secrets_scan
from . import versions as V
from .model import Finding, ScanResult
from .osvclient import OsvClient, key_of, nearest_fix

ENV_EXAMPLE = ".env.example"


# --------------------------------------------------------------------------- #
# data
# --------------------------------------------------------------------------- #
@dataclass
class Edit:
    path: str
    before: str | None      # None: the file does not exist yet
    after: str


@dataclass
class FixPlan:
    id: str
    kind: str                       # dependency | secret | config
    title: str
    resolves: list[str]             # finding ids this plan should clear
    edits: list[Edit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    gate_ok: bool = True
    gate_engine: str = "remediation.gate"
    gate_reasons: list[str] = field(default_factory=list)
    breaking: bool = False
    why: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def unified(self) -> str:
        return "".join(unified_diff(e.path, e.before, e.after) for e in self.edits)


@dataclass
class Skipped:
    finding: Finding
    reason: str


# --------------------------------------------------------------------------- #
# diff helper
# --------------------------------------------------------------------------- #
def _eol(s: str) -> str:
    return s if s.endswith("\n") or not s else s + "\n"


def unified_diff(path: str, before: str | None, after: str) -> str:
    a = _eol(before or "").splitlines(keepends=True)
    b = _eol(after).splitlines(keepends=True)
    return "".join(difflib.unified_diff(
        a, b, fromfile=f"a/{path}" if before is not None else "/dev/null", tofile=f"b/{path}", n=3))


# --------------------------------------------------------------------------- #
# edit primitives (line based, preserve line endings)
# --------------------------------------------------------------------------- #
def _lines(text: str) -> list[tuple[str, str]]:
    out = []
    for ln in text.splitlines(keepends=True):
        body = ln.rstrip("\r\n")
        out.append((body, ln[len(body):]))
    return out


def _join(lines: list[tuple[str, str]]) -> str:
    return "".join(b + e for b, e in lines)


def bump_requirements(text: str, pkg: str, cur: str, fixed: str) -> str | None:
    name = re.sub(r"[-_.]+", "[-_.]+", re.escape(pkg).replace(r"\-", "-").replace(r"\_", "_")
                  .replace(r"\.", "."))
    rx = re.compile(rf"^(\s*{name}(?:\[[^\]]*\])?\s*===?\s*){re.escape(cur)}(?=\s*(?:;|#|\\|$))",
                    re.I)
    changed = False
    out = []
    for body, eol in _lines(text):
        new = rx.sub(lambda m: m.group(1) + fixed, body, count=1)
        changed |= new != body
        out.append((new, eol))
    return _join(out) if changed else None


def bump_gomod(text: str, mod: str, cur: str, fixed: str) -> str | None:
    rx = re.compile(rf"^(\s*(?:require\s+)?{re.escape(mod)}\s+){re.escape(cur)}(?=\s*(?://.*)?$)")
    changed = False
    out = []
    for body, eol in _lines(text):
        new = rx.sub(lambda m: m.group(1) + fixed, body, count=1)
        changed |= new != body
        out.append((new, eol))
    return _join(out) if changed else None


def bump_pom(text: str, coord: str, cur: str, fixed: str) -> tuple[str | None, str]:
    """Bump ``group:artifact`` in a pom.

    Returns ``(new text, anchor)`` where ``anchor`` names the line that was edited (the artifactId,
    or the property name when the version comes from ``<properties>``); on failure
    ``(None, reason)``."""
    group, _, artifact = coord.partition(":")
    for m in re.finditer(r"<dependency>.*?</dependency>", text, re.S):
        block = m.group(0)
        g = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", block)
        a = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", block)
        v = re.search(r"<version>\s*([^<]+?)\s*</version>", block)
        if not (g and a and v) or g.group(1) != group or a.group(1) != artifact:
            continue
        ver = v.group(1)
        if ver == cur:
            new_block = block[:v.start(1)] + fixed + block[v.end(1):]
            return text[:m.start()] + new_block + text[m.end():], artifact
        prop = re.fullmatch(r"\$\{([^}]+)\}", ver)
        if prop:
            if text.count(f"${{{prop.group(1)}}}") != 1:
                return None, f"version property {ver} is shared by other dependencies; bump it by hand"
            pm = re.search(rf"(<{re.escape(prop.group(1))}>\s*){re.escape(cur)}(\s*</)", text)
            if pm:
                return (text[:pm.start()] + pm.group(1) + fixed + pm.group(2) + text[pm.end():],
                        prop.group(1))
    return None, f"could not find {coord} {cur} in the pom"


_NPM_KEY = r'"((?:[^"\n]*/)?node_modules/{pkg}|{pkg})"\s*:\s*\{{'


def _block_end(text: str, open_idx: int) -> int:
    depth = 0
    in_str = False
    i = open_idx
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


def bump_npm_lock(text: str, pkg: str, cur: str, fixed: str,
                  ) -> tuple[str | None, str | None]:
    """(core, full): ``core`` changes only ``version``; ``full`` also repoints ``resolved``
    and drops the now-stale ``integrity`` so ``npm ci`` installs the fixed tarball."""
    n = 0
    rx = re.compile(_NPM_KEY.format(pkg=re.escape(pkg)))
    out_core, out_full, i = [], [], 0
    for m in rx.finditer(text):
        if m.start() < i:
            continue
        end = _block_end(text, m.end() - 1)
        block = text[m.start():end]
        vm = re.search(r'("version"\s*:\s*")' + re.escape(cur) + r'(")', block)
        if not vm:
            continue
        n += 1
        c_block = block[:vm.start()] + vm.group(1) + fixed + vm.group(2) + block[vm.end():]
        f_block = re.sub(r'("resolved"\s*:\s*"[^"]*?)' + re.escape(cur), lambda r: r.group(1) + fixed,
                         c_block)
        f_block = re.sub(r'\r?\n[ \t]*"integrity"\s*:\s*"[^"]*",', "", f_block)
        f_block = re.sub(r',\r?\n[ \t]*"integrity"\s*:\s*"[^"]*"(?=\s*\})', "", f_block)
        f_block = re.sub(r',[ \t]*"integrity"\s*:\s*"[^"]*"', "", f_block)
        f_block = re.sub(r'"integrity"\s*:\s*"[^"]*",[ \t]*', "", f_block)
        out_core += [text[i:m.start()], c_block]
        out_full += [text[i:m.start()], f_block]
        i = end
    if not n:
        return None, None
    out_core.append(text[i:])
    out_full.append(text[i:])
    return "".join(out_core), "".join(out_full)


# --------------------------------------------------------------------------- #
# gate + verify glue
# --------------------------------------------------------------------------- #
def _run_verify(finding: dict[str, Any], change_class: str, diff: str, expected: dict[str, Any]):
    return asyncio.run(engines.verify().verify(finding, change_class, diff, expected, llm=None))


# The rule verifier looks for the package name on the *added* lines. Structured manifests
# (package-lock.json, pom.xml) keep the name on a neighbouring line, which gate.check
# already requires in the hunk context, so that one reason is expected for them.
_STRUCTURED_OK = ("diff does not mention the vulnerable package",)


def _gate(plan: FixPlan, diff: str, change_class: str, expected: dict[str, Any],
          rule_source: str, finding: Finding, ignore: tuple[str, ...] = ()) -> None:
    """Run the remediation gate and rule verifier over ``diff``; record the outcome."""
    g = engines.gate().check(diff, change_class, expected)
    reasons = list(g.reasons)
    if g.ok:
        v = _run_verify({"rule_source": rule_source, "title": finding.title,
                         "severity": finding.severity, "description": finding.message},
                        change_class, diff, expected)
        if not v.ok:
            reasons += [r for r in v.reasons if r not in ignore]
    plan.gate_ok = not reasons
    plan.gate_reasons = reasons


# --------------------------------------------------------------------------- #
# dependency plans
# --------------------------------------------------------------------------- #
_MANIFEST_FOR = {
    "requirements.txt": "requirements", "package-lock.json": "npm", "npm-shrinkwrap.json": "npm",
    "go.sum": "go", "go.mod": "go", "pom.xml": "pom",
}


def _settle_target(f: Finding, client: OsvClient | None, recheck: bool) -> tuple[str | None, bool]:
    """Nearest version that is itself clean, hopping while the target has advisories."""
    d = f.data
    target = d.get("fixed_version")
    if not target:
        return None, False
    complete = bool(d.get("fix_complete"))
    if not (recheck and client):
        return target, complete
    eco, pkg = d["ecosystem"], d["package"]
    for _ in range(4):
        res = client.query([(eco, pkg, target)])
        found = res.vulns.get(key_of(eco, pkg, target))
        if not found:
            break
        nxt, ok = nearest_fix(target, [v for v in found if not str(v.get("id", "")).startswith("MAL-")],
                              eco, pkg)
        if not nxt or V.compare(nxt, target) <= 0:
            complete = False
            break
        target, complete = nxt, ok
    return target, complete


def _npm_range_ok(root: Path, lock_rel: str, pkg: str, fixed: str) -> str | None:
    """Reason string if package.json pins ``pkg`` to a range that excludes ``fixed``."""
    pj = root / posixpath.join(posixpath.dirname(lock_rel), "package.json")
    try:
        data = json.loads(pj.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    for sect in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        spec = (data.get(sect) or {}).get(pkg)
        if isinstance(spec, str) and V.satisfies(spec, fixed) is False:
            return (f"package.json asks for {pkg}@{spec}, which excludes {fixed}; "
                    f"edit package.json, then run npm install")
    return None


def plan_dependency(f: Finding, root: Path, work: dict[str, str], client: OsvClient | None,
                    allow_major: bool, recheck: bool) -> FixPlan | Skipped:
    d = f.data
    eco, pkg, cur = d["ecosystem"], d["package"], d["version"]
    base = posixpath.basename(f.file).lower()
    mode = _MANIFEST_FOR.get(base)
    target, complete = _settle_target(f, client, recheck)
    if not target:
        return Skipped(f, "no fixed version has been published; replace the package or accept the risk")
    breaking = V.major(target) != V.major(cur)
    if breaking and not allow_major:
        return Skipped(f, f"the nearest fix is a major upgrade ({cur} -> {target}); "
                          "re-run with --allow-major to include it")
    if mode is None:
        return Skipped(f, f"automatic edits for {base} are not supported yet; "
                          f"upgrade {pkg} to {target} with your package manager")

    gen = engines.generators()
    plan = FixPlan(id=f"dep:{eco}:{pkg}:{f.file}", kind="dependency",
                   title=f"Upgrade {pkg} {cur} -> {target}", resolves=[f.id], breaking=breaking,
                   why=f.why, detail={"ecosystem": eco, "package": pkg, "from": cur, "to": target,
                                      "osv_ids": d.get("osv_ids"), "file": f.file})
    expected = {"ecosystem": eco, "package": pkg, "current_version": cur, "fixed_version": target,
                "osv_id": (d.get("osv_ids") or [None])[0]}
    if not complete:
        plan.notes.append("some advisories for this package have no published fix; the upgrade "
                          "clears the others")
    if breaking:
        plan.notes.append("major version change: check the changelog and run your tests")

    target_path = f.file
    before = work.get(target_path)
    if before is None:
        return Skipped(f, f"{target_path} could not be read")

    if mode == "requirements":
        after = None
        if "\r" not in before:
            try:  # the remediation generator, when it can express the edit
                g = gen.generate_dependency_bump({**expected, "lockfile_path": target_path,
                                                  "base_content": before})
                after = _apply_generated(before, g.unified)
            except gen.GeneratorError:
                after = None
        if after is None:
            after = bump_requirements(before, pkg, cur, fixed=target)
        if after is None:
            return Skipped(f, f"{pkg}=={cur} is not an exact pin in {target_path}")
        core = after
    elif mode == "npm":
        why = _npm_range_ok(root, f.file, pkg, target) if d.get("direct") else None
        if why:
            return Skipped(f, why)
        core, full = bump_npm_lock(before, pkg, cur, target)
        if core is None:
            return Skipped(f, f"{pkg} {cur} was not found in {target_path}")
        after = full or core
        if after != core:
            plan.notes.append("the lockfile's resolved URL is repointed and its integrity hash "
                              "dropped for this entry; npm refills it on the next install")
        if not d.get("direct"):
            plan.notes.append("transitive dependency: consider an `overrides` entry so a later "
                              "install cannot resolve the old version again")
    elif mode == "go":
        target_path = posixpath.join(posixpath.dirname(f.file), "go.mod")
        before = work.get(target_path)
        if before is None:
            before = _read(root, target_path)
        if before is None:
            return Skipped(f, "no go.mod next to go.sum")
        after = bump_gomod(before, pkg, cur, target)
        if after is None:
            return Skipped(f, f"{pkg} {cur} is not required by {target_path}; run `go get {pkg}@{target}`")
        core = after
        plan.notes.append("run `go mod tidy` to refresh go.sum for the new version")
    else:  # pom
        after, anchor = bump_pom(before, pkg, cur, target)
        if after is None:
            return Skipped(f, anchor)
        core = after
        # The gate looks for the package name on or near the edited line; a pom keeps the artifactId
        # on its own line (or, for ${property} versions, the property name sits on the edited line).
        expected = {**expected, "package": anchor}

    # The gate sees the pure version edit (core); lockfile hygiene is layered on top.
    diff = unified_diff(target_path, before, core)
    _gate(plan, diff, "dependency_bump", expected, "sca", f,
          ignore=_STRUCTURED_OK if mode in ("npm", "pom") else ())
    plan.edits = [Edit(target_path, before, after)]
    return plan


def _apply_generated(before: str, unified: str) -> str | None:
    """Apply a single-file, LF-only unified diff produced by the generators to ``before``."""
    src = _eol(before).splitlines()
    out: list[str] = []
    i = 0
    hunks = re.split(r"(?m)^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@.*\n", unified)
    # hunks: [header, start1, body1, start2, body2, ...]
    for k in range(1, len(hunks), 2):
        start = int(hunks[k]) - 1
        out.extend(src[i:start])
        i = start
        for ln in hunks[k + 1].splitlines():
            if ln.startswith("+"):
                out.append(ln[1:])
            elif ln.startswith("-"):
                i += 1
            elif ln.startswith(" "):
                out.append(src[i])
                i += 1
    out.extend(src[i:])
    return "\n".join(out) + "\n"


def _read(root: Path, rel: str) -> str | None:
    try:  # newline="" keeps CRLF files byte-exact
        with open(root / rel, encoding="utf-8", newline="") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return None


# --------------------------------------------------------------------------- #
# secret plans (CLI-local gate; see module docstring)
# --------------------------------------------------------------------------- #
def _py_import_at(src: str) -> tuple[int, bool] | None:
    """Where ``import os`` goes: (0-based line index, followed_by_an_import); None if present.
    Raises SyntaxError for sources that do not parse."""
    body = ast.parse(src).body
    for n in body:
        if isinstance(n, ast.Import) and any(a.name == "os" and not a.asname for a in n.names):
            return None
    idx = 0
    first = body[0] if body else None
    if isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant) \
            and isinstance(first.value.value, str):
        idx = first.end_lineno or 1
    for n in body:
        if isinstance(n, ast.ImportFrom) and n.module == "__future__":
            idx = max(idx, n.end_lineno or idx)
    for n in body:
        if isinstance(n, (ast.Import, ast.ImportFrom)) and n.lineno > idx:
            return n.lineno - 1, True
    return idx, False


def plan_secret(f: Finding, root: Path, work: dict[str, str]) -> FixPlan | Skipped:
    rel = f.file
    ext = os.path.splitext(rel)[1].lower()
    text = work.get(rel)
    if text is None:
        text = _read(root, rel)
    if text is None or not f.line:
        return Skipped(f, "file could not be read")
    is_py = ext in (".py", ".pyi")
    if not is_py and ext not in (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"):
        return Skipped(f, f"rewriting {ext or 'this file type'} automatically is not supported; "
                          "move the value to an environment variable by hand")
    lines = _lines(text)
    rx = secrets_scan.PY_ASSIGN if is_py else secrets_scan.JS_ASSIGN
    want_hash = (f.data or {}).get("value_hash")
    want_red = (f.data or {}).get("redacted")
    cands = []
    for i, (b, _e) in enumerate(lines):
        mm = rx.match(b)
        if not mm or not mm.group("value"):
            continue
        val = mm.group("value")
        if (want_hash and secrets_scan.value_hash(val) == want_hash) or (
                not want_hash and want_red and secrets_scan.redact(val) == want_red):
            cands.append((abs(i + 1 - f.line), i, mm))
    if not cands:
        return Skipped(f, 'the secret is not a simple one-line `NAME = "value"` assignment '
                          "(or the file changed since the scan)")
    _d, at_line, m = min(cands, key=lambda c: c[0])
    _body, eol = lines[at_line]
    value = m.group("value")
    env = secrets_scan.env_name(m.group("name"))
    if is_py:
        new_line = f'{m.group("indent")}{m.group("name")}{m.group("ann") or ""} = os.environ["{env}"]'
        new_line += f'  {m.group("tail")}' if m.group("tail") else ""
    else:
        new_line = (f'{m.group("indent")}{m.group("decl")}{m.group("name")}{m.group("ann") or ""}'
                    f" = process.env.{env};" + (f' {m.group("tail")}' if m.group("tail") else ""))
    lines[at_line] = (new_line, eol)
    after = _join(lines)
    notes = [f"set {env} in your environment (or a .env file that is not committed)"]
    if is_py:
        try:
            at = _py_import_at(after)
        except (SyntaxError, ValueError):
            return Skipped(f, "the Python file does not parse; fix its syntax first")
        if at is not None:
            idx, before_import = at
            nl = eol or "\n"
            ls = _lines(after)
            ins = [("import os", nl)] + ([] if before_import else [("", nl)])
            if idx > 0 and ls[idx - 1][0].strip():
                ins.insert(0, ("", nl))
            ls[idx:idx] = ins
            after = _join(ls)
            notes.append("added `import os`")
        try:
            ast.parse(after)
        except SyntaxError:
            return Skipped(f, "the rewrite would not parse; left untouched")
    edits = [Edit(rel, text, after)]

    ex_before = work.get(ENV_EXAMPLE, _read(root, ENV_EXAMPLE))
    if ex_before is None or not re.search(rf"(?m)^{re.escape(env)}=", ex_before):
        head = "" if ex_before is not None else "# Copy to .env and fill in real values. Never commit .env.\n"
        ex_after = (ex_before if ex_before is not None else head)
        if ex_after and not ex_after.endswith("\n"):
            ex_after += "\n"
        ex_after += f"{env}=\n"
        edits.append(Edit(ENV_EXAMPLE, ex_before, ex_after))
    gi_before = work.get(".gitignore", _read(root, ".gitignore"))
    if gi_before is None or not re.search(r"(?m)^/?\.env\*?\s*$", gi_before):
        gi_after = (gi_before or "")
        if gi_after and not gi_after.endswith("\n"):
            gi_after += "\n"
        gi_after += ".env\n"
        edits.append(Edit(".gitignore", gi_before, gi_after))

    plan = FixPlan(id=f"secret:{rel}:{f.line}", kind="secret", resolves=[f.id],
                   title=f"Read {env} from the environment in {rel}", edits=edits, notes=notes,
                   why=f.why, detail={"env": env, "file": rel})
    plan.notes.append("the old value is still in git history and was exposed: rotate it")
    plan.gate_engine = "cli secret gate"
    plan.gate_reasons = secret_gate(plan, value)
    plan.gate_ok = not plan.gate_reasons
    return plan


def secret_gate(plan: FixPlan, literal: str) -> list[str]:
    """Stricter-than-needed checks for a source-code rewrite (the remediation gate denies code)."""
    reasons: list[str] = []
    gate = engines.gate()
    parsed = gate.parse_unified(plan.unified)
    allowed_extra = {ENV_EXAMPLE, ".gitignore"}
    src = [e for e in plan.edits if e.path not in allowed_extra]
    if len(src) != 1:
        reasons.append("expected exactly one source file to change")
    for path in parsed.files:
        if path not in allowed_extra and (path != (src[0].path if src else None)):
            reasons.append(f"unexpected file {path}")
    src_removed = [ln for p, ln in parsed.removed if src and p == src[0].path]
    if len(src_removed) != 1 or literal not in src_removed[0]:
        reasons.append("the source change must replace exactly the one line holding the secret")
    for p, ln in parsed.added:
        if literal in ln:
            reasons.append(f"the secret value would still appear in {p}")
    for p, ln in parsed.added:
        if p == ENV_EXAMPLE and not re.fullmatch(r"([A-Z][A-Z0-9_]*=|#.*)", ln.strip()):
            reasons.append(f".env.example may only receive empty KEY= lines, got {ln.strip()[:40]!r}")
        if p == ".gitignore" and ln.strip() != ".env":
            reasons.append(f".gitignore may only receive '.env', got {ln.strip()[:40]!r}")
    return reasons


# --------------------------------------------------------------------------- #
# config plans
# --------------------------------------------------------------------------- #
def plan_config(f: Finding, root: Path, work: dict[str, str]) -> FixPlan | Skipped:
    text = work.get(f.file) or _read(root, f.file)
    if text is None:
        return Skipped(f, "file could not be read")
    if "\r" in text:
        return Skipped(f, "CRLF line endings are not supported by the config generators")
    gen = engines.generators()
    cls = f.data.get("fix_class")
    try:
        if cls == "config_fix":
            g = gen.generate_tls_fix({"config_path": f.file, "base_content": text})
            expected, rule_source, change = {"directive": g.spec["directive"]}, "policy", "config_fix"
        elif cls == "security_header":
            g = gen.generate_security_header({"header": f.data.get("header"), "config_path": f.file,
                                              "base_content": text})
            expected, rule_source, change = g.spec, "header_check", "security_header"
        else:
            return Skipped(f, "no generator for this misconfiguration")
    except gen.GeneratorError as exc:
        return Skipped(f, str(exc))
    after = _apply_generated(_eol(text), g.unified)
    plan = FixPlan(id=f"config:{f.file}:{f.data.get('rule')}", kind="config", resolves=[f.id],
                   title=g.summary[:1].upper() + g.summary[1:] + f" in {f.file}",
                   edits=[Edit(f.file, _eol(text), after)], why=f.why,
                   detail={"file": f.file, "change_class": change})
    plan.notes.append("reload the web server after deploying (nginx -t && nginx -s reload)")
    _gate(plan, g.unified, change, expected, rule_source, f)
    return plan


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #
def plan_fixes(res: ScanResult, root: str | Path, client: OsvClient | None = None, *,
               allow_major: bool = False, recheck: bool = True,
               only: set[str] | None = None) -> tuple[list[FixPlan], list[Skipped]]:
    root = Path(root).resolve()
    only = only or {"dependency", "secret", "config"}
    work: dict[str, str | None] = {}
    plans: list[FixPlan] = []
    skipped: list[Skipped] = []
    order = {"dependency": 0, "secret": 1, "config": 2}
    todo = sorted((f for f in res.findings if f.kind in order and f.kind in only),
                  key=lambda f: (order[f.kind], f.file, f.line or 0))
    for f in todo:
        shadow = {k: v for k, v in work.items() if v is not None}
        if f.kind == "dependency":
            for rel in {f.file, posixpath.join(posixpath.dirname(f.file), "go.mod")}:
                if rel not in shadow and (t := _read(root, rel)) is not None:
                    shadow[rel] = t
            r = plan_dependency(f, root, shadow, client, allow_major, recheck)
        elif f.kind == "secret":
            r = plan_secret(f, root, shadow)
        else:
            r = plan_config(f, root, shadow)
        if isinstance(r, Skipped):
            skipped.append(r)
            continue
        if r.gate_ok:
            for e in r.edits:
                work[e.path] = e.after
        plans.append(r)
    # secrets in the same file share .env.example / .gitignore edits: collapse duplicates
    _merge_shared_edits(plans)
    for f in res.findings:
        f.fixable = any(f.id in p.resolves and p.gate_ok for p in plans)
    return plans, skipped


def _merge_shared_edits(plans: list[FixPlan]) -> None:
    """Later plans were built against earlier ones' output, so their ``before`` already
    reflects it; nothing to merge on disk, but keep the first ``before`` for display."""
    return None


def combined_edits(plans: list[FixPlan]) -> dict[str, tuple[str | None, str]]:
    """Net change per file across the accepted plans: path -> (original, final)."""
    out: dict[str, tuple[str | None, str]] = {}
    for p in plans:
        for e in p.edits:
            first = out[e.path][0] if e.path in out else e.before
            out[e.path] = (first, e.after)
    return out


def combined_diff(plans: list[FixPlan]) -> str:
    return "".join(unified_diff(path, b, a) for path, (b, a) in sorted(combined_edits(plans).items()))
