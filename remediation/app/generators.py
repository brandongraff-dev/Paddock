"""Deterministic diff generators + templates (THREAT-MODEL LAYER 2).

The LLM NEVER writes free-form code. For each allowlisted change class, the
actual unified diff is produced HERE, by code, from VALIDATED parameters that
originate in the database (the OSV-confirmed fixed_version, the finding's
change class), not from the model and not from attacker-influenceable finding
text. The LLM may, at most, write a prose *explanation* for the PR body.

Change classes (narrow by design):
  * dependency_bump  — bump a package from version A -> B where B EQUALS the
    OSV ``sbom_component_vulns.fixed_version`` for the affected component. The
    only touched file is the ecosystem's lockfile/manifest.
  * security_header  — add ONE missing security header directive to a web
    server config (CSP / HSTS / X-Frame-Options / ...).
  * config_fix / tls_fix — pin ``ssl_protocols`` to safe versions (disable
    TLS1.0/1.1) in a web server config.
  * dotfile_block    — add a web-server rule that blocks access to /.git and
    friends.

Each generator returns a :class:`GeneratedDiff`: the unified diff text (what
goes into ``remediations.diff`` and what a PR would apply) plus a structured
spec the gate and verifier cross-check. The diff is computed with ``difflib``
from a before/after pair, so it is a real, parseable unified diff.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------- #
# Ecosystem -> lockfile/manifest that a dependency_bump is allowed to touch.
# --------------------------------------------------------------------------- #
ECOSYSTEM_LOCKFILE: dict[str, str] = {
    "pypi": "requirements.txt",
    "python": "requirements.txt",
    "npm": "package-lock.json",
    "node": "package-lock.json",
    "go": "go.mod",
    "crates.io": "Cargo.toml",
    "rust": "Cargo.toml",
    "rubygems": "Gemfile.lock",
    "maven": "pom.xml",
}

# The security-header templates. Keyed by a normalized header name; the VALUE is
# the exact directive line we are allowed to add. This is the allowlist: only
# these canonical, safe directives may ever be emitted.
SECURITY_HEADER_TEMPLATES: dict[str, str] = {
    "strict-transport-security":
        'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;',
    "content-security-policy":
        "add_header Content-Security-Policy \"default-src 'self'\" always;",
    "x-frame-options":
        'add_header X-Frame-Options "DENY" always;',
    "x-content-type-options":
        'add_header X-Content-Type-Options "nosniff" always;',
    "referrer-policy":
        'add_header Referrer-Policy "no-referrer" always;',
    "permissions-policy":
        'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
}

# The dotfile-block template: deny access to VCS/dotfiles at the web server.
DOTFILE_BLOCK_TEMPLATE = "location ~ /\\.(?!well-known) { deny all; return 404; }"

# The safe TLS protocol pin (config_fix / tls_fix).
TLS_PROTOCOLS_SAFE = "ssl_protocols TLSv1.2 TLSv1.3;"

DEFAULT_CONFIG_PATH = "nginx.conf"


class GeneratorError(ValueError):
    """Raised when a diff cannot be generated deterministically (e.g. the
    required DB-sourced facts are missing/ambiguous). The pipeline turns this
    into a clean ``rejected`` — never a half-built patch."""


@dataclass
class GeneratedDiff:
    change_class: str
    path: str
    unified: str
    summary: str
    # Structured, DB-sourced facts the gate & verifier cross-check against the
    # actual diff. Never sourced from the model.
    spec: dict[str, Any] = field(default_factory=dict)
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "change_class": self.change_class,
            "path": self.path,
            "summary": self.summary,
            "spec": self.spec,
            "added": self.added,
            "removed": self.removed,
        }


def _unified(path: str, before: str, after: str) -> str:
    """Build a real unified diff (git-style a/ b/ paths) from before/after."""
    before_lines = before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)
    if before_lines and not before_lines[-1].endswith("\n"):
        before_lines[-1] += "\n"
    if after_lines and not after_lines[-1].endswith("\n"):
        after_lines[-1] += "\n"
    diff = difflib.unified_diff(
        before_lines, after_lines,
        fromfile=f"a/{path}", tofile=f"b/{path}", n=3,
    )
    return "".join(diff)


def _changed_lines(before: str, after: str) -> tuple[list[str], list[str]]:
    sm = difflib.SequenceMatcher(
        a=before.splitlines(), b=after.splitlines(), autojunk=False
    )
    removed: list[str] = []
    added: list[str] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "delete"):
            removed.extend(before.splitlines()[i1:i2])
        if tag in ("replace", "insert"):
            added.extend(after.splitlines()[j1:j2])
    return removed, added


# --------------------------------------------------------------------------- #
# dependency_bump
# --------------------------------------------------------------------------- #

def generate_dependency_bump(spec: dict[str, Any]) -> GeneratedDiff:
    """Bump ``package`` from ``current_version`` -> ``fixed_version``.

    ``spec`` MUST carry DB-sourced facts:
      ecosystem, package, current_version, fixed_version   (required)
      lockfile_path, base_content                          (optional)

    ``fixed_version`` is the OSV-confirmed ``sbom_component_vulns.fixed_version``
    resolved from the database by the pipeline — NOT from the model and NOT from
    finding text. The gate independently re-verifies the emitted version against
    this same DB value.
    """
    ecosystem = str(spec.get("ecosystem") or "").strip().lower()
    package = str(spec.get("package") or "").strip()
    current = str(spec.get("current_version") or "").strip()
    fixed = str(spec.get("fixed_version") or "").strip()

    if not package:
        raise GeneratorError("dependency_bump: missing package name")
    if not current:
        raise GeneratorError("dependency_bump: missing current version")
    if not fixed:
        raise GeneratorError("dependency_bump: no OSV fixed_version for this vuln")
    if fixed == current:
        raise GeneratorError("dependency_bump: fixed_version equals current version")
    # Package names must be well-formed — a crafted package name is an attack.
    if not _safe_package_name(package):
        raise GeneratorError(f"dependency_bump: unsafe package name {package!r}")
    if not (_safe_version(current) and _safe_version(fixed)):
        raise GeneratorError("dependency_bump: unsafe version string")

    path = str(spec.get("lockfile_path") or ECOSYSTEM_LOCKFILE.get(ecosystem) or "")
    if not path:
        raise GeneratorError(f"dependency_bump: unknown ecosystem {ecosystem!r}")

    base = spec.get("base_content")
    basename = path.rsplit("/", 1)[-1]

    if basename == "requirements.txt":
        before, after = _bump_requirements(package, current, fixed, base)
    elif basename == "package-lock.json":
        before, after = _bump_npm_lock(package, current, fixed, base)
    else:
        # Generic "name <sep> version" manifests (go.mod, Cargo.toml, ...).
        before, after = _bump_generic(package, current, fixed, base)

    if before == after:
        raise GeneratorError(
            f"dependency_bump: {package} {current} not found in {basename}")

    unified = _unified(path, before, after)
    removed, added = _changed_lines(before, after)
    return GeneratedDiff(
        change_class="dependency_bump",
        path=path,
        unified=unified,
        summary=f"bump {package} {current} -> {fixed} ({basename})",
        spec={
            "ecosystem": ecosystem,
            "package": package,
            "current_version": current,
            "fixed_version": fixed,
            "osv_id": spec.get("osv_id"),
            "cve_id": spec.get("cve_id"),
        },
        added=added,
        removed=removed,
    )


def _bump_requirements(pkg: str, cur: str, fixed: str, base: Any) -> tuple[str, str]:
    if isinstance(base, str) and base.strip():
        before = base if base.endswith("\n") else base + "\n"
    else:
        before = f"{pkg}=={cur}\n"
    after_lines: list[str] = []
    for line in before.splitlines():
        stripped = line.strip()
        if _req_matches(stripped, pkg, cur):
            after_lines.append(line.replace(f"=={cur}", f"=={fixed}"))
        else:
            after_lines.append(line)
    return before, "\n".join(after_lines) + "\n"


def _req_matches(line: str, pkg: str, cur: str) -> bool:
    low = line.lower()
    return low.startswith(pkg.lower() + "==") and line.strip().endswith("==" + cur)


def _bump_npm_lock(pkg: str, cur: str, fixed: str, base: Any) -> tuple[str, str]:
    import json

    if isinstance(base, str) and base.strip():
        before = base if base.endswith("\n") else base + "\n"
        try:
            obj = json.loads(base)
        except Exception as exc:
            raise GeneratorError(f"dependency_bump: package-lock.json invalid JSON: {exc}")
    else:
        obj = {
            "name": "app",
            "lockfileVersion": 3,
            "packages": {f"node_modules/{pkg}": {"version": cur}},
            "dependencies": {pkg: {"version": cur}},
        }
        before = json.dumps(obj, indent=2) + "\n"

    found = _npm_set_version(obj, pkg, cur, fixed)
    if not found:
        return before, before  # no change -> caller raises
    after = json.dumps(obj, indent=2) + "\n"
    return before, after


def _npm_set_version(obj: Any, pkg: str, cur: str, fixed: str) -> bool:
    found = False
    pkgs = obj.get("packages") if isinstance(obj, dict) else None
    if isinstance(pkgs, dict):
        for key in (f"node_modules/{pkg}", pkg):
            entry = pkgs.get(key)
            if isinstance(entry, dict) and str(entry.get("version")) == cur:
                entry["version"] = fixed
                found = True
    deps = obj.get("dependencies") if isinstance(obj, dict) else None
    if isinstance(deps, dict):
        entry = deps.get(pkg)
        if isinstance(entry, dict) and str(entry.get("version")) == cur:
            entry["version"] = fixed
            found = True
    return found


def _bump_generic(pkg: str, cur: str, fixed: str, base: Any) -> tuple[str, str]:
    if isinstance(base, str) and base.strip():
        before = base if base.endswith("\n") else base + "\n"
    else:
        before = f"{pkg} {cur}\n"
    after = before.replace(cur, fixed)  # version token swap, context-preserving
    return before, after


def _safe_package_name(name: str) -> bool:
    import re
    # Allow scoped npm (@scope/name), extras, and common ecosystem characters.
    return bool(re.fullmatch(r"@?[A-Za-z0-9][A-Za-z0-9._/\-]{0,100}", name))


def _safe_version(v: str) -> bool:
    import re
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-+_]{0,60}", v))


# --------------------------------------------------------------------------- #
# security_header
# --------------------------------------------------------------------------- #

def generate_security_header(spec: dict[str, Any]) -> GeneratedDiff:
    """Add ONE missing, allowlisted security-header directive to a web config."""
    header = _normalize_header(spec.get("header"))
    if header not in SECURITY_HEADER_TEMPLATES:
        raise GeneratorError(f"security_header: no template for header {spec.get('header')!r}")
    directive = SECURITY_HEADER_TEMPLATES[header]
    path = str(spec.get("config_path") or DEFAULT_CONFIG_PATH)
    base = spec.get("base_content")
    before, after = _insert_into_server_block(path, base, directive)
    if before == after:
        raise GeneratorError("security_header: directive already present")
    unified = _unified(path, before, after)
    removed, added = _changed_lines(before, after)
    return GeneratedDiff(
        change_class="security_header",
        path=path,
        unified=unified,
        summary=f"add {header} header",
        spec={"header": header, "directive": directive},
        added=added,
        removed=removed,
    )


def _normalize_header(raw: Any) -> str:
    return str(raw or "").strip().lower()


# --------------------------------------------------------------------------- #
# config_fix / tls_fix
# --------------------------------------------------------------------------- #

def generate_tls_fix(spec: dict[str, Any]) -> GeneratedDiff:
    """Pin ``ssl_protocols`` to TLSv1.2 TLSv1.3 (disable TLS1.0/1.1)."""
    path = str(spec.get("config_path") or DEFAULT_CONFIG_PATH)
    base = spec.get("base_content")
    if isinstance(base, str) and base.strip():
        before = base if base.endswith("\n") else base + "\n"
        changed = False
        out: list[str] = []
        for line in before.splitlines():
            if line.strip().lower().startswith("ssl_protocols"):
                indent = line[: len(line) - len(line.lstrip())]
                out.append(indent + TLS_PROTOCOLS_SAFE)
                changed = True
            else:
                out.append(line)
        after = "\n".join(out) + "\n"
        if not changed:
            before, after = _insert_into_server_block(path, base, TLS_PROTOCOLS_SAFE)
    else:
        before = (
            "server {\n"
            "    listen 443 ssl;\n"
            "    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"
            "}\n"
        )
        after = before.replace(
            "    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n",
            "    " + TLS_PROTOCOLS_SAFE + "\n",
        )
    if before == after:
        raise GeneratorError("tls_fix: nothing to change")
    unified = _unified(path, before, after)
    removed, added = _changed_lines(before, after)
    return GeneratedDiff(
        change_class="config_fix",
        path=path,
        unified=unified,
        summary="disable TLS1.0/1.1 (pin ssl_protocols)",
        spec={"directive": TLS_PROTOCOLS_SAFE},
        added=added,
        removed=removed,
    )


# --------------------------------------------------------------------------- #
# dotfile_block
# --------------------------------------------------------------------------- #

def generate_dotfile_block(spec: dict[str, Any]) -> GeneratedDiff:
    """Add a web-server rule that blocks /.git and other dotfiles."""
    path = str(spec.get("config_path") or DEFAULT_CONFIG_PATH)
    base = spec.get("base_content")
    before, after = _insert_into_server_block(path, base, DOTFILE_BLOCK_TEMPLATE)
    if before == after:
        raise GeneratorError("dotfile_block: rule already present")
    unified = _unified(path, before, after)
    removed, added = _changed_lines(before, after)
    return GeneratedDiff(
        change_class="dotfile_block",
        path=path,
        unified=unified,
        summary="block web access to /.git and dotfiles",
        spec={"directive": DOTFILE_BLOCK_TEMPLATE},
        added=added,
        removed=removed,
    )


# --------------------------------------------------------------------------- #
# shared: insert a single directive inside the first server { } block
# --------------------------------------------------------------------------- #

def _insert_into_server_block(path: str, base: Any, directive: str) -> tuple[str, str]:
    if isinstance(base, str) and base.strip():
        before = base if base.endswith("\n") else base + "\n"
    else:
        before = "server {\n    listen 443 ssl;\n}\n"
    if directive in before:
        return before, before
    lines = before.splitlines()
    out: list[str] = []
    inserted = False
    for line in lines:
        out.append(line)
        if not inserted and line.rstrip().endswith("server {"):
            indent = line[: len(line) - len(line.lstrip())] + "    "
            out.append(indent + directive)
            inserted = True
    if not inserted:
        # No server block — append the directive on its own line (still a conf).
        out.append(directive)
    return before, "\n".join(out) + "\n"
