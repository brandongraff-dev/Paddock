"""Deterministic diff gate (THREAT-MODEL LAYER 3).

This is the hard boundary. A generated diff MUST pass every check here or it is
REJECTED. The gate is DETERMINISTIC and self-contained: it re-parses the actual
unified-diff text (the artifact a PR would apply) rather than trusting any
structured metadata or anything the LLM said. An LLM being present or absent
cannot change a single decision here.

Checks:
  1. Parse: the diff must be a non-empty, well-formed unified diff.
  2. File allowlist: every touched path must be allowed for the change class
     (lockfiles for a bump; web-server configs for header/config/dotfile).
  3. Hard denylist (ALWAYS, every class): never source code, never CI/
     .github/workflows, never secrets/dotenv/keys, never .git internals.
  4. Expected change only:
     * dependency_bump: every changed line is a version-string change for the
       target package to a version that EQUALS the OSV fixed_version verified
       against the DB (passed in as ``expected``), from the declared current
       version. Nothing else changes.
     * security_header / config_fix / dotfile_block: added lines must match the
       allowlisted directive template for the class; removals are bounded.
  5. Content safety on ADDED lines: no net-new network calls, no new scripts /
     shell, no eval/exec/curl|bash, no secrets.
  6. Size bounds: file count, changed-line count and byte size are capped.

``check(...)`` returns ``GateResult(ok, reasons, report)``; ``report`` is stored
in ``remediations.verifier_report['gate']``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------- #
# Allowlists / denylists
# --------------------------------------------------------------------------- #

# Per change class: the set of basenames (or suffix rules) a diff may touch.
_BUMP_LOCKFILES = frozenset({
    "requirements.txt", "requirements.in", "package-lock.json", "npm-shrinkwrap.json",
    "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "pipfile.lock",
    "go.mod", "go.sum", "cargo.toml", "cargo.lock", "gemfile.lock", "pom.xml",
})
_CONFIG_SUFFIXES = (".conf",)
_CONFIG_BASENAMES = frozenset({"nginx.conf", "default.conf", ".htaccess", "httpd.conf"})

ALLOWED_FILES: dict[str, Any] = {
    "dependency_bump": ("lockfile", _BUMP_LOCKFILES),
    "security_header": ("config", None),
    "config_fix": ("config", None),
    "tls_fix": ("config", None),
    "dotfile_block": ("config", None),
}

# Hard denylist — a touched path matching ANY of these fails regardless of class.
_SOURCE_SUFFIXES = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".java",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".php", ".rs", ".sh", ".bash",
    ".ps1", ".pl", ".lua", ".kt", ".scala", ".swift", ".sql",
)
_SECRET_MARKERS = (
    ".env", ".pem", ".key", ".p12", ".pfx", ".keystore", "id_rsa", "id_ed25519",
    "credentials", "secret", "secrets", ".npmrc", ".pypirc", ".netrc", ".htpasswd",
)
_CI_MARKERS = (
    ".github/workflows/", ".github/actions/", ".gitlab-ci.yml", "jenkinsfile",
    ".circleci/", "azure-pipelines", ".drone.yml", "bitbucket-pipelines",
    ".git/", ".gitattributes", "dockerfile", "makefile",
)

# Content-safety: ADDED lines must not introduce these.
_UNSAFE_CONTENT = [
    ("network_call", re.compile(r"\b(curl|wget|nc|ncat|netcat|ssh|scp|rsync|ftp)\b", re.I)),
    ("network_call", re.compile(r"https?://|ftp://|\bfetch\s*\(|\bXMLHttpRequest\b", re.I)),
    ("shell_pipe", re.compile(r"\|\s*(bash|sh|zsh|python|perl|ruby)\b", re.I)),
    ("code_exec", re.compile(r"\beval\s*\(|\bexec\s*\(|\b__import__\b|\bsystem\s*\(|\bpopen\b", re.I)),
    ("code_exec", re.compile(r"child_process|subprocess|os\.system|/bin/(ba)?sh", re.I)),
    ("install_hook", re.compile(r'"(preinstall|postinstall|install|prepare)"\s*:', re.I)),
    ("secret", re.compile(r"(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bbearer\s+[A-Za-z0-9._\-]{20,})", re.I)),
    ("template_inj", re.compile(r"\$\([^)]*\)|`[^`]*`|\$\{\{"), ),
]

# Per-class: ADDED lines must match ONE of these templates. (dependency_bump is
# handled specially by exact version comparison.)
_DIRECTIVE_WHITELIST: dict[str, list[re.Pattern[str]]] = {
    "security_header": [re.compile(r'^\s*add_header\s+[A-Za-z0-9\-]+\s+"[^"\n]*"\s*(always\s*)?;\s*$')],
    "config_fix": [re.compile(r"^\s*ssl_protocols\s+[A-Za-z0-9.\s]+;\s*$")],
    "tls_fix": [re.compile(r"^\s*ssl_protocols\s+[A-Za-z0-9.\s]+;\s*$")],
    "dotfile_block": [re.compile(r"^\s*location\s+~\s+/\\\.\S.*\{\s*deny\s+all;\s*return\s+404;\s*\}\s*$")],
}


@dataclass
class GateResult:
    ok: bool
    reasons: list[str] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "reasons": self.reasons, **self.report}


@dataclass
class ParsedDiff:
    files: list[str]
    added: list[tuple[str, str]]     # (path, line) without leading '+'
    removed: list[tuple[str, str]]   # (path, line) without leading '-'
    hunks: int


def parse_unified(diff_text: str) -> ParsedDiff:
    """Parse a unified diff into touched files and +/- content lines.

    Robust to git-style ``a/``/``b/`` prefixes and ``diff --git`` headers. Only
    content lines (not the +++/--- headers) are collected.
    """
    files: list[str] = []
    added: list[tuple[str, str]] = []
    removed: list[tuple[str, str]] = []
    hunks = 0
    current: str | None = None
    for raw in (diff_text or "").splitlines():
        if raw.startswith("diff --git"):
            continue
        if raw.startswith("+++ "):
            current = _strip_path(raw[4:])
            if current and current != "/dev/null" and current not in files:
                files.append(current)
            continue
        if raw.startswith("--- "):
            p = _strip_path(raw[4:])
            if p and p != "/dev/null" and p not in files:
                files.append(p)
            continue
        if raw.startswith("@@"):
            hunks += 1
            continue
        if raw.startswith("+"):
            added.append((current or "?", raw[1:]))
        elif raw.startswith("-"):
            removed.append((current or "?", raw[1:]))
    return ParsedDiff(files=files, added=added, removed=removed, hunks=hunks)


def _strip_path(token: str) -> str:
    token = token.strip().split("\t", 1)[0].strip()
    for pre in ("a/", "b/"):
        if token.startswith(pre):
            return token[len(pre):]
    return token


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1].lower()


def _is_denied_path(path: str) -> str | None:
    low = path.lower()
    base = _basename(path)
    for marker in _CI_MARKERS:
        if marker in low:
            return f"CI/build/vcs file ({marker})"
    for marker in _SECRET_MARKERS:
        if marker in base or low.endswith(marker):
            return f"secrets/credentials file ({marker})"
    for suf in _SOURCE_SUFFIXES:
        if low.endswith(suf):
            return f"source-code file ({suf})"
    return None


def _file_allowed(change_class: str, path: str) -> str | None:
    """Return None if allowed, else a reason string."""
    denied = _is_denied_path(path)
    if denied:
        return f"touches a forbidden {denied}"
    rule = ALLOWED_FILES.get(change_class)
    if rule is None:
        return f"unknown change class {change_class!r}"
    kind, allow = rule
    base = _basename(path)
    if kind == "lockfile":
        if base not in allow:
            return f"{base!r} is not an allowed lockfile for a dependency bump"
        return None
    if kind == "config":
        if base in _CONFIG_BASENAMES or base.endswith(_CONFIG_SUFFIXES):
            return None
        return f"{base!r} is not an allowed web-server config file"
    return "unhandled allowlist rule"  # pragma: no cover


_VERSION_TOKEN = re.compile(r"[0-9][0-9A-Za-z.\-+_]*")


def _check_dependency_bump(
    parsed: ParsedDiff, expected: dict[str, Any], diff_text: str = ""
) -> list[str]:
    """Every changed line must move the target package's version from the
    declared current version to EXACTLY the DB-confirmed fixed_version."""
    reasons: list[str] = []
    pkg = str(expected.get("package") or "")
    cur = str(expected.get("current_version") or "")
    fixed = str(expected.get("fixed_version") or "")
    if not (pkg and cur and fixed):
        return ["dependency_bump gate: missing expected package/current/fixed (DB spec)"]
    if fixed == cur:
        return ["dependency_bump gate: fixed_version equals current_version"]

    # The removed lines must mention the current version; the added lines must
    # mention the fixed version and NOT the current one. The fixed version is
    # taken from the DB spec, never from the diff/model.
    for path, line in parsed.removed:
        toks = set(_VERSION_TOKEN.findall(line))
        if cur not in toks and cur not in line:
            reasons.append(f"removed line does not reference current version {cur!r}: {line.strip()[:60]!r}")
    for path, line in parsed.added:
        if fixed not in line:
            reasons.append(f"added line does not set fixed_version {fixed!r}: {line.strip()[:60]!r}")
            continue
        # The added line must NOT still carry the vulnerable current version
        # (would mean we didn't actually bump, or bumped something else).
        toks = _VERSION_TOKEN.findall(line)
        if cur in toks and cur != fixed:
            reasons.append(f"added line still contains vulnerable version {cur!r}: {line.strip()[:60]!r}")
    # The package name must appear in the diff. For flat manifests
    # (requirements.txt) it is on the changed line; for structured lockfiles
    # (package-lock.json) the version line has no name, so the name is on an
    # adjacent context line within the same hunk — accept either.
    region = (" ".join(l for _, l in parsed.added + parsed.removed) + " " + diff_text).lower()
    if pkg.lower() not in region:
        reasons.append(f"changed lines do not mention target package {pkg!r}")
    return reasons


def _check_directive_class(change_class: str, parsed: ParsedDiff) -> list[str]:
    """For header/config/dotfile: every ADDED line must match an allowlisted
    directive template; removals are bounded to replaced directives."""
    reasons: list[str] = []
    patterns = _DIRECTIVE_WHITELIST.get(change_class, [])
    content_added = [l for _, l in parsed.added if l.strip()]
    if not content_added:
        reasons.append(f"{change_class}: no directive added")
    for line in content_added:
        if not any(p.match(line) for p in patterns):
            reasons.append(f"{change_class}: added line is not an allowlisted directive: {line.strip()[:70]!r}")
    # Removals allowed only for config_fix/tls_fix (replacing the weak protocol
    # line); header/dotfile should be pure additions.
    if change_class in ("security_header", "dotfile_block"):
        content_removed = [l for _, l in parsed.removed if l.strip()]
        if content_removed:
            reasons.append(f"{change_class}: unexpected line removals ({len(content_removed)})")
    return reasons


def _check_content_safety(parsed: ParsedDiff, change_class: str) -> list[str]:
    reasons: list[str] = []
    for path, line in parsed.added:
        for category, rx in _UNSAFE_CONTENT:
            # Allow the install-hook / template patterns to be scanned, but a
            # dependency bump legitimately edits JSON that never adds scripts.
            if rx.search(line):
                # ssl_protocols / add_header lines are safe config; the network
                # regex (https?://) would false-positive on a CSP value, so skip
                # the network_call check for the directive classes' header value.
                if category == "network_call" and change_class in (
                    "security_header", "config_fix", "tls_fix", "dotfile_block"
                ):
                    continue
                reasons.append(f"added line introduces {category}: {line.strip()[:70]!r}")
    return reasons


def check(
    diff_text: str,
    change_class: str,
    expected: dict[str, Any] | None = None,
    *,
    max_files: int = 2,
    max_changed_lines: int = 40,
    max_bytes: int = 8192,
) -> GateResult:
    expected = expected or {}
    reasons: list[str] = []

    if not diff_text or not diff_text.strip():
        return GateResult(False, ["empty diff"], {"gate": "empty"})

    if len(diff_text.encode("utf-8", "ignore")) > max_bytes:
        reasons.append(f"diff exceeds {max_bytes} bytes")

    parsed = parse_unified(diff_text)
    if not parsed.files:
        return GateResult(False, ["diff touches no recognizable files"], {})
    if parsed.hunks == 0 or (not parsed.added and not parsed.removed):
        return GateResult(False, ["diff has no changed lines"], {})

    # 2+3. File allowlist / denylist.
    if len(parsed.files) > max_files:
        reasons.append(f"diff touches {len(parsed.files)} files (max {max_files})")
    for path in parsed.files:
        why = _file_allowed(change_class, path)
        if why:
            reasons.append(f"path {path!r}: {why}")

    # size
    changed = len(parsed.added) + len(parsed.removed)
    if changed > max_changed_lines:
        reasons.append(f"diff changes {changed} lines (max {max_changed_lines})")

    # 4. Expected change only.
    if change_class == "dependency_bump":
        reasons.extend(_check_dependency_bump(parsed, expected, diff_text))
    elif change_class in ("security_header", "config_fix", "tls_fix", "dotfile_block"):
        reasons.extend(_check_directive_class(change_class, parsed))
    else:
        reasons.append(f"unknown change class {change_class!r}")

    # 5. Content safety.
    reasons.extend(_check_content_safety(parsed, change_class))

    report = {
        "gate": "deterministic",
        "change_class": change_class,
        "files": parsed.files,
        "added_lines": len(parsed.added),
        "removed_lines": len(parsed.removed),
        "hunks": parsed.hunks,
        "bytes": len(diff_text.encode("utf-8", "ignore")),
        "expected": {
            k: expected.get(k)
            for k in ("package", "current_version", "fixed_version", "osv_id", "header", "directive")
            if k in expected
        },
    }
    ok = not reasons
    return GateResult(ok=ok, reasons=reasons, report=report)
