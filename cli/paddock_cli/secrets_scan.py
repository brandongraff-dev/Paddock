"""Secret detection (CLI-local).

The codeanalysis engine already flags hard-coded credentials assigned to
secret-looking names in source. This adds what a repo-wide scan needs on top:
well-known token formats in *any* text file (AWS, GitHub, Slack, Stripe, Google,
npm, private-key blocks) and ``name = "value"`` assignments in configuration
files. Values are never printed or uploaded; only a redacted preview and a hash.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass
from typing import Iterator

_TOKEN_RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("aws-access-key-id", "AWS access key ID", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", "GitHub token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("github-fine-grained-pat", "GitHub fine-grained token", "high",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("slack-token", "Slack token", "high", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("stripe-live-key", "Stripe live key", "high", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b")),
    ("google-api-key", "Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("npm-token", "npm access token", "high", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("private-key", "Private key", "critical", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
]

_GENERIC = re.compile(
    r"""(?ix)
    (?P<name>[\w.\-]*(?:password|passwd|secret|api[_\-]?key|token|private[_\-]?key|access[_\-]?key)[\w.\-]*)
    (?P<sep>\s*[:=]\s*)
    (?P<q>["'])(?P<value>[^"'\s]{8,})(?P=q)""")

# generic name=value is only trusted in configuration-style files; source files go through SAST
_CONFIG_EXT = {".env", ".yml", ".yaml", ".json", ".properties", ".ini", ".cfg", ".conf", ".toml",
               ".sh", ".bash", ".tf", ".tfvars", ".xml", ".gradle", ".ps1"}
_CONFIG_NAMES = {"dockerfile", "docker-compose.yml", ".npmrc", ".pypirc", ".netrc"}
_SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "pipfile.lock",
               "cargo.lock", "gemfile.lock", "go.sum", "npm-shrinkwrap.json", "composer.lock"}
_PLACEHOLDER = re.compile(
    r"(?i)example|changeme|change_me|placeholder|your[_\-]|xxxx|<[^>]*>|\$\{|\{\{|%\(|dummy|sample|"
    r"redacted|\*{4,}|todo|fixme|^(true|false|null|none)$")


@dataclass
class SecretHit:
    rule: str
    label: str
    severity: str
    file: str
    line: int
    preview: str          # redacted
    value_hash: str       # sha256 prefix of the literal, for stable ids / dedupe
    var_name: str | None = None


def redact(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return "*" * len(v)
    return v[:4] + "*" * min(len(v) - 4, 12)


def value_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in freq.values())


def looks_secret(value: str) -> bool:
    """Not a placeholder, has both letters and digits, and some randomness."""
    if _PLACEHOLDER.search(value):
        return False
    return (len(value) >= 8 and any(c.isdigit() for c in value) and any(c.isalpha() for c in value)
            and _entropy(value) >= 2.8)


def _is_config_file(rel: str) -> bool:
    base = os.path.basename(rel).lower()
    if base in _CONFIG_NAMES or base.startswith(".env"):
        return True
    return os.path.splitext(base)[1] in _CONFIG_EXT


def _is_example_file(rel: str) -> bool:
    base = os.path.basename(rel).lower()
    return base.endswith((".example", ".sample", ".template", ".dist")) or ".example." in base


def scan_text(rel: str, text: str) -> Iterator[SecretHit]:
    base = os.path.basename(rel).lower()
    if base in _SKIP_NAMES or base.endswith((".min.js", ".svg", ".map")) or _is_example_file(rel):
        return
    config = _is_config_file(rel)
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            continue  # minified blobs
        seen_spans: list[tuple[int, int]] = []
        for rule, label, sev, rx in _TOKEN_RULES:
            for m in rx.finditer(line):
                if "EXAMPLE" in m.group(0).upper() and rule != "private-key":
                    continue  # the documented AWS sample keys, etc.
                seen_spans.append(m.span())
                yield SecretHit(rule, label, sev, rel, i, redact(m.group(0)) if rule != "private-key"
                                else "-----BEGIN ... PRIVATE KEY-----", value_hash(m.group(0)))
        if config:
            for m in _GENERIC.finditer(line):
                if any(s <= m.start("value") < e for s, e in seen_spans):
                    continue
                val = m.group("value")
                if not looks_secret(val):
                    continue
                yield SecretHit("generic-credential", "Hard-coded credential", "medium", rel, i,
                                redact(val), value_hash(val), m.group("name"))


# --- the one-line assignment shapes `paddock fix` knows how to rewrite ------- #

PY_ASSIGN = re.compile(
    r"""^(?P<indent>[ \t]*)(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P<ann>\s*:\s*[^=]+?)?\s*=\s*
        (?P<q>["'])(?P<value>[^"'\\]*)(?P=q)\s*(?P<tail>\#.*)?$""", re.X)
JS_ASSIGN = re.compile(
    r"""^(?P<indent>[ \t]*)(?P<decl>(?:export\s+)?(?:const|let|var)\s+)(?P<name>[A-Za-z_$][\w$]*)
        (?P<ann>\s*:\s*[\w.<>\[\]| ]+)?\s*=\s*(?P<q>["'`])(?P<value>[^"'`\\$]*)(?P=q)\s*;?\s*(?P<tail>//.*)?$""",
    re.X)


def env_name(identifier: str) -> str:
    """``dbPassword`` / ``DB_PASSWORD`` / ``db-password`` -> ``DB_PASSWORD``."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", identifier)
    s = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_").upper()
    if not s or s[0].isdigit():
        s = "SECRET_" + s
    return s
