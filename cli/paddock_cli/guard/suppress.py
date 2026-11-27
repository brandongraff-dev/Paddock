# SPDX-License-Identifier: AGPL-3.0-or-later
"""Inline suppressions and the baseline file (contract 3.10, D13).

Inline: ``paddock:ignore <ID> <reason>`` inside a comment on the finding's line or the line
directly above; ``paddock:ignore-file <ID> <reason>`` in the first 10 lines. The reason must be
at least 8 characters. Checks that are not ``inline_suppressible`` ignore inline comments (the
comment lives in the file an attacker controls); the engine reports that in ``notes``.

Baseline: ``.paddock/baseline.json``, written only through ``files.safe_write``.
"""
from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass
from typing import Any

from paddock_cli.guard import files, gitutil, model, textsafe
from paddock_cli.guard.errors import GuardError
from paddock_cli.guard.files import FileView

MIN_REASON = 8
MAX_ENTRIES = 10000
MAX_BASELINE_BYTES = 4 * 1024 * 1024
BASELINE_REL = ".paddock/baseline.json"
PADDOCK_GITIGNORE = "cache/\nledger.jsonl*\nbackups/\n"
_OPENERS = ("#", "//", "--", "/*", "<!--")
_MARK = re.compile(r"paddock:ignore(-file)?[ \t]+(\S+)[ \t]*(.*)")
_MARK_BARE = re.compile(r"paddock:ignore(-file)?(?:\s|$)")
_ID = re.compile(r"^(?:PG-[A-Z]{3,4}-\d{3}|PGX-[A-Z0-9-]{3,40}-\d{3})$")
_FP = re.compile(r"^[0-9a-f]{16}$")
_LINE_CAP = 4000


@dataclass(frozen=True)
class Suppression:
    check_id: str
    line: int
    scope: str  # "line" | "file"
    reason: str


def _note(fv: FileView, line: int, why: str) -> str:
    return "%s: malformed suppression at %s:%d (%s); it is ignored" % (
        model.META_MALFORMED_SUPPRESSION, textsafe.safe_text(fv.path, cap=120), line, why)


def scan_suppressions(fv: FileView) -> tuple[list[Suppression], list[str]]:
    """Valid suppressions of one file and the ``PG-META-001`` notes for malformed ones."""
    sups: list[Suppression] = []
    notes: list[str] = []
    if "paddock:ignore" not in fv.text:
        return sups, notes
    for i, raw in enumerate(fv.raw_lines, start=1):
        if "paddock:ignore" not in raw:
            continue
        line = raw[:_LINE_CAP]
        idx = line.find("paddock:ignore")
        if idx < 0 or not any(o in line[:idx] for o in _OPENERS):
            continue  # not inside a comment
        m = _MARK.search(line)
        if m is None:
            if _MARK_BARE.search(line):
                notes.append(_note(fv, i, "no check id and reason"))
            continue
        is_file = bool(m.group(1))
        cid = m.group(2)
        reason = m.group(3).strip()
        for closer in ("-->", "*/"):
            if reason.endswith(closer):
                reason = reason[: -len(closer)].strip()
        if not _ID.match(cid):
            notes.append(_note(fv, i, "unknown check id format"))
            continue
        if len(reason) < MIN_REASON:
            notes.append(_note(fv, i, "reason must be at least %d characters" % MIN_REASON))
            continue
        if is_file and i > 10:
            notes.append(_note(fv, i, "ignore-file must be in the first 10 lines"))
            continue
        sups.append(Suppression(cid, i, "file" if is_file else "line",
                                textsafe.safe_text(reason, cap=200, escape=False)))
    return sups, notes


def match(sups: list[Suppression], check_id: str, line: int | None) -> Suppression | None:
    """The suppression covering a finding, if any (same line, the line above, or file scope)."""
    for s in sups:
        if s.check_id != check_id:
            continue
        if s.scope == "file":
            return s
        if line is not None and s.line in (line, line - 1):
            return s
    return None


# ---- baseline ---------------------------------------------------------------------------------
@dataclass(frozen=True)
class BaselineEntry:
    fingerprint: str
    check_id: str
    file: str
    reason: str


@dataclass
class Baseline:
    created: str
    entries: list[BaselineEntry]

    @property
    def fingerprints(self) -> set[str]:
        return {e.fingerprint for e in self.entries}


def _today() -> str:
    return datetime.date.today().isoformat()


def create_baseline(findings: list[Any], *, today: str | None = None,
                    reason: str = "adopted when the baseline was created") -> Baseline:
    seen: set[str] = set()
    entries: list[BaselineEntry] = []
    for f in sorted(findings, key=lambda x: (x.file, x.check_id, x.fingerprint)):
        if f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        entries.append(BaselineEntry(
            f.fingerprint, textsafe.safe_text(f.check_id, cap=60, escape=False),
            textsafe.safe_text(f.file, cap=300, escape=False), textsafe.safe_text(reason, cap=200, escape=False)))
    return Baseline(today or _today(), entries)


def update_baseline(existing: Baseline, findings: list[Any]) -> Baseline:
    """Drop entries that no longer match a current finding; never adds one."""
    live = {f.fingerprint for f in findings}
    return Baseline(existing.created, [e for e in existing.entries if e.fingerprint in live])


def baseline_json(b: Baseline) -> str:
    return json.dumps({
        "schema": model.SCHEMA_BASELINE, "created": b.created,
        "entries": [{"fingerprint": e.fingerprint, "check_id": e.check_id, "file": e.file, "reason": e.reason}
                    for e in b.entries],
    }, indent=2) + "\n"


def parse_baseline(text: str) -> tuple[Baseline | None, str | None]:
    """Parse and validate baseline JSON; returns (baseline, problem)."""
    if len(text) > MAX_BASELINE_BYTES:
        return None, "larger than %d MB" % (MAX_BASELINE_BYTES // (1024 * 1024))
    try:
        doc = textsafe.loads_bounded(text)
    except ValueError:
        return None, "not valid JSON or nested too deeply"
    if not isinstance(doc, dict) or doc.get("schema") != model.SCHEMA_BASELINE:
        return None, "unknown schema"
    entries = doc.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        return None, "entries must be a list of at most %d" % MAX_ENTRIES
    out: list[BaselineEntry] = []
    for e in entries:
        if not isinstance(e, dict):
            return None, "entry is not an object"
        fp, cid, fl, rs = e.get("fingerprint"), e.get("check_id"), e.get("file"), e.get("reason", "")
        if not (isinstance(fp, str) and _FP.match(fp) and isinstance(cid, str) and isinstance(fl, str)
                and isinstance(rs, str)):
            return None, "entry has an invalid field"
        out.append(BaselineEntry(fp, textsafe.safe_text(cid, cap=60, escape=False),
                                 textsafe.safe_text(fl, cap=300, escape=False),
                                 textsafe.safe_text(rs, cap=200, escape=False)))
    created = doc.get("created")
    return Baseline(created if isinstance(created, str) and len(created) <= 20 else "", out), None


def load_baseline(root: str, *, ref: str | None = None) -> tuple[Baseline | None, list[str]]:
    """Read the baseline from the working tree, or from a git ref (``--baseline-ref``).

    A missing file is ``(None, [])``. A malformed or unreadable one is ``(None, [note])`` and is
    not trusted: findings then show as open (fail closed).
    """
    root_real = files.real_root(root)
    if ref is not None:
        sha = gitutil.resolve_ref(root_real, ref)
        try:
            r = gitutil.run_git(root_real, ["show", "--end-of-options", "%s:%s" % (sha, BASELINE_REL)])
        except GuardError:
            return None, ["baseline at the ref could not be read"]
        if r.returncode != 0:
            return None, []
        text = r.stdout
    else:
        view, why = files.read_file(root_real, BASELINE_REL, limit=MAX_BASELINE_BYTES)
        if view is None:
            if why == "missing":
                return None, []
            return None, ["baseline not read (%s); findings are shown as open" % why]
        text = view.text
    b, problem = parse_baseline(text)
    if b is None:
        return None, ["baseline ignored (%s); findings are shown as open" % problem]
    return b, []


def ensure_paddock_gitignore(root: str) -> None:
    """When ``.paddock/`` does not exist yet, write its ``.gitignore`` first (3.10)."""
    import os

    root_real = files.real_root(root)
    if not os.path.lexists(os.path.join(root_real, ".paddock")):
        files.safe_write(root_real, ".paddock/.gitignore", PADDOCK_GITIGNORE, exclusive=True)


def write_baseline(root: str, b: Baseline) -> str:
    ensure_paddock_gitignore(root)
    return files.safe_write(files.real_root(root), BASELINE_REL, baseline_json(b))
