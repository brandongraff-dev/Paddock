# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generic fixture runner (contract 4.0.3, 3.12): tp-*, neg-* and fn-* directories per check.

``fixtures/checks/<ID>/tp-<n>/`` must fire the check (also after CRLF, tab-indent, BOM and
leading-blank-line variants), ``neg-<n>/`` and ``fn-<n>/`` must not. Every fixture is expanded
into a temporary copy first (neutral names, ``{{fake:*}}`` markers, git stanza).
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

from paddock_cli.guard import config, context, engine, model

from . import expand

_TEXT = re.compile(rb"\x00")
MIN_TP = 3
MIN_NEG = 3
_TOKEN_SHAPES = (
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b"), re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), re.compile(r"\bglpat-[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
)


def discover(root: Path) -> dict[str, dict[str, list[Path]]]:
    out: dict[str, dict[str, list[Path]]] = {}
    if not root.is_dir():
        return out
    for cdir in sorted(p for p in root.iterdir() if p.is_dir()):
        kinds: dict[str, list[Path]] = {"tp": [], "neg": [], "fn": []}
        for sub in sorted(p for p in cdir.iterdir() if p.is_dir()):
            for k in kinds:
                if sub.name.startswith(k + "-"):
                    kinds[k].append(sub)
        out[cdir.name] = kinds
    return out


def count_problems(check_id: str, kinds: dict[str, list[Path]]) -> list[str]:
    probs = []
    if len(kinds["tp"]) < MIN_TP:
        probs.append("%s has %d tp fixtures, needs %d" % (check_id, len(kinds["tp"]), MIN_TP))
    if len(kinds["neg"]) < MIN_NEG:
        probs.append("%s has %d neg fixtures, needs %d" % (check_id, len(kinds["neg"]), MIN_NEG))
    return probs


def _scan(tree: Path, check_id: str, *, tier: str = "low"):
    cfg = config.load_config(str(tree))
    with context.ScanContext.open(str(tree), cfg, no_state=True) as ctx:
        return engine.run_checks(ctx, tier=tier, only=[check_id])


def _fires(report, check_id: str):
    return [f for f in report.findings if f.check_id == check_id]


def _rewrite_text_files(tree: Path, fn) -> None:
    for p in tree.rglob("*"):
        if not p.is_file() or ".git" in p.relative_to(tree).parts:
            continue
        data = p.read_bytes()
        if _TEXT.search(data[:4096]):
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        p.write_bytes(fn(text).encode("utf-8"))


def variants() -> dict[str, callable]:
    def tabs(t: str) -> str:
        return re.sub(r"(?m)^((?:    )+|(?:  )+)", lambda m: "\t" * (len(m.group(1)) // (4 if len(m.group(1)) % 4 == 0 else 2)), t)

    return {
        "crlf": lambda t: t.replace("\r\n", "\n").replace("\n", "\r\n"),
        "tabs": tabs,
        "bom": lambda t: "﻿" + t,
        "leading-blank-line": lambda t: "\n" + t,
    }


def run_case(case: Path, check_id: str, kind: str, tmp: Path) -> list[str]:
    """Problems for one fixture directory (empty when it behaves as its name says)."""
    probs: list[str] = []
    work = tmp / ("%s-%s" % (check_id, case.name))
    expect = expand.expand_fixture(case, work)
    if kind == "tp":
        if not (case / "expect.json").is_file():
            return ["%s/%s: expect.json is missing" % (check_id, case.name)]
        if expect.get("check") != check_id:
            probs.append("%s/%s: expect.json check is %r" % (check_id, case.name, expect.get("check")))
        found = _fires(_scan(work, check_id), check_id)
        if not found:
            return probs + ["%s/%s: the check did not fire on its own true-positive fixture" % (check_id, case.name)]
        if expect.get("files"):
            want = set(expect["files"])
            if not ({f.file for f in found} & want):
                probs.append("%s/%s: findings are in %s, expect.json wants %s" % (
                    check_id, case.name, sorted({f.file for f in found}), sorted(want)))
        if expect.get("anchor"):
            fps = {model.fingerprint(check_id, f.file, expect["anchor"]) for f in found}
            if not ({f.fingerprint for f in found} & fps):
                probs.append("%s/%s: no finding has the pinned anchor" % (check_id, case.name))
        base_fps = {f.fingerprint for f in found}
        for name, fn in variants().items():
            vdir = tmp / ("%s-%s-%s" % (check_id, case.name, name))
            shutil.copytree(work, vdir, symlinks=True)
            _rewrite_text_files(vdir, fn)
            vfound = _fires(_scan(vdir, check_id), check_id)
            if not vfound:
                probs.append("%s/%s: the check does not fire on the %s variant" % (check_id, case.name, name))
            elif name == "leading-blank-line" and expect.get("fingerprint_stable_under_line_shift"):
                if {f.fingerprint for f in vfound} != base_fps:
                    probs.append("%s/%s: fingerprints changed when a line was added above" % (check_id, case.name))
        return probs
    found = _fires(_scan(work, check_id), check_id)
    if found:
        probs.append("%s/%s: the check fired on a %s fixture: %s" % (check_id, case.name, kind, [f.file for f in found][:3]))
    note = case / "NOTE.md"
    if not note.is_file() or not note.read_text(encoding="utf-8").strip():
        probs.append("%s/%s: NOTE.md is missing or empty" % (check_id, case.name))
    return probs


def literal_token_problems(root: Path) -> list[str]:
    """Fixtures never store a token-shaped value; markers are expanded at test time (4.0.3)."""
    probs = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for rx in _TOKEN_SHAPES:
            for m in rx.finditer(text):
                v = m.group(0)
                if "EXAMPLE" in v or "xxxx" in v.lower() or re.search(r"(.)\1{7,}", v):
                    continue
                probs.append("%s holds a token-shaped literal (%s...)" % (p.relative_to(root), v[:6]))
    return probs
