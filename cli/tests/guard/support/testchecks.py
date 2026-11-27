# SPDX-License-Identifier: AGPL-3.0-or-later
"""Test-only checks that exercise the engine (contract 10, G0 build list).

They are never registered by the product. A test registers them inside ``registry_sandbox`` with
``register_all()``. Ids use the pack ``TST`` so nothing here can collide with a real check.
"""
from __future__ import annotations

import re
import time

from paddock_cli.guard import model, registry
from paddock_cli.guard.registry import Check

_WORD = re.compile(r"FORBIDDEN_[A-Z]{3,10}")


def _line_hits(fv, word_rx, family):
    ordinal = 0
    out = []
    for i, line in enumerate(fv.lines, start=1):
        for m in word_rx.finditer(line):
            ordinal += 1
            out.append(model.Hit(file=fv.path, line=i, end_line=i, anchor="%s:%s:%d" % (family, m.group(0), ordinal),
                                 evidence=line.strip()[:100], data={"name": m.group(0).lower()}))
    return out


def run_forbidden(ctx, fv):
    return _line_hits(fv, _WORD, "forbidden")


def run_medium(ctx, fv):
    return _line_hits(fv, re.compile(r"MEDIUMWORD"), "medium")


def run_low(ctx, fv):
    return _line_hits(fv, re.compile(r"LOWWORD"), "low")


def run_nosupp(ctx, fv):
    return _line_hits(fv, re.compile(r"NOSUPPWORD"), "nosupp")


def run_project(ctx, fv):
    """Project scope: fires when a ``.env`` file exists and ``.gitignore`` does not mention it."""
    if not ctx.exists(".env"):
        return []
    view = ctx.read(".gitignore")
    if view is None or ".env" not in view.text:
        return [model.Hit(file=".gitignore", line=None, anchor="env-not-ignored", evidence="no .env rule")]
    return []


def run_sleepy(ctx, fv):
    if "SLEEP" in fv.text:
        time.sleep(30)
    return []


def run_boom(ctx, fv):
    if "RAISE" in fv.text:
        raise ValueError("boom")
    return []


def run_capped(ctx, fv):
    out = []
    for i, line in enumerate(fv.lines, start=1):
        if "CAPPEDWORD" in line:
            out.append(model.Hit(file=fv.path, line=i, anchor="capped:%d" % i, evidence="x",
                                 data={"tier_cap": "medium"}))
        if "OPENFACTWORD" in line:
            out.append(model.Hit(file=fv.path, line=i, anchor="openfact:%d" % i, evidence="x",
                                 data={"unverified_id": "U-16"}))
    return out


def run_hostile(ctx, fv):
    if "HOSTILE" not in fv.text:
        return []
    return [model.Hit(
        file=fv.path, line=1, anchor="hostile",
        evidence="‮evil\x1b[31m​" + "A" * 400 + "\x07",
        data={"name": "ok-name", "bad key!": "x", "value": "has space", "n": 3, "flag": True, "Upper": "x"})]


def make_checks() -> list[Check]:
    common = dict(severity="high", proposed_tier="high", why="why", fix_hint="fix it")
    return [
        Check(id="PG-TST-001", title="Forbidden word", scope="file", globs=("**/*.txt", "**/*.py"), cwe="CWE-1",
              agent_prompt="Remove {name} from {file}:{line}.", run=run_forbidden, **common),
        Check(id="PG-TST-002", title="Medium word", severity="medium", proposed_tier="medium", scope="file",
              globs=("**/*.txt",), agent_prompt="Review {file}.", run=run_medium, why="w", fix_hint="f"),
        Check(id="PG-TST-003", title="Low advice", severity="low", proposed_tier="low", scope="file",
              globs=("**/*.txt",), agent_prompt="Consider {file}.", run=run_low, why="w", fix_hint="f"),
        Check(id="PG-TST-004", title="Env not ignored", scope="project", triggers=(".gitignore",),
              agent_prompt="Add .env to .gitignore.", run=run_project, **common),
        Check(id="PG-TST-005", title="Not suppressible", scope="file", inline_suppressible=False, globs=("**/*.txt",),
              agent_prompt="Fix {file}.", run=run_nosupp, **common),
        Check(id="PG-TST-006", title="Sleepy", scope="file", globs=("slow.txt",), agent_prompt="x", run=run_sleepy, **common),
        Check(id="PG-TST-007", title="Raises", scope="file", globs=("boom.txt",), agent_prompt="x", run=run_boom, **common),
        Check(id="PG-TST-008", title="Capped sub-rule", scope="file", globs=("cap.txt",), agent_prompt="Fix {file}.",
              run=run_capped, **common),
        Check(id="PG-TST-009", title="Hostile hit", scope="file", globs=("hostile.txt",), agent_prompt="Fix {name} in {file}.",
              run=run_hostile, **common),
    ]


def register_all() -> list[Check]:
    return [registry.register(c) for c in make_checks()]
