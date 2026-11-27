# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fixture expansion (contract 3.12, D35).

``expand_fixture(src, dst)`` copies a fixture into ``dst``, applies the neutral-name rename map,
expands ``{{fake:*}}`` markers and, when ``expect.json`` has a ``git`` stanza
(``{"init": true, "tracked": [...], "ignored": [...]}``), runs ``git init`` and ``git add`` through
the isolated git helper. ``expect.json`` and ``NOTE.md`` at the fixture root are not copied.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE.parent) not in sys.path:  # runnable as a script: find fakes.py
    sys.path.insert(0, str(_HERE.parent))

import fakes  # noqa: E402

from . import gitenv  # noqa: E402  (relative import; script mode goes through expand_app)

RENAME_MAP = json.loads((_HERE / "rename_map.json").read_text(encoding="utf-8"))
_DOT = RENAME_MAP["dot_prefix"]
_UNDER = RENAME_MAP["underscore_names"]
_SKIP_AT_ROOT = ("expect.json", "NOTE.md")


def real_name(component: str) -> str:
    """Neutral fixture name to the real name (``dot-env`` to ``.env``, ``_dist`` to ``dist``)."""
    if component in _UNDER:
        return _UNDER[component]
    if component.startswith(_DOT) and len(component) > len(_DOT):
        return "." + component[len(_DOT):]
    return component


def real_path(rel: str) -> str:
    return "/".join(real_name(p) for p in rel.split("/"))


def _is_text(data: bytes) -> bool:
    return b"\x00" not in data[:4096]


def expand_tree(src: str | Path, dst: str | Path, *, skip_root: tuple[str, ...] = _SKIP_AT_ROOT) -> list[str]:
    """Copy ``src`` to ``dst`` with renames and marker expansion; return the real relative paths."""
    srcp, dstp = Path(src), Path(dst)
    dstp.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for dirpath, dirnames, filenames in os.walk(srcp):
        dirnames.sort()
        rel_dir = os.path.relpath(dirpath, srcp)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        for name in sorted(filenames):
            rel = (rel_dir + "/" + name) if rel_dir else name
            if not rel_dir and name in skip_root:
                continue
            target_rel = real_path(rel)
            target = dstp / target_rel
            target.parent.mkdir(parents=True, exist_ok=True)
            data = (srcp / rel).read_bytes()
            if _is_text(data):
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    target.write_bytes(data)
                else:
                    target.write_bytes(fakes.expand_text(text).encode("utf-8"))
            else:
                target.write_bytes(data)
            shutil.copymode(srcp / rel, target)
            written.append(target_rel)
    return written


def expand_fixture(src: str | Path, dst: str | Path) -> dict:
    """Expand a fixture and materialise its git stanza; return the parsed ``expect.json`` (or {})."""
    srcp, dstp = Path(src), Path(dst)
    expect: dict = {}
    ej = srcp / "expect.json"
    if ej.is_file():
        expect = json.loads(ej.read_text(encoding="utf-8"))
    expand_tree(srcp, dstp)
    stanza = expect.get("git")
    if stanza and stanza.get("init"):
        gitenv.init_repo(dstp)
        for rel in stanza.get("tracked", []):
            assert (dstp / rel).exists(), "git stanza: tracked path missing after expansion: %s" % rel
            gitenv.git(dstp, "add", "-f", "--", rel)
        for rel in stanza.get("ignored", []):
            r = gitenv.git(dstp, "check-ignore", "-q", "--", rel, check=False)
            assert r.returncode == 0, "git stanza: %s is declared ignored but git does not ignore it" % rel
    return expect
