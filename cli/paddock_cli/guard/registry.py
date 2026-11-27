# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check registry, tiers and discovery (contract 3.3, 3.4, 4.0.8, D8).

``Check`` is a frozen dataclass; checks register themselves with ``register`` (as a function on a
``Check`` or as a decorator on the ``run`` callable). ``effective_tier`` combines the declared
proposal, ``data/tiers.json`` (written only by the precision study) and open UNVERIFIED ids.
"""
from __future__ import annotations

import importlib
import json
import os
import pkgutil
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator

from paddock_cli.guard import model
from paddock_cli.guard.errors import UsageError

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
TIERS_PATH = os.path.join(_DATA_DIR, "tiers.json")
VERIFIED_PATH = os.path.join(_DATA_DIR, "verified.json")
PACKS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packs")

ID_RE = re.compile(r"^PG-[A-Z]{3,4}-\d{3}$")
PACK_ID_RE = re.compile(r"^PGX-[A-Z0-9-]{3,40}-\d{3}$")
_TEMPLATE_FIELD = re.compile(r"\{([^{}]*)\}")
_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
BAR_STATUSES = frozenset({"measured", "ai-estimated"})
ALL_STATUSES = frozenset({"measured", "ai-estimated", "insufficient-n", "not-labellable"})

RunFn = Callable[[Any, Any], Iterable[model.Hit]]


@dataclass(frozen=True, kw_only=True)
class Check:
    id: str
    title: str
    severity: str
    proposed_tier: str
    scope: str = "file"
    pack: str = ""
    globs: tuple[str, ...] = ("**",)
    triggers: tuple[str, ...] = ()
    why: str = ""
    fix_hint: str = ""
    agent_prompt: str = ""
    cwe: str | None = None
    refs: tuple[str, ...] = ()
    fixer: str | None = None
    inline_suppressible: bool = True
    spec_status: str = "VERIFIED"
    unverified_ids: tuple[str, ...] = ()
    network: bool = False
    long_lines_ok: bool = False
    big_ok: bool = False
    include_build: bool = False
    origin: str = "builtin"  # builtin | pack | project-pack
    trusted: bool = True
    run: RunFn | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.severity not in model.SEVERITIES:
            raise ValueError("unknown severity %r for %s" % (self.severity, self.id))
        if self.proposed_tier not in model.TIERS:
            raise ValueError("unknown tier %r for %s" % (self.proposed_tier, self.id))
        if self.scope not in model.SCOPES:
            raise ValueError("unknown scope %r for %s" % (self.scope, self.id))
        if not self.pack:
            parts = self.id.split("-")
            object.__setattr__(self, "pack", parts[1] if len(parts) >= 3 else "")
        object.__setattr__(self, "globs", tuple(self.globs))
        object.__setattr__(self, "triggers", tuple(self.triggers))
        object.__setattr__(self, "refs", tuple(self.refs))
        object.__setattr__(self, "unverified_ids", tuple(self.unverified_ids))


_CHECKS: dict[str, Check] = {}
_IMPORT_ERRORS: list[tuple[str, str]] = []
_DISCOVERED = False
_TIERS_CACHE: dict[str, dict[str, Any]] | None = None
_VERIFIED_CACHE: set[str] | None = None


def register(check: Check | None = None, /, **fields: Any) -> Any:
    """Register a ``Check``; with keyword fields, return a decorator for its ``run`` function."""
    if check is not None:
        if fields:
            raise TypeError("pass a Check or keyword fields, not both")
        return _add(check)
    if "run" in fields:  # all fields given at once: register now
        return _add(Check(**fields))

    def deco(fn: RunFn) -> RunFn:
        _add(Check(run=fn, **fields))
        return fn

    return deco


def _add(check: Check) -> Check:
    if check.id in _CHECKS:
        raise ValueError("duplicate check id %s" % check.id)
    _CHECKS[check.id] = check
    return check


def unregister(check_id: str) -> None:
    _CHECKS.pop(check_id, None)


def all_checks() -> list[Check]:
    return [_CHECKS[k] for k in sorted(_CHECKS)]


def get(check_id: str) -> Check:
    try:
        return _CHECKS[check_id]
    except KeyError:
        raise UsageError("unknown check id") from None


def has(check_id: str) -> bool:
    return check_id in _CHECKS


def import_errors() -> list[tuple[str, str]]:
    """(module, exception class name) for every discovery import that failed."""
    return list(_IMPORT_ERRORS)


@contextmanager
def sandbox() -> Iterator[dict[str, Check]]:
    """Run with an empty registry and restore the previous one afterwards (tests)."""
    global _DISCOVERED, _IMPORT_ERRORS
    saved = (dict(_CHECKS), list(_IMPORT_ERRORS), _DISCOVERED)
    _CHECKS.clear()
    _IMPORT_ERRORS = []
    _DISCOVERED = True  # an empty sandbox must not trigger discovery
    try:
        yield _CHECKS
    finally:
        _CHECKS.clear()
        _CHECKS.update(saved[0])
        _IMPORT_ERRORS = saved[1]
        _DISCOVERED = saved[2]


def reset_caches() -> None:
    global _TIERS_CACHE, _VERIFIED_CACHE
    _TIERS_CACHE = None
    _VERIFIED_CACHE = None


# ---- discovery -------------------------------------------------------------------------------
_OPTIONAL_MODULES = ("paddock_cli.guard.pkg.checks", "paddock_cli.guard.urlcheck.checks")


def _tolerable(name: str | None) -> bool:
    """A missing optional module (or its parent package) is not an error; anything else is."""
    if not name:
        return False
    for mod in _OPTIONAL_MODULES:
        if name == mod or mod.startswith(name + ".") and name.startswith("paddock_cli.guard."):
            return True
    return False


def discover(*, force: bool = False) -> None:
    """Import ``guard.checks.*``, ``guard.pkg.checks`` and ``guard.urlcheck.checks`` and load packs.

    A module that cannot be imported is recorded (``import_errors``) and does not stop the run;
    a ``ModuleNotFoundError`` is tolerated only for the two optional modules above (or their
    parent package) while those packages are not built.
    """
    global _DISCOVERED
    if _DISCOVERED and not force:
        return
    _DISCOVERED = True
    _IMPORT_ERRORS.clear()
    names: list[str] = []
    try:
        pkg = importlib.import_module("paddock_cli.guard.checks")
        for info in pkgutil.iter_modules(pkg.__path__):
            if not info.name.startswith("_"):
                names.append("paddock_cli.guard.checks." + info.name)
    except Exception as exc:  # noqa: BLE001
        _IMPORT_ERRORS.append(("paddock_cli.guard.checks", type(exc).__name__))
    names.extend(_OPTIONAL_MODULES)
    for name in sorted(names, key=lambda n: (n in _OPTIONAL_MODULES, n)):
        try:
            importlib.import_module(name)
        except ModuleNotFoundError as exc:
            if name in _OPTIONAL_MODULES and _tolerable(exc.name):
                continue
            _IMPORT_ERRORS.append((name, type(exc).__name__))
        except Exception as exc:  # noqa: BLE001  (a broken check module must not abort the run)
            _IMPORT_ERRORS.append((name, type(exc).__name__))
    _load_shipped_packs()


def _load_shipped_packs() -> None:
    from paddock_cli.guard import rulepack

    try:
        entries = sorted(os.listdir(PACKS_DIR))
    except OSError:
        return
    for fname in entries:
        if not fname.endswith(".toml") or fname == "example.toml":
            continue
        try:
            for chk in rulepack.load_pack_file(os.path.join(PACKS_DIR, fname), trusted=True, origin="pack"):
                if chk.id not in _CHECKS:
                    _CHECKS[chk.id] = chk
        except Exception as exc:  # noqa: BLE001
            _IMPORT_ERRORS.append(("pack:" + fname, type(exc).__name__))


# ---- tiers and verified ids --------------------------------------------------------------------
def _read_json(path: str) -> Any:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(4 * 1024 * 1024)
    except OSError:
        return None
    if raw.count(b"[") + raw.count(b"{") > 200000:
        return None
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, RecursionError, MemoryError):
        return None


def load_tiers() -> dict[str, dict[str, Any]]:
    """``data/tiers.json`` as ``{check_id: entry}``; absent or malformed means empty (D8).

    Accepted shapes: a list of entries, ``{"entries": [...]}`` or ``{check_id: entry}``.
    """
    global _TIERS_CACHE
    if _TIERS_CACHE is not None:
        return _TIERS_CACHE
    doc = _read_json(TIERS_PATH)
    out: dict[str, dict[str, Any]] = {}
    items: list[Any] = []
    if isinstance(doc, list):
        items = doc
    elif isinstance(doc, dict):
        if isinstance(doc.get("entries"), list):
            items = doc["entries"]
        elif isinstance(doc.get("checks"), list):
            items = doc["checks"]
        else:
            for k, v in doc.items():
                if isinstance(v, dict):
                    items.append({"check_id": k, **v})
    for e in items:
        if isinstance(e, dict) and isinstance(e.get("check_id"), str):
            out[e["check_id"]] = e
    _TIERS_CACHE = out
    return out


def load_verified() -> set[str]:
    """Ids closed in ``data/verified.json`` (a source row exists); absent means empty (7.9)."""
    global _VERIFIED_CACHE
    if _VERIFIED_CACHE is not None:
        return _VERIFIED_CACHE
    doc = _read_json(VERIFIED_PATH)
    items = doc.get("entries", []) if isinstance(doc, dict) else doc
    ids: set[str] = set()
    if isinstance(items, list):
        for e in items:
            if isinstance(e, dict) and isinstance(e.get("id"), str) and e.get("source"):
                ids.add(e["id"])
    _VERIFIED_CACHE = ids
    return ids


def open_unverified(check: Check) -> list[str]:
    closed = load_verified()
    return [u for u in check.unverified_ids if u not in closed]


def proposed_tier(check: Check) -> str:
    """The declared tier capped to ``medium`` while any ``unverified_ids`` entry is open (4.0.8)."""
    if check.proposed_tier == "high" and open_unverified(check):
        return "medium"
    return check.proposed_tier


def effective_tier(check: Check) -> tuple[str, str]:
    """(tier, evidence label). Decided by ``tiers.json`` when it has an entry (D8)."""
    entry = load_tiers().get(check.id)
    if entry is not None:
        tier = entry.get("tier") if entry.get("tier") in model.TIERS else "medium"
        status = entry.get("status") if entry.get("status") in ALL_STATUSES else "unmeasured"
        if tier == "high" and status not in BAR_STATUSES:
            tier = "medium"
        if tier == "high" and open_unverified(check):
            tier = "medium"
        return tier, status
    prop = proposed_tier(check)
    if model.REQUIRE_TIERS:
        # An unmeasured check never blocks in a release (D8); a ``low`` proposal stays ``low``.
        return ("medium" if prop == "high" else prop), "unmeasured"
    return prop, "unmeasured"


def why_text(check: Check) -> str:
    """Rationale for output: anecdotal unless it carries a ``source:`` URL (4.0.9)."""
    text = check.why.strip()
    if re.search(r"source:\s*https?://", text):
        return text
    return (text + " (anecdotal, unmeasured)").strip()


# ---- invariants (test_registry_invariants) -----------------------------------------------------
def template_fields(template: str) -> list[str]:
    return [m.group(1) for m in _TEMPLATE_FIELD.finditer(template or "")]


def invariant_problems(checks: Iterable[Check]) -> list[str]:
    """Violations of the registry invariants of 3.4 that do not need the contract file."""
    from paddock_cli.guard import fixers

    problems: list[str] = []
    seen: set[str] = set()
    for c in checks:
        if c.id in seen:
            problems.append("duplicate id %s" % c.id)
        seen.add(c.id)
        if c.origin == "builtin" and not ID_RE.match(c.id):
            problems.append("id %r does not match PG-XXX-NNN" % c.id)
        for f in template_fields(c.agent_prompt):
            if not _FIELD_NAME.match(f):
                problems.append("%s: agent_prompt template field %r is not allowed" % (c.id, f))
        if re.search(r"\{[^{}]*[^a-z0-9_{}][^{}]*\}", c.agent_prompt or ""):
            if not any("template field" in p and c.id in p for p in problems):
                problems.append("%s: agent_prompt template field is not allowed" % c.id)
        if c.fixer is not None and c.fixer not in fixers.FIXER_NAMES:
            problems.append("%s: fixer %r is not in FIXER_NAMES" % (c.id, c.fixer))
        if c.network and not (c.id.startswith("PG-PKG-") or c.id.startswith("PG-URL-")):
            problems.append("%s: network=True is only for PG-PKG and PG-URL checks" % c.id)
    return problems
