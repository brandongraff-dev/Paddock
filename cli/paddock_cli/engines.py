"""Load the Paddock engines as libraries, without installing their services.

Every service ships a top-level package called ``app``, so they would shadow
each other if imported normally. Each one is loaded here under a private alias
(``paddock_sca``, ``paddock_codeanalysis``, ...). Relative imports inside the
engines keep working because the alias *is* the package.

Resolution order: a vendored copy inside this package (wheel installs), then
``PADDOCK_ENGINES_DIR``, then the sibling service directory of a source checkout.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from functools import lru_cache
from pathlib import Path
from types import ModuleType

from .vendor import ENGINES

_HERE = Path(__file__).resolve().parent


class EngineUnavailable(RuntimeError):
    pass


def _roots(alias: str) -> list[Path]:
    src = ENGINES[alias][0]
    roots = [_HERE / "_vendor" / alias]
    env = os.environ.get("PADDOCK_ENGINES_DIR")
    if env:
        roots.append(Path(env) / src)
    roots.append(_HERE.parent.parent / src)
    return roots


@lru_cache(maxsize=None)
def load(alias: str) -> ModuleType:
    """Return the root package of one engine (``sca``, ``codeanalysis``, ...)."""
    if alias not in ENGINES:
        raise KeyError(alias)
    name = f"paddock_{alias}"
    if name in sys.modules:
        return sys.modules[name]
    for root in _roots(alias):
        init = root / "__init__.py"
        if init.is_file():
            spec = importlib.util.spec_from_file_location(
                name, init, submodule_search_locations=[str(root)])
            assert spec and spec.loader
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            try:
                spec.loader.exec_module(mod)
            except Exception:
                sys.modules.pop(name, None)
                raise
            return mod
    raise EngineUnavailable(
        f"the {alias!r} engine was not found; reinstall paddock-cli or run from a Paddock checkout")


def module(alias: str, dotted: str) -> ModuleType:
    """``module("sca", "parsers")`` -> the engine's ``app.parsers`` module."""
    load(alias)
    return importlib.import_module(f"paddock_{alias}.{dotted}")


# Convenience accessors (lazy; each import is cheap and cached).
def sca_parsers() -> ModuleType:
    return module("sca", "parsers")


def sca_osv() -> ModuleType:
    return module("sca", "osv")


def sca_risk() -> ModuleType:
    return module("sca", "risk")


def sca_findings() -> ModuleType:
    return module("sca", "orchestrator")


def sast() -> ModuleType:
    return module("codeanalysis", "sast")


def sast_normalize() -> ModuleType:
    return module("codeanalysis", "sast.normalize")


def gate() -> ModuleType:
    return module("remediation", "gate")


def generators() -> ModuleType:
    return module("remediation", "generators")


def verify() -> ModuleType:
    return module("remediation", "verify")


def injection() -> ModuleType:
    return module("remediation", "injection")


def standards() -> ModuleType:
    return module("orchestrator", "standards")
