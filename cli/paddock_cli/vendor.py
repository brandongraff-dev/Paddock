"""Copy the Paddock engines into ``paddock_cli/_vendor`` for a self-contained wheel.

The engines (``sca``, ``codeanalysis``, ``remediation``, orchestrator SARIF
writer) live in their service directories as a package literally named
``app``. They cannot all be installed side by side, so the CLI loads each one
under a private alias (see :mod:`paddock_cli.engines`). In a source checkout
the loader reads the service directories directly; a built wheel carries a
copy produced by this module (``setup.py`` runs it at build time).

Only the pure, import-clean modules are copied -- never the services' HTTP,
database or scheduler code.
"""
from __future__ import annotations

import shutil
from pathlib import Path

# alias -> (service dir relative to the repo root, files/dirs to copy from it)
ENGINES: dict[str, tuple[str, tuple[str, ...]]] = {
    "sca": ("sca/app", ("__init__.py", "osv.py", "orchestrator.py", "tenancy.py", "parsers", "risk")),
    "codeanalysis": ("codeanalysis/app", ("__init__.py", "sast", "data")),
    "remediation": ("remediation/app", ("__init__.py", "gate.py", "generators.py", "verify.py",
                                        "injection.py")),
    "orchestrator": ("orchestrator/app", ("__init__.py", "standards.py")),
    # Wargame is a stdlib-only subpackage of the correlation service. The service-bound modules
    # (store, twin_store, assess, graph_adapter: database / attack-path imports) and the demos are
    # deliberately left out. Its one outside import, ``..policy``, is supplied by engines.py.
    "wargame": ("correlation/app/engine/wargame", (
        "__init__.py", "model.py", "environment.py", "reachability.py", "rules.py", "safety.py",
        "fabric.py", "topology.py", "impossible.py", "ingest.py", "routing.py", "mincut.py",
        "report.py", "changegate.py", "agreement.py", "certificate.py", "signing.py", "identity.py",
        "parsers")),
}

_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", "tests")


def vendor_all(repo_root: Path, dest: Path) -> bool:
    """Copy every engine into ``dest``. Returns False when not in a checkout."""
    if not all((repo_root / src).is_dir() for src, _ in ENGINES.values()):
        return False
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    (dest / "__init__.py").write_text('"""Generated copy of the Paddock engines. Do not edit."""\n')
    for alias, (src, parts) in ENGINES.items():
        out = dest / alias
        out.mkdir()
        for part in parts:
            s = repo_root / src / part
            if s.is_dir():
                shutil.copytree(s, out / part, ignore=_IGNORE)
            else:
                shutil.copy2(s, out / part)
    return True


if __name__ == "__main__":  # python -m paddock_cli.vendor  (from a checkout)
    here = Path(__file__).resolve().parent
    ok = vendor_all(here.parent.parent, here / "_vendor")
    raise SystemExit(0 if ok else "not inside a Paddock checkout")
