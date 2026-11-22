"""Build hook: vendor the engines into the wheel/sdist when building in the monorepo.

The copy has to exist before ``setup()`` runs, because setuptools discovers the packages to ship
when it reads the configuration. Outside a checkout (building from an sdist) the vendored copy
is already there and this is a no-op.
"""
import importlib.util
from pathlib import Path

from setuptools import setup

HERE = Path(__file__).resolve().parent


def _vendor() -> None:
    spec = importlib.util.spec_from_file_location("_pv", HERE / "paddock_cli" / "vendor.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.vendor_all(HERE.parent, HERE / "paddock_cli" / "_vendor")


_vendor()
setup()
