"""Edge/coverage builders. Each module exposes SOURCE, async load(conn, now, **opts) and
build(rows, now, **opts) -> BuildOutput (pure). The registry imports them lazily by name so one
missing/broken builder never takes the others down."""
from __future__ import annotations

import importlib
import logging
from types import ModuleType

logger = logging.getLogger(__name__)

BUILDER_NAMES: tuple[str, ...] = ("aws_sg", "external_exposure", "sentry_flows")


def load_builders() -> list[ModuleType]:
    out: list[ModuleType] = []
    for name in BUILDER_NAMES:
        try:
            mod = importlib.import_module(f"{__name__}.{name}")
        except ImportError:
            logger.warning("assurance_builder_missing", extra={"builder": name})
            continue
        for attr in ("SOURCE", "load", "build"):
            if not hasattr(mod, attr):
                raise RuntimeError(f"builder {name} lacks {attr}")
        out.append(mod)
    return out
