"""Edge/coverage builders. Each module exposes SOURCE, async load(conn, now, **opts) and
build(rows, now, **opts) -> BuildOutput (pure). The registry imports them lazily by name so one
missing/broken builder never takes the others down."""
from __future__ import annotations

import importlib
import logging
from types import ModuleType

logger = logging.getLogger(__name__)

#: Order matters: ``host_fw`` reads the ``external_scan`` edges ``external_exposure`` has just persisted
#: (its cross-check of "the agent says closed, the scan connected"), so it is registered AFTER it.
BUILDER_NAMES: tuple[str, ...] = ("aws_sg", "external_exposure", "host_fw", "sentry_flows")


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
