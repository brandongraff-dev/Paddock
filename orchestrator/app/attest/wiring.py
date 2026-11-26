"""Router and loop discovery (docs/ASSURANCE_P3.md 7.1), so ``main.py`` is edited once.

* :func:`include` adds whichever of ``routers/attestations.py`` (private, ``/v1/attestations``) and
  ``routers/public_attest.py`` (public, ``/v1/public/attest``) exists, each through its module-level ``router``.
* :func:`start` runs ``attest.loop.attest_loop(app)`` as a task when that module exists; :func:`stop` cancels it.

Discovery uses ``importlib.util.find_spec``: a module that is **absent** is skipped (the packages land in different
waves), but a module that is **found** is imported for real and any error inside it propagates. Swallowing it would
ship an application whose attestation routes or loop are silently missing, the opposite of fail safe.
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import logging
from typing import Any

logger = logging.getLogger(__name__)

#: the package the modules below live in (``app``); tests point it elsewhere
BASE_PACKAGE = __name__.split(".")[0]
ROUTER_MODULES = ("routers.attestations", "routers.public_attest")
LOOP_MODULE = "attest.loop"
LOOP_ENTRY = "attest_loop"
STATE_ATTR = "attest_task"


class WiringError(Exception):
    """A discovered module does not have the shape the hook needs."""


def _exists(relative: str) -> str | None:
    """The full module name if it exists on the import path, else None. Only the target (or one of ITS parent
    packages) being absent counts as absence; any other ImportError is a bug in code that exists."""
    full = f"{BASE_PACKAGE}.{relative}"
    try:
        spec = importlib.util.find_spec(full)
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if missing == full or full.startswith(missing + "."):
            return None
        raise
    return full if spec is not None else None


def include(app: Any) -> list[str]:
    """Include every router module that exists; returns the module names included (in order)."""
    included: list[str] = []
    for relative in ROUTER_MODULES:
        full = _exists(relative)
        if full is None:
            continue
        module = importlib.import_module(full)
        router = getattr(module, "router", None)
        if router is None:
            raise WiringError(f"{full} exists but has no module-level 'router'")
        app.include_router(router)
        included.append(full)
    return included


def start(app: Any) -> asyncio.Task | None:
    """Start the attestation loop if ``attest.loop`` exists. Idempotent while the task is running. Call from the
    lifespan (a running event loop is needed)."""
    existing = getattr(app.state, STATE_ATTR, None)
    if existing is not None and not existing.done():
        return existing
    full = _exists(LOOP_MODULE)
    if full is None:
        return None
    module = importlib.import_module(full)
    entry = getattr(module, LOOP_ENTRY, None)
    if entry is None or not callable(entry):
        raise WiringError(f"{full} exists but has no callable '{LOOP_ENTRY}(app)'")
    task = asyncio.create_task(entry(app), name="attest_loop")
    setattr(app.state, STATE_ATTR, task)
    return task


async def stop(app: Any) -> None:
    """Cancel the loop and wait for it. Safe to call without ``start`` and more than once; a loop that crashed does not
    make shutdown fail."""
    task = getattr(app.state, STATE_ATTR, None)
    setattr(app.state, STATE_ATTR, None)
    if task is None:
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001 -- shutdown must complete; the loop logs its own failures
        logger.exception("attest_loop_failed_at_shutdown")
