"""Background runner: public exposure jobs + due supplier assessments.

One task started from the FastAPI lifespan. It only ever runs the passive
engine (DNS + CT); a failing tick is logged and the loop carries on.
"""
from __future__ import annotations

import asyncio
import logging
import time

from . import exposure, suppliers
from .config import growth_settings

logger = logging.getLogger(__name__)


async def growth_loop(app) -> None:
    last_suppliers = 0.0
    while True:
        try:
            await asyncio.sleep(growth_settings.runner_interval_sec)
            pool = app.state.pool
            await exposure.run_pending(pool)
            now = time.monotonic()
            if growth_settings.supplier_enabled and now - last_suppliers >= growth_settings.supplier_interval_sec:
                last_suppliers = now
                await suppliers.run_due(pool)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 -- never let a bad tick end the loop
            logger.exception("growth_tick_failed")
