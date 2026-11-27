# SPDX-License-Identifier: AGPL-3.0-or-later
"""Absolute-time assertions that honour ``PADDOCK_GUARD_PERF=0`` (contract D29, 3.12 timing rules).

The variable is read when this module is first imported (collection time), because the autouse
isolation fixture removes every ``PADDOCK_GUARD_*`` variable before a test body runs. Growth-ratio
and injected-clock tests do not need this; only a test with a flat wall or CPU limit does.
"""
from __future__ import annotations

import os

PERF_ENABLED = os.environ.get("PADDOCK_GUARD_PERF") != "0"


def within(elapsed: float, limit: float, *, what: str = "run", enabled: bool | None = None) -> None:
    """Assert ``elapsed < limit`` unless absolute timings are switched off (shared, loaded machine)."""
    on = PERF_ENABLED if enabled is None else enabled
    if on:
        assert elapsed < limit, "%s took %.2fs, limit %.2fs (set PADDOCK_GUARD_PERF=0 to skip)" % (what, elapsed, limit)
