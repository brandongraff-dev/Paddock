"""Per-tenant build + evaluate loop. Owned by the runner work package (docs/ASSURANCE_P1.md section 7)."""
from __future__ import annotations

import asyncio


async def assurance_loop(app) -> None:  # pragma: no cover - replaced by the runner work package
    while True:
        await asyncio.sleep(3600)
