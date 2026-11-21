"""Feed-source adapters.

Each adapter exposes an async `sync()` coroutine that returns a stats
dict ({"ingested": N, ...}) and updates the stored cursor on success.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class TokenBucket:
    """Simple asyncio-friendly token bucket for per-source rate limiting.

    `capacity` tokens refill linearly over `window` seconds. `acquire()`
    waits until a token is available, then takes one.
    """

    capacity: int
    window: float
    _tokens: float = 0.0
    _last: float = 0.0
    _lock: asyncio.Lock | None = None

    def __post_init__(self) -> None:
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, n: int = 1) -> None:
        assert self._lock is not None
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                # linear refill: capacity tokens per window seconds
                self._tokens = min(
                    float(self.capacity),
                    self._tokens + elapsed * (self.capacity / self.window),
                )
                if self._tokens >= n:
                    self._tokens -= n
                    return
                # sleep just long enough for one more token
                deficit = n - self._tokens
                sleep_for = deficit * (self.window / self.capacity)
                await asyncio.sleep(max(sleep_for, 0.05))
