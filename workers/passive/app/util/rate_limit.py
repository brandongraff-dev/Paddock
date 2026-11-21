"""Per-source async token-bucket rate limiter.

Each public source (crt.sh, GitHub, Shodan, Wayback, bgpview, CertStream) gets
its own bucket. The limiter is purely in-process; we don't need cross-process
coordination because each worker enforces its own quota and the sources we
hit tolerate a handful of req/s per client.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class TokenBucket:
    rate: float            # tokens per second
    capacity: float        # max tokens (burst)
    tokens: float = field(init=False)
    last_refill: float = field(init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    async def acquire(self, cost: float = 1.0) -> None:
        """Block until `cost` tokens are available, then consume them."""
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self.last_refill
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self.last_refill = now
                if self.tokens >= cost:
                    self.tokens -= cost
                    return
                # How long until we'll have enough?
                deficit = cost - self.tokens
                wait_s = deficit / self.rate if self.rate > 0 else 1.0
            await asyncio.sleep(wait_s)


class RateLimiter:
    """Named bucket registry; sources are string-keyed."""

    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def register(self, name: str, rate: float, capacity: float | None = None) -> None:
        async with self._lock:
            if name not in self._buckets:
                self._buckets[name] = TokenBucket(rate=rate, capacity=capacity or max(1.0, rate))

    def register_sync(self, name: str, rate: float, capacity: float | None = None) -> None:
        """Set up at startup before the event loop is hot — bypasses the lock."""
        if name not in self._buckets:
            self._buckets[name] = TokenBucket(rate=rate, capacity=capacity or max(1.0, rate))

    async def acquire(self, name: str, cost: float = 1.0) -> None:
        bucket = self._buckets.get(name)
        if bucket is None:
            # Unknown source: default to 1 rps so we never accidentally hammer.
            await self.register(name, rate=1.0)
            bucket = self._buckets[name]
        await bucket.acquire(cost)
