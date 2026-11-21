"""Rate-limit + cache unit tests."""
from __future__ import annotations

import asyncio
import time

import pytest

from app.util.cache import TTLCache
from app.util.rate_limit import RateLimiter, TokenBucket


async def test_token_bucket_blocks_until_refill() -> None:
    bucket = TokenBucket(rate=10.0, capacity=1.0)   # 10/sec, burst of 1
    await bucket.acquire()
    start = time.monotonic()
    await bucket.acquire()
    elapsed = time.monotonic() - start
    # Should have waited ~0.1s for the second token
    assert elapsed >= 0.05


async def test_rate_limiter_registers_unknown_source_at_1_rps() -> None:
    rl = RateLimiter()
    # unknown name: registered at 1 rps and allows the first acquire immediately
    start = time.monotonic()
    await rl.acquire("something-new")
    assert (time.monotonic() - start) < 0.05


async def test_ttl_cache_expires() -> None:
    cache: TTLCache[str] = TTLCache(ttl_seconds=0.05)
    await cache.set("k", "v")
    assert await cache.get("k") == "v"
    await asyncio.sleep(0.08)
    assert await cache.get("k") is None


async def test_ttl_cache_eviction_at_max_size() -> None:
    cache: TTLCache[str] = TTLCache(ttl_seconds=60, max_entries=2)
    await cache.set("a", "1")
    await cache.set("b", "2")
    await cache.set("c", "3")
    # one of a/b was evicted; c is present.
    assert await cache.get("c") == "3"
    assert cache.size() <= 2
