from __future__ import annotations

import asyncio
import time

import pytest

from app.sources import TokenBucket


@pytest.mark.asyncio
async def test_bucket_initially_full() -> None:
    b = TokenBucket(capacity=3, window=30.0)
    start = time.monotonic()
    for _ in range(3):
        await b.acquire()
    assert time.monotonic() - start < 0.1  # all three were already available


@pytest.mark.asyncio
async def test_bucket_refills_over_time() -> None:
    # Capacity 2 per 1 second window -> takes ~0.5s per token to refill.
    b = TokenBucket(capacity=2, window=1.0)
    await b.acquire()
    await b.acquire()
    start = time.monotonic()
    await b.acquire()  # should wait roughly half a window
    elapsed = time.monotonic() - start
    assert elapsed >= 0.4
    # Give it an upper bound so a bug (e.g. infinite sleep) is caught.
    assert elapsed < 1.5
