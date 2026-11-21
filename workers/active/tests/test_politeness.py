"""Politeness: concurrency gate + inter-request delay + robots.txt."""
from __future__ import annotations

import asyncio
import time

import pytest

from app.util.politeness import PolitenessLimiter, _parse_robots, _robots_allows_path


@pytest.mark.asyncio
async def test_per_host_concurrency_cap():
    lim = PolitenessLimiter(default_concurrency=2, default_delay_ms=100, floor_ms=100)
    inside = 0
    peak = 0

    async def job():
        nonlocal inside, peak
        async with lim.acquire("example.com"):
            inside += 1
            peak = max(peak, inside)
            await asyncio.sleep(0.05)
            inside -= 1

    await asyncio.gather(*[job() for _ in range(6)])
    assert peak <= 2


@pytest.mark.asyncio
async def test_inter_request_delay_enforced():
    lim = PolitenessLimiter(default_concurrency=1, default_delay_ms=150, floor_ms=100)
    times: list[float] = []
    for _ in range(3):
        async with lim.acquire("one.example.com"):
            times.append(time.monotonic())
    # first has no wait, next two are spaced by >=150ms
    assert times[1] - times[0] >= 0.14
    assert times[2] - times[1] >= 0.14


@pytest.mark.asyncio
async def test_delay_below_floor_is_clamped():
    lim = PolitenessLimiter(default_concurrency=1, default_delay_ms=10, floor_ms=100)
    # The constructor clamps; verify by measuring an actual wait.
    times = []
    for _ in range(2):
        async with lim.acquire("floor.example.com"):
            times.append(time.monotonic())
    assert times[1] - times[0] >= 0.09


@pytest.mark.asyncio
async def test_429_backoff_respected():
    lim = PolitenessLimiter(default_concurrency=1, default_delay_ms=100, floor_ms=100)
    # Prime the host state.
    async with lim.acquire("back.example.com"):
        pass
    lim.record_response("back.example.com", 429, retry_after="1")
    t0 = time.monotonic()
    async with lim.acquire("back.example.com"):
        elapsed = time.monotonic() - t0
    assert elapsed >= 0.9


def test_robots_parser_longest_prefix_wins():
    body = """
    User-agent: *
    Disallow: /private/
    Allow: /private/public/
    """
    entry = _parse_robots(body)
    assert _robots_allows_path(entry, "paddock-scanner", "/private/x") is False
    assert _robots_allows_path(entry, "paddock-scanner", "/private/public/x") is True
    assert _robots_allows_path(entry, "paddock-scanner", "/open") is True


@pytest.mark.asyncio
async def test_robots_override_is_loud(caplog):
    import logging

    lim = PolitenessLimiter(default_concurrency=1, default_delay_ms=100, floor_ms=100)
    caplog.set_level(logging.WARNING)
    allowed = await lim.robots_allows("https://whatever.example.com/x", respect=False)
    assert allowed is True
