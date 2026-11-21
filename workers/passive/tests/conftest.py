"""Shared pytest fixtures for the passive worker tests."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import AsyncIterator

import aiohttp
import pytest
import pytest_asyncio

from app.config import Settings
from app.context import ModuleContext
from app.orchestrator import OrchestratorClient
from app.util.rate_limit import RateLimiter


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str):
    path = FIXTURES_DIR / name
    with path.open("r", encoding="utf-8") as f:
        if name.endswith(".json"):
            return json.load(f)
        return f.read()


@pytest.fixture
def settings() -> Settings:
    # All tests run against mocked HTTP; the base URL just has to parse.
    return Settings(
        orchestrator_url="http://orchestrator.test",
        redis_url="redis://localhost:6379/0",
        worker_id="test-worker",
        rate_crtsh_rps=1000,  # don't actually wait in tests
        rate_github_rps=1000,
        rate_shodan_rps=1000,
        rate_internetdb_rps=1000,
        rate_wayback_rps=1000,
        rate_bgpview_rps=1000,
        rate_dns_rps=1000,
        scope_cache_ttl_s=60,
        http_timeout_s=5.0,
    )


@pytest.fixture
def rate_limiter(settings: Settings) -> RateLimiter:
    rl = RateLimiter()
    for name in ("crtsh", "censys", "github", "shodan", "internetdb",
                 "wayback", "bgpview", "ripe", "dns"):
        rl.register_sync(name, rate=1000.0, capacity=1000.0)
    return rl


@pytest_asyncio.fixture
async def http_session() -> AsyncIterator[aiohttp.ClientSession]:
    async with aiohttp.ClientSession() as s:
        yield s


@pytest_asyncio.fixture
async def orchestrator(settings: Settings) -> AsyncIterator[OrchestratorClient]:
    async with OrchestratorClient(settings) as c:
        yield c


@pytest_asyncio.fixture
async def ctx(
    settings: Settings,
    orchestrator: OrchestratorClient,
    rate_limiter: RateLimiter,
    http_session: aiohttp.ClientSession,
) -> ModuleContext:
    return ModuleContext(
        settings=settings,
        orchestrator=orchestrator,
        rate_limiter=rate_limiter,
        http=http_session,
    )
