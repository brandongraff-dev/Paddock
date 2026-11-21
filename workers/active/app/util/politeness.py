"""Politeness limiter: this is the heart of the defensive stance.

For every target host we enforce:

* a per-host asyncio Semaphore (configurable, default 2)
* a minimum inter-request delay (default 250ms, floor 100ms)
* 429 / Retry-After backoff
* optional robots.txt compliance for the crawler (10 min cache)

The floor is a hard rule: it cannot be configured below ``floor_ms``.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlsplit

import httpx
import structlog

from app import USER_AGENT
from app.config import settings

log = structlog.get_logger(__name__)


def _host_of(target: str) -> str:
    """Cheap host extractor. ``example.com``, ``https://x:8080/a`` and
    ``1.2.3.4:443`` all reduce to a stable key.
    """
    t = target.strip().lower()
    if "://" in t:
        return urlsplit(t).hostname or t
    # host or host:port
    return t.split("/", 1)[0].split(":", 1)[0]


@dataclass
class _HostState:
    semaphore: asyncio.Semaphore
    last_request_ts: float = 0.0
    backoff_until_ts: float = 0.0
    delay_ms: int = 0
    concurrency: int = 0


@dataclass
class RobotsCacheEntry:
    fetched_at: float
    disallow_rules: list[tuple[str, str]] = field(default_factory=list)  # (ua, path_prefix)
    # Simplified: for a given UA, any path starting with a disallow prefix
    # is forbidden unless a longer allow prefix matches.
    allow_rules: list[tuple[str, str]] = field(default_factory=list)


class PolitenessLimiter:
    """Global singleton-friendly limiter.

    Not strictly a singleton — tests want their own — but worker.main uses one
    instance for the lifetime of the process.
    """

    def __init__(
        self,
        *,
        default_concurrency: int | None = None,
        default_delay_ms: int | None = None,
        floor_ms: int | None = None,
        robots_cache_ttl_sec: int | None = None,
    ):
        self._default_concurrency = default_concurrency or settings.max_concurrency_per_target
        self._default_delay = default_delay_ms or settings.politeness_delay_ms
        self._floor = floor_ms or settings.politeness_delay_floor_ms
        if self._default_delay < self._floor:
            # Enforce the floor rather than quietly honour a too-small value.
            log.warning(
                "politeness.delay.clamped",
                requested_ms=self._default_delay,
                floor_ms=self._floor,
            )
            self._default_delay = self._floor
        self._robots_ttl = robots_cache_ttl_sec or settings.robots_cache_ttl_sec
        self._hosts: dict[str, _HostState] = {}
        self._hosts_lock = asyncio.Lock()
        self._robots: dict[str, RobotsCacheEntry | None] = {}

    # -------- per-host state ----------------------------------------------

    async def configure_host(self, host: str, *, concurrency: int | None = None, delay_ms: int | None = None) -> None:
        """Set per-host overrides (e.g. from a scope entry's metadata)."""
        key = _host_of(host)
        delay = delay_ms if delay_ms is not None else self._default_delay
        if delay < self._floor:
            log.warning("politeness.delay.clamped", host=key, requested_ms=delay, floor_ms=self._floor)
            delay = self._floor
        conc = concurrency or self._default_concurrency
        async with self._hosts_lock:
            state = self._hosts.get(key)
            if state is None:
                state = _HostState(
                    semaphore=asyncio.Semaphore(conc),
                    delay_ms=delay,
                    concurrency=conc,
                )
                self._hosts[key] = state
            else:
                state.delay_ms = delay
                if conc != state.concurrency:
                    # replace the semaphore (naive but safe at reconfig points).
                    state.semaphore = asyncio.Semaphore(conc)
                    state.concurrency = conc

    async def _get_state(self, host: str) -> _HostState:
        key = _host_of(host)
        async with self._hosts_lock:
            state = self._hosts.get(key)
            if state is None:
                state = _HostState(
                    semaphore=asyncio.Semaphore(self._default_concurrency),
                    delay_ms=self._default_delay,
                    concurrency=self._default_concurrency,
                )
                self._hosts[key] = state
        return state

    # -------- the gate ----------------------------------------------------

    def acquire(self, host: str):
        """``async with limiter.acquire(host): ...`` to enter the polite region."""
        return _PolitenessContext(self, host)

    async def _enter(self, host: str) -> _HostState:
        state = await self._get_state(host)
        await state.semaphore.acquire()
        # Backoff from a prior 429.
        now = time.monotonic()
        if state.backoff_until_ts > now:
            await asyncio.sleep(state.backoff_until_ts - now)
        # Honor the inter-request delay.
        wait = state.last_request_ts + state.delay_ms / 1000.0 - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        return state

    def _leave(self, state: _HostState) -> None:
        state.last_request_ts = time.monotonic()
        state.semaphore.release()

    # -------- feedback from responses -------------------------------------

    def record_response(self, host: str, status_code: int, retry_after: str | None = None) -> None:
        """Feed a response back in. On 429 (or 503 + Retry-After) we back off."""
        state = self._hosts.get(_host_of(host))
        if state is None:
            return
        if status_code == 429 or (status_code == 503 and retry_after):
            secs = _parse_retry_after(retry_after)
            if secs is None:
                secs = min(60.0, max(1.0, (state.delay_ms / 1000.0) * 4))
            state.backoff_until_ts = max(state.backoff_until_ts, time.monotonic() + secs)
            log.warning("politeness.backoff", host=host, status=status_code, seconds=secs)

    # -------- robots ------------------------------------------------------

    async def robots_allows(self, url: str, *, user_agent: str | None = None, respect: bool = True) -> bool:
        """Return True if the given URL may be fetched under robots.txt.

        If ``respect`` is False, the caller has explicitly opted out via a
        per-scan ``respect_robots: false`` — we log loudly and return True.
        """
        if not respect:
            log.warning("robots.override", url=url, note="respect_robots=false for this scan")
            return True
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            return True
        host = parsed.hostname
        ua = (user_agent or USER_AGENT).split("/", 1)[0]
        entry = await self._robots_for(host, parsed.scheme, parsed.port)
        if entry is None:
            # No robots.txt or fetch failed -> treat as permissive (per RFC 9309).
            return True
        return _robots_allows_path(entry, ua, parsed.path or "/")

    async def _robots_for(self, host: str, scheme: str, port: int | None) -> RobotsCacheEntry | None:
        key = f"{scheme}://{host}:{port or ''}"
        entry = self._robots.get(key)
        now = time.time()
        if entry is not None and (now - entry.fetched_at) < self._robots_ttl:
            return entry
        # Fetch /robots.txt. This request itself is subject to polite pacing
        # from the caller's perspective, so we use a dedicated client here.
        url = f"{scheme}://{host}" + (f":{port}" if port else "") + "/robots.txt"
        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": USER_AGENT}, timeout=10.0, follow_redirects=True
            ) as c:
                r = await c.get(url)
                if r.status_code >= 400:
                    self._robots[key] = RobotsCacheEntry(fetched_at=now)  # empty -> permissive
                    return self._robots[key]
                parsed = _parse_robots(r.text)
                parsed.fetched_at = now
                self._robots[key] = parsed
                return parsed
        except Exception as e:
            log.info("robots.fetch_failed", url=url, error=str(e))
            self._robots[key] = RobotsCacheEntry(fetched_at=now)
            return self._robots[key]


class _PolitenessContext:
    def __init__(self, limiter: PolitenessLimiter, host: str):
        self._limiter = limiter
        self._host = host
        self._state: _HostState | None = None

    async def __aenter__(self) -> _HostState:
        self._state = await self._limiter._enter(self._host)
        return self._state

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._state is not None:
            self._limiter._leave(self._state)


# ----- helpers -------------------------------------------------------------


def _parse_retry_after(value: str | None) -> Optional[float]:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        from email.utils import parsedate_to_datetime

        dt = parsedate_to_datetime(value)
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        delta = (dt - now).total_seconds()
        return max(0.0, delta)
    except Exception:
        return None


def _parse_robots(body: str) -> RobotsCacheEntry:
    """Minimal robots.txt parser.

    Enough to be courteous: honours User-agent, Disallow and Allow. Precedence
    is longest-prefix-wins (RFC 9309). Wildcards are treated as literal "*"
    prefix only when a rule is exactly "*".
    """
    entry = RobotsCacheEntry(fetched_at=0.0)
    current_uas: list[str] = []
    in_group_rules_started = False
    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            continue
        name, _, val = line.partition(":")
        name = name.strip().lower()
        val = val.strip()
        if name == "user-agent":
            if in_group_rules_started:
                current_uas = [val]
                in_group_rules_started = False
            else:
                current_uas.append(val)
        elif name == "disallow":
            in_group_rules_started = True
            for ua in current_uas or ["*"]:
                entry.disallow_rules.append((ua.lower(), val))
        elif name == "allow":
            in_group_rules_started = True
            for ua in current_uas or ["*"]:
                entry.allow_rules.append((ua.lower(), val))
    return entry


def _robots_allows_path(entry: RobotsCacheEntry, ua_token: str, path: str) -> bool:
    ua = ua_token.lower()

    def rules_for(kind: list[tuple[str, str]]) -> list[str]:
        specific = [p for u, p in kind if u == ua]
        if specific:
            return specific
        return [p for u, p in kind if u == "*"]

    disallow = rules_for(entry.disallow_rules)
    allow = rules_for(entry.allow_rules)

    best_block: int = -1
    best_allow: int = -1
    for rule in disallow:
        if rule == "":
            continue  # empty Disallow means allow all
        if path.startswith(rule):
            best_block = max(best_block, len(rule))
    for rule in allow:
        if path.startswith(rule):
            best_allow = max(best_allow, len(rule))

    if best_block < 0:
        return True
    return best_allow >= best_block
