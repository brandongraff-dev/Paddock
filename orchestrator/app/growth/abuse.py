"""Abuse controls for the public (unauthenticated) endpoints.

* fixed-window counters in Redis -- per client IP, per domain, and a global
  daily cap. A Redis outage FAILS CLOSED (503): an open public endpoint with
  no limiter is worse than a short outage.
* a pluggable CAPTCHA hook. The default verifier is a no-op so the feature
  works out of the box; set ``GROWTH_CAPTCHA_PROVIDER=turnstile`` (and the
  secret) to enforce Cloudflare Turnstile, or register your own verifier with
  :func:`set_captcha_verifier`.
* IP addresses are never stored: only a salted SHA-256, enough to correlate
  abuse without keeping the address.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Protocol

from fastapi import HTTPException

from ..netkey import client_key
from .config import growth_settings

logger = logging.getLogger(__name__)


def ip_hash(ip: str | None) -> str:
    raw = f"{growth_settings.ip_hash_salt}|{client_key(ip)}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def domain_key(domain: str) -> str:
    return hashlib.sha256(domain.encode()).hexdigest()[:24]


class RateLimited(HTTPException):
    def __init__(self, what: str, retry_after: int) -> None:
        super().__init__(
            status_code=429,
            detail=f"too many requests ({what}); try again later",
            headers={"Retry-After": str(max(1, retry_after))},
        )


async def hit(redis, key: str, limit: int, window_sec: int, *, what: str) -> int:
    """Count one event in a fixed window; raise 429 past ``limit``."""
    try:
        n = await redis.incr(key)
        if n == 1:
            await redis.expire(key, window_sec)
        ttl = await redis.ttl(key)
        if ttl is None or ttl < 0:  # key lost its expiry (crash between INCR/EXPIRE)
            await redis.expire(key, window_sec)
            ttl = window_sec
    except Exception as exc:  # noqa: BLE001
        logger.warning("growth_limiter_unavailable", extra={"error": type(exc).__name__})
        raise HTTPException(status_code=503, detail="temporarily unavailable") from exc
    if n > limit:
        raise RateLimited(what, ttl)
    return n


async def peek(redis, key: str) -> int:
    try:
        v = await redis.get(key)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail="temporarily unavailable") from exc
    return int(v) if v else 0


def today() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d")


async def limit_ip_post(redis, ip: str | None) -> None:
    await hit(redis, f"growth:ip:{ip_hash(ip)}:post:h", growth_settings.ip_requests_per_hour, 3600, what="per address")


async def limit_ip_get(redis, ip: str | None) -> None:
    await hit(redis, f"growth:ip:{ip_hash(ip)}:get:m", growth_settings.ip_reads_per_minute, 60, what="per address")


async def limit_domain(redis, domain: str) -> None:
    await hit(redis, f"growth:dom:{domain_key(domain)}:{today()}", growth_settings.domain_requests_per_day,
              86400, what="per domain")


async def limit_global(redis) -> None:
    await hit(redis, f"growth:global:{today()}", growth_settings.global_daily_cap, 86400, what="daily capacity")


# --------------------------------------------------------------------------- #
# CAPTCHA hook
# --------------------------------------------------------------------------- #

class CaptchaVerifier(Protocol):
    async def verify(self, token: str | None, ip: str | None) -> bool: ...


class NoopVerifier:
    """Default: accepts everything. Rate limits are the only gate."""

    async def verify(self, token: str | None, ip: str | None) -> bool:
        return True


class TurnstileVerifier:
    def __init__(self, secret: str, url: str, transport=None) -> None:
        self._secret, self._url, self._transport = secret, url, transport

    async def verify(self, token: str | None, ip: str | None) -> bool:
        if not token or len(token) > 4096:
            return False
        import httpx

        data = {"secret": self._secret, "response": token}
        if ip:
            data["remoteip"] = ip
        try:
            async with httpx.AsyncClient(timeout=5.0, transport=self._transport) as c:
                r = await c.post(self._url, data=data)
            return r.status_code == 200 and bool(r.json().get("success"))
        except Exception:  # noqa: BLE001 -- fail closed
            return False


_verifier: CaptchaVerifier | None = None


def set_captcha_verifier(v: CaptchaVerifier | None) -> None:
    """Install a verifier (tests, custom providers). ``None`` -> from settings."""
    global _verifier
    _verifier = v


def get_captcha_verifier() -> CaptchaVerifier:
    if _verifier is not None:
        return _verifier
    if growth_settings.captcha_provider == "turnstile" and growth_settings.turnstile_secret:
        return TurnstileVerifier(growth_settings.turnstile_secret, growth_settings.turnstile_verify_url)
    return NoopVerifier()
