"""Shared plumbing for the safe verification checks.

Everything a check may do to a target is defined here, so the safety envelope
is reviewable in one file:

* HTTP: ``GET`` and ``HEAD`` only (``SafeFetcher._send`` refuses anything
  else), ``Accept-Encoding: identity`` (no decompression bombs), a hard byte
  cap per response, a strict timeout, at most ``MAX_REDIRECTS`` redirects, and
  the scope guard on EVERY request including each redirect hop. Redirects are
  followed by hand and ONLY to the same hostname: the job's proof-of-control
  covers the finding's host, so a hop to another (possibly unproven) host is
  refused and recorded (``Fetch.redirect_blocked``) instead of fetched.
  Connections dial only the addresses the orchestrator vetted (see
  ``app/pinned.py``); TCP/TLS checks do the same.
* TLS: handshake only (``tls.py``); TCP: connect + passive banner read
  (``port.py``). Nothing is ever written to a service socket.
* Evidence: redacted (secret-shaped values never leave the worker) and
  size-capped before it is returned.
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Literal
from urllib.parse import urlsplit

import httpx
import structlog

from app.orchestrator import new_outbound_row
from app.scope_guard import ScopeDenied  # noqa: F401  (re-exported: callers catch it)

log = structlog.get_logger(__name__)

Verdict = Literal["confirmed", "not_reproducible", "inconclusive"]

ALLOWED_METHODS = frozenset({"GET", "HEAD"})
HTTP_TIMEOUT_SEC = 8.0
MAX_REDIRECTS = 3
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_BODY_BYTES = 16 * 1024          # per response, read cap
MAX_EXCERPT_CHARS = 160
MAX_EVIDENCE_BYTES = 4096           # serialized evidence cap
CONNECT_TIMEOUT_SEC = 6.0


class MethodRefused(RuntimeError):
    """A check tried to use an HTTP method outside GET/HEAD. A bug, never normal."""


# --------------------------------------------------------------------------- #
# Redaction + size cap
# --------------------------------------------------------------------------- #

_KV_SECRET = re.compile(
    r"(?im)^(\s*[A-Za-z0-9_.\-]*(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|credential|auth)[A-Za-z0-9_.\-]*\s*[=:]\s*)\S.*$"
)
_ENV_LINE = re.compile(r"(?m)^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=\s*).+$")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{8,}")
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9+/_\-]{32,}={0,2}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")
_URL_CRED = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s:@]+:[^/\s@]+@")


def redact_text(text: str) -> str:
    """Strip secret-shaped content from a text excerpt."""
    text = _PRIVATE_KEY.sub("<redacted private key>", text)
    text = _URL_CRED.sub(r"\1<redacted>@", text)
    text = _KV_SECRET.sub(r"\1<redacted>", text)
    text = _ENV_LINE.sub(r"\1<redacted>", text)
    text = _AWS_KEY.sub("<redacted>", text)
    text = _BEARER.sub(r"\1 <redacted>", text)
    text = _LONG_TOKEN.sub("<redacted>", text)
    return text


def excerpt(data: bytes | str, limit: int = MAX_EXCERPT_CHARS) -> str:
    """A short, printable, redacted excerpt of a response body."""
    if isinstance(data, bytes):
        data = data[: limit * 8].decode("utf-8", errors="replace")
    data = redact_text(data)
    data = "".join(ch if ch.isprintable() or ch in "\n\t" else "?" for ch in data)
    data = re.sub(r"[ \t]+", " ", data).strip()
    return data[:limit] + ("..." if len(data) > limit else "")


def sha_prefix(data: bytes, n: int = 16) -> str:
    return hashlib.sha256(data).hexdigest()[:n]


def cap_evidence(ev: dict[str, Any], limit: int = MAX_EVIDENCE_BYTES) -> dict[str, Any]:
    """Return ``ev`` with every string clipped and the whole dict <= ``limit``
    bytes when JSON-serialised (longest values are dropped first)."""
    import json

    def clip(v: Any, depth: int = 0) -> Any:
        if isinstance(v, str):
            return v if len(v) <= 300 else v[:300] + "..."
        if isinstance(v, (list, tuple)):
            return [clip(x, depth + 1) for x in list(v)[:20]]
        if isinstance(v, dict) and depth < 3:
            return {str(k)[:64]: clip(x, depth + 1) for k, x in list(v.items())[:30]}
        if isinstance(v, (int, float, bool)) or v is None:
            return v
        return str(v)[:300]

    out = {str(k)[:64]: clip(v) for k, v in ev.items()}
    while len(json.dumps(out, default=str)) > limit and out:
        # drop the biggest value until it fits
        biggest = max(out, key=lambda k: len(json.dumps(out[k], default=str)))
        if len(out) == 1:
            out[biggest] = "<truncated>"
            break
        del out[biggest]
        out["truncated"] = True
    return out


# --------------------------------------------------------------------------- #
# Context objects
# --------------------------------------------------------------------------- #

@dataclass
class CheckResult:
    verdict: Verdict
    check_id: str
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "check_id": self.check_id,
            "reason": self.reason[:500],
            "evidence": cap_evidence(self.evidence),
            "checked_at": self.checked_at,
        }


def confirmed(check_id: str, reason: str, **evidence: Any) -> CheckResult:
    return CheckResult("confirmed", check_id, reason, evidence)


def not_reproducible(check_id: str, reason: str, **evidence: Any) -> CheckResult:
    return CheckResult("not_reproducible", check_id, reason, evidence)


def inconclusive(check_id: str, reason: str, **evidence: Any) -> CheckResult:
    return CheckResult("inconclusive", check_id, reason, evidence)


@dataclass
class FindingCtx:
    """The slice of a finding a check needs (sent by the orchestrator)."""

    id: str
    rule_id: str
    rule_source: str
    severity: str = "info"
    title: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    asset_kind: str = "endpoint"
    asset_value: str = ""

    @classmethod
    def from_job(cls, d: dict[str, Any]) -> "FindingCtx":
        asset = d.get("asset") or {}
        return cls(
            id=str(d.get("id") or ""),
            rule_id=str(d.get("rule_id") or ""),
            rule_source=str(d.get("rule_source") or ""),
            severity=str(d.get("severity") or "info"),
            title=str(d.get("title") or ""),
            evidence=dict(d.get("evidence") or {}),
            metadata=dict(d.get("metadata") or {}),
            asset_kind=str(asset.get("kind") or d.get("asset_kind") or "endpoint"),
            asset_value=str(asset.get("value") or d.get("asset_value") or ""),
        )

    # -- derived targets ---------------------------------------------------- #

    def evidence_url(self) -> str | None:
        for k in ("url", "matched_at", "matched-at", "target_url"):
            v = self.evidence.get(k)
            if isinstance(v, str) and v.startswith(("http://", "https://")):
                return v
        return None

    @property
    def host(self) -> str:
        u = self.evidence_url()
        if u:
            return (urlsplit(u).hostname or "").lower()
        return _host_port(self.asset_value)[0]

    @property
    def port(self) -> int | None:
        u = self.evidence_url()
        if u:
            sp = urlsplit(u)
            return sp.port or (443 if sp.scheme == "https" else 80)
        p = self.evidence.get("port")
        if isinstance(p, int) or (isinstance(p, str) and p.isdigit()):
            return int(p)
        return _host_port(self.asset_value)[1]

    def base_url(self) -> str | None:
        u = self.evidence_url()
        if u:
            sp = urlsplit(u)
            return f"{sp.scheme}://{sp.netloc}/"
        h, p = _host_port(self.asset_value)
        if not h:
            return None
        if "://" in self.asset_value:
            sp = urlsplit(self.asset_value)
            return f"{sp.scheme}://{sp.netloc}/"
        return f"https://{h}{':' + str(p) if p not in (None, 443) else ''}/"


def _host_port(value: str) -> tuple[str, int | None]:
    v = (value or "").strip()
    if "://" in v:
        sp = urlsplit(v)
        return (sp.hostname or "").lower(), sp.port
    v = v.split("/", 1)[0]
    if v.startswith("["):  # [v6]:port
        host, _, rest = v[1:].partition("]")
        return host.lower(), int(rest[1:]) if rest[1:].isdigit() else None
    host, sep, port = v.rpartition(":")
    if sep and port.isdigit() and ":" not in host:
        return host.lower(), int(port)
    return v.lower(), None


@dataclass
class CheckEnv:
    """Everything a check may touch. Built once per job by the runner."""

    scope: Any                      # ScopeGuard
    politeness: Any | None = None   # PolitenessLimiter
    orchestrator: Any | None = None  # OrchestratorClient (audit log)
    # Seams for tests (real implementations are the defaults).
    tls_handshake: Callable[..., Awaitable[Any]] | None = None
    tcp_banner: Callable[..., Awaitable[Any]] | None = None
    cname_lookup: Callable[[str], Awaitable[tuple[list[str], str | None]]] | None = None
    http_client_kwargs: dict[str, Any] = field(default_factory=dict)
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)

    async def audit(self, **row: Any) -> None:
        if self.orchestrator is None:
            return
        try:
            await self.orchestrator.outbound_log(new_outbound_row(**row))
        except Exception:  # noqa: BLE001 -- audit is best effort here; the orchestrator also logs
            log.warning("safe_check.audit_failed")


async def vetted_addrs(env: "CheckEnv", host: str, port: int) -> list[str]:
    """Scope-check ``host:port`` and return the vetted addresses a raw TCP/TLS
    connection may dial (raises ScopeDenied when none)."""
    return await env.scope.vetted_addrs(f"{host}:{port}")


# --------------------------------------------------------------------------- #
# HTTP: GET / HEAD only
# --------------------------------------------------------------------------- #

@dataclass
class Fetch:
    url: str                      # final URL after redirects
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)   # lower-cased names
    body: bytes = b""
    truncated: bool = False
    error: str | None = None
    redirected: bool = False
    redirect_blocked: str | None = None   # cross-host redirect target we refused to follow

    @property
    def ok(self) -> bool:
        return self.error is None and self.status > 0

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class SafeFetcher:
    """GET/HEAD with a byte cap, strict timeout and scope-checked redirects."""

    def __init__(self, env: CheckEnv, tool: str):
        self.env = env
        self.tool = f"safe_check:{tool}"

    async def get(self, url: str, *, max_bytes: int = MAX_BODY_BYTES) -> Fetch:
        return await self._send("GET", url, max_bytes)

    async def head(self, url: str) -> Fetch:
        return await self._send("HEAD", url, 0)

    async def _send(self, method: str, url: str, max_bytes: int) -> Fetch:
        if method not in ALLOWED_METHODS:  # defense in depth: no check may ever mutate
            raise MethodRefused(method)
        scope = self.env.scope
        await scope.allow(url)  # raises ScopeDenied: nothing is sent
        host = (urlsplit(url).hostname or "").lower()
        kwargs = dict(self.env.http_client_kwargs)
        client = scope.build_client(
            follow_redirects=False,  # hops are followed below, same host only
            timeout=httpx.Timeout(HTTP_TIMEOUT_SEC),
            verify=False,  # reading the response is the point; cert state has its own checks
            headers={"Accept-Encoding": "identity"},
            **kwargs,
        )
        started = time.monotonic()
        out = Fetch(url=url)
        try:
            async with _polite(self.env.politeness, host):
                cur = url
                for hop in range(MAX_REDIRECTS + 1):
                    async with client.stream(method, cur) as resp:
                        out.url = str(resp.url)
                        out.status = resp.status_code
                        out.headers = {k.lower(): v for k, v in resp.headers.items()}
                        loc = resp.headers.get("location")
                        if resp.status_code in REDIRECT_STATUSES and loc:
                            nxt = str(resp.url.join(loc))
                            if hop >= MAX_REDIRECTS:
                                out.error = "too many redirects"
                                break
                            out.redirected = True
                            # Same scope + proof gate as the first request.
                            await scope.allow(nxt)
                            if (urlsplit(nxt).hostname or "").lower() != host:
                                # The job proves THIS host only; another in-scope
                                # host may be unproven. Record, do not fetch.
                                out.url = nxt
                                out.redirect_blocked = nxt
                                break
                            cur = nxt
                            continue
                        if method == "GET" and max_bytes > 0:
                            buf = bytearray()
                            try:
                                async for chunk in resp.aiter_raw():
                                    buf += chunk
                                    if len(buf) >= max_bytes:
                                        out.truncated = True
                                        break
                            except httpx.StreamConsumed:  # in-memory transports pre-read the body
                                buf = bytearray(resp.content)
                                out.truncated = len(buf) > max_bytes
                            out.body = bytes(buf[:max_bytes])
                        break
                if self.env.politeness is not None:
                    self.env.politeness.record_response(
                        host, out.status, out.headers.get("retry-after"))
        except ScopeDenied:
            raise
        except httpx.TooManyRedirects:
            out.error = "too many redirects"
        except httpx.TimeoutException:
            out.error = "timeout"
        except httpx.HTTPError as e:
            out.error = f"{type(e).__name__}: {str(e)[:120]}"
        finally:
            await client.aclose()
        await self.env.audit(
            target=out.url, tool=self.tool, method=method,
            response_code=out.status or None, scope_matched=True,
            duration_ms=int((time.monotonic() - started) * 1000),
            bytes_in=len(out.body), error=out.error,
        )
        return out


class _polite:
    """``async with`` wrapper that is a no-op without a limiter."""

    def __init__(self, limiter: Any | None, host: str):
        self._cm = limiter.acquire(host) if limiter is not None else None

    async def __aenter__(self):
        if self._cm is not None:
            await self._cm.__aenter__()

    async def __aexit__(self, *exc):
        if self._cm is not None:
            return await self._cm.__aexit__(*exc)
        return False


# Statuses that say "the server is refusing/failing us", not "the thing is gone".
SUSPECT_BLOCK = frozenset({403, 406, 418, 451})
TRANSIENT = frozenset({408, 425, 429, 500, 502, 503, 504})


async def blocked_by_server(fetcher: SafeFetcher, base_url: str, status: int) -> str | None:
    """A 403 on the exact path may be a WAF blocking the scanner rather than a fix.
    Fetch the site root as a control: if it is blocked or unreachable too, the
    path result proves nothing. Returns a reason string when blocked, else None.
    """
    if status not in SUSPECT_BLOCK:
        return None
    ctl = await fetcher.get(base_url, max_bytes=1024)
    if not ctl.ok:
        return f"control request to {base_url} failed ({ctl.error})"
    if ctl.status in SUSPECT_BLOCK or ctl.status in TRANSIENT:
        return f"site root also answers {ctl.status}; the host may be blocking the verifier"
    return None
