"""Proof-of-control for scope entries (schema 021).

A scope entry is a claim -- "we may scan this". In a hosted scanner that claim
has to be PROVEN before it authorises anything, the same way ACME proves
domain control before issuing a certificate:

* ``domain``             -> DNS TXT ``_paddock-challenge.<domain>`` = token,
                            or an HTTPS file
                            ``https://<domain>/.well-known/paddock-verification/<token>``
                            whose body is the token.
* ``subdomain_wildcard`` -> DNS TXT only. Serving a file on the apex proves
                            control of one web server, not of the zone; ACME
                            draws the same line for wildcard certificates.
* ``ipv4_cidr`` / ``ipv6_cidr`` / ``asn`` -> nothing can be checked
                            automatically, so an admin records an
                            *attestation*: the authorization (LOA) reference,
                            the named approver, and who recorded it when.

With ``REQUIRE_SCOPE_PROOF=true`` only entries whose status is ``verified`` or
``attested`` match in :func:`app.scope.check`. The scheduler calls
:func:`reverify_due` to re-check verified proofs; one that keeps failing for
longer than the grace period is expired.

The verifier's own lookups are outbound requests to (or about) the target, so
they are deliberately minimal: one TXT query, or one HTTPS GET that reads at
most 1 KiB, identifies itself in the User-Agent, refuses private/metadata
addresses (shared guardrails in ``app.scope``), and never follows a redirect
off the host being verified. Checks of one entry are rate-limited.
"""
from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit

import asyncpg
from pydantic import BaseModel, Field

from . import scope as scope_svc
from .config import settings
from .models import ScopeEntryOut

logger = logging.getLogger(__name__)

ProofStatus = Literal["pending", "verified", "attested", "expired"]
ProofMethod = Literal["dns_txt", "http_file", "attestation"]

#: Statuses that authorise scans when REQUIRE_SCOPE_PROOF is on.
PROVEN_STATUSES = scope_svc.PROVEN_STATUSES

TXT_LABEL = "_paddock-challenge"
WELL_KNOWN = "/.well-known/paddock-verification/"
_HISTORY_MAX = 20
_BODY_MAX = 1024
_MAX_REDIRECTS = 3

_METHODS_BY_KIND: dict[str, tuple[str, ...]] = {
    "domain": ("dns_txt", "http_file"),
    "subdomain_wildcard": ("dns_txt",),
    "ipv4_cidr": ("attestation",),
    "ipv6_cidr": ("attestation",),
    "asn": ("attestation",),
}


def methods_for(kind: str) -> tuple[str, ...]:
    return _METHODS_BY_KIND.get(kind, ())


def is_automatic(kind: str) -> bool:
    return "dns_txt" in methods_for(kind)


def base_domain(value: str) -> str:
    v = value.strip().lower().rstrip(".")
    return v[2:] if v.startswith("*.") else v


def challenge_name(base: str) -> str:
    return f"{TXT_LABEL}.{base}"


def challenge_url(base: str, token: str) -> str:
    return f"https://{base}{WELL_KNOWN}{token}"


def new_token() -> str:
    # URL-safe (A-Z a-z 0-9 - _), fits a TXT string and a URL path segment.
    return secrets.token_urlsafe(24)


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(ts: datetime | None) -> datetime | None:
    if ts is None:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


# --------------------------------------------------------------------------- #
# API models (kept in this module; models.py is shared)
# --------------------------------------------------------------------------- #

class ScopeProofOut(BaseModel):
    status: ProofStatus = "pending"
    method: ProofMethod | None = None
    methods: list[str] = Field(default_factory=list)
    token_issued: bool = False
    verified_at: datetime | None = None
    last_checked_at: datetime | None = None
    last_ok_at: datetime | None = None
    last_error: str | None = None
    failing_since: datetime | None = None
    grace_until: datetime | None = None
    expired_at: datetime | None = None
    loa_ref: str | None = None
    approver: str | None = None
    attested_by: str | None = None
    attested_at: datetime | None = None
    attestation_expires_at: datetime | None = None
    #: REQUIRE_SCOPE_PROOF is on for this deployment.
    required: bool = False
    #: This entry authorises scans right now (active + proof, when required).
    effective: bool = True


class ScopeEntryWithProofOut(ScopeEntryOut):
    proof: ScopeProofOut = Field(default_factory=ScopeProofOut)


class ChallengeOut(BaseModel):
    scope_entry_id: int
    kind: str
    domain: str
    token: str
    methods: list[str]
    dns_txt: dict[str, str]
    http_file: dict[str, str] | None = None
    proof: ScopeProofOut


class VerifyIn(BaseModel):
    #: dns_txt / http_file for domains (omit to try every allowed method);
    #: attestation for IP ranges and ASNs.
    method: ProofMethod | None = None
    loa_ref: str | None = Field(default=None, max_length=512)
    approver: str | None = Field(default=None, max_length=256)
    valid_until: datetime | None = None


class CheckOut(BaseModel):
    ok: bool
    method: str
    detail: str


class VerifyOut(BaseModel):
    scope_entry_id: int
    check: CheckOut
    proof: ScopeProofOut


# --------------------------------------------------------------------------- #
# Row -> model
# --------------------------------------------------------------------------- #

_PROOF_COLS = (
    "status, method, token, token_issued_at, verified_at, last_checked_at, "
    "last_ok_at, last_error, failing_since, expired_at, loa_ref, approver, "
    "attested_by, attested_at, attestation_expires_at, history"
)


def proof_out(kind: str, active: bool, row: Any | None) -> ScopeProofOut:
    d = dict(row) if row is not None else {}
    status = d.get("status") or "pending"
    failing = _aware(d.get("failing_since"))
    grace_until = (
        failing + timedelta(hours=settings.scope_proof_grace_hours) if failing else None
    )
    required = bool(settings.require_scope_proof)
    effective = bool(active) and (not required or status in PROVEN_STATUSES)
    return ScopeProofOut(
        status=status,
        method=d.get("method"),
        methods=list(methods_for(kind)),
        token_issued=bool(d.get("token")),
        verified_at=d.get("verified_at"),
        last_checked_at=d.get("last_checked_at"),
        last_ok_at=d.get("last_ok_at"),
        last_error=d.get("last_error"),
        failing_since=failing,
        grace_until=grace_until,
        expired_at=d.get("expired_at"),
        loa_ref=d.get("loa_ref"),
        approver=d.get("approver"),
        attested_by=d.get("attested_by"),
        attested_at=d.get("attested_at"),
        attestation_expires_at=d.get("attestation_expires_at"),
        required=required,
        effective=effective,
    )


async def fetch_proof_row(con, entry_id: int):
    return await con.fetchrow(
        f"SELECT {_PROOF_COLS} FROM scope_proofs WHERE scope_entry_id = $1", entry_id
    )


async def fetch_proof_rows(con, entry_ids: list[int]) -> dict[int, Any]:
    """Proof rows keyed by entry id; {} when schema 021 isn't applied yet."""
    if not entry_ids:
        return {}
    try:
        rows = await con.fetch(
            f"SELECT scope_entry_id, {_PROOF_COLS} FROM scope_proofs "
            "WHERE scope_entry_id = ANY($1::int[])",
            entry_ids,
        )
    except asyncpg.UndefinedTableError:
        logger.warning("scope_proofs table missing; apply schema/021_scope_proof.sql")
        return {}
    return {r["scope_entry_id"]: r for r in rows}


# --------------------------------------------------------------------------- #
# The checks (outbound; tests replace lookup_txt / fetch_http)
# --------------------------------------------------------------------------- #

@dataclass
class CheckResult:
    ok: bool
    method: str
    detail: str


async def lookup_txt(name: str) -> list[str]:
    """Return every TXT string at ``name`` (chunks joined). [] if none."""
    try:
        import dns.asyncresolver  # type: ignore
        import dns.exception  # type: ignore
        import dns.resolver  # type: ignore
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise RuntimeError("DNS TXT lookup unavailable (dnspython not installed)") from exc
    try:
        answer = await dns.asyncresolver.resolve(
            name.rstrip(".") + ".", "TXT", lifetime=settings.scope_proof_timeout_sec,
            search=False,
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        raise RuntimeError(f"DNS lookup failed: {exc.__class__.__name__}") from exc
    out: list[str] = []
    for rdata in answer:
        chunks = getattr(rdata, "strings", ()) or ()
        out.append(b"".join(chunks).decode("utf-8", "replace"))
    return out


class FetchRefused(Exception):
    """The verifier refused to make (or continue) the request."""


async def fetch_http(url: str) -> tuple[int, str]:
    """GET ``url`` minimally: https only, public addresses only, same-host
    redirects only (max 3), first 1 KiB of the body only."""
    import httpx

    from .integrations.netsafety import UnsafeURL, validate_outbound_url

    host = scope_svc.normalize(url)
    headers = {
        "User-Agent": settings.scope_proof_user_agent,
        "Accept": "text/plain, */*;q=0.1",
    }
    async with httpx.AsyncClient(
        timeout=settings.scope_proof_timeout_sec, follow_redirects=False, headers=headers,
    ) as client:
        current = url
        for _ in range(_MAX_REDIRECTS + 1):
            if urlsplit(current).scheme != "https":
                raise FetchRefused("only https is used for the file check")
            if scope_svc.normalize(current) != host:
                raise FetchRefused("redirect to a different host refused")
            try:
                await validate_outbound_url(current)
            except UnsafeURL as exc:
                raise FetchRefused(str(exc)) from exc
            async with client.stream("GET", current) as resp:
                if resp.is_redirect:
                    loc = resp.headers.get("location", "")
                    current = urljoin(current, loc)
                    continue
                body = b""
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) >= _BODY_MAX:
                        break
                return resp.status_code, body[:_BODY_MAX].decode("utf-8", "replace")
        raise FetchRefused("too many redirects")


async def check_dns(base: str, token: str) -> CheckResult:
    name = challenge_name(base)
    try:
        values = await lookup_txt(name)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(False, "dns_txt", f"TXT lookup for {name} failed: {exc}")
    cleaned = [v.strip().strip('"').strip() for v in values]
    if token in cleaned:
        return CheckResult(True, "dns_txt", f"TXT {name} matches")
    if not cleaned:
        return CheckResult(False, "dns_txt", f"no TXT record at {name}")
    return CheckResult(False, "dns_txt", f"TXT record at {name} does not contain the token")


async def check_http(base: str, token: str) -> CheckResult:
    url = challenge_url(base, token)
    try:
        status, body = await fetch_http(url)
    except FetchRefused as exc:
        return CheckResult(False, "http_file", f"{url}: refused: {exc}")
    except Exception as exc:  # noqa: BLE001
        return CheckResult(False, "http_file", f"{url}: {exc.__class__.__name__}")
    if status != 200:
        return CheckResult(False, "http_file", f"{url} returned HTTP {status}")
    if body.strip() != token:
        return CheckResult(False, "http_file", f"{url} body does not equal the token")
    return CheckResult(True, "http_file", f"{url} matches")


_CHECKS = {"dns_txt": check_dns, "http_file": check_http}


async def run_check(kind: str, base: str, token: str, method: str | None) -> CheckResult:
    allowed = [m for m in methods_for(kind) if m in _CHECKS]
    if method is not None and method not in allowed:
        return CheckResult(False, method, f"{method} cannot prove a {kind} entry")
    details: list[str] = []
    for m in [method] if method else allowed:
        res = await _CHECKS[m](base, token)
        if res.ok:
            return res
        details.append(res.detail)
    return CheckResult(False, method or "+".join(allowed), "; ".join(details))


# --------------------------------------------------------------------------- #
# State transitions
# --------------------------------------------------------------------------- #

def _history(row: Any | None, item: dict[str, Any]) -> str:
    prev = []
    if row is not None:
        h = row["history"]
        prev = json.loads(h) if isinstance(h, str) else list(h or [])
    return json.dumps(([item] + prev)[:_HISTORY_MAX], default=str)


async def ensure_challenge(pool, entry: dict[str, Any]) -> tuple[str, Any]:
    """Return the entry's challenge token, issuing one if it has none.

    Idempotent: the token is stable per entry (re-verification checks the
    same value), so re-opening the wizard shows the same record to publish.
    """
    async with pool.acquire() as con:
        async with con.transaction():
            row = await con.fetchrow(
                f"SELECT {_PROOF_COLS} FROM scope_proofs WHERE scope_entry_id = $1 FOR UPDATE",
                entry["id"],
            )
            if row is not None and row["token"]:
                return row["token"], row
            token = new_token()
            row = await con.fetchrow(
                f"""
                INSERT INTO scope_proofs (scope_entry_id, token, token_issued_at)
                VALUES ($1, $2, NOW())
                ON CONFLICT (scope_entry_id) DO UPDATE
                   SET token = EXCLUDED.token, token_issued_at = NOW(), updated_at = NOW()
                RETURNING {_PROOF_COLS}
                """,
                entry["id"],
                token,
            )
            return token, row


class TooSoon(Exception):
    def __init__(self, retry_after: float) -> None:
        super().__init__(retry_after)
        self.retry_after = retry_after


async def verify_entry(
    pool, entry: dict[str, Any], method: str | None, actor: str, now: datetime | None = None,
    *, enforce_interval: bool = True,
) -> tuple[CheckResult, Any, str | None, str]:
    """Run an automatic check for ``entry`` and record the outcome.

    Returns (result, new_row, old_status, new_status). Raises ``LookupError``
    when no challenge was issued and ``TooSoon`` when rate-limited.
    """
    now = now or _now()
    async with pool.acquire() as con:
        row = await fetch_proof_row(con, entry["id"])
    if row is None or not row["token"]:
        raise LookupError("no challenge issued for this entry; POST .../challenge first")
    last = _aware(row["last_checked_at"])
    if enforce_interval and last is not None:
        elapsed = (now - last).total_seconds()
        # (A last check "in the future" -- clock skew -- never locks an entry.)
        if 0 <= elapsed < settings.scope_proof_min_interval_sec:
            raise TooSoon(settings.scope_proof_min_interval_sec - elapsed)

    result = await run_check(entry["kind"], base_domain(entry["value"]), row["token"], method)
    new_row, old, new = await _record(pool, entry["id"], result, actor, now)
    return result, new_row, old, new


async def _record(pool, entry_id: int, result: CheckResult, actor: str, now: datetime):
    grace = timedelta(hours=settings.scope_proof_grace_hours)
    async with pool.acquire() as con:
        async with con.transaction():
            row = await con.fetchrow(
                f"SELECT {_PROOF_COLS} FROM scope_proofs WHERE scope_entry_id = $1 FOR UPDATE",
                entry_id,
            )
            old = row["status"] if row is not None else "pending"
            failing = _aware(row["failing_since"]) if row is not None else None
            hist = _history(row, {
                "at": now.isoformat(), "method": result.method, "ok": result.ok,
                "detail": result.detail[:300], "by": actor,
            })
            if result.ok:
                new, failing, expired_at, err = "verified", None, None, None
                method = result.method
            else:
                err = result.detail[:500]
                method = row["method"] if row is not None else None
                expired_at = row["expired_at"] if row is not None else None
                if old == "verified":
                    failing = failing or now
                    new = "verified"
                    if now - failing >= grace:
                        new, expired_at = "expired", now
                else:
                    new = old  # pending stays pending, expired stays expired
            updated = await con.fetchrow(
                f"""
                UPDATE scope_proofs
                   SET status = $2, method = $3,
                       verified_at = CASE WHEN $4::bool THEN COALESCE(verified_at, $5) ELSE verified_at END,
                       last_ok_at = CASE WHEN $4::bool THEN $5 ELSE last_ok_at END,
                       last_checked_at = $5, last_error = $6, failing_since = $7,
                       expired_at = $8, history = $9::jsonb, updated_at = NOW()
                 WHERE scope_entry_id = $1
             RETURNING {_PROOF_COLS}
                """,
                entry_id, new, method, result.ok, now, err, failing, expired_at, hist,
            )
    if new != old:
        scope_svc.scope_cache.invalidate()
        logger.info(
            "scope_proof_status_changed",
            extra={"scope_entry_id": entry_id, "from": old, "to": new, "method": result.method},
        )
    return updated, old, new


async def attest_entry(
    pool, entry: dict[str, Any], *, loa_ref: str, approver: str, actor: str,
    valid_until: datetime | None, now: datetime | None = None,
):
    """Record an authorization attestation for an IP range / ASN entry."""
    now = now or _now()
    hist_item = {
        "at": now.isoformat(), "method": "attestation", "ok": True,
        "detail": f"LOA {loa_ref[:120]} approved by {approver[:80]}", "by": actor,
    }
    async with pool.acquire() as con:
        async with con.transaction():
            row = await con.fetchrow(
                f"SELECT {_PROOF_COLS} FROM scope_proofs WHERE scope_entry_id = $1 FOR UPDATE",
                entry["id"],
            )
            old = row["status"] if row is not None else "pending"
            updated = await con.fetchrow(
                f"""
                INSERT INTO scope_proofs
                    (scope_entry_id, status, method, loa_ref, approver, attested_by,
                     attested_at, attestation_expires_at, last_checked_at, last_ok_at,
                     history)
                VALUES ($1, 'attested', 'attestation', $2, $3, $4, $5, $6, $5, $5, $7::jsonb)
                ON CONFLICT (scope_entry_id) DO UPDATE
                   SET status = 'attested', method = 'attestation',
                       loa_ref = EXCLUDED.loa_ref, approver = EXCLUDED.approver,
                       attested_by = EXCLUDED.attested_by, attested_at = EXCLUDED.attested_at,
                       attestation_expires_at = EXCLUDED.attestation_expires_at,
                       last_checked_at = EXCLUDED.last_checked_at,
                       last_ok_at = EXCLUDED.last_ok_at, last_error = NULL,
                       failing_since = NULL, expired_at = NULL,
                       history = EXCLUDED.history, updated_at = NOW()
             RETURNING {_PROOF_COLS}
                """,
                entry["id"], loa_ref, approver, actor, now, valid_until,
                _history(row, hist_item),
            )
    scope_svc.scope_cache.invalidate()
    return updated, old


# --------------------------------------------------------------------------- #
# Periodic re-verification (called from the scheduler loop)
# --------------------------------------------------------------------------- #

_last_sweep: float = 0.0


async def reverify_due(pool, r=None, now: datetime | None = None, *, batch: int = 20) -> dict[str, int]:
    """Re-check verified proofs that are due and expire lapsed ones.

    * attestation past ``attestation_expires_at``      -> expired
    * verified proof failing longer than the grace     -> expired
    * verified proof not checked for REVERIFY hours    -> re-checked (the same
      method that proved it); a failing proof is re-checked hourly.

    Bounded to ``batch`` outbound checks per call so a big scope list never
    turns the scheduler into a request generator.
    """
    now = now or _now()
    grace = timedelta(hours=settings.scope_proof_grace_hours)
    every = timedelta(hours=settings.scope_proof_reverify_hours)
    failing_every = min(every, timedelta(hours=1))
    summary = {"checked": 0, "ok": 0, "failed": 0, "expired": 0}
    async with pool.acquire() as con:
        try:
            lapsed = await con.fetch(
                """
                UPDATE scope_proofs
                   SET status = 'expired', expired_at = $1, updated_at = NOW(),
                       last_error = CASE WHEN status = 'attested'
                                         THEN 'attestation validity ended'
                                         ELSE COALESCE(last_error, 'proof lost') END
                 WHERE (status = 'attested' AND attestation_expires_at IS NOT NULL
                        AND attestation_expires_at <= $1)
                    OR (status = 'verified' AND failing_since IS NOT NULL
                        AND failing_since <= $2)
             RETURNING scope_entry_id
                """,
                now, now - grace,
            )
        except asyncpg.UndefinedTableError:
            return summary
        due = await con.fetch(
            """
            SELECT e.id, e.kind, e.value, p.method
              FROM scope_proofs p JOIN scope_entries e ON e.id = p.scope_entry_id
             WHERE e.active = TRUE
               AND p.status = 'verified'
               AND p.method IN ('dns_txt', 'http_file')
               AND (p.last_checked_at IS NULL
                    OR (p.failing_since IS NULL AND p.last_checked_at <= $1)
                    OR (p.failing_since IS NOT NULL AND p.last_checked_at <= $2))
             ORDER BY p.last_checked_at NULLS FIRST
             LIMIT $3
            """,
            now - every, now - failing_every, batch,
        )
    summary["expired"] += len(lapsed)
    expired_ids = [row["scope_entry_id"] for row in lapsed]
    for row in due:
        entry = dict(row)
        try:
            res, _, _, new = await verify_entry(
                pool, entry, entry.get("method"), "scheduler", now, enforce_interval=False,
            )
        except Exception:  # noqa: BLE001 - one bad entry never stops the sweep
            logger.exception("scope_proof_reverify_failed", extra={"scope_entry_id": entry["id"]})
            continue
        summary["checked"] += 1
        summary["ok" if res.ok else "failed"] += 1
        if new == "expired":
            summary["expired"] += 1
            expired_ids.append(entry["id"])
    if expired_ids:
        scope_svc.scope_cache.invalidate()
        logger.warning("scope_proof_expired", extra={"scope_entry_ids": expired_ids})
        if r is not None:
            from .queue import publish_event

            for eid in expired_ids:
                try:
                    await publish_event(r, {"event": "scope_proof_expired", "scope_entry_id": eid})
                except Exception:  # noqa: BLE001
                    logger.exception("publish_event_failed")
    return summary


async def maybe_reverify(pool, r=None) -> None:
    """Scheduler hook: sweep at most every 5 minutes (the loop ticks faster)."""
    global _last_sweep
    import time

    if time.monotonic() - _last_sweep < 300:
        return
    _last_sweep = time.monotonic()
    summary = await reverify_due(pool, r)
    if any(summary.values()):
        logger.info("scope_proof_sweep", extra=summary)


__all__ = [
    "PROVEN_STATUSES",
    "ChallengeOut",
    "ScopeEntryWithProofOut",
    "ScopeProofOut",
    "VerifyIn",
    "VerifyOut",
    "attest_entry",
    "base_domain",
    "challenge_name",
    "challenge_url",
    "ensure_challenge",
    "methods_for",
    "proof_out",
    "reverify_due",
    "run_check",
    "verify_entry",
]
