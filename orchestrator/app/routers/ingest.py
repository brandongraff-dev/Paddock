"""Universal ingest: ``POST /v1/ingest`` + ingest-source management.

``POST /v1/ingest`` takes the raw output of a scanner (SARIF, CycloneDX, SPDX,
OCSF, Trivy, Grype, Semgrep, Nuclei, ZAP, CSV; auto-detected) and turns it into
findings / components / assets with source attribution and the same lifecycle
dedupe as Paddock's own engines.

Authentication (the route is public at the RBAC layer; the handler decides):

* an **ingest token** (``X-Paddock-Ingest-Token``, ``Authorization: Bearer
  pdi_...`` or ``?token=``) minted for one *source* by an admin. It is scoped
  to ingest only, revocable, rate-limited per source and every accepted or
  rejected upload is written to the audit chain and the ingest log;
* or a normal API key / session with the ``scan`` capability.

Management (admin): ``/v1/ingest/sources`` (create / list / patch / rotate /
revoke). Read: ``/v1/ingest/log``, ``/v1/ingest/formats``.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import time
from collections import deque
from typing import Any, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .. import audit, tenancy
from ..auth import client_ip
from ..db import get_pool
from ..netkey import client_key
from ..ingest import CSV_COLUMNS, FORMATS, Hints, IngestError, decode_body, parse_payload, store, tokens
from ..queue import get_redis, publish_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/ingest", tags=["ingest"])

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PROJECT_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,200}$")
MAX_EVENTS = 1000


def _int_env(name: str, default: int) -> int:
    try:
        return max(1024, int(os.environ.get(name, default)))
    except ValueError:
        return default


def max_bytes() -> int:
    return _int_env("PADDOCK_INGEST_MAX_BYTES", 25 * 1024 * 1024)


def max_findings() -> int:
    return _int_env("PADDOCK_INGEST_MAX_FINDINGS", 50_000)


class _Window:
    """Sliding one-minute window per key (in process memory; bounded)."""

    MAX_KEYS = 10_000

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}

    def _sweep(self, now: float) -> None:
        for k in [k for k, v in self._hits.items() if not v or now - v[-1] > 60.0]:
            self._hits.pop(k, None)
        if len(self._hits) >= self.MAX_KEYS:  # all live: drop the least active tenth
            for k in sorted(self._hits, key=lambda k: len(self._hits[k]))[: self.MAX_KEYS // 10]:
                self._hits.pop(k, None)

    def _queue(self, key: str, now: float) -> deque[float]:
        q = self._hits.get(key)
        if q is None:
            if len(self._hits) >= self.MAX_KEYS:
                self._sweep(now)
            q = self._hits[key] = deque(maxlen=6001)
        while q and now - q[0] > 60.0:
            q.popleft()
        return q

    def allow(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        q = self._queue(key, now)
        if len(q) >= limit:
            return False
        q.append(now)
        return True

    def hit(self, key: str) -> int:
        now = time.monotonic()
        q = self._queue(key, now)
        q.append(now)
        return len(q)

    def reset(self) -> None:
        self._hits.clear()


rate_limiter = _Window()          # per source id
failure_limiter = _Window()       # bad-token attempts per client ip
FAILED_PER_MIN = 30


def _json(status: int, body: dict[str, Any], headers: Optional[dict[str, str]] = None) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers=headers)


def _extract_token(request: Request, query_token: Optional[str]) -> Optional[str]:
    t = request.headers.get("x-paddock-ingest-token")
    if not t:
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer ") and auth[7:].strip().startswith(tokens.TOKEN_PREFIX):
            t = auth[7:].strip()
    return (t or query_token or "").strip() or None


async def _read_body(request: Request, limit: int) -> bytes:
    cl = request.headers.get("content-length")
    if cl is not None:
        if not cl.isdigit():
            raise IngestError("bad Content-Length", 400)
        if int(cl) > limit:
            raise IngestError(f"body exceeds {limit} bytes", 413)
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > limit:
            raise IngestError(f"body exceeds {limit} bytes", 413)
    return bytes(buf)


def _parse_sync(raw: bytes, *, gzipped: bool, fmt: Optional[str], hints: Hints, limit: int):
    return parse_payload(decode_body(raw, gzipped=gzipped, max_bytes=limit), fmt, hints)


async def _log(pool, *, source_id: Any, source_name: str, actor: str, fmt: Optional[str], status: str,
               http_status: int, counts: dict[str, Any], errors: list[dict[str, str]], nbytes: int,
               digest: Optional[str], project: Optional[str], ip: Optional[str], con=None) -> Optional[int]:
    sql = (
        "INSERT INTO ingest_log (source_id, source_name, actor, format, status, http_status, findings_new, "
        "findings_updated, components, assets, skipped, duplicates, suppressed, errors, bytes, sha256, project, "
        "client_ip) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,$16,$17,$18) RETURNING id")
    args = (source_id, source_name[:100], actor[:200], fmt, status, http_status,
            counts.get("findings_new", 0), counts.get("findings_updated", 0), counts.get("components", 0),
            counts.get("assets", 0), counts.get("skipped", 0), counts.get("duplicates", 0),
            counts.get("suppressed", 0), json.dumps(errors[:50]), nbytes, digest,
            (project or "")[:200] or None, ip)
    try:
        if con is not None:
            return await con.fetchval(sql, *args)
        async with pool.acquire() as c:
            return await c.fetchval(sql, *args)
    except Exception:  # noqa: BLE001 -- never fail an upload because the log insert failed
        logger.exception("ingest_log_failed")
        return None


@router.post("")
async def ingest(
    request: Request,
    format: Optional[str] = Query(None, description="Force a format instead of auto-detecting: " + ", ".join(FORMATS)),
    project: Optional[str] = Query(None, max_length=200, description="Repository / project the results belong to"),
    asset: Optional[str] = Query(None, max_length=512, description="Attach every finding to this asset"),
    asset_kind: Optional[str] = Query(None, max_length=40),
    source: Optional[str] = Query(None, max_length=64, description="Label for API-key callers (token callers use their source)"),
    dry_run: bool = Query(False, description="Parse and validate only; store nothing"),
    strict: bool = Query(False, description="Reject the whole upload if any record is invalid"),
    token: Optional[str] = Query(None, description="Ingest token (prefer the header)"),
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    ip = client_ip(request)
    presented = _extract_token(request, token)
    src: Optional[dict[str, Any]] = None
    tenant_id: Optional[str] = None
    ctx: Any = None

    if presented:
        parsed = tokens.parse_token(presented)
        row = None
        if parsed is not None:
            tenant_id, sid, secret = parsed
            with tenancy.tenant_context(tenant_id):
                async with pool.acquire() as con:
                    row = await con.fetchrow(
                        "SELECT id, tenant_id, name, token_hash, enabled, revoked_at, default_project, "
                        "allowed_formats, rate_limit_per_min FROM ingest_sources "
                        "WHERE id = $1 AND tenant_id = $2::uuid", UUID(sid), tenant_id)
            ok = row is not None and tokens.verify(secret, row["token_hash"])
        else:
            ok = False
        if not ok or row is None or not row["enabled"] or row["revoked_at"] is not None:
            if failure_limiter.hit(f"fail:{client_key(ip)}") > FAILED_PER_MIN:
                return _json(429, {"detail": "too many invalid tokens"}, {"Retry-After": "60"})
            return _json(401, {"detail": "invalid ingest token"})
        src = dict(row)
        actor = f"ingest:{src['name']}"
        if not rate_limiter.allow(str(src["id"]), int(src["rate_limit_per_min"])):
            return _json(429, {"detail": "rate limit exceeded for this source"}, {"Retry-After": "60"})
        ctx = tenancy.tenant_context(tenant_id)
    else:
        principal = getattr(request.state, "principal", None)
        if principal is None:
            return _json(401, {"detail": "ingest token or API key required"})
        if not principal.has("scan"):
            return _json(403, {"detail": "requires capability 'scan' (or use a per-source ingest token)"})
        actor = principal.actor
        label = source or "api"
        if not _NAME_RE.match(label):
            return _json(422, {"detail": "source must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}"})
        src = {"id": None, "name": label, "default_project": None, "allowed_formats": []}
        if not rate_limiter.allow(f"p:{principal.actor}", 600):
            return _json(429, {"detail": "rate limit exceeded"}, {"Retry-After": "60"})
        ctx = contextlib.nullcontext()

    if project is not None and not _PROJECT_RE.match(project):
        return _json(422, {"detail": "project must be 1-200 printable characters"})
    if asset_kind is not None and not re.fullmatch(r"[a-z_]{2,30}", asset_kind):
        return _json(422, {"detail": "invalid asset_kind"})

    limit = max_bytes()
    sname = src["name"]
    fmt_hint = (format or "").strip().lower() or None
    with ctx:
        raw = b""
        res = None
        try:
            raw = await _read_body(request, limit)
            hints = Hints(project=project or src.get("default_project"), asset=asset, asset_kind=asset_kind,
                          fallback=sname, max_findings=max_findings())
            gz = (request.headers.get("content-encoding") or "").lower() in ("gzip", "x-gzip")
            res = await asyncio.to_thread(_parse_sync, raw, gzipped=gz, fmt=fmt_hint, hints=hints, limit=limit)
            allowed = list(src.get("allowed_formats") or [])
            if allowed and res.format not in allowed:
                raise IngestError(f"this source only accepts: {', '.join(allowed)} (got {res.format})", 403)
            if strict and res.errors:
                raise IngestError(f"strict mode: {res.skipped} invalid record(s); first: "
                                  f"{res.errors[0]['where']}: {res.errors[0]['message']}", 422)
            if not res.findings and not res.components and res.sbom is None and not res.skipped:
                raise IngestError("the document parsed but contains no findings or components", 422)
        except IngestError as exc:
            digest = hashlib.sha256(raw).hexdigest() if raw else None
            await _log(pool, source_id=src["id"], source_name=sname, actor=actor, fmt=getattr(res, "format", None),
                       status="rejected", http_status=exc.status, counts={}, errors=[{"where": "body", "message": str(exc)}],
                       nbytes=len(raw), digest=digest, project=project, ip=ip)
            return _json(exc.status, {"detail": str(exc)})

        digest = hashlib.sha256(raw).hexdigest()
        counts: dict[str, Any] = {"skipped": res.skipped}
        project_name = project or src.get("default_project")
        if dry_run:
            counts.update(findings_new=len(res.findings),
                          components=len((res.sbom or {}).get("components") or res.components))
            await _log(pool, source_id=src["id"], source_name=sname, actor=actor, fmt=res.format, status="dry_run",
                       http_status=200, counts=counts, errors=res.errors, nbytes=len(raw), digest=digest,
                       project=project_name, ip=ip)
            return _json(200, _body(res, counts, sname, dry_run=True, status="dry_run", log_id=None))

        events: list[dict[str, Any]] = []
        try:
            async with pool.acquire() as con:
                async with con.transaction():
                    stored, events = await store.persist(con, res, source=sname, project=project_name)
                    counts.update(stored)
                    status = "partial" if res.errors else "ok"
                    log_id = await _log(pool, source_id=src["id"], source_name=sname, actor=actor, fmt=res.format,
                                        status=status, http_status=200, counts=counts, errors=res.errors,
                                        nbytes=len(raw), digest=digest, project=project_name, ip=ip, con=con)
                    if src["id"] is not None:
                        await con.execute(
                            "UPDATE ingest_sources SET last_used_at = NOW(), ingest_count = ingest_count + 1 WHERE id = $1",
                            src["id"])
                    await audit.record(
                        pool, action="ingest", actor=actor, resource_type="ingest",
                        resource_id=str(src["id"] or sname), method="POST", path="/v1/ingest", status=200,
                        ip=ip, request_id=getattr(request.state, "request_id", None), con=con,
                        tenant_id=tenant_id,
                        details={"format": res.format, "tool": res.tool, "sha256": digest, "bytes": len(raw),
                                 "findings_new": counts.get("findings_new", 0),
                                 "findings_updated": counts.get("findings_updated", 0),
                                 "components": counts.get("components", 0), "skipped": res.skipped})
        except Exception:  # noqa: BLE001
            logger.exception("ingest_store_failed")
            await _log(pool, source_id=src["id"], source_name=sname, actor=actor, fmt=res.format, status="rejected",
                       http_status=500, counts={}, errors=[{"where": "store", "message": "storage failed"}],
                       nbytes=len(raw), digest=digest, project=project_name, ip=ip)
            return _json(500, {"detail": "ingest failed while storing; nothing was saved"})

    for ev in events[:MAX_EVENTS]:
        try:
            await publish_event(r, ev)
        except Exception:  # noqa: BLE001
            logger.exception("publish_event_failed")
    return _json(200, _body(res, counts, sname, status=status, log_id=log_id))


def _body(res, counts: dict[str, Any], source: str, *, status: str, dry_run: bool = False,
          log_id: Optional[int]) -> dict[str, Any]:
    return {
        "source": source, "format": res.format, "tool": res.tool, "status": status, "dry_run": dry_run,
        "findings_new": counts.get("findings_new", 0), "findings_updated": counts.get("findings_updated", 0),
        "duplicates": counts.get("duplicates", 0), "suppressed": counts.get("suppressed", 0),
        "components": counts.get("components", 0), "vulnerabilities": counts.get("vulnerabilities", 0),
        "assets": counts.get("assets", 0), "skipped": res.skipped, "errors": res.errors[:50],
        "project": counts.get("project"), "log_id": log_id,
    }


# --------------------------------------------------------------------------- #
# Reference
# --------------------------------------------------------------------------- #

@router.get("/formats")
async def formats():
    return {"formats": list(FORMATS), "csv_columns": CSV_COLUMNS,
            "max_bytes": max_bytes(), "max_findings": max_findings(),
            "notes": ["gzip bodies are accepted with Content-Encoding: gzip",
                      "XML is refused; export JSON", "NDJSON / JSON arrays accepted for nuclei and ocsf"]}


# --------------------------------------------------------------------------- #
# Source management (admin)
# --------------------------------------------------------------------------- #

class SourceIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: Optional[str] = Field(default=None, max_length=500)
    default_project: Optional[str] = Field(default=None, max_length=200)
    allowed_formats: list[str] = Field(default_factory=list, max_length=len(FORMATS))
    rate_limit_per_min: int = Field(default=60, ge=1, le=6000)


class SourcePatch(BaseModel):
    description: Optional[str] = Field(default=None, max_length=500)
    default_project: Optional[str] = Field(default=None, max_length=200)
    allowed_formats: Optional[list[str]] = Field(default=None, max_length=len(FORMATS))
    rate_limit_per_min: Optional[int] = Field(default=None, ge=1, le=6000)
    enabled: Optional[bool] = None


_SOURCE_COLS = ("id, name, description, token_prefix, default_project, allowed_formats, rate_limit_per_min, "
                "enabled, created_by, created_at, rotated_at, revoked_at, revoked_by, last_used_at, ingest_count")


def _source_out(row, request: Request, token: Optional[str] = None) -> dict[str, Any]:
    d = dict(row)
    d.pop("token_hash", None)
    for k in ("id", "created_at", "rotated_at", "revoked_at", "last_used_at"):
        if d.get(k) is not None:
            d[k] = str(d[k]) if k == "id" else d[k].isoformat()
    d["allowed_formats"] = list(d.get("allowed_formats") or [])
    d["url"] = str(request.base_url).rstrip("/") + "/v1/ingest"
    if token:
        d["token"] = token
    return d


def _check_formats(fmts: list[str]) -> list[str]:
    bad = [f for f in fmts if f not in FORMATS]
    if bad:
        raise HTTPException(status_code=422, detail=f"unknown format(s): {', '.join(bad)}; supported: {', '.join(FORMATS)}")
    return sorted(set(fmts))


def _check_project(p: Optional[str]) -> Optional[str]:
    if p is not None and p != "" and not _PROJECT_RE.match(p):
        raise HTTPException(status_code=422, detail="default_project must be 1-200 printable characters")
    return p or None


def _uuid(v: str) -> UUID:
    try:
        return UUID(v)
    except ValueError:
        raise HTTPException(status_code=404, detail="source not found") from None


@router.post("/sources", status_code=201)
async def create_source(body: SourceIn, request: Request, pool=Depends(get_pool)):
    if not _NAME_RE.match(body.name):
        raise HTTPException(status_code=422, detail="name must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
    fmts = _check_formats(body.allowed_formats)
    secret, prefix, digest = tokens.new_secret()
    principal = getattr(request.state, "principal", None)
    actor = principal.actor if principal else "unknown"
    sid = uuid4()
    async with pool.acquire() as con:
        if await con.fetchval("SELECT 1 FROM ingest_sources WHERE lower(name) = lower($1) AND revoked_at IS NULL",
                              body.name):
            raise HTTPException(status_code=409, detail="a source with this name already exists")
        row = await con.fetchrow(
            "INSERT INTO ingest_sources (id, name, description, token_hash, token_prefix, default_project, "
            "allowed_formats, rate_limit_per_min, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) "
            f"RETURNING {_SOURCE_COLS}, tenant_id",
            sid, body.name, body.description, digest, prefix, _check_project(body.default_project), fmts,
            body.rate_limit_per_min, actor)
    tok = tokens.build_token(str(row["tenant_id"]), str(sid), secret)
    out = _source_out({k: v for k, v in dict(row).items() if k != "tenant_id"}, request, tok)
    return out


@router.get("/sources")
async def list_sources(request: Request, include_revoked: bool = Query(False), pool=Depends(get_pool)):
    async with pool.acquire() as con:
        rows = await con.fetch(
            f"SELECT {_SOURCE_COLS} FROM ingest_sources "
            + ("" if include_revoked else "WHERE revoked_at IS NULL ") + "ORDER BY created_at DESC LIMIT 500")
    return {"items": [_source_out(r, request) for r in rows]}


@router.patch("/sources/{source_id}")
async def patch_source(source_id: str, body: SourcePatch, request: Request, pool=Depends(get_pool)):
    sid = _uuid(source_id)
    sets, args = [], [sid]
    data = body.model_dump(exclude_unset=True)
    if "allowed_formats" in data and data["allowed_formats"] is not None:
        data["allowed_formats"] = _check_formats(data["allowed_formats"])
    if "default_project" in data:
        data["default_project"] = _check_project(data["default_project"])
    for k, v in data.items():
        if k in ("enabled", "rate_limit_per_min", "allowed_formats") and v is None:
            continue
        args.append(v)
        sets.append(f"{k} = ${len(args)}")
    if not sets:
        raise HTTPException(status_code=422, detail="nothing to update")
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"UPDATE ingest_sources SET {', '.join(sets)} WHERE id = $1 AND revoked_at IS NULL "
            f"RETURNING {_SOURCE_COLS}", *args)
    if row is None:
        raise HTTPException(status_code=404, detail="source not found")
    return _source_out(row, request)


@router.post("/sources/{source_id}/rotate")
async def rotate_source(source_id: str, request: Request, pool=Depends(get_pool)):
    sid = _uuid(source_id)
    secret, prefix, digest = tokens.new_secret()
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "UPDATE ingest_sources SET token_hash = $2, token_prefix = $3, rotated_at = NOW() "
            f"WHERE id = $1 AND revoked_at IS NULL RETURNING {_SOURCE_COLS}, tenant_id", sid, digest, prefix)
    if row is None:
        raise HTTPException(status_code=404, detail="source not found")
    tok = tokens.build_token(str(row["tenant_id"]), str(sid), secret)
    return _source_out({k: v for k, v in dict(row).items() if k != "tenant_id"}, request, tok)


@router.delete("/sources/{source_id}")
async def revoke_source(source_id: str, request: Request, pool=Depends(get_pool)):
    sid = _uuid(source_id)
    principal = getattr(request.state, "principal", None)
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "UPDATE ingest_sources SET revoked_at = NOW(), revoked_by = $2, enabled = FALSE, token_hash = 'revoked' "
            f"WHERE id = $1 AND revoked_at IS NULL RETURNING {_SOURCE_COLS}",
            sid, principal.actor if principal else "unknown")
    if row is None:
        raise HTTPException(status_code=404, detail="source not found")
    return _source_out(row, request)


@router.get("/log")
async def ingest_log(
    source_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None, pattern="^(ok|partial|rejected|dry_run)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    where, args = [], []
    if source_id:
        args.append(_uuid(source_id))
        where.append(f"source_id = ${len(args)}")
    if status:
        args.append(status)
        where.append(f"status = ${len(args)}")
    args += [limit, offset]
    async with pool.acquire() as con:
        rows = await con.fetch(
            "SELECT id, source_id, source_name, actor, format, status, http_status, findings_new, findings_updated, "
            "components, assets, skipped, duplicates, suppressed, errors, bytes, sha256, project, client_ip, created_at "
            f"FROM ingest_log {'WHERE ' + ' AND '.join(where) if where else ''} "
            f"ORDER BY id DESC LIMIT ${len(args) - 1} OFFSET ${len(args)}", *args)
    items = []
    for r in rows:
        d = dict(r)
        d["source_id"] = str(d["source_id"]) if d["source_id"] else None
        d["created_at"] = d["created_at"].isoformat()
        if isinstance(d["errors"], str):
            d["errors"] = json.loads(d["errors"])
        items.append(d)
    return {"items": items, "limit": limit, "offset": offset}
