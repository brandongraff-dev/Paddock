"""Request-id injection, structured JSON logging, and the
`require_scope_admin` compatibility shim.

Real auth now lives in `app/auth.py` (schema 011). `require_scope_admin` is
retained as a thin alias onto `require('admin')` so the routers that already
wire it onto scope/alert/schedule/owner mutations keep working unchanged;
the `GovernanceMiddleware` added in `main.py` is the primary enforcement gate.
"""
from __future__ import annotations

import logging
import time
import re
import uuid
from typing import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from pythonjsonlogger.json import JsonFormatter

from .config import settings


REQUEST_ID_HEADER = "X-Request-ID"


def configure_logging() -> None:
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler()
    handler.setFormatter(
        JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root.addHandler(handler)
    root.setLevel(settings.log_level.upper())
    # Quiet asyncpg's INFO-level pool noise; keep warnings.
    logging.getLogger("asyncpg").setLevel(logging.WARNING)


_RID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request-id and emit one structured access log per request."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # A client-supplied id is only kept when it is a plain token; anything
        # else is replaced so it can't be used to forge/poison audit rows.
        rid = request.headers.get(REQUEST_ID_HEADER) or ""
        if not _RID_RE.fullmatch(rid):
            rid = uuid.uuid4().hex
        request.state.request_id = rid
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            dur_ms = int((time.perf_counter() - start) * 1000)
            logging.getLogger("http").exception(
                "http_error",
                extra={
                    "request_id": rid,
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": dur_ms,
                },
            )
            raise
        dur_ms = int((time.perf_counter() - start) * 1000)
        response.headers[REQUEST_ID_HEADER] = rid
        logging.getLogger("http").info(
            "http_request",
            extra={
                "request_id": rid,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": dur_ms,
            },
        )
        return response


async def require_scope_admin(request: Request):
    """Compatibility shim: now enforces the `admin` role.

    Previously a no-op placeholder. It is remapped onto `auth.require('admin')`
    so every router that already depends on it (scope, alert-rules, schedules,
    owners) gains real admin enforcement without a router edit. Returns the
    resolved admin principal.
    """
    # Imported lazily to avoid a circular import (auth -> audit -> ... ).
    from .auth import require

    return await require("admin")(request)
