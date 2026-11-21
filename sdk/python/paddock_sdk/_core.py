"""Hand-written transport core: auth, retries, errors, pagination.

The generated operations (``_generated.py``) only ever call
:meth:`BaseClient._request`; everything about *how* a request is sent lives
here so it can be tested against a mocked ``httpx`` transport.
"""
from __future__ import annotations

import email.utils
import os
import random
import time
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import quote

import httpx

from . import __version__

DEFAULT_URL = "http://localhost:8080"


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class PaddockError(Exception):
    """Base class for every SDK error."""


class TransportError(PaddockError):
    """The server could not be reached (DNS, connect, timeout...)."""


class APIError(PaddockError):
    """The server answered with a non-2xx status."""

    def __init__(self, status: int, detail: Any, *, method: str, url: str,
                 request_id: str | None = None, headers: Mapping[str, str] | None = None) -> None:
        self.status = status
        self.detail = detail
        self.method = method
        self.url = url
        self.request_id = request_id
        self.headers = dict(headers or {})
        msg = detail if isinstance(detail, str) else (detail.get("error") if isinstance(detail, dict) else None)
        super().__init__(f"{method} {url} -> HTTP {status}: {msg or detail}")


class AuthenticationError(APIError):
    """401: missing/invalid/expired credentials."""


class PermissionDenied(APIError):
    """403: authenticated, but the role/API-key scope lacks the capability."""


class FeatureNotLicensed(APIError):
    """402: the feature needs a higher Paddock edition (see docs/EDITIONS.md)."""


class NotFound(APIError):
    """404: no such object -- or the server predates this endpoint."""


class Conflict(APIError):
    """409."""


class ValidationError(APIError):
    """422: the request body/params failed validation."""


class RateLimited(APIError):
    """429."""


class ServerError(APIError):
    """5xx."""


_STATUS_ERRORS: dict[int, type[APIError]] = {
    401: AuthenticationError,
    402: FeatureNotLicensed,
    403: PermissionDenied,
    404: NotFound,
    409: Conflict,
    422: ValidationError,
    429: RateLimited,
}


def error_for(status: int) -> type[APIError]:
    if status in _STATUS_ERRORS:
        return _STATUS_ERRORS[status]
    return ServerError if status >= 500 else APIError


# --------------------------------------------------------------------------- #
# Retries
# --------------------------------------------------------------------------- #

@dataclass
class RetryPolicy:
    """Exponential backoff with full jitter.

    Only idempotent methods are retried on 5xx/transport errors. 429 is
    retried for every method (the server refused before doing work) and
    ``Retry-After`` is honoured.
    """

    max_retries: int = 3
    backoff_factor: float = 0.5
    max_backoff: float = 10.0
    retry_statuses: frozenset[int] = frozenset({429, 502, 503, 504})
    idempotent_methods: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
    sleep: Callable[[float], None] = field(default=time.sleep, repr=False)

    def should_retry(self, method: str, attempt: int, status: int | None) -> bool:
        if attempt >= self.max_retries:
            return False
        if status is None:
            return method in self.idempotent_methods
        if status == 429:
            return True
        return status in self.retry_statuses and method in self.idempotent_methods

    def delay(self, attempt: int, retry_after: str | None = None) -> float:
        if retry_after:
            try:
                return min(self.max_backoff, max(0.0, float(retry_after)))
            except ValueError:
                try:
                    dt = email.utils.parsedate_to_datetime(retry_after)
                    return min(self.max_backoff, max(0.0, dt.timestamp() - time.time()))
                except (TypeError, ValueError):
                    pass
        return random.uniform(0, min(self.max_backoff, self.backoff_factor * (2 ** attempt)))


NO_RETRY = RetryPolicy(max_retries=0)


# --------------------------------------------------------------------------- #
# Client core
# --------------------------------------------------------------------------- #

class BaseClient:
    """Synchronous HTTP core shared by every generated operation.

    Credentials: ``api_key`` (``pak_...``; sent as ``Authorization: Bearer``)
    or ``token`` (a JWT from ``/v1/auth/login``). With neither, the
    ``PADDOCK_API_KEY`` / ``PADDOCK_TOKEN`` environment variables are used.
    """

    def __init__(
        self,
        base_url: str | None = None,
        *,
        api_key: str | None = None,
        token: str | None = None,
        timeout: float = 30.0,
        retry: RetryPolicy | None = None,
        transport: httpx.BaseTransport | None = None,
        headers: Mapping[str, str] | None = None,
        verify: bool | str = True,
    ) -> None:
        self.base_url = (base_url or os.environ.get("PADDOCK_URL") or DEFAULT_URL).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("PADDOCK_API_KEY")
        self.token = token if token is not None else os.environ.get("PADDOCK_TOKEN")
        self.retry = retry or RetryPolicy()
        self._warned: set[str] = set()
        h = {"User-Agent": f"paddock-sdk-python/{__version__}", "Accept": "application/json"}
        h.update(headers or {})
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout, transport=transport,
                                  headers=h, verify=verify)

    # -- lifecycle --------------------------------------------------------- #
    def close(self) -> None:
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- auth -------------------------------------------------------------- #
    def _auth_headers(self) -> dict[str, str]:
        cred = self.api_key or self.token
        return {"Authorization": f"Bearer {cred}"} if cred else {}

    def login_with_password(self, username: str, password: str) -> dict[str, Any]:
        """Exchange a username/password for a JWT and use it for later calls."""
        out = self._request("POST", "/v1/auth/login", body={"username": username, "password": password})
        self.token = out.get("access_token") or out.get("token")
        self.api_key = None
        return out

    # -- request ----------------------------------------------------------- #
    @staticmethod
    def _render_path(template: str, path: Mapping[str, Any] | None) -> str:
        if not path:
            return template
        out = template
        for k, v in path.items():
            out = out.replace("{" + k + "}", quote(str(v), safe=""))
        return out

    @staticmethod
    def _clean_query(query: Mapping[str, Any] | None) -> dict[str, Any]:
        if not query:
            return {}
        out: dict[str, Any] = {}
        for k, v in query.items():
            if v is None:
                continue
            if isinstance(v, bool):
                v = "true" if v else "false"
            out[k] = v
        return out

    def _request(
        self,
        method: str,
        path: str,
        *,
        path_params: Mapping[str, Any] | None = None,
        query: Mapping[str, Any] | None = None,
        body: Any = None,
    ) -> Any:
        """Entry point for generated operations: ``path`` is the URL template."""
        url = self._render_path(path, path_params)
        return self.request(method, url, query=query, body=body)

    def request(self, method: str, url: str, *, query: Mapping[str, Any] | None = None,
                body: Any = None, raw: bool = False) -> Any:
        """Send a request with auth + retries; return decoded JSON (or None for 204)."""
        method = method.upper()
        attempt = 0
        while True:
            try:
                resp = self._http.request(
                    method, url, params=self._clean_query(query),
                    json=body if body is not None else None,
                    headers=self._auth_headers(),
                )
            except httpx.TransportError as exc:
                if self.retry.should_retry(method, attempt, None):
                    self.retry.sleep(self.retry.delay(attempt))
                    attempt += 1
                    continue
                raise TransportError(f"{method} {self.base_url}{url}: {exc}") from exc

            if resp.status_code >= 400 and self.retry.should_retry(method, attempt, resp.status_code):
                self.retry.sleep(self.retry.delay(attempt, resp.headers.get("retry-after")))
                attempt += 1
                continue
            break

        self._note_deprecation(method, url, resp)
        if resp.status_code >= 400:
            try:
                payload = resp.json()
                detail = payload.get("detail", payload) if isinstance(payload, dict) else payload
            except ValueError:
                detail = resp.text
            raise error_for(resp.status_code)(
                resp.status_code, detail, method=method, url=url,
                request_id=resp.headers.get("x-request-id"), headers=resp.headers,
            )
        if raw:
            return resp
        if resp.status_code == 204 or not resp.content:
            return None
        ctype = resp.headers.get("content-type", "")
        if "json" in ctype:
            return resp.json()
        return resp.text

    def _note_deprecation(self, method: str, url: str, resp: httpx.Response) -> None:
        dep = resp.headers.get("deprecation")
        if not dep:
            return
        key = f"{method} {url.split('?')[0]}"
        if key in self._warned:
            return
        self._warned.add(key)
        sunset = resp.headers.get("sunset")
        link = resp.headers.get("link", "")
        warnings.warn(
            f"{key} is deprecated" + (f"; sunset {sunset}" if sunset else "") + (f" ({link})" if link else ""),
            DeprecationWarning,
            stacklevel=4,
        )

    # -- pagination -------------------------------------------------------- #
    def paginate(
        self,
        operation: Callable[..., Any] | str,
        *args: Any,
        page_size: int = 100,
        max_items: int | None = None,
        **kwargs: Any,
    ) -> Iterator[Any]:
        """Iterate every item of a ``limit``/``offset`` operation.

        Works for both response shapes the API uses: a page object
        (``{"items": [...], "total": N, ...}``) and a bare list.

            for f in client.paginate(client.list_findings_paged, severity="critical"):
                ...
        """
        fn = getattr(self, operation) if isinstance(operation, str) else operation
        offset = int(kwargs.pop("offset", 0) or 0)
        seen = 0
        while True:
            page = fn(*args, limit=page_size, offset=offset, **kwargs)
            if isinstance(page, dict) and "items" in page:
                items = page.get("items") or []
                total = page.get("total")
            elif isinstance(page, list):
                items, total = page, None
            else:
                raise PaddockError("operation is not paginated (expected a list or a page object)")
            for item in items:
                yield item
                seen += 1
                if max_items is not None and seen >= max_items:
                    return
            offset += len(items)
            if not items or len(items) < page_size or (total is not None and offset >= int(total)):
                return
