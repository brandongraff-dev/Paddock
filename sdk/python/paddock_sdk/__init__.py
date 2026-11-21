"""Paddock SDK: a typed Python client for the Paddock /v1 API.

    from paddock_sdk import PaddockClient

    with PaddockClient("https://paddock.example.internal", api_key="pak_...") as pc:
        for f in pc.paginate(pc.list_findings_paged, severity="critical"):
            print(f["title"])

Models (``paddock_sdk.models``) and operations are generated from
docs/api/openapi.json by ``sdk/python/codegen.py``; the transport core
(auth, retries, errors, pagination) is hand-written in ``_core.py``.
"""
from __future__ import annotations

__version__ = "0.1.0"

from ._core import (  # noqa: E402
    NO_RETRY,
    APIError,
    AuthenticationError,
    Conflict,
    FeatureNotLicensed,
    NotFound,
    PaddockError,
    PermissionDenied,
    RateLimited,
    RetryPolicy,
    ServerError,
    TransportError,
    ValidationError,
)
from .client import PaddockClient  # noqa: E402

__all__ = [
    "APIError",
    "AuthenticationError",
    "Conflict",
    "FeatureNotLicensed",
    "NO_RETRY",
    "NotFound",
    "PaddockClient",
    "PaddockError",
    "PermissionDenied",
    "RateLimited",
    "RetryPolicy",
    "ServerError",
    "TransportError",
    "ValidationError",
    "__version__",
]
