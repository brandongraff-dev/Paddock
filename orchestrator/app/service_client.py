"""Calling the compute services (brain, mlrisk, correlation, ...) as a tenant.

The services authenticate the orchestrator with the shared ``SERVICE_API_KEY``
and take the tenant of the call from ``X-Paddock-Tenant`` (they refuse a tenant
header that arrives without the key). The tenant is the CURRENT request's
tenant (``tenancy``), so a proxied call can never act for a tenant other than
the principal that made it.
"""
from __future__ import annotations

from . import tenancy
from .config import settings


def service_headers() -> dict[str, str]:
    """``X-API-Key`` + ``X-Paddock-Tenant`` for an orchestrator -> service call."""
    h: dict[str, str] = {}
    if settings.service_api_key:
        h["X-API-Key"] = settings.service_api_key
    tid = tenancy.current_tenant_id()
    if tid:
        h[tenancy.TENANT_HEADER] = tid
    return h
