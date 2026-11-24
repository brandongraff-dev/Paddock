"""Service-key ingest of aggregated passive flows from otdiscovery (schema 039 reach_flow_obs).

Owned by the Sentry work package (docs/ASSURANCE_P1.md section 6.3). Registered in main.py,
auth.py (write) and service_routes.py (COMPUTE_ROUTES).
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/v1/reach", tags=["assurance"])
