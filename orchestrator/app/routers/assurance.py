"""Provable containment API: invariants, zones, labels, reach graph, coverage, evaluation.

Owned by the API work package (docs/ASSURANCE_P1.md section 8). Registered in main.py.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["assurance"])
