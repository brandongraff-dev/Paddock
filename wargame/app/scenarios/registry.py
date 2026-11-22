"""Registry of proving-ground scenarios. Mirrors safe_checks/registry.py."""
from __future__ import annotations

from typing import Any, Optional

from .base import Scenario, ScenarioCtx
from .cve_repro import CveContainerRepro
from .default_cred import DefaultCredentialReplica
from .unauth_access import UnauthEndpointReplica

# Order matters: first match wins, specific before generic. A CVE-tagged
# finding on a default-cred rule is better proven by the login than by version.
REGISTRY: list[Scenario] = [
    DefaultCredentialReplica(),
    UnauthEndpointReplica(),
    CveContainerRepro(),
]


def resolve(ctx: ScenarioCtx) -> Optional[Scenario]:
    for scenario in REGISTRY:
        try:
            if scenario.matches(ctx):
                return scenario
        except Exception:  # noqa: BLE001 -- a bad matcher must not break proving
            continue
    return None


def catalogue() -> list[dict[str, Any]]:
    return [s.catalogue_row() for s in REGISTRY]
