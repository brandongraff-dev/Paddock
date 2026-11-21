"""Connector implementations. Importing this package registers all of them.

Each module defines one or more ``@register``-ed ``Connector`` subclasses.
Add new modules to ``_MODULES`` so they load at startup.
"""
from __future__ import annotations

import importlib
import logging

log = logging.getLogger(__name__)

_MODULES: tuple[str, ...] = (
    "webhook",
    "slack",
    "teams",
    "pagerduty",
    "email",
    "jira",
    "servicenow",
    "linear",
    # SIEM (OCSF 1.3): see docs/INTEGRATIONS-SIEM.md
    "splunk_hec",
    "sentinel",
    "elastic",
    "syslog",
    "google_secops",
    # context SOURCE connectors (read-only)
    "aws",
    "microsoft_defender",
    "crowdstrike",
    "servicenow_cmdb",
    "gcp",
    "azure",
    # network ACTION connectors (Sentry quarantine; approve gate only)
    "unifi",
    "meraki",
)


def load_all() -> None:
    for name in _MODULES:
        try:
            importlib.import_module(f"{__name__}.{name}")
        except Exception:  # pragma: no cover - a broken connector must not take down the API
            log.exception("failed to load connector module %s", name)
