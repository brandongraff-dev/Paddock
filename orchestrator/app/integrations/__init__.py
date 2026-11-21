"""Integrations: one framework for every system Paddock talks to.

The contract lives in ``base.py`` (Connector interface, Event catalogue,
results), ``secrets.py`` (encryption at rest for credentials) and
``netsafety.py`` (outbound URL validation so a customer-supplied webhook can
never be turned into SSRF against Paddock's own network). Connectors live in
``connectors/`` and register themselves with ``@register``.
"""
from .base import (  # noqa: F401
    EVENT_TYPES,
    REGISTRY,
    Capability,
    Connector,
    DeliveryResult,
    Event,
    HealthResult,
    InboundUpdate,
    SourceBatch,
    get_connector_class,
    register,
)
