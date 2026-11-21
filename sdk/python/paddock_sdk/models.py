"""Typed request/response models (``TypedDict``), generated from the OpenAPI spec.

    from paddock_sdk.models import FindingLifecycleOut, ScopeEntryIn
"""
from __future__ import annotations

from ._generated import *  # noqa: F401,F403
from ._generated import API_VERSION, OPERATIONS  # noqa: F401
from ._generated import FindingLifecycleOut, FindingLifecyclePage

# Deprecated aliases: GET /v1/findings returned FindingOut / FindingPage
# before the lifecycle fields were added. The shape only grew (all new fields
# are optional), so old imports keep working.
FindingOut = FindingLifecycleOut
FindingPage = FindingLifecyclePage
