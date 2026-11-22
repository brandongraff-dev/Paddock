"""MSP console (managed service providers): see docs/MSP.md.

* :mod:`app.msp.core`      -- settings, grants, switch token, delegated audit
* :mod:`app.msp.health`    -- per-customer rollup + billing usage
* :mod:`app.msp.lifecycle` -- provision / suspend / invites / templates / grants
* ``python -m app.msp``    -- operator CLI (promote a tenant to an MSP)
"""
from .core import (  # noqa: F401
    DelegationError,
    MspContext,
    delegated_route_denied,
    delegation_details,
    is_switch_token,
    mirror_to_msp_trail,
    msp_settings,
    principal_from_switch_token,
)
