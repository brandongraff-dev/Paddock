"""What the shared service key may do under ``TENANCY_STRICT`` (short-term mitigation).

The fleet shares ONE ``SERVICE_API_KEY`` and a service principal can name any
active tenant (``X-Paddock-Tenant``). Until per-service keys / per-job tokens
exist (docs/trust/TENANCY.md, "What the service key can still do"), strict mode
narrows it to exactly the routes the fleet really calls:

* ``JOB_ROUTES``: routes only an active/passive WORKER calls, in the middle of a
  job. They MUST carry ``X-Paddock-Scan`` and the scan must belong to the
  claimed tenant (``job_binding``). A stolen key without a live job id of that
  tenant cannot use them.
* ``SHARED_WRITE_ROUTES``: bulk upserts that workers AND compute services
  (intel, sca, correlation, ...) use. A compute service has no job, so the scan
  is optional; but a caller that identifies as a worker (``X-Worker-Id``) must
  carry one, and any scan header that IS sent is verified.
* ``COMPUTE_ROUTES``: the other routes compute services call, by explicit
  allow-list.

Anything not on a list is refused for the service key in strict mode (403):
users, keys, scope writes, integrations, audit, MSP, billing, reports, ...
Outside strict mode (single-tenant installs, tests) nothing changes.
"""
from __future__ import annotations

import re

_ID = r"[0-9a-fA-F-]{36}"


def _r(methods: str, pattern: str) -> tuple[frozenset[str], re.Pattern[str]]:
    return frozenset(methods.split()), re.compile("^" + pattern + "/?$")


# Worker-only callbacks: a live job of the claimed tenant is mandatory.
JOB_ROUTES = [
    _r("POST", r"/v1/scope/check"),
    _r("POST", r"/v1/scans"),                                   # child scan
    _r("PATCH", rf"/v1/scans/{_ID}"),
    _r("POST", rf"/v1/scans/{_ID}/(?:start|complete|fail|status)"),
    _r("POST", rf"/v1/verifications/{_ID}/result"),
    _r("POST", r"/v1/tls-grades/bulk"),
    _r("POST", r"/v1/outbound/bulk"),
]

# Used by workers and compute services alike (compute services have no job).
SHARED_WRITE_ROUTES = [
    _r("POST", r"/v1/findings/bulk"),
    _r("POST", r"/v1/assets/bulk"),
    _r("POST", r"/v1/edges/bulk"),
]

# Compute services only (intel, sca, codeanalysis, threatintel, correlation,
# otdiscovery). The sensor routes authenticate the SENSOR (X-Sensor-Token);
# the service key just carries them across.
COMPUTE_ROUTES = [
    _r("GET", r"/v1/assets"),
    _r("GET", rf"/v1/assets/{_ID}"),
    _r("PATCH", rf"/v1/findings/{_ID}"),
    _r("POST", r"/v1/chains"),
    _r("GET", r"/v1/system/ai/credential"),                      # brain: the operator-saved model key
    _r("POST", r"/v1/sensors/enroll"),
    _r("POST", r"/v1/sensors/heartbeat"),
    _r("POST", r"/v1/sensors/ingest/(?:claim|done)"),
]

WORKER_HEADER = "x-worker-id"


def _match(rules, method: str, path: str) -> bool:
    return any(method in m and p.match(path) for m, p in rules)


def requires_job(method: str, path: str, headers) -> bool:
    """True when this service-key call must carry a verified ``X-Paddock-Scan``."""
    if _match(JOB_ROUTES, method, path):
        return True
    return _match(SHARED_WRITE_ROUTES, method, path) and bool(headers.get(WORKER_HEADER))


def permitted(method: str, path: str) -> bool:
    """Is this route on the service key's allow-list at all?"""
    return (
        _match(JOB_ROUTES, method, path)
        or _match(SHARED_WRITE_ROUTES, method, path)
        or _match(COMPUTE_ROUTES, method, path)
    )
