"""API lifecycle helpers: deprecation + sunset signalling (docs/API.md).

Mark an operation deprecated by BOTH flagging it in OpenAPI and attaching the
dependency, so clients see it in the spec and on every response::

    from ..api_lifecycle import deprecated

    @router.get(
        "/findings/list",
        deprecated=True,
        dependencies=[Depends(deprecated(sunset="2027-06-30", successor="/v1/findings"))],
    )

Responses then carry (RFC 9745 / RFC 8594 / RFC 8288)::

    Deprecation: @1767225600            (when it was deprecated; or "true")
    Sunset: Wed, 30 Jun 2027 00:00:00 GMT
    Link: </v1/findings>; rel="successor-version", </docs/API.md>; rel="deprecation"

The SDKs surface these headers as warnings; the breaking-change detector
(scripts/openapi_diff.py) still refuses the eventual removal unless the PR is
labelled ``api-breaking``.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from email.utils import format_datetime

from fastapi import Response

POLICY_URL = "/docs/API.md#versioning-and-deprecation"
MIN_SUNSET_DAYS = 180


def _as_dt(d: str | date | datetime) -> datetime:
    if isinstance(d, str):
        d = date.fromisoformat(d)
    if isinstance(d, datetime):
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    return datetime(d.year, d.month, d.day, tzinfo=timezone.utc)


def deprecation_headers(
    *,
    sunset: str | date | datetime | None = None,
    since: str | date | datetime | None = None,
    successor: str | None = None,
) -> dict[str, str]:
    headers = {"Deprecation": f"@{int(_as_dt(since).timestamp())}" if since else "true"}
    if sunset is not None:
        headers["Sunset"] = format_datetime(_as_dt(sunset), usegmt=True)
    links = []
    if successor:
        links.append(f'<{successor}>; rel="successor-version"')
    links.append(f'<{POLICY_URL}>; rel="deprecation"')
    headers["Link"] = ", ".join(links)
    return headers


def deprecated(
    *,
    sunset: str | date | datetime | None = None,
    since: str | date | datetime | None = None,
    successor: str | None = None,
):
    """FastAPI dependency factory that stamps deprecation headers on responses.

    ``sunset`` must be at least ``MIN_SUNSET_DAYS`` after ``since`` (when both
    are given) -- the /v1 stability promise.
    """
    if sunset is not None and since is not None:
        if (_as_dt(sunset) - _as_dt(since)).days < MIN_SUNSET_DAYS:
            raise ValueError(f"/v1 sunset must be >= {MIN_SUNSET_DAYS} days after deprecation")
    headers = deprecation_headers(sunset=sunset, since=since, successor=successor)

    async def _dep(response: Response) -> None:
        for k, v in headers.items():
            response.headers[k] = v

    return _dep
