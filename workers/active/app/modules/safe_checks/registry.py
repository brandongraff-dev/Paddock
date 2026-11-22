"""Registry of safe checks, keyed by finding rule/class."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable

from .base import CheckEnv, CheckResult, FindingCtx
from .http_checks import HTTP_CHECKS
from .network_checks import NETWORK_CHECKS
from .tls import TLS_CHECKS


@dataclass(frozen=True)
class SafeCheck:
    id: str
    title: str
    description: str
    matches: Callable[[FindingCtx], bool]
    run: Callable[[FindingCtx, CheckEnv], Awaitable[CheckResult]]
    methods: tuple[str, ...]   # what the check sends to the target (all non-mutating)


# Order matters: the first matching check wins, so the specific ones come first.
REGISTRY: list[SafeCheck] = [
    SafeCheck(*row) for row in (*NETWORK_CHECKS[:1], *TLS_CHECKS, *HTTP_CHECKS, *NETWORK_CHECKS[1:])
]


def resolve(finding: FindingCtx) -> SafeCheck | None:
    for check in REGISTRY:
        try:
            if check.matches(finding):
                return check
        except Exception:  # noqa: BLE001 -- a bad matcher must not break verification
            continue
    return None


async def run(finding: FindingCtx, env: CheckEnv) -> CheckResult | None:
    """Run the matching check; ``None`` when no safe check exists for this rule."""
    check = resolve(finding)
    if check is None:
        return None
    return await check.run(finding, env)


def catalogue() -> list[dict]:
    return [{"id": c.id, "title": c.title, "description": c.description,
             "sends": list(c.methods)} for c in REGISTRY]
