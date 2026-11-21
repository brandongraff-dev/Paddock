"""Pure helpers: claim lookup, group extraction, domain allow-list, role mapping.

Shared by OIDC, SAML and SCIM so all three resolve roles identically:
mappings are an ordered list and the FIRST mapping whose ``group`` matches
one of the user's groups (case-insensitively) wins. No match -> the
provider's default role/clearance (or a denial if ``require_mapping``).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence


def claim_lookup(claims: Mapping[str, Any], path: str) -> Any:
    """Find a claim by exact key first (namespaced URL claims contain dots,
    e.g. Auth0 ``https://paddock.example/groups``), then by dotted path
    (Keycloak ``realm_access.roles``)."""
    if not path:
        return None
    if path in claims:
        return claims[path]
    cur: Any = claims
    for part in path.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Mapping):
        return []
    if isinstance(value, Iterable):
        out = []
        for v in value:
            if isinstance(v, (str, int)) and str(v):
                out.append(str(v))
            elif isinstance(v, Mapping):  # SCIM-ish [{"value": ...}]
                inner = v.get("value") or v.get("display")
                if inner:
                    out.append(str(inner))
        return out
    return [str(value)]


def extract_groups(claims: Mapping[str, Any], path: str) -> list[str]:
    return as_str_list(claim_lookup(claims, path))


def email_domain(email: str | None) -> str | None:
    if not email or "@" not in email:
        return None
    return email.rsplit("@", 1)[1].strip().lower().rstrip(".") or None


def domain_allowed(
    email: str | None,
    allowed: Sequence[str],
    *,
    hosted_domain: str | None = None,
) -> bool:
    """Empty allow-list admits everyone. Otherwise the email's domain must be
    listed and, when the IdP asserts one (Google ``hd``), so must that."""
    if not allowed:
        return True
    allowed_set = {a.lower() for a in allowed}
    dom = email_domain(email)
    if dom is None or dom not in allowed_set:
        return False
    if hosted_domain is not None and hosted_domain.lower() not in allowed_set:
        return False
    return True


@dataclass(frozen=True)
class RoleDecision:
    role: str
    clearance: str
    matched: str | None  # the mapping group that matched, None = default


def resolve_role(
    groups: Iterable[str],
    mappings: Sequence[Mapping[str, Any]],
    *,
    default_role: str,
    default_clearance: str,
) -> RoleDecision:
    have = {g.casefold() for g in groups}
    for m in mappings:
        grp = str(m.get("group") or "")
        if grp and grp.casefold() in have:
            return RoleDecision(
                role=str(m["role"]),
                clearance=str(m.get("clearance") or default_clearance),
                matched=grp,
            )
    return RoleDecision(role=default_role, clearance=default_clearance, matched=None)
