"""Pydantic models for SSO providers, identity settings and SCIM tokens."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

RoleName = Literal["viewer", "analyst", "admin", "auditor"]
ClearanceName = Literal["public", "internal", "confidential", "restricted"]
ProviderKind = Literal["oidc", "saml"]
Preset = Literal["generic", "okta", "entra", "google", "auth0", "keycloak"]

_SLUG_RE = r"^[a-z0-9][a-z0-9-]{0,62}$"


def normalize_domains(v: list[str]) -> list[str]:
    out = []
    for d in v:
        d = d.strip().lower().lstrip("@").rstrip(".")
        if d:
            out.append(d)
    return sorted(set(out))


class RoleMapping(BaseModel):
    """One IdP group/claim value -> Paddock role (+ optional clearance)."""

    group: str = Field(min_length=1, max_length=512)
    role: RoleName
    clearance: ClearanceName | None = None


class OIDCConfig(BaseModel):
    issuer: str = Field(min_length=8, max_length=2048)
    client_id: str = Field(min_length=1, max_length=512)
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    token_auth_method: Literal["client_secret_basic", "client_secret_post", "none"] = (
        "client_secret_basic"
    )
    # Fetch the userinfo endpoint and merge its claims (e.g. Okta groups).
    use_userinfo: bool = False
    # Accept an email for account linking even without email_verified=true.
    # Off by default (account-takeover risk with IdPs that allow arbitrary
    # unverified emails); Entra links via the immutable `oid` instead.
    trust_unverified_email: bool = False
    allow_private: bool = False  # self-hosted Keycloak on the LAN, opt-in
    extra_auth_params: dict[str, str] = Field(default_factory=dict)

    @field_validator("scopes")
    @classmethod
    def _need_openid(cls, v: list[str]) -> list[str]:
        v = [s.strip() for s in v if s and s.strip()]
        if "openid" not in v:
            v.insert(0, "openid")
        return v

    @field_validator("extra_auth_params")
    @classmethod
    def _no_protocol_overrides(cls, v: dict[str, str]) -> dict[str, str]:
        reserved = {
            "client_id", "redirect_uri", "response_type", "scope", "state", "nonce",
            "code_challenge", "code_challenge_method", "response_mode",
        }
        bad = reserved & set(v)
        if bad:
            raise ValueError(f"extra_auth_params may not override {sorted(bad)}")
        return v


class SAMLConfig(BaseModel):
    idp_entity_id: str = Field(min_length=1, max_length=2048)
    idp_sso_url: str = Field(min_length=8, max_length=2048)
    idp_x509_cert: str = Field(min_length=64, max_length=20000)
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    email_attribute: str | None = None   # None = use NameID
    groups_attribute: str | None = None  # falls back to provider.groups_claim
    name_attribute: str | None = None
    want_messages_signed: bool = False   # assertions are ALWAYS required signed


class ProviderIn(BaseModel):
    slug: str = Field(pattern=_SLUG_RE)
    kind: ProviderKind
    preset: Preset = "generic"
    display_name: str = Field(min_length=1, max_length=128)
    enabled: bool = True
    oidc: OIDCConfig | None = None
    saml: SAMLConfig | None = None
    # Paste IdP metadata XML instead of filling `saml` by hand.
    saml_metadata_xml: str | None = Field(default=None, max_length=500_000)
    client_secret: str | None = Field(default=None, max_length=4096)
    allowed_domains: list[str] = Field(default_factory=list)
    jit_provisioning: bool = True
    sync_roles: bool = True
    require_mapping: bool = False
    default_role: RoleName = "viewer"
    default_clearance: ClearanceName = "internal"
    groups_claim: str = Field(default="groups", min_length=1, max_length=512)
    role_mappings: list[RoleMapping] = Field(default_factory=list)

    @field_validator("allowed_domains")
    @classmethod
    def _norm_domains(cls, v: list[str]) -> list[str]:
        return normalize_domains(v)


class ProviderPatch(BaseModel):
    """Partial update. ``client_secret``: omit = keep, "" = clear."""

    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool | None = None
    preset: Preset | None = None
    oidc: OIDCConfig | None = None
    saml: SAMLConfig | None = None
    saml_metadata_xml: str | None = Field(default=None, max_length=500_000)
    client_secret: str | None = Field(default=None, max_length=4096)
    allowed_domains: list[str] | None = None
    jit_provisioning: bool | None = None
    sync_roles: bool | None = None
    require_mapping: bool | None = None
    default_role: RoleName | None = None
    default_clearance: ClearanceName | None = None
    groups_claim: str | None = Field(default=None, min_length=1, max_length=512)
    role_mappings: list[RoleMapping] | None = None

    @field_validator("allowed_domains")
    @classmethod
    def _norm_domains(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else normalize_domains(v)


class ProviderOut(BaseModel):
    id: UUID
    slug: str
    kind: str
    preset: str
    display_name: str
    enabled: bool
    config: dict[str, Any]
    has_client_secret: bool
    allowed_domains: list[str]
    jit_provisioning: bool
    sync_roles: bool
    require_mapping: bool
    default_role: str
    default_clearance: str
    groups_claim: str
    role_mappings: list[dict[str, Any]]
    created_by: str | None = None
    created_at: datetime
    updated_at: datetime
    # Values to paste into the IdP.
    redirect_uri: str | None = None
    saml_acs_url: str | None = None
    saml_entity_id: str | None = None
    saml_metadata_url: str | None = None


class PublicProvider(BaseModel):
    slug: str
    kind: str
    preset: str
    display_name: str
    start_url: str


class PublicProvidersOut(BaseModel):
    providers: list[PublicProvider]
    sso_required: bool


class ExchangeIn(BaseModel):
    code: str = Field(min_length=16, max_length=256)
    verifier: str | None = Field(default=None, min_length=32, max_length=256)


class IdentitySettingsIn(BaseModel):
    sso_required: bool | None = None
    break_glass_users: list[str] | None = None
    scim_role_mappings: list[RoleMapping] | None = None
    scim_default_role: RoleName | None = None
    scim_default_clearance: ClearanceName | None = None


class IdentitySettingsOut(BaseModel):
    sso_required: bool
    break_glass_users: list[str]
    scim_role_mappings: list[dict[str, Any]]
    scim_default_role: str
    scim_default_clearance: str
    updated_by: str | None = None
    updated_at: datetime
    scim_base_url: str


class ScimTokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    expires_at: datetime | None = None


class ScimTokenOut(BaseModel):
    id: UUID
    name: str
    prefix: str
    created_by: str | None = None
    created_at: datetime
    last_used: datetime | None = None
    expires_at: datetime | None = None
    revoked: bool


class ScimTokenCreateOut(ScimTokenOut):
    token: str  # shown exactly once
