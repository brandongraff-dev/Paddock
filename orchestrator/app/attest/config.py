"""Attestation settings (docs/ASSURANCE_P3.md 5.11). Env prefix ``PADDOCK_ATTEST_``; ``app/config.py`` is not edited.

Secrets are ``SecretStr`` so ``repr(settings)``, ``model_dump()`` and logs never show them. Nothing here reads a file or
decodes a key: that happens at use time in ``crypto`` (no cache, so a rotated KEK file is picked up on the next call).
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class AttestSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PADDOCK_ATTEST_", env_file=".env", extra="ignore")

    #: global kill switch for issuing (the loop still runs revocation duties)
    issuing: bool = True

    # --- hosted-custody key encryption key (3.5). Deliberately NOT PADDOCK_SECRET_KEY. -----------------------------
    kek: SecretStr | None = None                  # 32 bytes, base64 (urlsafe or standard)
    kek_file: str | None = None                   # a file holding the same text
    kek_previous: SecretStr | None = None         # comma list of older KEKs, for rotation (open only)
    kek_kms_key_id: str | None = None             # KMS-wrapped KEK: reserved, not implemented (stub)

    # --- platform key material (3.1); loaded by attest.platform_keys (P3.3) ----------------------------------------
    issuer_key_file: str | None = None
    issuer_cert_file: str | None = None
    revoker_key_file: str | None = None
    revoker_cert_file: str | None = None
    platform_key_passphrase: SecretStr | None = None
    trust_roots_file: str | None = None

    # --- issuing (5.5) --------------------------------------------------------------------------------------------
    ttl_default_h: int = Field(24, ge=1, le=72)
    tick_s: int = Field(60, ge=1)
    upgrade_debounce_s: int = Field(300, ge=0)
    min_spacing_s: int = Field(300, ge=0)
    min_result_life_s: int = Field(900, ge=0)
    #: ``declared`` is never public (D11); ``tested`` is accepted here but the issuer caps it out until P5 ships.
    max_tier: Literal["configured", "observed", "tested"] = "observed"
    graph_leaf_cap: int = Field(500000, ge=1)
    require_anchor: bool = False                  # the hosted SaaS deployment sets true
    anchor_max_age_s: int = Field(7200, ge=1)

    # --- DNS binding and serving (4.2, 6.2) -----------------------------------------------------------------------
    dns_recheck_hours: int = Field(6, ge=1)
    dns_grace_hours: int = Field(6, ge=0)
    dns_resolvers: str | None = None              # comma list; unset = the system resolver
    dns_trust_ad: bool = False
    serving_sweep_s: int = Field(300, ge=1)
    history_served: int = Field(60, ge=1)
    statement_max_bytes: int = Field(262144, ge=1)
    public_base_url: str | None = None            # hosted TXT hint

    #: reserved: no BYOK route exists in P3 (D18)
    byok_enabled: bool = False

    @property
    def dns_resolver_list(self) -> list[str]:
        return [r.strip() for r in (self.dns_resolvers or "").split(",") if r.strip()]


settings = AttestSettings()
