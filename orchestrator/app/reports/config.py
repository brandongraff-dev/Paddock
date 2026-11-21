"""Reporting settings (env prefix ``REPORTS_``), kept out of the shared config."""

from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class ReportSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="REPORTS_", env_file=".env", extra="ignore")

    # Shown on the cover of every report.
    org_name: str = "Your organization"
    # Base URL of the dashboard, for deep links in the digest ("" = none).
    public_url: str = ""
    # Printed page size for PDF output ("A4" or "Letter").
    page_size: Literal["A4", "Letter"] = "A4"

    # Weekly digest. Runs from the existing scheduler loop; one per slot.
    digest_enabled: bool = True
    digest_weekday: int = 0  # 0 = Monday .. 6 = Sunday (UTC)
    digest_hour: int = 8  # hour of day, UTC
    digest_period_days: int = 7
    # Digests leave Paddock (Slack/Teams/email): cap what they may contain.
    digest_clearance: Literal["public", "internal", "confidential", "restricted"] = "internal"

    # Compliance: SLA compliance at or above this % counts as evidence "pass".
    sla_pass_pct: float = 90.0
    # Evidence older than this many days is treated as stale ("partial").
    evidence_fresh_days: int = 30


report_settings = ReportSettings()
