"""Pydantic models for the reporting API (kept out of the shared models.py)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


class Window(BaseModel):
    start: datetime
    end: datetime
    days: int
    prev_start: datetime
    label: str


class TrendPoint(BaseModel):
    at: datetime
    value: int


class ExposureTrend(BaseModel):
    points: list[TrendPoint]
    start_value: int
    end_value: int
    delta: int
    delta_pct: Optional[float] = None
    open_start: dict[str, int]
    open_end: dict[str, int]


class FindingBrief(BaseModel):
    id: UUID
    title: str
    severity: str
    status: str
    rule_id: str
    rule_source: str
    asset_value: Optional[str] = None
    asset_kind: Optional[str] = None
    first_seen: datetime
    team: Optional[str] = None


class NewFindings(BaseModel):
    by_severity: dict[str, int]
    previous_by_severity: dict[str, int]
    critical: int
    high: int
    previous_critical_high: int
    top: list[FindingBrief]


class Resolutions(BaseModel):
    fixed: int
    verified: int
    regressed: int
    pending_verification: int
    accepted_risk: int
    false_positive: int
    wontfix: int
    fixed_by_severity: dict[str, int]


class MttrRow(BaseModel):
    key: str
    count: int
    mean_hours: float
    median_hours: float
    critical_high: int = 0


class Mttr(BaseModel):
    overall: Optional[MttrRow] = None
    by_severity: list[MttrRow]
    by_team: list[MttrRow]


class SlaRow(BaseModel):
    severity: str
    policy_hours: Optional[int] = None
    met: int
    late: int
    breached_open: int
    overdue_end: int
    open_within_sla: int
    compliance_pct: Optional[float] = None


class SlaBreach(BaseModel):
    finding_id: UUID
    title: str
    severity: str
    asset_value: Optional[str] = None
    team: str
    due_at: datetime
    overdue_hours: float


class Sla(BaseModel):
    met: int
    late: int
    breached_open: int
    overdue_end: int
    compliance_pct: Optional[float] = None
    by_severity: list[SlaRow]
    breaches: list[SlaBreach]


class PathBrief(BaseModel):
    fingerprint: str
    title: str
    severity: str
    exploitability: Optional[float] = None
    kev_on_path: bool = False
    length: Optional[int] = None
    opened_at: datetime
    closed_at: Optional[datetime] = None
    open_days: Optional[float] = None


class AttackPaths(BaseModel):
    opened: int
    closed: int
    open_start: int
    open_end: int
    top_opened: list[PathBrief]
    top_closed: list[PathBrief]


class RiskyAsset(BaseModel):
    asset_id: UUID
    value: str
    kind: str
    score: int
    open_findings: int
    critical: int
    high: int


class ChangeRow(BaseModel):
    change_type: str
    count: int


class ChangeBrief(BaseModel):
    change_type: str
    severity: str
    summary: str
    asset_value: Optional[str] = None
    detected_at: datetime


class SurfaceChanges(BaseModel):
    total: int
    by_type: list[ChangeRow]
    new_assets_by_kind: dict[str, int]
    notable: list[ChangeBrief]


class DeviceRuleRow(BaseModel):
    rule_id: str
    label: str
    opened: int
    open_end: int


class Devices(BaseModel):
    iot_total: int
    ot_total: int
    new_devices: int
    segments: int
    observed_reachability: int
    behaviour: list[DeviceRuleRow]
    top: list[FindingBrief]


class CoverageKind(BaseModel):
    kind: str
    total: int
    seen_24h: int
    seen_7d: int
    seen_30d: int
    stale: int


class Coverage(BaseModel):
    assets_total: int
    by_kind: list[CoverageKind]
    scans_by_status: dict[str, int]
    last_completed_scan: Optional[datetime] = None
    sbom_projects: int
    sbom_components: int
    sbom_last_scanned: Optional[datetime] = None
    tls_graded: int
    tls_below_b: int
    fleet_agents: int
    fleet_agents_recent: int


class ReportData(BaseModel):
    generated_at: datetime
    org_name: str
    clearance: str
    window: Window
    highlights: list[str]
    exposure: ExposureTrend
    new_findings: NewFindings
    resolutions: Resolutions
    mttr: Mttr
    sla: Sla
    attack_paths: AttackPaths
    risky_assets: list[RiskyAsset]
    changes: SurfaceChanges
    devices: Devices
    coverage: Coverage


# --------------------------------------------------------------------------- #
# Compliance
# --------------------------------------------------------------------------- #

ControlStatus = Literal["satisfied", "partial", "gap", "requires_attestation"]
EvidenceStatus = Literal["pass", "partial", "fail", "none"]


class EvidenceOut(BaseModel):
    key: str
    title: str
    status: EvidenceStatus
    detail: str
    metrics: dict[str, Any] = Field(default_factory=dict)
    rows: list[dict[str, Any]] = Field(default_factory=list)


class ControlOut(BaseModel):
    id: str
    title: str
    family: str
    summary: str
    mode: Literal["automated", "manual"]
    status: ControlStatus
    max_status: Literal["satisfied", "partial"]
    rationale: str
    attestation: Optional[str] = None
    evidence: list[EvidenceOut]


class FrameworkSummary(BaseModel):
    id: str
    name: str
    version: str
    publisher: str
    url: Optional[str] = None
    description: str
    counts: dict[str, int]
    total: int
    automated: int


class CompliancePack(BaseModel):
    framework: FrameworkSummary
    generated_at: datetime
    org_name: str
    clearance: str
    disclaimer: str
    controls: list[ControlOut]


class DigestRunOut(BaseModel):
    id: Optional[UUID] = None
    workspace: str
    status: str
    event_id: Optional[str] = None
    detail: Optional[str] = None
    period_start: datetime
    period_end: datetime
