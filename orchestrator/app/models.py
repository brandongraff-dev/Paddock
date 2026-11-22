"""Pydantic request/response models.

Everything crossing the HTTP boundary is validated here. Models are kept
close to the Postgres schema (`/schema/*.sql`) so that the contract in
CONTRACTS.md and the schema stay in lockstep.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .constants import RULE_SOURCES


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #

ScopeKind = Literal["domain", "subdomain_wildcard", "ipv4_cidr", "ipv6_cidr", "asn"]


class ScopeEntryIn(BaseModel):
    kind: ScopeKind
    value: str = Field(min_length=1, max_length=512)
    added_by: str = Field(min_length=1, max_length=256)
    auth_doc_ref: str | None = None
    expires_at: datetime | None = None
    notes: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScopeEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: ScopeKind
    value: str
    added_by: str
    added_at: datetime
    expires_at: datetime | None
    auth_doc_ref: str | None
    active: bool
    notes: str | None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScopeCheckIn(BaseModel):
    target: str = Field(min_length=1, max_length=1024)
    worker: str = Field(default="api", max_length=256)
    reason: str = Field(default="", max_length=512)


class ScopeCheckOut(BaseModel):
    allow: bool
    normalized: str
    reason: str
    matched_entry: int | None = None
    matched_entry_metadata: dict[str, Any] = Field(default_factory=dict)
    # Addresses the decision vetted (allow only). Workers connect to these and
    # never re-resolve the hostname (DNS-rebinding defence).
    resolved_ips: list[str] = Field(default_factory=list)


class ScopeDecisionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    normalized: str
    decision: Literal["allow", "deny"]
    matched_entry: int | None
    worker: str
    reason: str | None
    decided_at: datetime


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #

ScanStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
_TERMINAL_SCAN_STATUSES = {"completed", "failed", "cancelled"}


class ScanIn(BaseModel):
    kind: str = Field(min_length=1, max_length=128)
    target: str = Field(min_length=1, max_length=1024)
    config: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=5, ge=0, le=9)
    parent_scan_id: UUID | None = None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    kind: str
    target: str
    status: ScanStatus
    priority: int
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    worker_id: str | None
    config: dict[str, Any]
    result_summary: dict[str, Any]
    error: str | None
    parent_scan_id: UUID | None


class ScanPatch(BaseModel):
    status: ScanStatus | None = None
    result_summary: dict[str, Any] | None = None
    error: str | None = None
    worker_id: str | None = None


class ScanStartIn(BaseModel):
    worker_id: str | None = None


class ScanCompleteIn(BaseModel):
    result_summary: dict[str, Any] = Field(default_factory=dict)


class ScanFailIn(BaseModel):
    error: str = Field(default="")


# --------------------------------------------------------------------------- #
# Assets
# --------------------------------------------------------------------------- #

AssetKind = Literal[
    "org",
    "domain",
    "subdomain",
    "ipv4",
    "ipv6",
    "port",
    "service",
    "technology",
    "certificate",
    "endpoint",
    "repository",
    "secret_candidate",
    "cloud_account",
    "cloud_resource",
    "iot_device",
    "ot_device",
    "network_segment",
]


class AssetIn(BaseModel):
    # NOTE: `_edge` is a sentinel used by the passive worker to piggyback
    # edge creation through the same bulk endpoint. It is not a real asset
    # kind and never ends up in the `assets` table.
    kind: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1, max_length=2048)
    canonical: str | None = None
    source: str = Field(min_length=1, max_length=128)
    confidence: int = Field(default=100, ge=0, le=100)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssetBulkIn(BaseModel):
    items: list[AssetIn] = Field(min_length=1, max_length=1000)


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    kind: AssetKind
    value: str
    canonical: str
    first_seen: datetime
    last_seen: datetime
    confidence: int
    source: str
    metadata: dict[str, Any]
    # Enriched: own metadata.blast_score, else MAX among open findings, else null.
    blast_score: float | None = None
    # ABAC classification label (schema 011). Null on the bulk/patch RETURNING
    # paths that don't select it; populated on list/detail reads.
    classification: str | None = None


class AssetEdgeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    src_id: UUID
    dst_id: UUID
    kind: str
    first_seen: datetime
    last_seen: datetime
    metadata: dict[str, Any]


class AssetGraphOut(BaseModel):
    root: UUID
    depth: int
    truncated: bool
    nodes: list[AssetOut]
    edges: list[AssetEdgeOut]


class AssetBulkOut(BaseModel):
    inserted: int
    updated: int
    items: list[AssetOut]
    edges_inserted: int = 0
    edges_updated: int = 0
    edges_skipped_missing_endpoint: int = 0


class EdgeIn(BaseModel):
    """An edge, either referenced by uuid or by (kind, canonical) pair."""

    src_id: UUID | None = None
    dst_id: UUID | None = None
    src_kind: str | None = None
    src_canonical: str | None = None
    dst_kind: str | None = None
    dst_canonical: str | None = None
    kind: str = Field(min_length=1, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EdgeBulkIn(BaseModel):
    edges: list[EdgeIn] = Field(min_length=1, max_length=1000)


class EdgeBulkOut(BaseModel):
    edges_inserted: int
    edges_updated: int
    edges_skipped_missing_endpoint: int


# Whole-surface graph (dashboard hero page)
class GraphNodeOut(BaseModel):
    id: UUID
    kind: str
    value: str
    canonical: str
    degree: int
    open_high_crit_count: int
    metadata: dict[str, Any] = Field(default_factory=dict)
    # Enriched: own metadata.blast_score, else MAX among open findings, else null.
    blast_score: float | None = None


class GraphEdgeOut(BaseModel):
    id: UUID
    src_id: UUID
    dst_id: UUID
    kind: str


class SurfaceGraphOut(BaseModel):
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

Severity = Literal["info", "low", "medium", "high", "critical"]
FindingStatus = Literal[
    "open", "triaged", "false_positive", "accepted_risk", "fixed", "wontfix",
    "accepted",  # schema 019: risk accepted (reason required, optional expiry)
]
# Single-sourced from app.constants.RULE_SOURCES (which mirrors the DB CHECK
# constraint on findings.rule_source). tests/test_rule_source_sync.py asserts
# the two stay equal, so this type can never silently drift from the schema.
RuleSource = Literal[*RULE_SOURCES]


class FindingIn(BaseModel):
    # asset_id is preferred; if absent, workers may send asset_value +
    # asset_kind and the orchestrator resolves / upserts the asset first.
    asset_id: UUID | None = None
    asset_value: str | None = None
    asset_kind: str | None = None  # defaults to 'endpoint' when asset_value given
    rule_id: str = Field(min_length=1, max_length=256)
    rule_source: RuleSource
    severity: Severity
    title: str = Field(min_length=1, max_length=512)
    description: str
    impact: str | None = None
    remediation: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    cvss: float | None = Field(default=None, ge=0, le=10)
    epss: float | None = Field(default=None, ge=0, le=1)
    references: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class FindingBulkIn(BaseModel):
    items: list[FindingIn] = Field(min_length=1, max_length=1000)


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: UUID
    rule_id: str
    rule_source: RuleSource
    severity: Severity
    title: str
    description: str
    impact: str | None
    remediation: str | None
    evidence: dict[str, Any]
    cvss: float | None
    epss: float | None
    references: list[str]
    status: FindingStatus
    first_seen: datetime
    last_seen: datetime
    assigned_to: str | None
    metadata: dict[str, Any]
    # Enriched join fields (populated by the list/detail endpoints; the
    # bulk/patch RETURNING paths leave them null).
    asset_value: str | None = None
    asset_kind: str | None = None
    blast_score: float | None = None
    # ABAC classification label (schema 011).
    classification: str | None = None


class FindingPatch(BaseModel):
    status: FindingStatus | None = None
    assigned_to: str | None = None
    notes: str | None = None


class FindingBulkOut(BaseModel):
    inserted: int
    updated: int
    items: list[FindingOut]


class FindingPage(BaseModel):
    items: list[FindingOut]
    total: int
    limit: int
    offset: int


class FindingDetailOut(BaseModel):
    """Single finding with its asset and any chain it participates in."""

    finding: FindingOut
    asset: AssetOut | None
    chains: list["ChainOut"] = Field(default_factory=list)


class ChainIn(BaseModel):
    chain_rule_id: str = Field(min_length=1, max_length=256)
    severity: Severity
    title: str = Field(min_length=1, max_length=512)
    description: str
    impact_narrative: str | None = None
    blast_radius_score: float | None = Field(default=None, ge=0, le=100)
    finding_ids: list[UUID] = Field(min_length=1, max_length=256)
    anchor_asset_id: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    chain_rule_id: str
    severity: str
    title: str
    description: str
    impact_narrative: str | None
    blast_radius_score: float | None
    created_at: datetime
    finding_ids: list[UUID]
    anchor_asset_id: UUID | None
    metadata: dict[str, Any]
    # Enriched join fields (populated by GET /v1/chains)
    anchor_asset: AssetOut | None = None
    finding_severities: list[Severity] = Field(default_factory=list)


FindingDetailOut.model_rebuild()


# --------------------------------------------------------------------------- #
# Outbound audit
# --------------------------------------------------------------------------- #

class OutboundLogIn(BaseModel):
    worker: str = Field(min_length=1, max_length=256)
    target: str = Field(min_length=1, max_length=2048)
    tool: str = Field(min_length=1, max_length=64)
    method: str | None = None
    request_summary: str | None = None
    response_code: int | None = None
    scope_matched: bool
    scope_entry_id: int | None = None
    # started_at may be a float epoch timestamp (what workers send) or an
    # ISO string / datetime. The router converts.
    started_at: float | datetime
    duration_ms: int | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    error: str | None = None


class OutboundBulkIn(BaseModel):
    entries: list[OutboundLogIn] = Field(min_length=1, max_length=5000)


class OutboundBulkOut(BaseModel):
    inserted: int


# --------------------------------------------------------------------------- #
# Timeline
# --------------------------------------------------------------------------- #


class TimelineDay(BaseModel):
    day: date
    asset_count: int
    finding_count: int
    # Breakdown the dashboard's severity charts need (was never populated,
    # so the Overview trend rendered all-zero).
    new_findings_by_severity: dict[str, int] = Field(default_factory=dict)
    scans_run: int = 0
    sample_assets: list[dict[str, Any]]
    sample_findings: list[dict[str, Any]]


class TimelineOut(BaseModel):
    from_: date = Field(alias="from")
    to: date
    days: list[TimelineDay]

    model_config = ConfigDict(populate_by_name=True)


# --------------------------------------------------------------------------- #
# Tier 1: attack paths
# --------------------------------------------------------------------------- #


class PathAssetRef(BaseModel):
    """Compact asset summary for a path's source/target or a hop node."""

    id: UUID | None = None
    value: str | None = None
    kind: str | None = None


class HopFindingRef(BaseModel):
    """A finding summary attached to a hop in the detail view."""

    id: UUID
    title: str
    severity: Severity


class AttackPathHopOut(BaseModel):
    # The hop's asset (enriched with value/kind from the assets table).
    asset_id: UUID | None = None
    kind: str | None = None
    value: str | None = None
    max_severity: Severity | None = None
    entry_cost: float | None = None
    edge_kind_in: str | None = None
    finding_ids: list[UUID] = Field(default_factory=list)
    # Populated only by the detail endpoint; empty in the list view.
    findings: list[HopFindingRef] = Field(default_factory=list)


class AttackPathOut(BaseModel):
    id: UUID
    source_asset_id: UUID | None = None
    target_asset_id: UUID | None = None
    # Nested summaries (value + kind) for the dashboard strip endpoints.
    source: PathAssetRef | None = None
    target: PathAssetRef | None = None
    length: int
    total_cost: float
    exploitability: float
    severity: Severity
    kev_on_path: bool
    title: str
    narrative: str | None = None
    hops: list[AttackPathHopOut] = Field(default_factory=list)
    computed_at: datetime
    fingerprint: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackPathPage(BaseModel):
    items: list[AttackPathOut]
    total: int
    limit: int
    offset: int


class RecomputeOut(BaseModel):
    """Result of POST /v1/attack-paths/recompute.

    `queued` is true when a recompute job was enqueued on Redis; `computed`
    is set when the synchronous correlation call returned a path count.
    `reason` explains a `queued:false` (correlation unreachable AND the
    fallback enqueue failed) without failing the request hard.
    """

    queued: bool
    computed: int | None = None
    reason: str | None = None


# --------------------------------------------------------------------------- #
# Tier 1: change intelligence
# --------------------------------------------------------------------------- #

ChangeType = Literal[
    "subdomain_discovered",
    "endpoint_discovered",
    "ip_discovered",
    "port_opened",
    "port_closed",
    "tech_detected",
    "tech_version_changed",
    "cert_added",
    "cert_expiring",
    "secret_found",
    "repository_found",
    "finding_opened",
    "finding_resolved",
    "exposure_increased",
    "asset_removed",
    "chain_detected",
    "attack_path_found",
]


class SurfaceChangeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    change_type: str
    asset_id: UUID | None
    asset_kind: str | None
    asset_value: str | None
    severity: Severity
    summary: str
    detail: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime
    acknowledged: bool
    ack_by: str | None
    ack_at: datetime | None


class ChangePage(BaseModel):
    items: list[SurfaceChangeOut]
    total: int
    limit: int
    offset: int


class ChangeSummaryDay(BaseModel):
    day: date
    info: int = 0
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class ChangeSummaryOut(BaseModel):
    by_type: dict[str, int] = Field(default_factory=dict)
    by_day: list[ChangeSummaryDay] = Field(default_factory=list)
    total: int = 0


# --------------------------------------------------------------------------- #
# Tier 1: alert rules
# --------------------------------------------------------------------------- #

AlertChannel = Literal["log", "webhook", "slack"]


class AlertRuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    # match: {change_types:[...], min_severity:'high', kinds:[...]} (all optional).
    match: dict[str, Any] = Field(default_factory=dict)
    channel: AlertChannel
    target: str | None = Field(default=None, max_length=2048)
    enabled: bool = True


class AlertRulePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=256)
    match: dict[str, Any] | None = None
    channel: AlertChannel | None = None
    target: str | None = Field(default=None, max_length=2048)
    enabled: bool | None = None


class AlertRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    enabled: bool
    match: dict[str, Any] = Field(default_factory=dict)
    channel: str
    target: str | None
    created_at: datetime
    last_fired: datetime | None


class AlertDeliveryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: UUID | None
    change_id: UUID | None
    status: str
    channel: str
    response: str | None
    delivered_at: datetime


# --------------------------------------------------------------------------- #
# Tier 2: continuous-monitoring schedules
# --------------------------------------------------------------------------- #

# Open status set (mirrors the schema's partial-index predicate): a ticket is
# "open" / SLA-tracked while it is NOT in one of these terminal statuses.
TICKET_CLOSED_STATUSES = ("resolved", "closed", "wontfix")

TlsGrade = Literal["A+", "A", "B", "C", "D", "E", "F", "T"]
TicketStatus = Literal[
    "open", "acknowledged", "in_progress", "resolved", "closed", "wontfix"
]
TicketSystem = Literal["internal", "webhook", "github", "jira"]


class ScheduleIn(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    scan_kind: str = Field(min_length=1, max_length=128)
    target_scope: str = Field(min_length=1, max_length=512)
    # cron is NOT NULL in the schema; empty string == "interval-driven" (the
    # schedule runs off config.every_n_minutes instead of a cron string).
    cron: str = Field(default="", max_length=256)
    enabled: bool = True
    created_by: str | None = Field(default=None, max_length=256)
    config: dict[str, Any] = Field(default_factory=dict)


class SchedulePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=256)
    scan_kind: str | None = Field(default=None, min_length=1, max_length=128)
    target_scope: str | None = Field(default=None, min_length=1, max_length=512)
    cron: str | None = Field(default=None, max_length=256)
    enabled: bool | None = None
    config: dict[str, Any] | None = None


class ScheduleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    scan_kind: str
    target_scope: str
    cron: str
    enabled: bool
    last_run_at: datetime | None
    next_run_at: datetime | None
    last_status: str | None
    config: dict[str, Any] = Field(default_factory=dict)


class ScheduleRunOut(BaseModel):
    """Result of POST /v1/schedules/{id}/run-now (or a scheduler tick)."""

    schedule: ScheduleOut
    enqueued: int
    scan_ids: list[UUID] = Field(default_factory=list)
    status: str


# --------------------------------------------------------------------------- #
# Tier 2: TLS posture grades
# --------------------------------------------------------------------------- #


class TlsGradeIn(BaseModel):
    # The active worker always knows the asset it graded; asset_id is the
    # upsert key (schema UNIQUE(asset_id)).
    asset_id: UUID
    host: str = Field(min_length=1, max_length=512)
    grade: TlsGrade
    score: int = Field(ge=0, le=100)
    protocols: list[str] = Field(default_factory=list)
    weak_ciphers: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    cert_expires: datetime | None = None


class TlsGradeBulkIn(BaseModel):
    items: list[TlsGradeIn] = Field(min_length=1, max_length=1000)


class TlsGradeBulkOut(BaseModel):
    inserted: int
    updated: int


class TlsGradeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: UUID | None
    host: str
    grade: TlsGrade
    score: int
    protocols: list[str] = Field(default_factory=list)
    weak_ciphers: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    cert_expires: datetime | None
    graded_at: datetime
    # Enriched join field (populated by the list endpoint).
    asset_value: str | None = None


class TlsGradePage(BaseModel):
    items: list[TlsGradeOut]
    total: int
    limit: int
    offset: int


class TlsGradeSummary(BaseModel):
    # counts per grade for every grade bucket (A+..F, T), zero-filled.
    counts: dict[str, int] = Field(default_factory=dict)
    total: int = 0


# --------------------------------------------------------------------------- #
# Tier 2: tickets + owners + SLA
# --------------------------------------------------------------------------- #


class TicketAssetRef(BaseModel):
    value: str | None = None
    kind: str | None = None


class TicketFindingRef(BaseModel):
    title: str | None = None
    rule_source: str | None = None


class TicketOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    finding_id: UUID | None
    title: str
    severity: Severity
    owner_team: str | None
    contact: str | None
    system: TicketSystem
    external_url: str | None
    status: TicketStatus
    sla_hours: int | None
    sla_due: datetime | None
    breached: bool
    opened_at: datetime
    closed_at: datetime | None
    # Enriched via LEFT JOINs (no N+1).
    asset: TicketAssetRef | None = None
    finding: TicketFindingRef | None = None


class TicketPatch(BaseModel):
    status: TicketStatus | None = None
    owner_team: str | None = None
    contact: str | None = None


class TicketPage(BaseModel):
    items: list[TicketOut]
    total: int
    limit: int
    offset: int


class TicketSummary(BaseModel):
    open: int = 0
    breached: int = 0
    resolved_7d: int = 0
    by_team: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)


class OwnerIn(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    # match: {kinds:[...], value_regex:"", cidr:"", metadata_env:"", tag:""}
    match: dict[str, Any] = Field(default_factory=dict)
    team: str = Field(min_length=1, max_length=256)
    contact: str | None = Field(default=None, max_length=512)
    priority: int = Field(default=100, ge=0, le=32767)
    enabled: bool = True


class OwnerPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=256)
    match: dict[str, Any] | None = None
    team: str | None = Field(default=None, min_length=1, max_length=256)
    contact: str | None = Field(default=None, max_length=512)
    priority: int | None = Field(default=None, ge=0, le=32767)
    enabled: bool | None = None


class OwnerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    match: dict[str, Any] = Field(default_factory=dict)
    team: str
    contact: str | None
    priority: int
    enabled: bool
    created_at: datetime


class SlaPolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    severity: Severity
    hours: int


class SlaPolicyPatch(BaseModel):
    hours: int = Field(ge=0)


# --------------------------------------------------------------------------- #
# Tier 3: SCA / SBOM + supply-chain risk
# --------------------------------------------------------------------------- #

RiskType = Literal[
    "dependency_confusion",
    "typosquat",
    "abandoned",
    "malicious_version",
    "yanked",
    "unpinned",
    "install_scripts",
]


class SbomProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    source_ref: str | None
    ecosystems: list[str] = Field(default_factory=list)
    asset_id: UUID | None
    created_at: datetime
    last_scanned: datetime | None
    # Rolled-up counts (one grouped query, no N+1).
    component_count: int = 0
    vuln_count: int = 0


# Tier 4: how reachable the vulnerable symbol is from first-party code.
# reachable > potential > unreachable > unknown (used for the component rollup).
ReachabilityGrade = Literal["reachable", "potential", "unreachable", "unknown"]


class SbomVulnOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    component_id: UUID
    osv_id: str
    cve_id: str | None
    severity: Severity
    cvss: float | None
    summary: str | None
    fixed_version: str | None
    refs: list[Any] = Field(default_factory=list)
    matched_at: datetime
    # Tier 4 reachability (static call-graph analysis). Defaults keep the
    # Tier 3 shape valid for rows written before reachability existed.
    reachability: ReachabilityGrade = "unknown"
    reachable_symbol: str | None = None
    call_path: list[Any] = Field(default_factory=list)


class SbomComponentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    ecosystem: str
    name: str
    version: str
    purl: str | None
    direct: bool
    depth: int
    paths: list[Any] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)
    # Enriched (LEFT JOIN sbom_component_vulns, grouped; no N+1).
    vuln_count: int = 0
    max_vuln_severity: Severity | None = None
    # Tier 4: worst reachability among the component's vulns (reachable >
    # potential > unreachable > unknown), null when the component has no vulns,
    # plus how many of its vulns are actually `reachable`.
    reachability: ReachabilityGrade | None = None
    reachable_vuln_count: int = 0


class SbomComponentPage(BaseModel):
    items: list[SbomComponentOut]
    total: int
    limit: int
    offset: int


class SbomComponentDetailOut(BaseModel):
    """A component with its matched vulnerabilities."""

    component: SbomComponentOut
    vulns: list[SbomVulnOut] = Field(default_factory=list)


class SupplyChainRiskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID | None
    component_id: UUID | None
    risk_type: RiskType
    severity: Severity
    summary: str
    detail: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime
    # Enriched via LEFT JOINs (no N+1).
    component_name: str | None = None
    component_ecosystem: str | None = None
    project_name: str | None = None


class SupplyChainRiskPage(BaseModel):
    items: list[SupplyChainRiskOut]
    total: int
    limit: int
    offset: int


class SbomSummary(BaseModel):
    components: int = 0
    vulnerable_components: int = 0
    by_risk_type: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Tier 3: MITRE ATT&CK mapping
# --------------------------------------------------------------------------- #


class AttackTechniqueCoverage(BaseModel):
    technique_id: str
    technique: str
    tactic: str
    count: int


class AttackCoverageOut(BaseModel):
    by_tactic: dict[str, int] = Field(default_factory=dict)
    by_technique: list[AttackTechniqueCoverage] = Field(default_factory=list)
    total_findings_mapped: int = 0


class AttackCatalogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    match: dict[str, Any] = Field(default_factory=dict)
    technique_id: str
    technique: str
    tactic: str
    cwe: str | None
    priority: int
    enabled: bool


class FindingTechniqueOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    finding_id: UUID
    technique_id: str
    technique: str
    tactic: str
    cwe: str | None
    confidence: int
    mapped_at: datetime


# --------------------------------------------------------------------------- #
# Tier 3: LLM triage clusters + NL-query ("Ask")
# --------------------------------------------------------------------------- #


class ClusterOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    label: str
    summary: str | None
    severity: str | None
    finding_ids: list[UUID] = Field(default_factory=list)
    engine: str
    created_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class AskIn(BaseModel):
    question: str = Field(min_length=1, max_length=2048)
    asked_by: str | None = Field(default=None, max_length=256)


class AskOut(BaseModel):
    """Documented success shape forwarded from the brain service.

    The `POST /v1/ask` proxy forwards the brain's body verbatim (setting
    `ok` when the upstream omits it). When the brain is unreachable it degrades
    to `{ok:false, engine:"unavailable", note:"brain service not reachable"}`
    instead of raising -- see the router.
    """

    ok: bool = True
    engine: str | None = None
    note: str | None = None
    answer_rows: list[dict[str, Any]] = Field(default_factory=list)
    columns: list[str] = Field(default_factory=list)
    generated_sql: str | None = None


# --------------------------------------------------------------------------- #
# Tier 4: code findings (SAST) + reachability
# --------------------------------------------------------------------------- #


class DataflowStep(BaseModel):
    """One ordered step in a source->sink taint trace (shape is advisory;
    extra keys are tolerated so the SAST engine can enrich freely)."""

    model_config = ConfigDict(extra="allow")

    file: str | None = None
    line: int | None = None
    note: str | None = None


class CodeFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID | None
    asset_id: UUID | None = None
    finding_id: UUID | None = None
    engine: str
    rule: str
    message: str
    severity: Severity
    file: str
    start_line: int | None
    end_line: int | None
    source: str | None
    sink: str | None
    dataflow: list[Any] = Field(default_factory=list)
    cwe: str | None
    detected_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)
    # Enriched via LEFT JOIN to sca_projects (no N+1).
    project_name: str | None = None


class CodeFindingPage(BaseModel):
    items: list[CodeFindingOut]
    total: int
    limit: int
    offset: int


# --------------------------------------------------------------------------- #
# Tier 4: adaptive ML risk scores + models + anomalies
# --------------------------------------------------------------------------- #


class MlRiskRationale(BaseModel):
    """A single explainability entry: a feature and its signed contribution."""

    model_config = ConfigDict(extra="allow")

    feature: str
    contribution: float


class MlRiskFindingRef(BaseModel):
    title: str | None = None
    severity: Severity | None = None
    rule_source: str | None = None


class MlRiskAssetRef(BaseModel):
    value: str | None = None
    kind: str | None = None


class MlRiskRow(BaseModel):
    finding_id: UUID
    ml_risk: float
    model_version: int | None = None
    rationale: list[MlRiskRationale] = Field(default_factory=list)
    scored_at: datetime | None = None
    finding: MlRiskFindingRef | None = None
    asset: MlRiskAssetRef | None = None


class MlRiskPage(BaseModel):
    items: list[MlRiskRow]
    total: int
    limit: int
    offset: int


class MlModelOut(BaseModel):
    """One active model (risk_ranker or anomaly_detector). The GET /v1/ml/model
    endpoint returns {risk_ranker: MlModelOut|null, anomaly_detector: MlModelOut|null}."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    kind: str
    version: int
    algo: str
    trained_at: datetime
    n_samples: int
    metrics: dict[str, Any] = Field(default_factory=dict)
    feature_importance: dict[str, Any] = Field(default_factory=dict)
    cold_start: bool
    active: bool
    notes: str | None = None


class AnomalyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    subject_type: str
    subject_id: UUID | None
    subject_label: str
    score: float
    severity: Severity
    reason: str
    features: dict[str, Any] = Field(default_factory=dict)
    model_version: int | None
    detected_at: datetime
    acknowledged: bool


class AnomalyPage(BaseModel):
    items: list[AnomalyOut]
    total: int
    limit: int
    offset: int


# --------------------------------------------------------------------------- #
# Governance: auth, audit, provenance (schema 011)
# --------------------------------------------------------------------------- #

Role = Literal["viewer", "analyst", "admin", "auditor"]
Classification = Literal["public", "internal", "confidential", "restricted"]


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)


class LoginOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    clearance: str
    expires_in: int


class MeOut(BaseModel):
    actor: str
    role: str
    clearance: str
    capabilities: list[str]
    kind: str
    tenant_id: str | None = None


class ApiKeyCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    # Owning user; defaults to the admin issuing the key.
    username: str | None = None
    scopes: list[str] = Field(default_factory=lambda: ["read"])
    expires_at: datetime | None = None


class ApiKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    user_id: UUID | None
    name: str
    prefix: str
    scopes: list[str]
    created_at: datetime
    last_used: datetime | None
    expires_at: datetime | None
    revoked: bool


class ApiKeyCreateOut(ApiKeyOut):
    # The raw key is returned exactly once, on creation.
    api_key: str


class AuditEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    actor: str
    actor_role: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    method: str | None
    path: str | None
    status: int | None
    classification: str | None
    justification: str | None
    ip: str | None
    request_id: str | None
    details: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    entry_hash: str


class AuditPage(BaseModel):
    items: list[AuditEntryOut]
    total: int
    limit: int
    offset: int


class AuditVerifyOut(BaseModel):
    ok: bool
    checked: int
    first_broken_id: int | None = None
    # Why verification failed: chain_link | row_hash | downgrade | unknown_key |
    # unknown_alg | anchor_<status>. None when ok.
    reason: str | None = None
    tenant_id: str | None = None
    head_id: int | None = None
    head_hash: str | None = None
    # {status: not_configured|none|ok|truncated|mismatch|bad_signature|
    #  unknown_key|unsigned|unavailable|skipped, max_id?, head_hash?, ts?, sink?}
    anchor: dict[str, Any] | None = None


class AuditAnchorOut(BaseModel):
    anchored: bool
    reason: str | None = None
    anchor: dict[str, Any] | None = None
    receipt: dict[str, Any] | None = None


class ProvenanceIn(BaseModel):
    subject_type: Literal[
        "asset", "finding", "attack_path", "sbom_component", "ticket", "anomaly"
    ]
    subject_id: UUID
    source_service: str = Field(min_length=1, max_length=128)
    source_detail: str | None = None
    method: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    confidence: int = Field(default=100, ge=0, le=100)


class ProvenanceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    subject_type: str
    subject_id: UUID
    source_service: str
    source_detail: str | None
    method: str | None
    evidence: dict[str, Any] = Field(default_factory=dict)
    confidence: int
    recorded_at: datetime


class ProvenanceBackfillOut(BaseModel):
    created: dict[str, int]
