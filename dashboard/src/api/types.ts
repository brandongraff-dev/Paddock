/**
 * Shared TypeScript shapes. Mirror /schema/*.sql and /docs/CONTRACTS.md.
 * Keep this file source-of-truth: everything else imports from here.
 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";

/**
 * Data classification (governance §B). Ordered least→most sensitive; the
 * orchestrator filters reads above the caller's clearance in SQL, so a row
 * reaching the client is always at or below the caller's clearance. The same
 * ladder is reused as a user's `clearance` (see state/auth.ts).
 */
export type Classification = "public" | "internal" | "confidential" | "restricted";

export type FindingStatus =
  | "open"
  | "triaged"
  | "false_positive"
  | "accepted_risk"
  | "accepted"
  | "fixed"
  | "wontfix";

export type RuleSource =
  | "nuclei"
  | "cve_match"
  | "policy"
  | "chain"
  | "secret_scan"
  | "tls_check"
  | "header_check"
  | "exposed_file"
  | "manual";

export type AssetKind =
  | "org"
  | "domain"
  | "subdomain"
  | "ipv4"
  | "ipv6"
  | "port"
  | "service"
  | "technology"
  | "certificate"
  | "endpoint"
  | "repository"
  | "secret_candidate"
  | "cloud_account"
  | "cloud_resource";

export type ScanStatus = "queued" | "running" | "done" | "failed" | "scope_denied";

export interface Asset {
  id: string;
  kind: AssetKind;
  value: string;
  canonical: string;
  first_seen: string;
  last_seen: string;
  confidence: number;
  source: string;
  metadata: Record<string, unknown>;
  /** Derived by orchestrator — not a DB column; optional. */
  blast_score?: number | null;
  /** Count of open high/crit findings on this asset; drives graph pulse. */
  open_high?: number;
  /** Governance §B — ABAC data classification. Absent rows read as "public". */
  classification?: Classification;
}

export interface AssetEdge {
  id: string;
  src_id: string;
  dst_id: string;
  kind: string; // resolves_to, hosts, runs, has_version, …
  first_seen: string;
  last_seen: string;
  metadata: Record<string, unknown>;
}

export interface AssetGraphResponse {
  nodes: Asset[];
  edges: AssetEdge[];
}

export interface Finding {
  id: string;
  asset_id: string;
  rule_id: string;
  rule_source: RuleSource;
  severity: Severity;
  title: string;
  description: string;
  impact?: string | null;
  remediation?: string | null;
  evidence: Record<string, unknown>;
  cvss?: number | null;
  epss?: number | null;
  references?: string[];
  status: FindingStatus;
  first_seen: string;
  last_seen: string;
  assigned_to?: string | null;
  metadata: Record<string, unknown>;
  /** Hydrated by orchestrator (joined asset). Optional. */
  asset?: Asset;
  /**
   * Flattened asset columns surfaced on every finding row via the orchestrator's
   * LEFT JOIN to the finding's asset (a.value / a.kind). Null when the asset row
   * is missing. Prefer these over the heavier hydrated `asset` for table display.
   */
  asset_value?: string | null;
  asset_kind?: AssetKind | null;
  /** Derived; propagates from the asset. */
  blast_score?: number | null;
  /** Rare but present when the CVE is in CISA KEV. */
  kev?: boolean;
  /** Governance §B — ABAC data classification. Absent rows read as "public". */
  classification?: Classification;

  /* ---- Finding lifecycle (schema 019). All optional: older servers omit them. ---- */
  /** Why it was accepted / marked false positive / reopened. */
  status_reason?: string | null;
  status_by?: string | null;
  status_changed_at?: string | null;
  /** Acceptance expiry; the server reopens the finding after this. */
  accepted_until?: string | null;
  suppressed?: boolean;
  suppressed_by?: string | null;
  fingerprint?: string | null;
  /** Primary finding this one collapsed into (cross-engine dedupe). */
  duplicate_of?: string | null;
  sources?: FindingSource[];
  source_count?: number;
  due_at?: string | null;
  sla_hours?: number | null;
  sla_breached?: boolean;
  owner?: string | null;
  /** 0-100; the sum of `why` weights (capped). */
  priority_score?: number | null;
  why?: WhyFactor[];
  /** Detail endpoint only: transition timeline, newest first. */
  history?: StatusHistoryEntry[];

  /* ---- Verified findings (schema 026). Optional: older servers omit them. ---- */
  /** Safe-check verdict: unverified | confirmed | not_reproducible | inconclusive. */
  exploitability?: "unverified" | "confirmed" | "not_reproducible" | "inconclusive";
  last_verified_at?: string | null;
  /** Set when a re-check after the fix could no longer reproduce it ("verified fixed"). */
  fix_verified_at?: string | null;
}

export interface WhyFactor {
  key: string;
  label: string;
  weight: number;
}

export interface FindingSource {
  finding_id: string;
  rule_source: string;
  rule_id: string;
  status: FindingStatus;
  last_seen: string;
  primary: boolean;
}

export interface StatusHistoryEntry {
  id: string;
  from_status: FindingStatus | null;
  to_status: FindingStatus;
  reason: string | null;
  accepted_until: string | null;
  actor: string;
  at: string;
}

/** Paged findings envelope; hidden-by-default rows are counted, not listed. */
export interface FindingPage {
  items: Finding[];
  total: number;
  limit: number;
  offset: number;
  suppressed_total?: number;
  duplicates_total?: number;
}

export type SuppressedFilter = "exclude" | "include" | "only";

export interface Suppression {
  id: string;
  name: string | null;
  rule_id: string | null;
  rule_source: string | null;
  asset_pattern: string | null;
  tag: string | null;
  reason: string;
  author: string;
  expires_at: string | null;
  enabled: boolean;
  active: boolean;
  match_count: number;
  suppressed_now: number;
  last_matched_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface SuppressionInput {
  name?: string | null;
  rule_id?: string | null;
  rule_source?: string | null;
  asset_pattern?: string | null;
  tag?: string | null;
  reason: string;
  expires_at?: string | null;
  enabled?: boolean;
}

export interface TransitionResult {
  finding: Finding;
  from_status: FindingStatus;
  to_status: FindingStatus;
  propagated_to: number;
  suppression_id: string | null;
}

export interface FindingChain {
  id: string;
  chain_rule_id: string;
  severity: Severity;
  title: string;
  description: string;
  impact_narrative?: string | null;
  blast_radius_score?: number | null;
  created_at: string;
  finding_ids: string[];
  anchor_asset_id?: string | null;
  metadata: Record<string, unknown>;
  /** Hydrated (optional). */
  anchor_asset?: Asset;
  findings?: Finding[];
}

/** Must match the orchestrator's ScopeKind (orchestrator/app/models.py). */
export type ScopeKind = "domain" | "subdomain_wildcard" | "ipv4_cidr" | "ipv6_cidr" | "asn";

export interface ScopeEntry {
  id: string;
  kind: ScopeKind;
  value: string;
  active: boolean;
  added_by: string;
  added_at: string;
  auth_doc_ref?: string | null;
  expires_at?: string | null;
  notes?: string | null;
  /** Proof-of-control status (schema 021); absent on older servers. */
  proof?: import("./onboarding").ScopeProof;
}

export interface ScopeDecision {
  id: string;
  entry_id: string | null;
  target: string;
  normalized: string;
  allow: boolean;
  reason: string;
  decided_at: string;
  worker_id?: string | null;
}

export interface Scan {
  id: string;
  kind: string;
  target: string;
  status: ScanStatus;
  queued_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  worker_id?: string | null;
  config?: Record<string, unknown>;
  result_summary?: Record<string, unknown> | null;
  error?: string | null;
}

export interface TimelineDay {
  date: string; // YYYY-MM-DD
  new_assets: number;
  new_findings_by_severity: Partial<Record<Severity, number>>;
  scans_run: number;
  cumulative_assets?: number;
  cumulative_findings?: number;
}

/** Fields the client may attach to any live event, regardless of variant. */
export interface LiveEventMeta {
  /**
   * True when the event was synthesized client-side from recent findings/assets/
   * scans to seed the ticker before the SSE stream emits anything live. Rendered
   * dimmer ("past"); never produced by the server.
   */
  seeded?: boolean;
}

/** Events over /v1/events (SSE). Intersection distributes over the union. */
export type LiveEvent = LiveEventMeta &
  (
  | {
      event: "asset_added";
      ts: string;
      asset_id: string;
      kind: AssetKind;
      value: string;
    }
  | {
      event: "finding_opened";
      ts: string;
      finding_id: string;
      severity: Severity;
      asset_id: string;
      title?: string;
      asset_value?: string;
    }
  | {
      event: "finding_closed";
      ts: string;
      finding_id: string;
    }
  | {
      event: "cve_published";
      ts: string;
      cve_id: string;
      cvss?: number;
      affected?: string[];
    }
  | {
      event: "scan_started" | "scan_completed" | "scan_failed";
      ts: string;
      scan_id: string;
      kind?: string;
      target?: string;
      status?: ScanStatus;
    }
  );

/* ------------------------------------------------------------------ *
 * Tier 1 — attack paths + change intelligence.                        *
 * Mirrors schema/007_tier1.sql and the orchestrator endpoints in      *
 * docs/TIER1_CONTRACT.md. Compute services own the tables; the        *
 * dashboard only reads these shapes + the mutations below.            *
 * ------------------------------------------------------------------ */

/** A single node along an attack path, enriched by the orchestrator. */
export interface AttackPathHop {
  asset_id: string;
  kind: AssetKind;
  value: string;
  max_severity: Severity;
  finding_ids: string[];
}

/** Lightweight asset summary carried on the path endpoints (value + kind). */
export interface AttackPathAssetRef {
  /** Present on the full {id} response; absent on list summaries. */
  id?: string | null;
  value: string;
  kind: AssetKind;
}

/**
 * A weighted route through the asset graph from an internet-facing source to
 * a crown-jewel target. Ranked by `exploitability` (0–100, higher = easier).
 */
export interface AttackPath {
  id: string;
  source_asset: AttackPathAssetRef;
  target_asset: AttackPathAssetRef;
  length: number;
  total_cost: number;
  exploitability: number;
  severity: Severity;
  kev_on_path: boolean;
  title: string;
  narrative: string;
  hops: AttackPathHop[];
}

/** Envelope returned by GET /v1/attack-paths. */
export interface AttackPathPage {
  items: AttackPath[];
  total: number;
  limit: number;
  offset: number;
}

/**
 * Surface-change ledger entry. `change_type` matches the CHECK constraint in
 * schema/007_tier1.sql (a superset of the discovery/finding/exposure events).
 */
export type ChangeType =
  | "subdomain_discovered"
  | "endpoint_discovered"
  | "ip_discovered"
  | "port_opened"
  | "port_closed"
  | "tech_detected"
  | "tech_version_changed"
  | "cert_added"
  | "cert_expiring"
  | "secret_found"
  | "repository_found"
  | "finding_opened"
  | "finding_resolved"
  | "exposure_increased"
  | "asset_removed"
  | "chain_detected"
  | "attack_path_found";

export interface SurfaceChange {
  id: string;
  change_type: ChangeType;
  asset_kind: AssetKind | null;
  asset_value: string | null;
  severity: Severity;
  summary: string;
  /** JSONB in the DB; an object or stringified blob depending on the row. */
  detail?: Record<string, unknown> | string | null;
  detected_at: string;
  acknowledged: boolean;
  /** schema column; used to deep-link the asset drawer when present. */
  asset_id?: string | null;
  ack_by?: string | null;
  ack_at?: string | null;
  /** Client-only: synthesized from the live SSE stream, not yet persisted. */
  live?: boolean;
}

export interface ChangePage {
  items: SurfaceChange[];
  total: number;
  limit: number;
  offset: number;
}

/** Per-day severity counts returned by GET /v1/changes/summary. */
export interface ChangeSummaryDay {
  day: string;
  info: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface ChangeSummary {
  by_type: Partial<Record<ChangeType, number>>;
  by_day: ChangeSummaryDay[];
  total: number;
}

export type AlertChannel = "log" | "webhook" | "slack";

/** Rule match: all keys optional, AND-ed; an absent key is a wildcard. */
export interface AlertRuleMatch {
  change_types?: ChangeType[];
  min_severity?: Severity;
  kinds?: AssetKind[];
}

export interface AlertRule {
  id: string;
  name: string;
  enabled: boolean;
  match: AlertRuleMatch;
  channel: AlertChannel;
  /** webhook/slack URL; stored server-side (treated as a secret). */
  target?: string | null;
  created_at?: string;
  last_fired?: string | null;
}

export interface AlertDelivery {
  id: string;
  rule_id: string;
  change_id?: string | null;
  status: "sent" | "failed" | "suppressed";
  channel: AlertChannel;
  response?: string | null;
  delivered_at: string;
}

/* ------------------------------------------------------------------ *
 * Tier 2 — posture grading, ticketing/ownership, monitoring.          *
 * Mirrors schema/008_tier2.sql and the orchestrator endpoints in      *
 * docs/TIER2_CONTRACT.md §4. The dashboard only reads these shapes +  *
 * the mutations below; compute/triage/orchestrator own the tables.    *
 * ------------------------------------------------------------------ */

/** TLS letter grade. `T` is a trust/validation failure (expired/untrusted). */
export type Grade = "A+" | "A" | "B" | "C" | "D" | "E" | "F" | "T";

/** The 0–100 scored TLS report-card row for a host (one per graded asset). */
export interface TlsGrade {
  id: string;
  asset_id: string;
  host: string;
  grade: Grade;
  score: number;
  protocols: string[];
  weak_ciphers: string[];
  issues: string[];
  /** ISO timestamp of certificate expiry (drives the countdown). */
  cert_expires: string | null;
  graded_at: string;
}

/** Envelope returned by GET /v1/tls-grades. */
export interface TlsGradePage {
  items: TlsGrade[];
  total: number;
  limit: number;
  offset: number;
}

/** GET /v1/tls-grades/summary — count per grade bucket. */
export type TlsGradeSummary = Partial<Record<Grade, number>>;

export type TicketStatus =
  | "open"
  | "ack"
  | "in_progress"
  | "resolved"
  | "closed"
  | "wontfix";

/** Where a ticket is tracked. `internal` = DB only; others POST a webhook. */
export type TicketSystem = "internal" | "webhook" | "github" | "jira";

/**
 * A triage ticket: an owned, SLA-bound wrapper around a finding. Created by
 * the triage service; status is driven from the dashboard via PATCH.
 */
export interface Ticket {
  id: string;
  finding_id: string;
  title: string;
  severity: Severity;
  owner_team: string | null;
  contact: string | null;
  system: TicketSystem | string;
  external_url: string | null;
  status: TicketStatus | string;
  sla_hours: number;
  /** ISO deadline = opened_at + sla_hours; the countdown is computed from it. */
  sla_due: string;
  breached: boolean;
  opened_at: string;
  closed_at: string | null;
  /** Joined summaries (orchestrator LEFT JOINs). Null when the row is gone. */
  asset: { value: string; kind: AssetKind } | null;
  finding: { title: string; rule_source: RuleSource | string } | null;
}

export interface TicketPage {
  items: Ticket[];
  total: number;
  limit: number;
  offset: number;
}

/** GET /v1/tickets/summary — header-tile counts. */
export interface TicketSummary {
  open?: number;
  breached?: number;
  /** Resolved in the trailing 7 days (name per contract §5 "resolved-this-week"). */
  resolved_7d?: number;
  by_team?: Record<string, number>;
  by_severity?: Partial<Record<Severity, number>>;
}

/**
 * An ownership rule: AND of present match keys, evaluated by `priority` ASC
 * (first match wins). Mirrors the triage resolver in contract §3.
 */
export interface OwnerMatch {
  kinds?: AssetKind[];
  value_regex?: string;
  cidr?: string;
  metadata_env?: string;
  tag?: string;
}

export interface Owner {
  id: string;
  name: string;
  match: OwnerMatch;
  team: string;
  contact: string | null;
  priority: number;
  enabled: boolean;
  created_at: string;
}

/** SLA window per severity (hours until a ticket breaches). */
export interface SlaPolicy {
  severity: Severity;
  hours: number;
}

/* ------------------------------------------------------------------ *
 * Tier 3 — SCA / SBOM, supply-chain risk, ATT&CK coverage, NL-query.  *
 * Mirrors schema/009_tier3.sql and the orchestrator endpoints in      *
 * docs/TIER3_CONTRACT.md §E/§F. The dashboard only reads these shapes *
 * (plus POST /v1/ask); the SCA/brain/correlation services own writes. *
 * ------------------------------------------------------------------ */

/** Package ecosystem a component belongs to. Open string — new ones appear. */
export type Ecosystem =
  | "npm"
  | "pypi"
  | "go"
  | "cargo"
  | "maven"
  | "rubygems"
  | "nuget"
  | "composer"
  | "hex"
  | (string & {});

/** Defensive supply-chain risk categories (detection only; contract §A). */
export type RiskType =
  | "dependency_confusion"
  | "typosquat"
  | "abandoned"
  | "malicious_version"
  | "yanked"
  | "unpinned"
  | (string & {});

/** An SBOM project — one per scanned repo/lockfile set. */
export interface SbomProject {
  id: string;
  name: string;
  source_ref?: string | null;
  /** Ecosystems present in the project (union across its components). */
  ecosystems?: Ecosystem[];
  component_count?: number;
  vulnerable_count?: number;
  created_at?: string;
}

/** A single SBOM component (dependency) row from GET /v1/sbom/components. */
export interface SbomComponent {
  id: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  /** Direct dependency (declared) vs transitive (pulled in). */
  direct: boolean;
  /** Depth in the dependency tree (0 = direct). */
  depth: number;
  purl?: string | null;
  vuln_count: number;
  /** Worst severity among this component's vulns; null when clean. */
  max_vuln_severity: Severity | null;
  /**
   * Tier 4 — codeanalysis reachability rollup for the component (the strongest
   * grade across its vulns). Absent when the service hasn't graded it.
   */
  reachability?: ReachabilityGrade;
  /** Count of this component's vulns graded `reachable` in first-party code. */
  reachable_vuln_count?: number;
}

/** One vuln affecting a component (GET /v1/sbom/components/{id}). */
export interface SbomVuln {
  osv_id: string;
  cve_id?: string | null;
  severity: Severity;
  cvss?: number | null;
  summary?: string | null;
  /** Version the advisory says fixes it — drives the "upgrade to X" hint. */
  fixed_version?: string | null;
  /** Tier 4 — per-vuln reachability grade from the codeanalysis call graph. */
  reachability?: ReachabilityGrade;
  /** The affected symbol the advisory names, when reachable/potential. */
  reachable_symbol?: string | null;
  /** Ordered call path source → … → vulnerable symbol (best-effort). */
  call_path?: string[];
}

/** GET /v1/sbom/components/{id} — a component with its full vuln list. */
export interface SbomComponentDetail extends SbomComponent {
  vulns: SbomVuln[];
  /** Dependency paths that pull this component in (best-effort). */
  paths?: string[];
}

/** Envelope returned by GET /v1/sbom/components. */
export interface SbomComponentPage {
  items: SbomComponent[];
  total: number;
  limit: number;
  offset: number;
}

/** A defensive supply-chain exposure (GET /v1/supply-chain-risks). */
export interface SupplyChainRisk {
  id: string;
  risk_type: RiskType;
  severity: Severity;
  summary: string;
  /** Narrative/evidence; a string, or a small JSON object depending on row. */
  detail?: string | Record<string, unknown> | null;
  component_id?: string | null;
}

/**
 * GET /v1/sbom/summary — header-tile counts. `ecosystems`/`by_ecosystem` are
 * tolerated-optional: the page derives the ecosystem count from components
 * when the summary omits them (see contract §E — summary lists component/vuln
 * counts + by_risk_type/by_severity; ecosystem breakdown is a convenience).
 */
export interface SbomSummary {
  components?: number;
  vulnerable_components?: number;
  by_risk_type?: Partial<Record<RiskType, number>>;
  by_severity?: Partial<Record<Severity, number>>;
  ecosystems?: number;
  by_ecosystem?: Partial<Record<Ecosystem, number>>;
}

/** A mapped MITRE ATT&CK technique with its finding count. */
export interface AttackTechnique {
  technique_id: string; // e.g. "T1190"
  technique: string;
  tactic: string;
  count: number;
}

/** GET /v1/attack/coverage — tactic→count, technique rows, total mapped. */
export interface AttackCoverage {
  by_tactic: Record<string, number>;
  by_technique: AttackTechnique[];
  total_findings_mapped: number;
}

/**
 * POST /v1/ask result. `rows` are positional (aligned to `columns`) or, from
 * some engines, column-keyed objects — the page normalizes both. `engine`
 * reports how the SQL was produced; `ok=false` carries `error`/`note`.
 */
export interface AskResult {
  ok: boolean;
  columns: string[];
  rows: Array<Array<string | number | boolean | null> | Record<string, unknown>>;
  generated_sql: string;
  engine: "llm" | "fallback" | "unavailable" | (string & {});
  note?: string | null;
  error?: string | null;
}

/** GET /v1/clusters — an LLM/template triage cluster over open findings. */
export interface FindingCluster {
  id: string;
  label: string;
  summary?: string | null;
  remediation?: string | null;
  engine: "llm" | "template" | (string & {});
  severity?: Severity | null;
  /** Number of findings in the cluster (alias: finding_ids.length). */
  size?: number;
  finding_ids?: string[];
}

/** Scan kinds a schedule can enqueue (contract §5 create form). */
export type ScanKind =
  | "passive_full"
  | "full_recon"
  | "nuclei"
  | "tls_grade"
  | "takeover_scan"
  | "passive_ct_watch";

/**
 * A continuous-monitoring schedule. The orchestrator scheduler loop enqueues
 * `scan_kind` over `target_scope` on each `cron` tick (or every_n_minutes in
 * config when croniter is unavailable).
 */
export interface Schedule {
  id: string;
  name: string;
  scan_kind: ScanKind | string;
  target_scope: string;
  cron: string | null;
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
  last_status: string | null;
  config: Record<string, unknown>;
}

/* ------------------------------------------------------------------ *
 * Tier 4 — reachability, SAST code-findings, adaptive ML risk.        *
 * Mirrors schema/010_tier4.sql + docs/TIER4_CONTRACT.md §D/§E. The    *
 * dashboard reads these shapes (plus the ack / retrain mutations);    *
 * codeanalysis + mlrisk + orchestrator own the tables and scoring.    *
 * ------------------------------------------------------------------ */

/**
 * Reachability of a dependency vuln in first-party code, from the static
 * call-graph analysis:
 *   reachable   — the vulnerable symbol is called from an app entrypoint
 *   potential   — the module is imported but no direct call path was proven
 *   unreachable — not referenced from any entrypoint ("not reached")
 *   unknown     — the advisory names no symbol, or source was absent (no guess)
 */
export type ReachabilityGrade = "reachable" | "potential" | "unreachable" | "unknown";

/** One ordered hop in a SAST source→sink taint trace. */
export interface DataflowStep {
  file: string;
  line: number;
  /** What flows at this hop (human text), e.g. "tainted `req.query.id`". */
  note?: string | null;
  /** Optional inert code excerpt for the hop (rendered as data, never run). */
  code?: string | null;
  /** Role in the taint path when the scanner labels it. */
  kind?: "source" | "propagation" | "sanitizer" | "sink" | (string & {});
}

/**
 * A static-analysis (Semgrep / taint-pattern) code finding from the
 * codeanalysis service. `dataflow` is the ordered source→sink trace.
 */
export interface CodeFinding {
  id: string;
  rule: string;
  message: string;
  severity: Severity;
  file: string;
  start_line: number;
  end_line: number;
  /** Source (where taint enters) / sink (where it lands); short mono labels. */
  source?: string | null;
  sink?: string | null;
  dataflow: DataflowStep[];
  /** CWE id when the rule maps to one, e.g. "CWE-89". */
  cwe?: string | null;
  /** Project the finding belongs to (echoed from the filter). */
  project?: string | null;
  /** Scanner that produced it, when reported ("semgrep" / "taint-fallback"). */
  source_tool?: string | null;
}

export interface CodeFindingPage {
  items: CodeFinding[];
  total: number;
  limit: number;
  offset: number;
}

/**
 * One signed contributing signal behind an ML risk score. `contribution` is on
 * the same 0–100 scale as the score (feature_importance × value): positive
 * raises risk, negative lowers it (e.g. a dismissed-pattern match).
 */
export interface MlRationaleSignal {
  feature: string;
  contribution: number;
}

/**
 * A ranked adaptive-risk row: the model's `ml_risk` for an open finding plus
 * the rationale that explains it and light finding/asset summaries.
 */
export interface MlRiskRow {
  finding_id: string;
  ml_risk: number;
  model_version: string;
  rationale: MlRationaleSignal[];
  finding: { title: string; severity: Severity; rule_source: RuleSource | string };
  asset: { value: string; kind: AssetKind };
}

export interface MlRiskPage {
  items: MlRiskRow[];
  total: number;
  limit: number;
  offset: number;
}

/** One trained model (risk ranker or anomaly detector) from GET /v1/ml/model. */
export interface MlSubModel {
  version: string;
  algo: string;
  trained_at: string;
  n_samples: number;
  /** True while there is too little triage data; scores use a heuristic prior. */
  cold_start: boolean;
  /** Eval metrics keyed by name (auc, precision, …) — optional. */
  metrics?: Record<string, number>;
  /** Learned feature weights (0–1), drives the insight bars. Ranker only. */
  feature_importance?: Record<string, number>;
}

/** GET /v1/ml/model — the active risk ranker + anomaly detector. */
export interface MlModel {
  risk_ranker: MlSubModel;
  anomaly_detector: MlSubModel;
}

/** POST /v1/ml/retrain — proxied to mlrisk; `available:false` when it's down. */
export interface MlRetrainResult {
  available?: boolean;
  version?: string;
  cold_start?: boolean;
  n_samples?: number;
  note?: string | null;
}

/**
 * An anomaly flagged by the IsolationForest / z-score detector over per-asset
 * feature vectors + change velocity. `reason` is human-readable.
 */
export interface Anomaly {
  id: string;
  /** What the anomaly is about: "asset" | "host" | "change_stream" | … */
  subject_type: string;
  /** Display label for the subject (host, asset value, stream name). */
  subject_label: string;
  score: number;
  severity: Severity;
  reason: string;
  features: Record<string, unknown>;
  detected_at: string;
  acknowledged: boolean;
}

export interface AnomalyPage {
  items: Anomaly[];
  total: number;
  limit: number;
  offset: number;
}

/* ------------------------------------------------------------------ *
 * Governance — auth, roles, tamper-evident audit log, provenance.     *
 * Mirrors docs/GOVERNANCE_CONTRACT.md §A/§B and schema/011_governance *
 * .sql. The dashboard reads these shapes; the orchestrator owns auth, *
 * the audit chain, and provenance writes.                             *
 * ------------------------------------------------------------------ */

/** RBAC role (contract §A AuthZ). viewer/auditor read-only; analyst triages. */
export type Role = "viewer" | "auditor" | "analyst" | "admin";

/** The authenticated principal, from POST /v1/auth/login + GET /v1/auth/me. */
export interface AuthUser {
  username: string;
  role: Role;
  clearance: Classification;
}

/** POST /v1/auth/login response. `expires_in` is seconds (JWT lifetime). */
export interface LoginResponse {
  access_token: string;
  role: Role;
  clearance: Classification;
  expires_in: number;
}

/**
 * One row of the hash-chained audit log (contract §A). `entry_hash` =
 * sha256(prev_hash || canonical_json(row)); walking the chain proves it
 * hasn't been tampered with. `classification` is the sensitivity touched by
 * the recorded action; `justification` is the optional X-Justification header.
 */
export interface AuditEntry {
  id: string | number;
  ts: string;
  actor: string;
  role: Role | string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  classification: Classification | null;
  justification: string | null;
  method?: string | null;
  path?: string | null;
  status?: number | null;
  request_id?: string | null;
  ip?: string | null;
  prev_hash?: string | null;
  entry_hash?: string | null;
}

export interface AuditPage {
  items: AuditEntry[];
  total: number;
  limit: number;
  offset: number;
}

/**
 * GET /v1/audit/verify — walks the chain and reports integrity. `checked` is
 * the number of entries verified; `first_broken_id` names the first row whose
 * recomputed hash didn't match (present only when `ok` is false).
 */
export interface AuditVerifyResult {
  ok: boolean;
  checked: number;
  first_broken_id?: string | number | null;
}

/**
 * One provenance / lineage record for a produced fact (contract §A). Answers
 * "where did this come from": which service, by what method, with what
 * evidence and confidence, recorded when.
 */
export interface ProvenanceRecord {
  id?: string;
  subject_type: string;
  subject_id: string;
  source_service: string;
  source_detail?: string | null;
  method: string;
  evidence?: Record<string, unknown> | string | null;
  confidence?: number | null;
  recorded_at: string;
}
