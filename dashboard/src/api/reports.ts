/**
 * Reports API — executive report, compliance evidence packs, digest preview.
 * Types mirror orchestrator/app/reports/models.py (only the fields the
 * dashboard reads).
 */
import { ApiError, apiFetch, authHeaders, buildUrl } from "./client";
import type { Severity } from "./types";

export type SevCounts = Record<Severity, number>;

export interface ReportWindow {
  start: string;
  end: string;
  days: number;
  label: string;
}

export interface MttrRow {
  key: string;
  count: number;
  mean_hours: number;
  median_hours: number;
  critical_high: number;
}

export interface SlaRow {
  severity: Severity;
  policy_hours: number | null;
  met: number;
  late: number;
  breached_open: number;
  overdue_end: number;
  open_within_sla: number;
  compliance_pct: number | null;
}

export interface PathBrief {
  fingerprint: string;
  title: string;
  severity: Severity;
  exploitability: number | null;
  kev_on_path: boolean;
  opened_at: string;
  closed_at: string | null;
  open_days: number | null;
}

export interface FindingBrief {
  id: string;
  title: string;
  severity: Severity;
  status: string;
  asset_value: string | null;
  first_seen: string;
  team: string | null;
}

export interface ExecutiveReport {
  generated_at: string;
  org_name: string;
  clearance: string;
  window: ReportWindow;
  highlights: string[];
  exposure: {
    points: { at: string; value: number }[];
    start_value: number;
    end_value: number;
    delta: number;
    delta_pct: number | null;
    open_start: SevCounts;
    open_end: SevCounts;
  };
  new_findings: {
    by_severity: SevCounts;
    critical: number;
    high: number;
    previous_critical_high: number;
    top: FindingBrief[];
  };
  resolutions: {
    fixed: number;
    verified: number;
    regressed: number;
    pending_verification: number;
    accepted_risk: number;
  };
  mttr: { overall: MttrRow | null; by_severity: MttrRow[]; by_team: MttrRow[] };
  sla: {
    met: number;
    late: number;
    breached_open: number;
    overdue_end: number;
    compliance_pct: number | null;
    by_severity: SlaRow[];
  };
  attack_paths: {
    opened: number;
    closed: number;
    open_start: number;
    open_end: number;
    top_opened: PathBrief[];
    top_closed: PathBrief[];
  };
  changes: { total: number };
  devices: { iot_total: number; ot_total: number; behaviour: { rule_id: string; label: string; opened: number; open_end: number }[] };
  coverage: { assets_total: number; last_completed_scan: string | null; sbom_components: number };
}

export type ControlStatus = "satisfied" | "partial" | "gap" | "requires_attestation";
export type EvidenceStatus = "pass" | "partial" | "fail" | "none";

export interface FrameworkSummary {
  id: string;
  name: string;
  version: string;
  publisher: string;
  url: string | null;
  description: string;
  counts: Record<ControlStatus, number>;
  total: number;
  automated: number;
}

export interface Evidence {
  key: string;
  title: string;
  status: EvidenceStatus;
  detail: string;
  metrics: Record<string, unknown>;
  rows: Record<string, unknown>[];
}

export interface Control {
  id: string;
  title: string;
  family: string;
  summary: string;
  mode: "automated" | "manual";
  status: ControlStatus;
  max_status: "satisfied" | "partial";
  rationale: string;
  attestation: string | null;
  evidence: Evidence[];
}

export interface CompliancePack {
  framework: FrameworkSummary;
  generated_at: string;
  clearance: string;
  disclaimer: string;
  controls: Control[];
}

export function getExecutiveReport(days: number): Promise<ExecutiveReport> {
  return apiFetch<ExecutiveReport>("/v1/reports/executive", { query: { period: `${days}d` } });
}

export function listFrameworks(): Promise<FrameworkSummary[]> {
  return apiFetch<FrameworkSummary[]>("/v1/reports/compliance");
}

export function getCompliancePack(framework: string): Promise<CompliancePack> {
  return apiFetch<CompliancePack>(`/v1/reports/compliance/${encodeURIComponent(framework)}`);
}

export function executiveDocPath(days: number, format: "html" | "pdf") {
  return { path: "/v1/reports/executive", query: { period: `${days}d`, format } };
}

export function compliancePackDocPath(framework: string, format: "html" | "pdf") {
  return { path: `/v1/reports/compliance/${encodeURIComponent(framework)}`, query: { format } };
}

/**
 * Fetch a rendered report with the session's auth header and hand it to the
 * browser: PDFs download, HTML opens in a new tab. (A plain <a href> can't
 * carry the bearer token.)
 */
export async function openDocument(
  doc: { path: string; query: Record<string, string> },
  filename: string,
  mode: "download" | "open",
): Promise<void> {
  const res = await fetch(buildUrl(doc.path, doc.query), { headers: { ...authHeaders() } });
  if (!res.ok) {
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      /* not json */
    }
    const detail = (body as { detail?: string } | null)?.detail;
    throw new ApiError(detail ?? `request failed (${res.status})`, res.status, body);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  if (mode === "open") {
    window.open(url, "_blank", "noopener");
  } else {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
