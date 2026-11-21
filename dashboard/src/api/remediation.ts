import { apiFetch } from "./client";

/**
 * Auto-remediation endpoints (orchestrator /v1/remediation). Proposed fixes are
 * constrained to an allowlisted change class, the diff is generated
 * deterministically (never by an LLM), double-checked for prompt injection, and
 * PROPOSED — never auto-merged. This module mirrors the other api/* modules'
 * envelope-unwrap convention and keeps its TS types self-contained (types.ts is
 * shared source-of-truth; this feature ships without editing it).
 */

export type RemediationKind =
  | "dependency_bump"
  | "security_header"
  | "config_fix"
  | "tls_fix"
  | "dotfile_block";

export type RemediationStatus =
  | "proposed"
  | "verifying"
  | "verified"
  | "rejected"
  | "pr_open"
  | "merged"
  | "failed";

export interface InjectionSummary {
  flagged: boolean;
  blocked: boolean;
  categories: string[];
  summary: string;
}

export interface VerifierSummary {
  gate_ok: boolean | null;
  verify_ok: boolean | null;
  verdict: string | null;
  summary: string | null;
  rejection_reason: string | null;
  pr_opened: boolean | null;
}

export interface RemediationRow {
  id: string;
  finding_id: string | null;
  repo: string | null;
  kind: RemediationKind;
  summary: string;
  status: RemediationStatus;
  base_branch: string | null;
  head_branch: string | null;
  pr_url: string | null;
  pr_number: number | null;
  created_by: string | null;
  created_at: string;
  verified_at: string | null;
  injection: InjectionSummary;
  verifier: VerifierSummary;
}

export interface RemediationDetail extends RemediationRow {
  diff: string | null;
  verifier_report: Record<string, unknown>;
  injection_checks: Record<string, unknown>;
}

export interface RemediationPage {
  items: RemediationRow[];
  total: number;
  limit: number;
  offset: number;
}

/** Response of the propose proxy (degrade-friendly). */
export interface ProposeResult {
  ok?: boolean;
  status?: string;
  reason?: string;
  note?: string;
  remediation?: RemediationDetail;
  [k: string]: unknown;
}

export type RemediationFilter = {
  status?: RemediationStatus;
  limit?: number;
  offset?: number;
};

export function listRemediations(q?: RemediationFilter): Promise<RemediationPage> {
  return apiFetch<RemediationPage | RemediationRow[]>("/v1/remediation", { query: q }).then((r) =>
    Array.isArray(r)
      ? { items: r, total: r.length, limit: q?.limit ?? r.length, offset: q?.offset ?? 0 }
      : r,
  );
}

export function getRemediation(id: string): Promise<RemediationDetail> {
  return apiFetch<RemediationDetail>(`/v1/remediation/${encodeURIComponent(id)}`);
}

/** POST /v1/remediation/propose — proxied to the service; degrades if down. */
export function proposeRemediation(findingId: string): Promise<ProposeResult> {
  return apiFetch<ProposeResult>("/v1/remediation/propose", {
    method: "POST",
    body: { finding_id: findingId },
  });
}
