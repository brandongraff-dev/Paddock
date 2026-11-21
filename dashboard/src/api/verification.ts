import { apiFetch } from "./client";

/** Safe-check verdicts (schema 026): is the finding real / did the fix hold. */
export type Exploitability = "unverified" | "confirmed" | "not_reproducible" | "inconclusive";
export type VerificationStatus =
  | "scheduled" | "queued" | "done" | "refused" | "unsupported" | "error" | "cancelled";

export interface Verification {
  id: string;
  finding_id: string;
  purpose: "exploitability" | "fix";
  trigger: string;
  requested_by: string;
  status: VerificationStatus;
  verdict?: Exclude<Exploitability, "unverified"> | null;
  check_id?: string | null;
  target?: string | null;
  scope_proof?: string | null;
  evidence: Record<string, unknown>;
  reason?: string | null;
  requested_at: string;
  checked_at?: string | null;
  completed_at?: string | null;
  already_in_flight?: boolean;
}

export interface VerificationHistory {
  finding_id: string;
  exploitability: Exploitability;
  last_verified_at?: string | null;
  fix_verified_at?: string | null;
  items: Verification[];
}

export function listVerifications(findingId: string): Promise<VerificationHistory> {
  return apiFetch<VerificationHistory>(`/v1/findings/${encodeURIComponent(findingId)}/verifications`);
}

/** Queue a safe check. A refusal (scope / proof-of-control) is a 403 ApiError whose
 *  `body.detail` is `{error, reason, verification_id}`. */
export function verifyFinding(findingId: string): Promise<Verification> {
  return apiFetch<Verification>(`/v1/findings/${encodeURIComponent(findingId)}/verify`, {
    method: "POST",
    body: {},
  });
}

export interface BulkVerifyResult {
  requested: number;
  queued: number;
  refused: number;
  items: { finding_id: string; outcome: string; verification_id?: string | null; reason?: string | null }[];
}

export function verifyBulk(findingIds: string[]): Promise<BulkVerifyResult> {
  return apiFetch<BulkVerifyResult>("/v1/findings/verify/bulk", {
    method: "POST",
    body: { finding_ids: findingIds },
  });
}
