/**
 * Audit-log endpoints (governance §A). Auditor/admin only — the orchestrator
 * enforces the role; the dashboard also hides the nav entry.
 */

import { apiFetch } from "./client";
import type { AuditEntry, AuditPage, AuditVerifyResult } from "./types";

export type AuditFilter = {
  actor?: string;
  action?: string;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
};

/** GET /v1/audit — paged hash-chained log. Tolerates a bare-array response. */
export function listAudit(filter: AuditFilter = {}): Promise<AuditPage> {
  return apiFetch<AuditPage | AuditEntry[]>("/v1/audit", { query: filter }).then((r) =>
    Array.isArray(r)
      ? { items: r, total: r.length, limit: filter.limit ?? r.length, offset: filter.offset ?? 0 }
      : r,
  );
}

/** GET /v1/audit/verify — walk the chain and report integrity. */
export function verifyAudit(): Promise<AuditVerifyResult> {
  return apiFetch<AuditVerifyResult>("/v1/audit/verify");
}
