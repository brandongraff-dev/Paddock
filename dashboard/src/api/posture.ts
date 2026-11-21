import { apiFetch } from "./client";
import { listFindings } from "./findings";
import type { Finding, Grade, TlsGrade, TlsGradePage, TlsGradeSummary } from "./types";

export type TlsGradeFilter = {
  grade?: Grade;
  limit?: number;
  offset?: number;
};

/**
 * GET /v1/tls-grades — orchestrator returns {items,total,limit,offset}.
 * Unwrap to the bare array the page filters client-side, mirroring
 * listFindings(). Tolerates a raw array too.
 */
export function listTlsGrades(q?: TlsGradeFilter): Promise<TlsGrade[]> {
  return apiFetch<TlsGradePage | TlsGrade[]>("/v1/tls-grades", { query: q }).then((r) =>
    Array.isArray(r) ? r : r.items ?? [],
  );
}

/** GET /v1/tls-grades/summary — orchestrator returns {counts:{A+:n,…}, total}; flatten to {A+:n,…}. */
export function getTlsGradeSummary(): Promise<TlsGradeSummary> {
  return apiFetch<TlsGradeSummary | { counts: TlsGradeSummary; total: number }>(
    "/v1/tls-grades/summary",
  ).then((r) => ("counts" in r ? r.counts : r) as TlsGradeSummary);
}

/**
 * Takeover-risk cards reuse the findings endpoint (contract §5): all findings
 * produced by the subdomain-takeover detector carry rule_source='takeover'.
 */
export function listTakeoverFindings(): Promise<Finding[]> {
  return listFindings({ rule_source: "takeover", limit: 200 });
}
