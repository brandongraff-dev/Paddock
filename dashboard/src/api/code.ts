import { apiFetch } from "./client";
import type { CodeFinding, CodeFindingPage, Severity } from "./types";

/**
 * SAST code-findings read endpoint (Tier 4, contract §D). Follows the same
 * envelope-unwrap convention as the other paged list endpoints: tolerate both
 * the {items,total,limit,offset} page envelope and a bare array.
 */

export type CodeFindingFilter = {
  project?: string;
  severity?: Severity;
  limit?: number;
  offset?: number;
};

/** GET /v1/code-findings — paged; returns the envelope so callers see `total`. */
export function listCodeFindings(q?: CodeFindingFilter): Promise<CodeFindingPage> {
  return apiFetch<CodeFindingPage | CodeFinding[]>("/v1/code-findings", { query: q }).then((r) =>
    Array.isArray(r)
      ? { items: r, total: r.length, limit: q?.limit ?? r.length, offset: q?.offset ?? 0 }
      : r,
  );
}

/** GET /v1/code-findings/{id} — a single finding with its full dataflow. */
export function getCodeFinding(id: string): Promise<CodeFinding> {
  return apiFetch<CodeFinding>(`/v1/code-findings/${encodeURIComponent(id)}`);
}
