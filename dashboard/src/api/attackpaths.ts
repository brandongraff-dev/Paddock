import { apiFetch } from "./client";
import type { AttackPath, AttackPathPage, Severity } from "./types";

export type AttackPathFilter = {
  severity?: Severity;
  kev?: boolean;
  limit?: number;
  offset?: number;
};

/**
 * GET /v1/attack-paths — orchestrator returns {items,total,limit,offset}.
 * Unwrap to the bare array the page ranks + filters client-side, mirroring
 * listFindings(). Tolerates a raw array too.
 */
export function listAttackPaths(q?: AttackPathFilter): Promise<AttackPath[]> {
  return apiFetch<AttackPathPage | AttackPath[]>("/v1/attack-paths", { query: q }).then((r) =>
    Array.isArray(r) ? r : r.items ?? [],
  );
}

export function getAttackPath(id: string): Promise<AttackPath> {
  return apiFetch<AttackPath>(`/v1/attack-paths/${encodeURIComponent(id)}`);
}

/** POST /v1/attack-paths/recompute — enqueues a recompute; returns {queued}. */
export function recomputeAttackPaths(): Promise<{ queued: boolean }> {
  return apiFetch<{ queued: boolean }>("/v1/attack-paths/recompute", { method: "POST", body: {} });
}
