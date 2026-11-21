import { apiFetch } from "./client";
import type { AttackCoverage, AttackTechnique } from "./types";

/**
 * MITRE ATT&CK coverage read endpoints (contract §E). The correlation service
 * owns finding→technique mapping; the dashboard only reads the aggregates.
 */

/** GET /v1/attack/coverage — tactic counts, per-technique rows, total mapped. */
export function getAttackCoverage(): Promise<AttackCoverage> {
  return apiFetch<AttackCoverage>("/v1/attack/coverage").then((r) => ({
    by_tactic: r?.by_tactic ?? {},
    by_technique: r?.by_technique ?? [],
    total_findings_mapped: r?.total_findings_mapped ?? 0,
  }));
}

/** GET /v1/attack/catalog — the full seeded technique map (optional lookup). */
export function getAttackCatalog(): Promise<AttackTechnique[]> {
  return apiFetch<{ items: AttackTechnique[] } | AttackTechnique[]>("/v1/attack/catalog").then((r) =>
    Array.isArray(r) ? r : r.items ?? [],
  );
}
