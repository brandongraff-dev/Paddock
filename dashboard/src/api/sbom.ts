import { apiFetch } from "./client";
import type {
  Ecosystem,
  RiskType,
  SbomComponent,
  SbomComponentDetail,
  SbomComponentPage,
  SbomProject,
  SbomSummary,
  Severity,
  SupplyChainRisk,
} from "./types";

/**
 * SCA / SBOM read endpoints (contract §E). Follows the same envelope-unwrap
 * convention as listFindings/listTickets: tolerate both the {items,total,…}
 * page envelope and a bare array.
 */

export function listSbomProjects(): Promise<SbomProject[]> {
  return apiFetch<{ items: SbomProject[] } | SbomProject[]>("/v1/sbom/projects").then((r) =>
    Array.isArray(r) ? r : r.items ?? [],
  );
}

export type SbomComponentFilter = {
  project?: string;
  vulnerable?: boolean;
  ecosystem?: Ecosystem;
  limit?: number;
  offset?: number;
};

/**
 * GET /v1/sbom/components — paged. Returns the envelope so callers can read
 * `total`; synthesizes one from a bare array for tolerance.
 */
export function listSbomComponents(q?: SbomComponentFilter): Promise<SbomComponentPage> {
  return apiFetch<SbomComponentPage | SbomComponent[]>("/v1/sbom/components", { query: q }).then((r) =>
    Array.isArray(r)
      ? { items: r, total: r.length, limit: q?.limit ?? r.length, offset: q?.offset ?? 0 }
      : r,
  );
}

/** GET /v1/sbom/components/{id} — the component plus its full vuln list. */
export function getSbomComponent(id: string): Promise<SbomComponentDetail> {
  return apiFetch<SbomComponentDetail>(`/v1/sbom/components/${encodeURIComponent(id)}`);
}

export type SupplyChainRiskFilter = {
  type?: RiskType;
  severity?: Severity;
  limit?: number;
  offset?: number;
};

/** GET /v1/supply-chain-risks — paged; unwrap to the array the panel groups. */
export function listSupplyChainRisks(q?: SupplyChainRiskFilter): Promise<SupplyChainRisk[]> {
  return apiFetch<{ items: SupplyChainRisk[] } | SupplyChainRisk[]>("/v1/supply-chain-risks", {
    query: q,
  }).then((r) => (Array.isArray(r) ? r : r.items ?? []));
}

/** GET /v1/sbom/summary — header-tile counts. */
export function getSbomSummary(): Promise<SbomSummary> {
  return apiFetch<SbomSummary>("/v1/sbom/summary");
}
