import { apiFetch } from "./client";
import type {
  WargameAssessment,
  WargameAssessmentPage,
  WargameBoundary,
  WargameCertificate,
  WargameChangeImpact,
  WargameChangeImpactRequest,
  WargameFixSet,
  WargameRecomputeResult,
  WargameRoutePage,
  WargameTwinIngestResult,
  WargameTwinSummary,
} from "./types";

/**
 * Wargame read API + triggers (orchestrator/app/routers/wargame.py).
 * Everything here is read-only against the customer's estate: config is
 * parsed into the twin, never applied; nothing is probed or exploited.
 */

const seg = (id: string) => encodeURIComponent(id);

/** GET /v1/wargame/assessments — newest first, `{items,total,limit,offset}`. */
export function listWargameAssessments(q?: { limit?: number; offset?: number }): Promise<WargameAssessmentPage> {
  return apiFetch<WargameAssessmentPage | WargameAssessment[]>("/v1/wargame/assessments", { query: q }).then((r) =>
    Array.isArray(r) ? { items: r, total: r.length, limit: r.length, offset: 0 } : { ...r, items: r.items ?? [] },
  );
}

export function getWargameAssessment(id: string): Promise<WargameAssessment> {
  return apiFetch<WargameAssessment>(`/v1/wargame/assessments/${seg(id)}`);
}

/** GET /{id}/routes — paged open routes to a crown jewel (shortest first). */
export function listWargameRoutes(id: string, q?: { limit?: number; offset?: number }): Promise<WargameRoutePage> {
  return apiFetch<WargameRoutePage>(`/v1/wargame/assessments/${seg(id)}/routes`, { query: q }).then((r) => ({
    ...r,
    items: r.items ?? [],
  }));
}

export function listWargameBoundaries(id: string): Promise<WargameBoundary[]> {
  return apiFetch<WargameBoundary[]>(`/v1/wargame/assessments/${seg(id)}/boundaries`);
}

export function listWargameCertificates(id: string): Promise<WargameCertificate[]> {
  return apiFetch<WargameCertificate[]>(`/v1/wargame/assessments/${seg(id)}/certificates`);
}

/** GET /{id}/fix-set — 404 when the run has no fix set (e.g. nothing open). */
export function getWargameFixSet(id: string): Promise<WargameFixSet> {
  return apiFetch<WargameFixSet>(`/v1/wargame/assessments/${seg(id)}/fix-set`);
}

/** POST /v1/wargame/recompute — never fails hard; read `status`. */
export function recomputeWargame(): Promise<WargameRecomputeResult> {
  return apiFetch<WargameRecomputeResult>("/v1/wargame/recompute", { method: "POST", body: {} });
}

/** GET /v1/wargame/twin — row counts of the persisted twin. */
export function getWargameTwin(): Promise<WargameTwinSummary> {
  return apiFetch<WargameTwinSummary>("/v1/wargame/twin");
}

/** POST /v1/wargame/twin/config — one read-only vendor export into the twin. */
export function ingestWargameConfig(body: { vendor: string; raw: string; source?: string }): Promise<WargameTwinIngestResult> {
  return apiFetch<WargameTwinIngestResult>("/v1/wargame/twin/config", { method: "POST", body });
}

/**
 * POST /v1/wargame/change-impact — what a proposed change (a `terraform show
 * -json` plan) would open to a crown jewel, and which observed flows it would
 * break. Advisory: nothing is applied.
 */
export function checkWargameChangeImpact(body: WargameChangeImpactRequest): Promise<WargameChangeImpact> {
  return apiFetch<WargameChangeImpact>("/v1/wargame/change-impact", { method: "POST", body });
}
