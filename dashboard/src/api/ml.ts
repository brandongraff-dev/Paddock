import { apiFetch } from "./client";
import type {
  Anomaly,
  AnomalyPage,
  MlModel,
  MlRetrainResult,
  MlRiskPage,
  MlRiskRow,
} from "./types";

/**
 * Adaptive-ML read + mutation endpoints (Tier 4, contract §D). The mlrisk
 * service owns scoring/training; the orchestrator proxies these and degrades
 * cleanly ({available:false}) when mlrisk is down. Same envelope-unwrap
 * convention as the other paged endpoints.
 */

export type MlRiskFilter = { limit?: number; offset?: number };

/** GET /v1/ml/risk — open findings joined with ml_risk DESC + rationale. */
export function listMlRisk(q?: MlRiskFilter): Promise<MlRiskPage> {
  return apiFetch<MlRiskPage | MlRiskRow[]>("/v1/ml/risk", { query: q }).then((r) =>
    Array.isArray(r)
      ? { items: r, total: r.length, limit: q?.limit ?? r.length, offset: q?.offset ?? 0 }
      : r,
  );
}

/** GET /v1/ml/model — active risk ranker + anomaly detector (metrics, weights). */
export function getMlModel(): Promise<MlModel> {
  return apiFetch<MlModel>("/v1/ml/model");
}

export type AnomalyFilter = {
  acknowledged?: boolean;
  limit?: number;
  offset?: number;
};

/** GET /v1/anomalies — paged; unwrap to the envelope the feed renders. */
export function listAnomalies(q?: AnomalyFilter): Promise<AnomalyPage> {
  return apiFetch<AnomalyPage | Anomaly[]>("/v1/anomalies", { query: q }).then((r) =>
    Array.isArray(r)
      ? { items: r, total: r.length, limit: q?.limit ?? r.length, offset: q?.offset ?? 0 }
      : r,
  );
}

/** POST /v1/anomalies/{id}/ack — mark an anomaly acknowledged. */
export function ackAnomaly(id: string): Promise<Anomaly | { ok: boolean }> {
  return apiFetch<Anomaly | { ok: boolean }>(
    `/v1/anomalies/${encodeURIComponent(id)}/ack`,
    { method: "POST" },
  );
}

/** POST /v1/ml/retrain — kick a retrain; `available:false` when mlrisk is down. */
export function retrainModel(): Promise<MlRetrainResult> {
  return apiFetch<MlRetrainResult>("/v1/ml/retrain", { method: "POST" });
}
