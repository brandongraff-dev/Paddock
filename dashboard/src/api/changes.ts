import { apiFetch } from "./client";
import type {
  AlertChannel,
  AlertDelivery,
  AlertRule,
  AlertRuleMatch,
  ChangePage,
  ChangeSummary,
  ChangeType,
  Severity,
  SurfaceChange,
} from "./types";

export type ChangeFilter = {
  type?: ChangeType;
  severity?: Severity;
  since?: string;
  acknowledged?: boolean;
  limit?: number;
  offset?: number;
};

/**
 * GET /v1/changes — {items,total,limit,offset}, newest first. Unwrap to the
 * array the feed renders (same convention as listFindings).
 */
export function listChanges(q?: ChangeFilter): Promise<SurfaceChange[]> {
  return apiFetch<ChangePage | SurfaceChange[]>("/v1/changes", { query: q }).then((r) =>
    Array.isArray(r) ? r : r.items ?? [],
  );
}

/** POST /v1/changes/{id}/ack → {acknowledged:true}. */
export function ackChange(id: string): Promise<{ acknowledged: boolean }> {
  return apiFetch<{ acknowledged: boolean }>(`/v1/changes/${encodeURIComponent(id)}/ack`, {
    method: "POST",
    body: {},
  });
}

/** GET /v1/changes/summary — counts by type + per-day severity buckets. */
export function getChangeSummary(windowDays = 7): Promise<ChangeSummary> {
  return apiFetch<ChangeSummary>("/v1/changes/summary", { query: { window_days: windowDays } });
}

/* ----------------------------- alert rules ----------------------------- */

export function listAlertRules(): Promise<AlertRule[]> {
  return apiFetch<{ items: AlertRule[] } | AlertRule[]>("/v1/alert-rules").then((r) =>
    Array.isArray(r) ? r : r.items ?? [],
  );
}

export interface AlertRuleInput {
  name: string;
  channel: AlertChannel;
  match: AlertRuleMatch;
  target?: string | null;
  enabled?: boolean;
}

export function createAlertRule(body: AlertRuleInput): Promise<AlertRule> {
  return apiFetch<AlertRule>("/v1/alert-rules", { method: "POST", body });
}

export function patchAlertRule(id: string, patch: Partial<AlertRuleInput>): Promise<AlertRule> {
  return apiFetch<AlertRule>(`/v1/alert-rules/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: patch,
  });
}

export function deleteAlertRule(id: string): Promise<void> {
  return apiFetch<void>(`/v1/alert-rules/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export function listAlertDeliveries(id: string, limit = 20): Promise<AlertDelivery[]> {
  return apiFetch<{ items: AlertDelivery[] } | AlertDelivery[]>(
    `/v1/alert-rules/${encodeURIComponent(id)}/deliveries`,
    { query: { limit } },
  ).then((r) => (Array.isArray(r) ? r : r.items ?? []));
}
