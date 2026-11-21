import { apiFetch } from "./client";

/**
 * Context SOURCE connectors: sync status, "Sync now", and the scope
 * suggestions a cloud inventory (GCP / Azure / AWS...) produced.
 *
 *   GET  /v1/integration-sync                         latest run per SOURCE integration
 *   POST /v1/integration-sync/{id}                    sync now (admin)
 *   GET  /v1/integration-sync/suggestions             pending (or ?status=...) suggestions
 *   POST /v1/integration-sync/suggestions/{id}/accept normal scope add; proof still required
 *   POST /v1/integration-sync/suggestions/{id}/dismiss
 *
 * A suggestion is NEVER scope. Accepting one adds a scope entry through the
 * same endpoint as a manual add, and the entry still needs proof-of-control.
 */

export type SyncRunStatus = "running" | "ok" | "error" | "abandoned";

export interface SyncRun {
  id: number;
  integration_id: string;
  trigger: "schedule" | "manual";
  status: SyncRunStatus;
  started_at: string;
  finished_at: string | null;
  counts: Record<string, number>;
  detail: string | null;
}

export interface SyncStatus {
  integration_id: string;
  kind: string;
  name: string;
  enabled: boolean;
  last_run: SyncRun | null;
  interval_minutes: number | null;
  next_run_at: string | null;
  pending_suggestions: number;
}

export interface SyncNowResult {
  status: string;
  detail: string | null;
  counts: Record<string, number>;
  run_id: number | null;
}

export type SuggestionStatus = "pending" | "accepted" | "dismissed";

export interface ScopeSuggestion {
  id: number;
  integration_id: string;
  integration_name: string | null;
  source: string;
  kind: string;
  value: string;
  evidence: Record<string, unknown>;
  status: SuggestionStatus;
  first_seen: string;
  last_seen: string;
  decided_by: string | null;
  decided_at: string | null;
  scope_entry_id: number | null;
}

export interface AcceptResult {
  suggestion: ScopeSuggestion;
  scope_entry: { id: number; kind: string; value: string; proof?: { status?: string } | null };
}

const BASE = "/v1/integration-sync";

export const getSyncStatus = () => apiFetch<SyncStatus[]>(BASE);

export const syncNow = (integrationId: string) =>
  apiFetch<SyncNowResult>(`${BASE}/${encodeURIComponent(integrationId)}`, { method: "POST" });

export const listSuggestions = (status: SuggestionStatus | "all" = "pending") =>
  apiFetch<ScopeSuggestion[]>(`${BASE}/suggestions`, { query: { status } });

export const acceptSuggestion = (id: number, body: { auth_doc_ref?: string; notes?: string } = {}) =>
  apiFetch<AcceptResult>(`${BASE}/suggestions/${id}/accept`, { method: "POST", body });

export const dismissSuggestion = (id: number, reason?: string) =>
  apiFetch<ScopeSuggestion>(`${BASE}/suggestions/${id}/dismiss`, { method: "POST", body: { reason } });
