import { apiFetch } from "./client";
import type { ScopeDecision, ScopeEntry, ScopeKind } from "./types";

export function listScope(): Promise<ScopeEntry[]> {
  return apiFetch<ScopeEntry[]>("/v1/scope");
}

export function addScopeEntry(entry: {
  kind: ScopeKind;
  value: string;
  added_by: string;
  auth_doc_ref?: string;
  expires_at?: string;
  notes?: string;
}): Promise<ScopeEntry> {
  return apiFetch<ScopeEntry>("/v1/scope", { body: entry });
}

export function deactivateScopeEntry(id: string): Promise<{ ok: true }> {
  return apiFetch<{ ok: true }>(`/v1/scope/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export interface ScopeCheckResult {
  allow: boolean;
  matched_entry?: ScopeEntry;
  normalized: string;
  reason: string;
}

export function checkScope(target: string): Promise<ScopeCheckResult> {
  return apiFetch<ScopeCheckResult>("/v1/scope/check", { body: { target } });
}

/**
 * Not formally in CONTRACTS.md yet but documented in DASHBOARD_NOTES.md.
 * Returns the last-N audit decisions for an entry; the UI uses it for the
 * expandable row on the Scope page.
 */
export function entryDecisions(
  entryId: string,
  limit = 10,
): Promise<ScopeDecision[]> {
  return apiFetch<ScopeDecision[]>(
    `/v1/scope/${encodeURIComponent(entryId)}/decisions`,
    { query: { limit } },
  );
}
