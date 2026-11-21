import { apiFetch } from "./client";
import type {
  Asset,
  Finding,
  FindingChain,
  FindingPage,
  FindingStatus,
  Severity,
  SuppressedFilter,
  Suppression,
  SuppressionInput,
  TimelineDay,
  TransitionResult,
} from "./types";

export interface FindingQuery {
  severity?: Severity;
  status?: FindingStatus;
  asset_id?: string;
  rule_source?: string;
  kev?: boolean;
  q?: string;
  limit?: number;
  offset?: number;
  suppressed?: SuppressedFilter;
  include_duplicates?: boolean;
  sla_breached?: boolean;
  sort?: "last_seen" | "due_at" | "severity";
}

export function listFindings(q?: FindingQuery): Promise<Finding[]> {
  // Orchestrator now returns {items, total, limit, offset}; unwrap to the
  // bare array the UI still expects. Legacy path /v1/findings/list also exists.
  return apiFetch<{ items: Finding[] } | Finding[]>("/v1/findings", {
    query: q as Record<string, string | number | boolean | undefined>,
  })
    .then((r) => (Array.isArray(r) ? r : r.items ?? []));
}

/** Paged envelope incl. `suppressed_total` / `duplicates_total` counts. */
export function listFindingsPage(q?: FindingQuery): Promise<FindingPage> {
  return apiFetch<FindingPage | Finding[]>("/v1/findings", {
    query: q as Record<string, string | number | boolean | undefined>,
  }).then((r) =>
    Array.isArray(r)
      ? { items: r, total: r.length, limit: r.length, offset: 0 }
      : { ...r, items: r.items ?? [] },
  );
}

interface FindingDetailEnvelope {
  finding: Finding;
  asset?: Asset | null;
  chains?: FindingChain[];
  history?: Finding["history"];
}

/**
 * GET /v1/findings/{id} returns `{finding, asset, chains, history}`. Flatten it
 * into a Finding (hydrated `asset`, `history`) — older mocks/servers that
 * return a bare finding pass through unchanged.
 */
export function getFinding(id: string): Promise<Finding> {
  return apiFetch<Finding | FindingDetailEnvelope>(`/v1/findings/${encodeURIComponent(id)}`).then(
    (r) => {
      const env = r as FindingDetailEnvelope;
      if (env && typeof env === "object" && env.finding && typeof env.finding === "object") {
        return {
          ...env.finding,
          asset: env.asset ?? env.finding.asset,
          history: env.history ?? env.finding.history,
        };
      }
      return r as Finding;
    },
  );
}

/* --------------------------- lifecycle transitions --------------------------- */

export interface DismissBody {
  reason: string;
  /** ISO datetime; the server reopens the finding after it. */
  accepted_until?: string | null;
  /** false-positive only: also create a suppression for this rule on this asset. */
  suppress?: boolean;
}

export function acceptFinding(id: string, body: DismissBody): Promise<TransitionResult> {
  return apiFetch<TransitionResult>(`/v1/findings/${encodeURIComponent(id)}/accept`, {
    method: "POST",
    body,
  });
}

export function markFalsePositive(id: string, body: DismissBody): Promise<TransitionResult> {
  return apiFetch<TransitionResult>(`/v1/findings/${encodeURIComponent(id)}/false-positive`, {
    method: "POST",
    body,
  });
}

export function reopenFinding(id: string, reason?: string): Promise<TransitionResult> {
  return apiFetch<TransitionResult>(`/v1/findings/${encodeURIComponent(id)}/reopen`, {
    method: "POST",
    body: reason ? { reason } : {},
  });
}

/* -------------------------------- suppressions ------------------------------- */

export function listSuppressions(active?: boolean): Promise<Suppression[]> {
  return apiFetch<Suppression[] | { items: Suppression[] }>("/v1/suppressions", {
    query: { active },
  }).then((r) => (Array.isArray(r) ? r : r.items ?? []));
}

export function createSuppression(body: SuppressionInput): Promise<Suppression> {
  return apiFetch<Suppression>("/v1/suppressions", { method: "POST", body });
}

export function patchSuppression(
  id: string,
  body: Partial<Pick<Suppression, "name" | "reason" | "expires_at" | "enabled">>,
): Promise<Suppression> {
  return apiFetch<Suppression>(`/v1/suppressions/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body,
  });
}

export function deleteSuppression(id: string): Promise<unknown> {
  return apiFetch(`/v1/suppressions/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export function patchFinding(
  id: string,
  patch: { status?: FindingStatus; assigned_to?: string | null; notes?: string },
): Promise<Finding> {
  return apiFetch<Finding>(`/v1/findings/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: patch,
  });
}

export function listChains(): Promise<FindingChain[]> {
  return apiFetch<FindingChain[]>("/v1/chains");
}

interface OrchDay {
  day: string;
  asset_count?: number;
  finding_count?: number;
  new_findings_by_severity?: Partial<Record<Severity, number>>;
  scans_run?: number;
  sample_assets?: unknown[];
  sample_findings?: unknown[];
}
interface OrchTimelineEnvelope {
  from?: string;
  to?: string;
  days?: OrchDay[];
}

export function listTimeline(q?: { from?: string; to?: string }): Promise<TimelineDay[]> {
  return apiFetch<OrchTimelineEnvelope | TimelineDay[] | OrchDay[]>("/v1/timeline", { query: q }).then(
    (r) => {
      const rows: (OrchDay | TimelineDay)[] = Array.isArray(r) ? r : r.days ?? [];
      return rows.map((d) => {
        const row = d as OrchDay & TimelineDay;
        return {
          date: row.date ?? row.day ?? "",
          new_assets: row.new_assets ?? row.asset_count ?? 0,
          new_findings_by_severity: row.new_findings_by_severity ?? {},
          scans_run: row.scans_run ?? 0,
          cumulative_assets: row.cumulative_assets,
          cumulative_findings: row.cumulative_findings,
        };
      });
    },
  );
}
