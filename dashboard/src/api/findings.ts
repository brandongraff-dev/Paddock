import { apiFetch } from "./client";
import type { Finding, FindingChain, FindingStatus, Severity, TimelineDay } from "./types";

export function listFindings(q?: {
  severity?: Severity;
  status?: FindingStatus;
  asset_id?: string;
  rule_source?: string;
  kev?: boolean;
  q?: string;
  limit?: number;
  offset?: number;
}): Promise<Finding[]> {
  // Orchestrator now returns {items, total, limit, offset}; unwrap to the
  // bare array the UI still expects. Legacy path /v1/findings/list also exists.
  return apiFetch<{ items: Finding[] } | Finding[]>("/v1/findings", { query: q })
    .then((r) => (Array.isArray(r) ? r : r.items ?? []));
}

export function getFinding(id: string): Promise<Finding> {
  return apiFetch<Finding>(`/v1/findings/${encodeURIComponent(id)}`);
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
