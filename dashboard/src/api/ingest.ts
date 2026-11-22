/**
 * Universal ingest API client: /v1/ingest/sources (admin) and /v1/ingest/log.
 *
 * The token is returned exactly once, by create / rotate. Listings never carry
 * it, only a short non-secret prefix for display.
 */

import { apiFetch } from "./client";

export const INGEST_FORMATS = [
  "sarif", "cyclonedx", "spdx", "ocsf", "trivy", "grype", "semgrep", "nuclei", "zap", "csv",
] as const;
export type IngestFormat = (typeof INGEST_FORMATS)[number];

export interface IngestSource {
  id: string;
  name: string;
  description: string | null;
  token_prefix: string;
  default_project: string | null;
  allowed_formats: string[];
  rate_limit_per_min: number;
  enabled: boolean;
  created_by: string;
  created_at: string;
  rotated_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  ingest_count: number;
  url: string;
  /** Present only on the create / rotate response. */
  token?: string;
}

export interface IngestSourceInput {
  name: string;
  description?: string;
  default_project?: string;
  allowed_formats?: string[];
  rate_limit_per_min?: number;
}

export interface IngestLogRow {
  id: number;
  source_id: string | null;
  source_name: string;
  actor: string;
  format: string | null;
  status: "ok" | "partial" | "rejected" | "dry_run";
  http_status: number | null;
  findings_new: number;
  findings_updated: number;
  components: number;
  assets: number;
  skipped: number;
  duplicates: number;
  suppressed: number;
  errors: Array<{ where: string; message: string }>;
  bytes: number;
  project: string | null;
  created_at: string;
}

const BASE = "/v1/ingest";

export const listIngestSources = () =>
  apiFetch<{ items: IngestSource[] }>(`${BASE}/sources`);

export const createIngestSource = (body: IngestSourceInput) =>
  apiFetch<IngestSource>(`${BASE}/sources`, { method: "POST", body });

export const patchIngestSource = (id: string, body: Partial<Pick<IngestSource, "enabled" | "rate_limit_per_min" | "default_project" | "allowed_formats" | "description">>) =>
  apiFetch<IngestSource>(`${BASE}/sources/${encodeURIComponent(id)}`, { method: "PATCH", body });

export const rotateIngestSource = (id: string) =>
  apiFetch<IngestSource>(`${BASE}/sources/${encodeURIComponent(id)}/rotate`, { method: "POST", body: {} });

export const revokeIngestSource = (id: string) =>
  apiFetch<IngestSource>(`${BASE}/sources/${encodeURIComponent(id)}`, { method: "DELETE" });

export const listIngestLog = (limit = 8) =>
  apiFetch<{ items: IngestLogRow[] }>(`${BASE}/log`, { query: { limit } });
