import { apiFetch } from "./client";

/**
 * Threat-intel fusion endpoints (contract §TI / orchestrator /v1/ti). Follows
 * the same envelope-unwrap convention as the other api/* modules: tolerate
 * both the {items,total,…} page envelope and a bare array.
 *
 * Local TS types live here (types.ts is shared + source-of-truth; this feature
 * ships self-contained rather than editing it). Feed URLs are user-configured
 * and stored server-side; the browser never contacts a feed directly.
 */

export type TiSeverity = "info" | "low" | "medium" | "high" | "critical";

export type TiIndicatorType =
  | "ipv4"
  | "ipv6"
  | "domain"
  | "url"
  | "file_sha256"
  | "file_md5"
  | "email"
  | "cidr";

export type TiFeedKind = "taxii" | "stix_url" | "stix_upload" | "manual";

export interface TiFeed {
  id: string;
  name: string;
  kind: TiFeedKind;
  url: string | null;
  collection: string | null;
  enabled: boolean;
  last_poll: string | null;
  last_status: string | null;
  indicator_count: number;
  created_at: string;
}

export interface TiFeedInput {
  name: string;
  kind: TiFeedKind;
  url?: string | null;
  collection?: string | null;
  enabled?: boolean;
}

export interface TiIndicator {
  id: string;
  stix_id: string | null;
  type: TiIndicatorType;
  value: string;
  pattern: string | null;
  labels: string[];
  malware: string[];
  threat_actor: string | null;
  confidence: number;
  valid_from: string | null;
  valid_until: string | null;
  feed_id: string | null;
  feed_name: string | null;
  source: string | null;
  created_at: string;
}

export interface TiIndicatorPage {
  items: TiIndicator[];
  total: number;
  limit: number;
  offset: number;
}

export interface TiMatchIndicator {
  id: string;
  type: TiIndicatorType;
  value: string;
  labels: string[];
  malware: string[];
  threat_actor: string | null;
  confidence: number;
}

export interface TiMatchSubject {
  asset_id: string | null;
  asset_kind: string | null;
  asset_value: string | null;
  finding_id: string | null;
  finding_title: string | null;
  finding_severity: TiSeverity | null;
}

export interface TiMatch {
  id: string;
  subject_type: "asset" | "finding" | "endpoint" | "ip" | "domain";
  matched_value: string;
  severity: TiSeverity;
  finding_id: string | null;
  matched_at: string;
  indicator: TiMatchIndicator;
  subject: TiMatchSubject;
}

export interface TiMatchPage {
  items: TiMatch[];
  total: number;
  limit: number;
  offset: number;
}

export interface TiSummary {
  indicators: number;
  matches: number;
  feeds: number;
  by_type: Record<string, number>;
}

/** Response shape of the poll / ingest proxies (degrade-friendly). */
export interface TiProxyResult {
  ok?: boolean;
  note?: string;
  [k: string]: unknown;
}

/* ------------------------------- summary ------------------------------- */

export function getTiSummary(): Promise<TiSummary> {
  return apiFetch<TiSummary>("/v1/ti/summary");
}

/* -------------------------------- feeds -------------------------------- */

export function listTiFeeds(): Promise<TiFeed[]> {
  return apiFetch<{ items: TiFeed[] } | TiFeed[]>("/v1/ti/feeds").then((r) =>
    Array.isArray(r) ? r : r.items ?? [],
  );
}

export function createTiFeed(body: TiFeedInput): Promise<TiFeed> {
  return apiFetch<TiFeed>("/v1/ti/feeds", { method: "POST", body });
}

export function deleteTiFeed(id: string): Promise<void> {
  return apiFetch<void>(`/v1/ti/feeds/${encodeURIComponent(id)}`, { method: "DELETE" });
}

/** POST /v1/ti/feeds/{id}/poll — proxied to the service; degrades if down. */
export function pollTiFeed(id: string): Promise<TiProxyResult> {
  return apiFetch<TiProxyResult>(`/v1/ti/feeds/${encodeURIComponent(id)}/poll`, {
    method: "POST",
    body: {},
  });
}

/* ------------------------------ indicators ----------------------------- */

export type TiIndicatorFilter = {
  type?: TiIndicatorType;
  label?: string;
  q?: string;
  limit?: number;
  offset?: number;
};

export function listTiIndicators(q?: TiIndicatorFilter): Promise<TiIndicatorPage> {
  return apiFetch<TiIndicatorPage | TiIndicator[]>("/v1/ti/indicators", { query: q }).then((r) =>
    Array.isArray(r)
      ? { items: r, total: r.length, limit: q?.limit ?? r.length, offset: q?.offset ?? 0 }
      : r,
  );
}

/* ------------------------------- matches ------------------------------- */

export function listTiMatches(q?: { limit?: number; offset?: number }): Promise<TiMatchPage> {
  return apiFetch<TiMatchPage | TiMatch[]>("/v1/ti/matches", { query: q }).then((r) =>
    Array.isArray(r)
      ? { items: r, total: r.length, limit: q?.limit ?? r.length, offset: q?.offset ?? 0 }
      : r,
  );
}

/* -------------------------------- ingest ------------------------------- */

/**
 * POST /v1/ti/ingest — hand a STIX bundle (parsed JSON) or {url} to the
 * service via the orchestrator proxy. Degrades to {ok:false,note} if down.
 */
export function ingestStix(bundleOrUrl: unknown): Promise<TiProxyResult> {
  return apiFetch<TiProxyResult>("/v1/ti/ingest", { method: "POST", body: bundleOrUrl });
}
