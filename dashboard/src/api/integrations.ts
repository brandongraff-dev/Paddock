/**
 * Integrations API client — /v1/integrations (see docs/INTEGRATIONS.md).
 *
 * Secrets are write-only: the server returns them as "********" (set) or ""
 * (unset). Sending "********" back means "keep"; "" means "clear".
 */

import { apiFetch } from "./client";

export type IntegrationSeverity = "info" | "low" | "medium" | "high" | "critical";
export type DeliveryStatus = "pending" | "sent" | "failed" | "dead" | "skipped";
export type IntegrationStatus = "ok" | "error" | "never" | "disabled";

/** The JSON-schema subset connectors use for their config form. */
export interface SchemaProp {
  type?: "string" | "integer" | "number" | "boolean" | "array" | "object";
  title?: string;
  description?: string;
  enum?: Array<string | number>;
  default?: unknown;
  format?: "uri" | "email" | "hostname" | string;
  minimum?: number;
  maximum?: number;
  maxLength?: number;
  items?: SchemaProp;
}

export interface ConfigSchema {
  type?: "object";
  properties?: Record<string, SchemaProp>;
  required?: string[];
  additionalProperties?: boolean;
}

export interface ConnectorInfo {
  kind: string;
  display_name: string;
  category: string;
  capabilities: string[];
  config_schema: ConfigSchema;
  secret_fields: string[];
  required_secrets?: string[];
  docs_url: string | null;
}

export interface Catalog {
  connectors: ConnectorInfo[];
  events: Array<{ type: string; description: string }>;
  severities: IntegrationSeverity[];
  filters: string[];
}

export interface DeliveryStats {
  pending: number;
  failed: number;
  dead: number;
  sent_24h: number;
}

export interface Integration {
  id: string;
  kind: string;
  name: string;
  display_name: string;
  category: string;
  capabilities: string[];
  enabled: boolean;
  config: Record<string, unknown>;
  secrets: Record<string, string>;
  secret_fields: string[];
  secrets_error: string | null;
  events: string[];
  min_severity: IntegrationSeverity;
  filters: Record<string, string[]>;
  allow_private: boolean;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
  last_ok_at: string | null;
  last_error: string | null;
  last_error_at: string | null;
  status: IntegrationStatus;
  available: boolean;
  stats: DeliveryStats;
}

export interface IntegrationInput {
  kind?: string;
  name?: string;
  enabled?: boolean;
  config?: Record<string, unknown>;
  secrets?: Record<string, string | null>;
  events?: string[];
  min_severity?: IntegrationSeverity;
  filters?: Record<string, string[]>;
  allow_private?: boolean;
}

export interface TestResult {
  mode: "deliver" | "health";
  ok: boolean;
  status_code: number | null;
  detail: string;
  external_id: string | null;
  external_url: string | null;
  retryable: boolean;
  delivery_id: number | null;
}

export interface Delivery {
  id: number;
  event_id: string;
  event_type: string;
  status: DeliveryStatus;
  attempts: number;
  next_attempt_at: string | null;
  status_code: number | null;
  detail: string | null;
  created_at: string | null;
  updated_at: string | null;
  title: string | null;
  severity: IntegrationSeverity | null;
  url: string | null;
}

export interface DeliveryPage {
  items: Delivery[];
  total: number;
  limit: number;
  offset: number;
}

export interface IntegrationsHealth {
  status: "ok" | "degraded" | "empty";
  integrations: { total: number; enabled: number; ok: number; error: number; never: number; disabled: number };
  deliveries: DeliveryStats & { oldest_due_at: string | null; stalled: boolean };
  secret_key_persistent: boolean;
  items: Array<{ id: string; kind: string; name: string; status: IntegrationStatus; last_error: string | null }>;
}

const BASE = "/v1/integrations";
const id = (s: string) => encodeURIComponent(s);

export const getCatalog = () => apiFetch<Catalog>(`${BASE}/catalog`);
export const getIntegrationsHealth = () => apiFetch<IntegrationsHealth>(`${BASE}/health`);
export const listIntegrations = () => apiFetch<{ items: Integration[]; total: number }>(BASE);
export const getIntegration = (iid: string) => apiFetch<Integration>(`${BASE}/${id(iid)}`);

export const createIntegration = (body: IntegrationInput) =>
  apiFetch<Integration>(BASE, { method: "POST", body });

export const updateIntegration = (iid: string, body: IntegrationInput) =>
  apiFetch<Integration>(`${BASE}/${id(iid)}`, { method: "PATCH", body });

export const deleteIntegration = (iid: string) =>
  apiFetch<{ ok: true; id: string }>(`${BASE}/${id(iid)}`, { method: "DELETE" });

export const setIntegrationEnabled = (iid: string, enabled: boolean) =>
  apiFetch<Integration>(`${BASE}/${id(iid)}/${enabled ? "enable" : "disable"}`, { method: "POST" });

export const testIntegration = (iid: string, mode: "deliver" | "health" = "deliver") =>
  apiFetch<TestResult>(`${BASE}/${id(iid)}/test`, { method: "POST", body: { mode } });

export const listDeliveries = (
  iid: string,
  opts: { status?: DeliveryStatus | ""; limit?: number; offset?: number } = {},
) =>
  apiFetch<DeliveryPage>(`${BASE}/${id(iid)}/deliveries`, {
    query: { status: opts.status || undefined, limit: opts.limit ?? 25, offset: opts.offset ?? 0 },
  });

export const retryDelivery = (iid: string, did: number) =>
  apiFetch<Delivery>(`${BASE}/${id(iid)}/deliveries/${did}/retry`, { method: "POST" });

/** Pull the human-readable messages out of an ApiError body (422 shape). */
export function errorMessages(err: unknown): string[] {
  const body = (err as { body?: unknown })?.body as { detail?: unknown } | undefined;
  const detail = body?.detail;
  if (typeof detail === "string") return [detail];
  if (detail && typeof detail === "object" && !Array.isArray(detail)) {
    const d = detail as { message?: string; errors?: string[] };
    return [...(d.message ? [d.message] : []), ...(d.errors ?? [])];
  }
  if (Array.isArray(detail)) {
    return detail.map((e: { loc?: unknown[]; msg?: string }) =>
      `${(e.loc ?? []).slice(1).join(".")}: ${e.msg ?? "invalid"}`,
    );
  }
  return [err instanceof Error ? err.message : "Request failed"];
}
