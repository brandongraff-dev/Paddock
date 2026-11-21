/**
 * MSP console API (orchestrator schema 033, docs/MSP.md).
 *
 *   GET  /v1/msp/me                         who am I (msp user / delegated / ordinary)
 *   GET  /v1/msp/customers                  paginated customers with health (my grants only)
 *   GET  /v1/msp/summary                    fleet totals
 *   POST /v1/msp/customers                  provision a customer (+ one-time onboarding invite)
 *   POST /v1/msp/customers/{id}/switch      exchange for a short-lived customer-scoped token
 *   POST /v1/msp/customers/{id}/suspend|reactivate
 *   GET  /v1/msp/usage?format=csv           per-customer billing usage
 */

import { apiFetch, authHeaders, buildUrl } from "./client";

export type Grade = "A" | "B" | "C" | "D" | "F";
export type GrantRole = "viewer" | "analyst" | "admin";

export interface MspMe {
  mode: "none" | "msp" | "delegated";
  is_msp: boolean;
  org?: { name: string; max_customers: number | null };
  /** Present while acting inside a customer. */
  msp?: { name: string; slug: string };
  msp_user?: string;
  customer?: { id: string; slug: string; name: string };
  grant_role?: GrantRole;
}

export interface CustomerHealth {
  grade: Grade;
  exposure_index: number;
  open_findings: number;
  open_criticals: number;
  sla_breaches: number;
  verified_fixes: number;
  last_scan_at: string | null;
  monitored_assets: number;
  seats_used: number;
  seats_limit: number | null;
  assets_limit: number | null;
  computed_at: string;
}

export interface Customer {
  id: string;
  slug: string;
  name: string;
  status: "active" | "suspended";
  role: GrantRole;
  created_at: string;
  health: CustomerHealth | null;
}

export interface CustomerPage {
  items: Customer[];
  total: number;
  limit: number;
  offset: number;
  sort: string;
  order: "asc" | "desc";
}

export interface MspSummary {
  customers: number;
  with_health: number;
  open_criticals: number;
  sla_breaches: number;
  verified_fixes: number;
  at_risk: number;
}

export type CustomerSort =
  | "name" | "created" | "grade" | "exposure" | "criticals"
  | "sla_breaches" | "verified_fixes" | "last_scan" | "assets";

export interface CustomerQuery {
  q?: string;
  sort?: CustomerSort;
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
  refresh?: boolean;
}

export interface SwitchResult {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  role: GrantRole;
  clearance: string;
  customer: { id: string; slug: string; name: string };
  msp: { slug: string; name: string };
}

export interface Invite {
  id: string;
  token: string;
  expires_at: string;
  redeem_path: string;
}

export interface CreatedCustomer {
  id: string;
  slug: string;
  name: string;
  status: string;
  invite: Invite;
}

export const getMspMe = () => apiFetch<MspMe>("/v1/msp/me");

export const listCustomers = (q: CustomerQuery) =>
  apiFetch<CustomerPage>("/v1/msp/customers", { query: { ...q } });

export const getMspSummary = () => apiFetch<MspSummary>("/v1/msp/summary");

export const createCustomer = (body: { slug: string; name: string }) =>
  apiFetch<CreatedCustomer>("/v1/msp/customers", { method: "POST", body });

export const switchCustomer = (id: string) =>
  apiFetch<SwitchResult>(`/v1/msp/customers/${encodeURIComponent(id)}/switch`, { method: "POST" });

export const setCustomerStatus = (id: string, action: "suspend" | "reactivate") =>
  apiFetch<{ id: string; status: string }>(
    `/v1/msp/customers/${encodeURIComponent(id)}/${action}`,
    { method: "POST" },
  );

/** Download the per-customer usage CSV (needs the Authorization header, so not a bare link). */
export async function downloadUsageCsv(month?: string): Promise<void> {
  const res = await fetch(buildUrl("/v1/msp/usage", { format: "csv", month }), {
    headers: { ...authHeaders() },
  });
  if (!res.ok) throw new Error(`usage export failed (${res.status})`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `paddock-msp-usage-${month ?? "current"}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
