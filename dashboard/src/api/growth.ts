/**
 * Growth API: the free exposure check (public), shareable trust pages
 * (public view + admin management) and supplier monitoring.
 *
 * Everything behind /v1/public/* is UNAUTHENTICATED: those calls deliberately
 * do not send the session token (publicFetch), so a signed-in user's token is
 * never attached to an anonymous endpoint.
 */
import { ApiError, apiFetch, buildUrl } from "./client";

/** fetch for the anonymous endpoints: never attaches Authorization. */
export async function publicFetch<T = unknown>(
  path: string,
  opts: { method?: string; body?: unknown; headers?: Record<string, string> } = {},
): Promise<T> {
  const url = buildUrl(path);
  const method = opts.method ?? (opts.body === undefined ? "GET" : "POST");
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: {
        Accept: "application/json",
        ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
        ...(opts.headers ?? {}),
      },
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    });
  } catch (e) {
    throw new ApiError(`network error calling ${url}`, 0, String(e));
  }
  const text = await res.text();
  let parsed: unknown = text;
  if (text && /^[[{]/.test(text.trimStart())) {
    try {
      parsed = JSON.parse(text);
    } catch {
      /* leave as text */
    }
  }
  if (!res.ok) {
    const retry = Number(res.headers.get("retry-after") ?? "");
    const err = new ApiError(`${res.status} ${res.statusText} on ${method} ${path}`, res.status, parsed);
    (err as ApiError & { retryAfter?: number }).retryAfter = Number.isFinite(retry) && retry > 0 ? retry : undefined;
    throw err;
  }
  return parsed as T;
}

/** The API's `detail` for an error: `{code, message}`, a string, or null. */
export function errorDetail(e: unknown): { code?: string; message?: string } {
  if (!(e instanceof ApiError)) return {};
  const body = e.body as { detail?: unknown } | undefined;
  const d = body?.detail;
  if (typeof d === "string") return { message: d };
  if (d && typeof d === "object") return d as { code?: string; message?: string };
  return {};
}

/* ------------------------------ exposure check ------------------------------ */

export type Grade = "A" | "B" | "C" | "D" | "F";
export type Sev = "info" | "low" | "medium" | "high" | "critical";

export interface ExposureSubmit {
  id: string;
  domain: string;
  status: "queued" | "running" | "done" | "failed";
  cached: boolean;
  email_stored: boolean;
}

export interface ExposureSummary {
  grade: Grade;
  score: number;
  reasons: string[];
  findings_total: number;
  by_severity: Record<Sev, number>;
  by_category: Record<string, number>;
  checks: { key: string; label: string; status: "pass" | "warn" | "fail" | "unknown" }[];
  stats: {
    subdomains: number;
    live_hosts: number;
    certificates_valid: number;
    wildcard_certificates: number;
    issuers: number;
    nameservers: number;
    dnssec: boolean;
    ct_available: boolean;
  };
  email: { spf: string; dmarc: string; dkim_found: boolean; mta_sts: boolean };
  assessed_at: string;
}

export interface ExposureReport {
  id: string;
  domain: string;
  status: "queued" | "running" | "done" | "failed";
  created_at: string;
  finished_at: string | null;
  error: "domain_not_found" | "assessment_failed" | null;
  summary: ExposureSummary | null;
  teaser: {
    shown: { severity: Sev; category: string; title: string; confidence: string; host: string | null }[];
    hidden: number;
  } | null;
  cta: { text: string; url: string } | null;
  passive_notice: string;
}

export const submitExposure = (body: {
  domain: string;
  email?: string;
  consent?: boolean;
  captcha_token?: string;
}) => publicFetch<ExposureSubmit>("/v1/public/exposure-report", { body });

export const getExposure = (id: string) =>
  publicFetch<ExposureReport>(`/v1/public/exposure-report/${encodeURIComponent(id)}`);

/* ------------------------------- trust pages -------------------------------- */

export type TrustSection = "grade" | "verified_fixes" | "sla" | "compliance" | "coverage";

export const TRUST_SECTIONS: { key: TrustSection; label: string; hint: string }[] = [
  { key: "grade", label: "Security grade", hint: "A–F grade, open findings by severity, trend" },
  { key: "verified_fixes", label: "Verified fixes", hint: "Fixed and verified counts, time to fix" },
  { key: "sla", label: "SLA compliance", hint: "Remediation within policy, by severity" },
  { key: "compliance", label: "Compliance packs", hint: "Control status counts per framework" },
  { key: "coverage", label: "Coverage", hint: "Assets monitored, scan freshness" },
];

export interface TrustView {
  organization: string | null;
  generated_at: string;
  period_days: number;
  expires_at: string;
  sections: TrustSection[];
  data: {
    grade?: {
      grade: Grade;
      score: number;
      trend: "improving" | "stable" | "worsening";
      open_by_severity: Record<string, number>;
      open_critical_high: number;
    };
    verified_fixes?: {
      fixed: number;
      verified: number;
      regressed: number;
      pending_verification: number;
      fixed_by_severity: Record<string, number>;
      median_hours_to_fix: number | null;
    };
    sla?: {
      compliance_pct: number | null;
      met: number;
      late: number;
      breached_open: number;
      by_severity: {
        severity: string;
        policy_hours: number | null;
        met: number;
        late: number;
        breached_open: number;
        compliance_pct: number | null;
      }[];
    };
    compliance?: {
      id: string;
      name: string;
      version: string;
      total: number;
      automated: number;
      counts: Record<string, number>;
    }[];
    coverage?: {
      assets_total: number;
      by_kind: { kind: string; total: number; seen_7d: number; stale: number }[];
      scans_by_status: Record<string, number>;
      last_completed_scan: string | null;
      sbom_projects: number;
      tls_graded: number;
      tls_below_b: number;
      fleet_agents: number;
      fleet_agents_recent: number;
    };
  };
}

export const viewTrust = (token: string, password?: string) =>
  password === undefined
    ? publicFetch<TrustView>(`/v1/public/trust/${encodeURIComponent(token)}`)
    : publicFetch<TrustView>(`/v1/public/trust/${encodeURIComponent(token)}`, { body: { password } });

export interface TrustLink {
  id: string;
  label: string;
  sections: TrustSection[];
  period_days: number;
  created_at: string;
  created_by: string | null;
  expires_at: string;
  revoked_at: string | null;
  password_protected: boolean;
  view_count: number;
  last_viewed_at: string | null;
  token_hint: string;
  status: "active" | "expired" | "revoked";
}
export interface TrustLinkCreated extends TrustLink {
  token: string;
  path: string;
}
export interface TrustLinkInput {
  label: string;
  sections: TrustSection[];
  expires_in_days: number;
  period_days: number;
  password?: string;
}

export const listTrustLinks = () => apiFetch<TrustLink[]>("/v1/trust-links");
export const createTrustLink = (body: TrustLinkInput) =>
  apiFetch<TrustLinkCreated>("/v1/trust-links", { body });
export const revokeTrustLink = (id: string) =>
  apiFetch<TrustLink>(`/v1/trust-links/${id}`, { method: "DELETE" });

/* -------------------------------- suppliers --------------------------------- */

export type Criticality = "low" | "medium" | "high" | "critical";

export interface Supplier {
  id: string;
  domain: string;
  name: string;
  criticality: Criticality;
  notes: string | null;
  enabled: boolean;
  interval_hours: number;
  next_run_at: string;
  last_assessed_at: string | null;
  last_grade: Grade | null;
  last_score: number | null;
  last_error: string | null;
  created_at: string;
}

export interface SupplierChanges {
  first: boolean;
  grade_from: Grade | null;
  grade_to: Grade;
  grade_direction: "none" | "drop" | "improve";
  score_from: number | null;
  score_to: number;
  score_delta: number | null;
  new: { id: string; rule: string; severity: Sev; title: string; host: string | null }[];
  resolved: { id: string; rule: string; severity: Sev; title: string; host: string | null }[];
  new_dangling: { id: string; title: string; host: string | null }[];
  new_cert_expiring: { id: string; title: string; host: string | null }[];
}

export interface SupplierDetail extends Supplier {
  history: { id: string; created_at: string; grade: Grade; score: number; changes: SupplierChanges }[];
  findings: {
    id: string;
    rule: string;
    category: string;
    severity: Sev;
    title: string;
    detail: string;
    fix: string;
    host: string | null;
    confidence: "confirmed" | "possible";
  }[];
  summary: ExposureSummary | null;
}

export interface SupplierInput {
  domain: string;
  name?: string;
  criticality: Criticality;
  interval_hours: number;
  notes?: string;
}

export const listSuppliers = () => apiFetch<Supplier[]>("/v1/suppliers");
export const getSupplier = (id: string) => apiFetch<SupplierDetail>(`/v1/suppliers/${id}`);
export const addSupplier = (body: SupplierInput) => apiFetch<Supplier>("/v1/suppliers", { body });
export const patchSupplier = (id: string, body: Partial<Pick<Supplier, "name" | "criticality" | "interval_hours" | "enabled" | "notes">>) =>
  apiFetch<Supplier>(`/v1/suppliers/${id}`, { method: "PATCH", body });
export const deleteSupplier = (id: string) => apiFetch<void>(`/v1/suppliers/${id}`, { method: "DELETE" });
export const assessSupplierNow = (id: string) =>
  apiFetch<Supplier>(`/v1/suppliers/${id}/assess`, { method: "POST", body: {} });
