/**
 * Billing API (hosted edition): plan + usage, Stripe Checkout / Portal, and
 * the shared parser for the orchestrator's HTTP 402 "upgrade" body.
 * Mirrors orchestrator/app/billing/router.py and gate.py.
 */
import { ApiError, apiFetch } from "./client";

export interface QuotaState {
  used: number | null;
  limit: number | null;
  over: boolean;
}

export interface BillingPlan {
  key: "team" | "enterprise";
  name: string;
  edition: string;
  seats: number | null;
  sites: number | null;
  assets: number | null;
  purchasable: boolean;
}

export interface Billing {
  enabled: boolean;
  enforcement: boolean;
  edition: string;
  /** trialing | active | past_due | trial_expired | payment_failed | canceled | community | grace | expired … */
  status: string;
  source: string;
  plan: string | null;
  features: string[];
  limits: Record<"seats" | "sites" | "assets", number | null>;
  usage: Record<"seats" | "sites" | "assets", QuotaState>;
  trial_ends_at: string | null;
  trial_days_left: number | null;
  grace_ends_at: string | null;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  downgraded: boolean;
  dunning: boolean;
  read_only: boolean;
  can_manage: boolean;
  plans: BillingPlan[];
  upgrade_url: string;
}

export const getBilling = () => apiFetch<Billing>("/v1/billing");

export const startCheckout = (plan: BillingPlan["key"]) =>
  apiFetch<{ url: string }>("/v1/billing/checkout", { method: "POST", body: { plan } });

export const openPortal = () => apiFetch<{ url: string }>("/v1/billing/portal", { method: "POST" });

/* ---------------------------- 402 handling ----------------------------- */

/** Machine-readable body of an HTTP 402 from the feature / quota gate. */
export interface PaymentRequiredInfo {
  /** The feature (`scim`, `compliance_packs`) or quota dimension (`assets`). */
  feature: string;
  required_edition: string;
  upgrade_url: string;
  /** `payment_required` (plan lacks the feature) or `quota_exceeded`. */
  kind: "payment_required" | "quota_exceeded" | "feature_not_licensed";
  description?: string;
  current_edition?: string;
  reason?: string;
  used?: number;
  limit?: number;
}

/**
 * If `err` is an HTTP 402 carrying the upgrade body, return it. Accepts both
 * the flat body and FastAPI's `{detail: {...}}` wrapper (which the older
 * `licensing.require_feature` gate still uses). Anything else → null.
 */
export function paymentRequired(err: unknown): PaymentRequiredInfo | null {
  if (!(err instanceof ApiError) || err.status !== 402) return null;
  const raw = (err.body ?? {}) as Record<string, unknown>;
  const b = (typeof raw.detail === "object" && raw.detail !== null ? raw.detail : raw) as Record<string, unknown>;
  const feature = typeof b.feature === "string" ? b.feature : "this feature";
  const error = typeof b.error === "string" ? b.error : "payment_required";
  return {
    feature,
    required_edition: typeof b.required_edition === "string" ? b.required_edition : "team",
    upgrade_url: typeof b.upgrade_url === "string" ? b.upgrade_url : "/settings/billing",
    kind: error === "quota_exceeded" || error === "feature_not_licensed" ? error : "payment_required",
    description: typeof b.description === "string" ? b.description : undefined,
    current_edition: typeof b.current_edition === "string" ? b.current_edition : undefined,
    reason: typeof b.reason === "string" ? b.reason : undefined,
    used: typeof b.used === "number" ? b.used : undefined,
    limit: typeof b.limit === "number" ? b.limit : undefined,
  };
}

/** Where the "Upgrade" button goes: in-app when the URL points at this app. */
export function upgradeHref(info: PaymentRequiredInfo): string {
  try {
    const u = new URL(info.upgrade_url, window.location.origin);
    if (u.origin === window.location.origin) return u.pathname + u.search;
    return u.href;
  } catch {
    return "/settings/billing";
  }
}
