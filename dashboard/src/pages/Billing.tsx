/**
 * Settings → Billing (admin). Current plan, trial countdown, usage against
 * quota, and the Stripe hand-offs (Checkout to upgrade, Customer Portal to
 * manage). Hosted edition only: when billing is off the page says so and
 * points at license keys.
 *
 * Money never moves in this page: both buttons redirect to Stripe-hosted
 * pages; the plan changes when Stripe's webhook reaches the orchestrator.
 */
import { useMutation, useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { getBilling, openPortal, startCheckout, type Billing, type BillingPlan } from "../api/billing";
import Gate from "../components/Gate";
import StatTile from "../components/StatTile";
import "../styles/billing.css";

const EDITION_LABEL: Record<string, string> = {
  community: "Community",
  team: "Team",
  enterprise: "Enterprise",
  edge: "Edge",
};

const STATUS_LABEL: Record<string, string> = {
  trialing: "Trial",
  active: "Active",
  past_due: "Payment failing",
  payment_failed: "Payment failed",
  trial_expired: "Trial ended",
  canceled: "Canceled",
  community: "Community",
  grace: "License in grace",
  expired: "License expired",
  invalid: "License invalid",
};

const DIMENSIONS = [
  { key: "assets", label: "Monitored assets", hint: "Seen in the last 30 days" },
  { key: "sites", label: "Sites", hint: "Locations with a Sentry sensor" },
  { key: "seats", label: "Seats", hint: "Active users" },
] as const;

function errText(e: unknown): string {
  if (e instanceof ApiError) {
    const b = e.body as { detail?: { error?: string; message?: string } | string } | undefined;
    const d = b?.detail;
    if (typeof d === "string") return d;
    if (d?.error === "billing_public_url_not_set") return "Billing return URL is not configured on this deployment.";
    if (d?.error === "plan_not_configured") return "This plan is not available for purchase yet.";
    if (d?.error === "already_subscribed") return "You already have a subscription — use Manage billing to change it.";
    if (d?.message) return d.message;
    return e.message;
  }
  return e instanceof Error ? e.message : "Request failed.";
}

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function fmtLimit(n: number | null | undefined): string {
  return n == null ? "Unlimited" : n.toLocaleString();
}

/** A horizontal usage-vs-quota meter. `limit === null` = unlimited (a plain count). */
export function UsageMeter({
  label, hint, used, limit, over,
}: { label: string; hint: string; used: number | null; limit: number | null; over: boolean }) {
  const pct = used != null && limit != null && limit > 0 ? Math.min(100, (used / limit) * 100) : used && limit === 0 ? 100 : 0;
  const tone = over ? "over" : pct >= 80 ? "near" : "ok";
  return (
    <div className="bill-meter" data-tone={tone}>
      <div className="bill-meter-head">
        <span className="bill-meter-label">{label}</span>
        <span className="bill-meter-figure mono">
          {used == null ? "unknown" : used.toLocaleString()}
          <span className="bill-meter-of"> / {fmtLimit(limit)}</span>
        </span>
      </div>
      <div
        className="bill-meter-track"
        role="meter"
        aria-label={`${label} usage`}
        aria-valuemin={0}
        aria-valuemax={limit ?? undefined}
        aria-valuenow={used ?? undefined}
      >
        <span style={{ width: `${limit == null ? 0 : pct}%` }} />
      </div>
      <div className="bill-meter-hint">
        {over ? "Over your allowance. Existing data is kept; new growth is paused." : hint}
      </div>
    </div>
  );
}

function Notices({ b }: { b: Billing }) {
  const items: { tone: "info" | "warn" | "bad"; title: string; body: string }[] = [];
  if (b.status === "trialing" && b.trial_days_left != null) {
    items.push({
      tone: b.trial_days_left <= 3 ? "warn" : "info",
      title: `${b.trial_days_left} ${b.trial_days_left === 1 ? "day" : "days"} left in your Team trial`,
      body: `The trial ends ${fmtDate(b.trial_ends_at)}. Choose a plan before then to keep Team features; nothing is deleted either way.`,
    });
  }
  if (b.dunning) {
    items.push({
      tone: "bad",
      title: "Your last payment failed",
      body: `Update your payment method by ${fmtDate(b.grace_ends_at)} to keep your plan. After that the workspace drops to Community limits (your data stays).`,
    });
  }
  if (b.downgraded) {
    const why: Record<string, string> = {
      trial_expired: "Your trial has ended.",
      payment_failed: "A payment could not be collected.",
      canceled: "Your subscription was canceled.",
    };
    items.push({
      tone: b.read_only ? "bad" : "warn",
      title: "You are on Community limits",
      body:
        `${why[b.status] ?? "Your plan has ended."} ` +
        (b.read_only
          ? "You are over an allowance, so new scans are paused and paid features are read-only. Nothing has been deleted."
          : "Paid features are locked; your data and everything in Community stay available."),
    });
  }
  if (b.cancel_at_period_end && b.status === "active") {
    items.push({
      tone: "warn",
      title: "Your subscription will end",
      body: `It is set to cancel on ${fmtDate(b.current_period_end)}. You can undo this in Manage billing.`,
    });
  }
  if (items.length === 0) return null;
  return (
    <div className="bill-notices">
      {items.map((n) => (
        <div key={n.title} className={`bill-notice tone-${n.tone}`} role="status">
          <div className="bill-notice-title">{n.title}</div>
          <div className="bill-notice-body">{n.body}</div>
        </div>
      ))}
    </div>
  );
}

function PlanCard({
  plan, current, highlighted, onChoose, busy,
}: {
  plan: BillingPlan; current: boolean; highlighted: boolean; onChoose: () => void; busy: boolean;
}) {
  return (
    <div className={`bill-plan${highlighted ? " is-highlighted" : ""}${current ? " is-current" : ""}`} data-plan={plan.key}>
      <div className="bill-plan-h">
        <h3>{plan.name}</h3>
        {current && <span className="chip bill-chip">Current</span>}
      </div>
      <ul className="bill-plan-list">
        <li>{plan.key === "team" ? "SAML single sign-on, branded reports" : "Everything in Team, plus SCIM, audit export, compliance packs, multi-tenant"}</li>
        <li>{fmtLimit(plan.assets)} monitored assets</li>
        <li>{fmtLimit(plan.sites)} sites</li>
        <li>{plan.seats == null ? "Unlimited seats" : `${plan.seats} seats`}</li>
      </ul>
      <Gate need="admin">
        <button
          type="button"
          className={current ? "" : "primary"}
          disabled={busy || current || !plan.purchasable}
          onClick={onChoose}
          title={!plan.purchasable ? "This plan is not available for purchase yet" : undefined}
        >
          {current ? "Your plan" : `Choose ${plan.name}`}
        </button>
      </Gate>
    </div>
  );
}

export default function BillingPage() {
  const [params] = useSearchParams();
  const justPaid = params.get("checkout") === "success";
  const wantedPlan = params.get("plan");
  const wantedFeature = params.get("feature");

  const q = useQuery({
    queryKey: ["billing"],
    queryFn: getBilling,
    // Stripe's webhook lags the redirect by a few seconds: keep checking.
    refetchInterval: (query) => (justPaid && query.state.data?.source !== "subscription" ? 3000 : false),
  });

  const checkout = useMutation({
    mutationFn: (plan: BillingPlan["key"]) => startCheckout(plan),
    onSuccess: (r) => window.location.assign(r.url),
  });
  const portal = useMutation({
    mutationFn: openPortal,
    onSuccess: (r) => window.location.assign(r.url),
  });

  const b = q.data;
  const busy = checkout.isPending || portal.isPending;
  const err = checkout.error ?? portal.error;

  return (
    <div className="page billing-page">
      <div className="page-header">
        <div>
          <h1>Billing</h1>
          <div className="subtitle">Your plan, what you have used, and how to change either. Payments are handled by Stripe.</div>
        </div>
        {b?.enabled && b.can_manage && (
          <Gate need="admin">
            <button type="button" disabled={busy} onClick={() => portal.mutate()}>
              Manage billing
            </button>
          </Gate>
        )}
      </div>

      {q.isLoading && <div className="empty">Loading plan…</div>}
      {q.isError && <div className="empty">Billing details are unavailable right now.</div>}
      {err && <div className="login-error" role="alert">{errText(err)}</div>}
      {justPaid && b && b.source !== "subscription" && (
        <div className="bill-notice tone-info" role="status">
          <div className="bill-notice-title">Thanks. Activating your subscription…</div>
          <div className="bill-notice-body">This usually takes a few seconds while Stripe confirms the payment.</div>
        </div>
      )}

      {b && !b.enabled && (
        <section className="panel">
          <div className="panel-h"><h2>Self-hosted</h2></div>
          <p className="bill-copy">
            Online billing is not enabled on this deployment. Self-hosted Paddock runs as <b>{EDITION_LABEL[b.edition] ?? b.edition}</b>
            {b.edition === "community" ? " with no usage caps" : " under your license key"}. Commercial editions are
            activated with a signed license file; see Editions &amp; licensing in the docs.
          </p>
        </section>
      )}

      {b && b.enabled && (
        <>
          <Notices b={b} />
          <div className="bill-tiles">
            <StatTile
              label="Plan"
              value={EDITION_LABEL[b.edition] ?? b.edition}
              hint={STATUS_LABEL[b.status] ?? b.status}
            />
            {b.status === "trialing" ? (
              <StatTile label="Trial ends" value={fmtDate(b.trial_ends_at)} hint={`${b.trial_days_left ?? 0} days left`} />
            ) : (
              <StatTile
                label={b.cancel_at_period_end ? "Ends" : "Renews"}
                value={b.source === "subscription" && !b.downgraded ? fmtDate(b.current_period_end) : "—"}
              />
            )}
            <StatTile label="Features" value={b.features.length} hint="included on this plan" />
          </div>

          <section className="panel bill-usage">
            <div className="panel-h"><h2>Usage</h2></div>
            <div className="bill-meters">
              {DIMENSIONS.map((d) => (
                <UsageMeter
                  key={d.key}
                  label={d.label}
                  hint={d.hint}
                  used={b.usage[d.key].used}
                  limit={b.usage[d.key].limit}
                  over={b.usage[d.key].over}
                />
              ))}
            </div>
          </section>

          <section className="panel">
            <div className="panel-h"><h2>Plans</h2></div>
            {wantedFeature && (
              <p className="bill-copy">
                <b>{wantedFeature.replace(/_/g, " ")}</b> needs {wantedPlan === "enterprise" ? "Enterprise" : "a paid plan"}.
              </p>
            )}
            <div className="bill-plans">
              {b.plans.map((p) => (
                <PlanCard
                  key={p.key}
                  plan={p}
                  current={b.source === "subscription" && !b.downgraded && b.plan === p.key}
                  highlighted={wantedPlan === p.key}
                  busy={busy}
                  onChoose={() => (b.can_manage && b.source === "subscription" && !b.downgraded ? portal.mutate() : checkout.mutate(p.key))}
                />
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
