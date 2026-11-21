/**
 * Reusable "upgrade" empty state, shown where an API answered HTTP 402.
 *
 *   {q.isError && <UpgradePrompt error={q.error} fallback={<div className="empty">…</div>} />}
 *
 * Renders nothing special for non-402 errors: it returns `fallback` (or null),
 * so callers can drop it into their existing error branch. It sits inside
 * the existing panel / glass surfaces and adds no surface style of its own.
 */
import type { ReactNode } from "react";
import { paymentRequired, upgradeHref, type PaymentRequiredInfo } from "../api/billing";
import "../styles/billing.css";

const EDITION_LABEL: Record<string, string> = {
  community: "Community",
  team: "Team",
  enterprise: "Enterprise",
  edge: "Edge",
};

const FEATURE_LABEL: Record<string, string> = {
  sso_saml: "SAML single sign-on",
  scim: "SCIM provisioning",
  compliance_packs: "Compliance evidence packs",
  audit_anchoring: "Anchored audit chain",
  audit_export: "Audit export",
  multi_tenant: "Multi-tenant workspaces",
  digest_branding: "Branded digests",
  assets: "Monitored assets",
  seats: "Seats",
  sites: "Sites",
};

export function featureLabel(feature: string): string {
  return FEATURE_LABEL[feature] ?? feature.replace(/_/g, " ");
}

export function UpgradeCard({ info, compact = false }: { info: PaymentRequiredInfo; compact?: boolean }) {
  const need = EDITION_LABEL[info.required_edition] ?? info.required_edition;
  const quota = info.kind === "quota_exceeded";
  const title = quota
    ? `${featureLabel(info.feature)} allowance reached`
    : `${featureLabel(info.feature)} is part of ${need}`;
  const hint = quota
    ? `Your plan includes ${info.limit ?? "a limited number of"} ${featureLabel(info.feature).toLowerCase()}` +
      (info.used != null ? ` and ${info.used} are in use` : "") +
      ". Existing data stays readable; upgrade to add more."
    : (info.description ?? `Upgrade to ${need} to turn this on.`);
  return (
    <div className={`upgrade-prompt${compact ? " compact" : ""}`} role="status" data-feature={info.feature}>
      <div className="upgrade-mark" aria-hidden="true">{quota ? "◔" : "✦"}</div>
      <div className="upgrade-title">{title}</div>
      <div className="upgrade-hint">{hint}</div>
      <a className="upgrade-cta" href={upgradeHref(info)}>
        {quota ? "Review plans" : `Upgrade to ${need}`}
      </a>
    </div>
  );
}

export default function UpgradePrompt({
  error,
  fallback = null,
  compact,
}: {
  error: unknown;
  fallback?: ReactNode;
  compact?: boolean;
}) {
  const info = paymentRequired(error);
  if (!info) return <>{fallback}</>;
  return <UpgradeCard info={info} compact={compact} />;
}
