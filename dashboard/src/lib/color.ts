/**
 * Severity / asset-kind color helpers.
 * Keep in lockstep with tokens.css — these hex values are a copy of the
 * same tokens, exposed for places that can't read CSS vars (e.g. recharts
 * props, inline SVG, canvas).
 */

import type { AssetKind, Severity } from "../api/types";

/** Single-hue ordinal ramp (validated for dark surfaces); info is neutral. */
export const SEV_COLOR: Record<Severity, string> = {
  info: "#8a8175",
  low: "#f3c6a5",
  medium: "#ee9d72",
  high: "#e67350",
  critical: "#d5493c",
};

export const SEV_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];
export const SEV_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityColor(s: Severity | string | undefined | null): string {
  if (!s) return SEV_COLOR.info;
  return (SEV_COLOR as Record<string, string>)[s] ?? SEV_COLOR.info;
}

export const KIND_COLOR: Record<AssetKind, string> = {
  org: "#b9a3d6",
  domain: "#9fc2d8",
  subdomain: "#b6d3e3",
  ipv4: "#8fbf8a",
  ipv6: "#76a872",
  port: "#e3b265",
  service: "#e9c48f",
  technology: "#c9b5e0",
  certificate: "#e3a3b4",
  endpoint: "#e67350",
  repository: "#ece6da",
  secret_candidate: "#d5493c",
  cloud_account: "#7fc4c4",
  cloud_resource: "#6fb0c8",
};

export function kindColor(k: AssetKind | string | undefined | null): string {
  if (!k) return "#9fc2d8";
  return (KIND_COLOR as Record<string, string>)[k] ?? "#9fc2d8";
}

/**
 * Asset-kind colours for the graph canvas only: a warm Daguerreotype ladder
 * (cream, sand, amber, ember, clay, stone) with no blues or greens, so the
 * canvas sits in the same palette as the rest of the product. Kinds stay
 * distinguishable through the icon on each card; colour is a secondary cue.
 */
export const CANVAS_KIND_COLOR: Record<AssetKind, string> = {
  org: "#cbbba6",
  domain: "#ece2d0",
  subdomain: "#d8c3a3",
  ipv4: "#c2a27e",
  ipv6: "#b39572",
  port: "#e3b265",
  service: "#e9c48f",
  technology: "#bfa58c",
  certificate: "#d9a08a",
  endpoint: "#e67350",
  repository: "#a89f94",
  secret_candidate: "#d5493c",
  cloud_account: "#9e9184",
  cloud_resource: "#8f8478",
};

export function canvasKindColor(k: AssetKind | string | undefined | null): string {
  return (k && (CANVAS_KIND_COLOR as Record<string, string>)[k]) || "#cbbba6";
}

/** Clamp a numeric blast score (0..100) to a width %. */
export function blastPct(score: number | undefined | null): number {
  if (score == null || Number.isNaN(score)) return 0;
  return Math.max(0, Math.min(100, score));
}

/**
 * Color a blast score (0..100) by band, reusing the severity palette:
 *   < 40  → low  (blue)
 *   40–70 → med  (amber)
 *   70+   → high (red)
 * Returned as a hex so it works in inline styles and non-CSS contexts.
 */
export function blastColor(score: number | undefined | null): string {
  const n = blastPct(score);
  if (n >= 70) return SEV_COLOR.high;
  if (n >= 40) return SEV_COLOR.medium;
  return SEV_COLOR.low;
}

/**
 * Change-type accent, drawn from the existing palette so the Changes feed
 * reads as one system: discovery → blue, ports → amber, tech → violet,
 * certs → pink, secrets/exposure → red, resolution → green, removal → muted.
 */
import type { ChangeType } from "../api/types";

export const CHANGE_TYPE_COLOR: Record<ChangeType, string> = {
  subdomain_discovered: "#b6d3e3",
  endpoint_discovered: "#e67350",
  ip_discovered: "#8fbf8a",
  port_opened: "#e3b265",
  port_closed: "#8a8175",
  tech_detected: "#c9b5e0",
  tech_version_changed: "#c9b5e0",
  cert_added: "#e3a3b4",
  cert_expiring: "#e3b265",
  secret_found: "#d5493c",
  repository_found: "#ece6da",
  finding_opened: "#e67350",
  finding_resolved: "#8fbf8a",
  exposure_increased: "#d5493c",
  asset_removed: "#8a8175",
  chain_detected: "#b9a3d6",
  attack_path_found: "#b9a3d6",
};

export function changeTypeColor(t: ChangeType | string | undefined | null): string {
  if (!t) return SEV_COLOR.info;
  return (CHANGE_TYPE_COLOR as Record<string, string>)[t] ?? SEV_COLOR.info;
}

/** Compact two–three letter tag for a change type (mono badge). */
export function changeTypeTag(t: ChangeType | string): string {
  const map: Record<string, string> = {
    subdomain_discovered: "SUB",
    endpoint_discovered: "EP",
    ip_discovered: "IP",
    port_opened: "PORT",
    port_closed: "PORT",
    tech_detected: "TECH",
    tech_version_changed: "TECH",
    cert_added: "CERT",
    cert_expiring: "CERT",
    secret_found: "SEC",
    repository_found: "REPO",
    finding_opened: "FND",
    finding_resolved: "FND",
    exposure_increased: "EXP",
    asset_removed: "RMV",
    chain_detected: "CHN",
    attack_path_found: "PATH",
  };
  return map[t] ?? "CHG";
}

/**
 * TLS letter-grade accent (Posture report-card). Drawn from the existing
 * palette so the grade strip reads as one system:
 *   A+/A → green (ok), B → teal (cloud_account cyan), C → amber (warn),
 *   D/E → orange (high), F/T → red (crit).
 * Hex so it works in inline styles and non-CSS contexts.
 */
import type { Grade } from "../api/types";

export const GRADE_COLOR: Record<Grade, string> = {
  "A+": "#8fbf8a",
  A: "#8fbf8a",
  B: "#7fc4c4",
  C: "#e3b265",
  D: "#e67350",
  E: "#e67350",
  F: "#d5493c",
  T: "#d5493c",
};

/** Grade display order for the distribution strip and filters. */
export const GRADE_ORDER: Grade[] = ["A+", "A", "B", "C", "D", "E", "F", "T"];

export function gradeColor(g: Grade | string | undefined | null): string {
  if (!g) return SEV_COLOR.info;
  return (GRADE_COLOR as Record<string, string>)[g] ?? SEV_COLOR.info;
}

/* ------------------------------------------------------------------ *
 * Governance — data classification (public → restricted).            *
 * A calm→alarming ramp so the top banner reads as one escalating      *
 * scale: public (muted green), internal (blue), confidential (amber), *
 * restricted (red). Hex so it works in inline styles + the banner.    *
 * ------------------------------------------------------------------ */

import type { Classification } from "../api/types";

export const CLASSIFICATION_ORDER: Classification[] = [
  "public",
  "internal",
  "confidential",
  "restricted",
];

export const CLASSIFICATION_RANK: Record<Classification, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  restricted: 3,
};

export const CLASSIFICATION_COLOR: Record<Classification, string> = {
  public: "#8fbf8a",
  internal: "#9fc2d8",
  confidential: "#e3b265",
  restricted: "#d5493c",
};

export const CLASSIFICATION_LABEL: Record<Classification, string> = {
  public: "PUBLIC",
  internal: "INTERNAL",
  confidential: "CONFIDENTIAL",
  restricted: "RESTRICTED",
};

export function classificationColor(c: Classification | string | undefined | null): string {
  if (!c) return CLASSIFICATION_COLOR.public;
  return (CLASSIFICATION_COLOR as Record<string, string>)[c] ?? CLASSIFICATION_COLOR.public;
}

export function classificationRank(c: Classification | string | undefined | null): number {
  if (!c) return 0;
  return (CLASSIFICATION_RANK as Record<string, number>)[c] ?? 0;
}

/** Fold a list of classifications to the most-sensitive one. */
export function maxClassification(
  list: (Classification | undefined | null)[],
): Classification | null {
  let best: Classification | null = null;
  for (const c of list) {
    if (!c) continue;
    if (best === null || classificationRank(c) > classificationRank(best)) best = c;
  }
  return best;
}

/** Highest severity among a list (for chain color). */
export function maxSeverity(list: (Severity | undefined | null)[]): Severity {
  let best: Severity = "info";
  for (const s of list) {
    if (!s) continue;
    if (SEV_RANK[s] > SEV_RANK[best]) best = s;
  }
  return best;
}

/* ------------------------------------------------------------------ *
 * Tier 3 — SCA / supply-chain + ATT&CK coverage helpers.             *
 * Drawn from the same palette so the new pages read as one system.   *
 * ------------------------------------------------------------------ */

import type { Ecosystem, RiskType } from "../api/types";

/** Ecosystem chip accent (SBOM table). Reuses the kind/severity palette. */
export const ECOSYSTEM_COLOR: Record<string, string> = {
  npm: "#e67350",
  pypi: "#9fc2d8",
  go: "#7fc4c4",
  cargo: "#e9c48f",
  maven: "#b9a3d6",
  rubygems: "#d5493c",
  nuget: "#8fbf8a",
  composer: "#c9b5e0",
  hex: "#e3a3b4",
};

export function ecosystemColor(e: Ecosystem | string | undefined | null): string {
  if (!e) return "#8a8175";
  return ECOSYSTEM_COLOR[String(e).toLowerCase()] ?? "#8a8175";
}

/** Human label for a supply-chain risk category. */
export const RISK_TYPE_LABEL: Record<string, string> = {
  dependency_confusion: "Dependency confusion",
  typosquat: "Typosquat",
  abandoned: "Abandoned",
  malicious_version: "Malicious version",
  yanked: "Yanked",
  unpinned: "Unpinned",
};

export function riskTypeLabel(t: RiskType | string): string {
  return RISK_TYPE_LABEL[t] ?? String(t).replace(/_/g, " ");
}

/** Canonical ordering for the supply-chain risk groups (worst-first-ish). */
export const RISK_TYPE_ORDER: RiskType[] = [
  "malicious_version",
  "dependency_confusion",
  "typosquat",
  "yanked",
  "abandoned",
  "unpinned",
];

/**
 * Heat style for an ATT&CK technique tile: background intensity scales with
 * the finding count relative to the busiest technique. 0 = faint outline only.
 * Returns inline-ready values (rgba drawn from the accent).
 */
export function attackHeat(
  count: number,
  max: number,
): { bg: string; border: string; text: string } {
  if (!count || count <= 0) {
    return { bg: "transparent", border: "var(--border)", text: "var(--text-2)" };
  }
  const frac = max > 0 ? Math.min(1, count / max) : 1;
  const op = (0.12 + frac * 0.46).toFixed(3); // 0.12 → 0.58
  return { bg: `rgba(159, 194, 216, ${op})`, border: "var(--accent-dim)", text: "var(--text-0)" };
}

/* ------------------------------------------------------------------ *
 * Tier 4 — reachability grade + adaptive ML risk helpers.            *
 * Same palette so the new surfaces read as one system.               *
 * ------------------------------------------------------------------ */

import type { ReachabilityGrade } from "../api/types";

/**
 * Reachability accent: reachable = red (prioritize), potential = amber,
 * unreachable = muted grey ("not reached"), unknown = faint (don't alarm).
 */
export const REACHABILITY_COLOR: Record<ReachabilityGrade, string> = {
  reachable: "#d5493c",
  potential: "#e3b265",
  unreachable: "#8a8175",
  unknown: "#4a5263",
};

/** Short badge label for a reachability grade. */
export const REACHABILITY_LABEL: Record<ReachabilityGrade, string> = {
  reachable: "reachable",
  potential: "potential",
  unreachable: "not reached",
  unknown: "—",
};

export function reachabilityColor(r: ReachabilityGrade | string | undefined | null): string {
  if (!r) return REACHABILITY_COLOR.unknown;
  return (REACHABILITY_COLOR as Record<string, string>)[r] ?? REACHABILITY_COLOR.unknown;
}

export function reachabilityLabel(r: ReachabilityGrade | string | undefined | null): string {
  if (!r) return REACHABILITY_LABEL.unknown;
  return (REACHABILITY_LABEL as Record<string, string>)[r] ?? REACHABILITY_LABEL.unknown;
}

/** Clamp an ML risk score to 0..100. */
export function mlRiskPct(score: number | undefined | null): number {
  if (score == null || Number.isNaN(score)) return 0;
  return Math.max(0, Math.min(100, score));
}

/**
 * Band-color an ML risk score (0..100), reusing the severity ramp so a 90
 * reads as "critical" and a 20 as "low":
 *   75+ → crit, 50–75 → high, 25–50 → med, <25 → low.
 */
export function mlRiskColor(score: number | undefined | null): string {
  const n = mlRiskPct(score);
  if (n >= 75) return SEV_COLOR.critical;
  if (n >= 50) return SEV_COLOR.high;
  if (n >= 25) return SEV_COLOR.medium;
  return SEV_COLOR.low;
}

/**
 * Color a signed rationale contribution: positive raises risk (orange/high),
 * negative lowers it (green/ok), ~zero is neutral grey.
 */
export function contributionColor(c: number | undefined | null): string {
  if (c == null || Number.isNaN(c) || Math.abs(c) < 0.5) return "#8a8175";
  return c > 0 ? SEV_COLOR.high : "#8fbf8a";
}

/** Humanize a model feature key ("on_kev_path" → "on KEV path"). */
export function featureLabel(key: string): string {
  const special: Record<string, string> = {
    cvss: "CVSS",
    epss: "EPSS",
    kev: "KEV",
    on_kev_path: "on KEV path",
    kev_on_path: "on KEV path",
    rule_source: "rule source",
    blast_score: "blast radius",
    internet_exposed: "internet-exposed",
    on_attack_path: "on attack path",
  };
  if (special[key]) return special[key];
  return key.replace(/_/g, " ").replace(/\bkev\b/gi, "KEV").replace(/\bcvss\b/gi, "CVSS");
}
