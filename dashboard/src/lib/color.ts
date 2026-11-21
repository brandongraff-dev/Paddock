/**
 * Severity / asset-kind color helpers.
 * Keep in lockstep with tokens.css — these hex values are a copy of the
 * same tokens, exposed for places that can't read CSS vars (e.g. recharts
 * props, inline SVG, canvas).
 */

import type { AssetKind, Severity } from "../api/types";

export const SEV_COLOR: Record<Severity, string> = {
  info: "#6f7a8c",
  low: "#4ea3ff",
  medium: "#f0b429",
  high: "#ff7a45",
  critical: "#ff4d6d",
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
  org: "#c084fc",
  domain: "#4ea3ff",
  subdomain: "#6cc6ff",
  ipv4: "#58d68d",
  ipv6: "#3eb673",
  port: "#f0b429",
  service: "#ffb86b",
  technology: "#c7a7ff",
  certificate: "#f78da7",
  endpoint: "#ff7a45",
  repository: "#e6edf7",
  secret_candidate: "#ff4d6d",
  cloud_account: "#22d3ee",
  cloud_resource: "#0ea5e9",
};

export function kindColor(k: AssetKind | string | undefined | null): string {
  if (!k) return "#4ea3ff";
  return (KIND_COLOR as Record<string, string>)[k] ?? "#4ea3ff";
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
  subdomain_discovered: "#6cc6ff",
  endpoint_discovered: "#ff7a45",
  ip_discovered: "#58d68d",
  port_opened: "#f0b429",
  port_closed: "#6f7a8c",
  tech_detected: "#c7a7ff",
  tech_version_changed: "#c7a7ff",
  cert_added: "#f78da7",
  cert_expiring: "#f0b429",
  secret_found: "#ff4d6d",
  repository_found: "#e6edf7",
  finding_opened: "#ff7a45",
  finding_resolved: "#58d68d",
  exposure_increased: "#ff4d6d",
  asset_removed: "#6f7a8c",
  chain_detected: "#c084fc",
  attack_path_found: "#c084fc",
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
  "A+": "#58d68d",
  A: "#58d68d",
  B: "#22d3ee",
  C: "#f0b429",
  D: "#ff7a45",
  E: "#ff7a45",
  F: "#ff4d6d",
  T: "#ff4d6d",
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
  public: "#58d68d",
  internal: "#4ea3ff",
  confidential: "#f0b429",
  restricted: "#ff4d6d",
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
  npm: "#ff7a45",
  pypi: "#4ea3ff",
  go: "#22d3ee",
  cargo: "#ffb86b",
  maven: "#c084fc",
  rubygems: "#ff4d6d",
  nuget: "#58d68d",
  composer: "#c7a7ff",
  hex: "#f78da7",
};

export function ecosystemColor(e: Ecosystem | string | undefined | null): string {
  if (!e) return "#6f7a8c";
  return ECOSYSTEM_COLOR[String(e).toLowerCase()] ?? "#6f7a8c";
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
  return { bg: `rgba(78, 163, 255, ${op})`, border: "var(--accent-dim)", text: "var(--text-0)" };
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
  reachable: "#ff4d6d",
  potential: "#f0b429",
  unreachable: "#6f7a8c",
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
  if (c == null || Number.isNaN(c) || Math.abs(c) < 0.5) return "#6f7a8c";
  return c > 0 ? SEV_COLOR.high : "#58d68d";
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
