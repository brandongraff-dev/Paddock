/**
 * Wargame presentation logic: the evidence ladder, boundary verdicts,
 * certificate status, and the plain-English sentences the page reads out.
 *
 * Honesty rules encoded here (docs/WARGAME.md §2.4, WARGAME_ENGINE.md §2/§9):
 *  - a route is only as strong as its weakest hop, so a hop is *styled* by
 *    its weakest label (its other labels are still listed);
 *  - conditional / inferred / unknown are the "weak" tier and never get the
 *    solid styling that proof gets;
 *  - an unrecognised label or verdict is shown verbatim in a neutral style:
 *    it is never upgraded to a known (stronger) one.
 */

import type {
  WargameChangeImpact,
  WargameFixSet,
  WargameHop,
  WargameRoute,
} from "../api/types";

/* ------------------------------------------------------------------ */
/* Evidence ladder                                                     */
/* ------------------------------------------------------------------ */

/** How the line between two nodes is drawn. */
export type EvidenceTier = "exploit" | "operational" | "config" | "weak";

export interface EvidenceMeta {
  key: string;
  /** 0 (unknown) … 8 (imported), engine `LABEL_STRENGTH`. */
  strength: number;
  /** Short plain-English label shown on the hop. */
  label: string;
  /** Precise meaning, for the tooltip. */
  tip: string;
  tier: EvidenceTier;
}

export const MAX_STRENGTH = 8;

const LADDER: EvidenceMeta[] = [
  {
    key: "imported",
    strength: 8,
    label: "Exploited by a third party",
    tip: "Imported: a third party (e.g. your pentester) demonstrated exploitation of this hop, recorded with attribution. Paddock never runs it.",
    tier: "exploit",
  },
  {
    key: "proved_replica",
    strength: 7,
    label: "Proved on a rebuilt copy",
    tip: "Proved (replica): exploit preconditions confirmed on a rebuilt, no-egress copy of the component. Vulnerable and reachable.",
    tier: "exploit",
  },
  {
    key: "proved_live_safe_check",
    strength: 6,
    label: "Proved by a safe check",
    tip: "Proved (live safe check): preconditions confirmed on the in-scope asset (version, config, exposure). Vulnerable and reachable.",
    tier: "exploit",
  },
  {
    key: "observed",
    strength: 5,
    label: "Traffic seen",
    tip: "Observed: real traffic on this hop (completed handshake or destination-side view). Proves reachability in use, not exploitability.",
    tier: "operational",
  },
  {
    key: "tested_probe",
    strength: 4,
    label: "Probe got through",
    tip: "Tested (probe): a safe-check TCP connect crossed this boundary. Proves reachability in operation.",
    tier: "operational",
  },
  {
    key: "proved_config",
    strength: 3,
    label: "Config allows it",
    tip: "Proved (config): the rule solver shows the configuration permits this hop. No packets were sent.",
    tier: "config",
  },
  {
    key: "conditional",
    strength: 2,
    label: "Depends on runtime state",
    tip: "Conditional: allowed only subject to runtime state the config can't prove (App-ID, FQDN objects, dynamic groups…). Not proof either way.",
    tier: "weak",
  },
  {
    key: "inferred",
    strength: 1,
    label: "Inferred, not proved",
    tip: "Inferred: the graph suggests this hop; nothing has proved it yet.",
    tier: "weak",
  },
  {
    key: "unknown",
    strength: 0,
    label: "Unknown",
    tip: "Unknown: outside the model.",
    tier: "weak",
  },
];

const LADDER_BY_KEY = new Map(LADDER.map((m) => [m.key, m]));

export const EVIDENCE_LADDER: readonly EvidenceMeta[] = LADDER;

/** Meta for a label; an unrecognised one is shown as reported, at strength 0. */
export function evidenceMeta(label: string | null | undefined): EvidenceMeta {
  const key = String(label ?? "unknown").toLowerCase();
  const known = LADDER_BY_KEY.get(key);
  if (known) return known;
  return {
    key,
    strength: 0,
    label: key.replace(/_/g, " "),
    tip: `"${key}" is not a label this console recognises; it is shown as reported and treated as no proof.`,
    tier: "weak",
  };
}

/** The weakest label on a hop (what the hop is styled by). */
export function hopWeakest(hop: WargameHop): EvidenceMeta {
  const labels = hop.labels?.length ? hop.labels : ["unknown"];
  return labels.map(evidenceMeta).reduce((a, b) => (b.strength < a.strength ? b : a));
}

/** Labels on a hop, strongest first. */
export function hopLabels(hop: WargameHop): EvidenceMeta[] {
  const labels = hop.labels?.length ? hop.labels : ["unknown"];
  return labels.map(evidenceMeta).sort((a, b) => b.strength - a.strength);
}

/**
 * "Proved except hop 3 (inferred)". Reads the route the way the engine does:
 * as strong as its weakest hop.
 */
export function routeStrengthSentence(route: WargameRoute): string {
  const hops = route.hops ?? [];
  if (!hops.length) return `Weakest evidence: ${evidenceMeta(route.weakest_label).label.toLowerCase()}.`;
  const weak = hops
    .map((h, i) => ({ i: i + 1, m: hopWeakest(h) }))
    .filter((x) => x.m.tier === "weak");
  if (weak.length === 0) {
    const min = hops.map(hopWeakest).reduce((a, b) => (b.strength < a.strength ? b : a));
    return min.tier === "config"
      ? "Every hop is allowed by config (no packets sent)."
      : "Every hop is proved or seen in traffic.";
  }
  if (weak.length === hops.length) {
    return "Nothing on this route is proved yet: treat it as a lead, not a finding.";
  }
  const parts = weak.map((w) => `hop ${w.i} (${w.m.label.toLowerCase()})`);
  return `Proved except ${joinList(parts)}.`;
}

/* ------------------------------------------------------------------ */
/* Boundary verdicts + certificates                                    */
/* ------------------------------------------------------------------ */

export type VerdictTone = "pass" | "proved" | "open" | "conditional" | "insufficient" | "unknown";

export interface VerdictMeta {
  key: string;
  label: string;
  tip: string;
  tone: VerdictTone;
  /** Glyph shown before the label so colour is never the only signal. */
  glyph: string;
}

const VERDICTS: Record<string, VerdictMeta> = {
  pass: {
    key: "pass",
    label: "Shut, proved and tested",
    tip: "Pass: the config proves it closed, a safe-check probe was blocked, and no real traffic was seen crossing.",
    tone: "pass",
    glyph: "✓✓",
  },
  proved_config: {
    key: "proved_config",
    label: "Shut on paper",
    tip: "Proved (config): the rule solver proves the config blocks this, but no probe has tested it in operation yet.",
    tone: "proved",
    glyph: "✓",
  },
  fail_open: {
    key: "fail_open",
    label: "Open",
    tip: "Fail (open): at least one source (config, probe or observed traffic) shows traffic can cross this boundary.",
    tone: "open",
    glyph: "✕",
  },
  conditional: {
    key: "conditional",
    label: "Depends on runtime state",
    tip: "Conditional: closure rests on a rule whose effect depends on runtime state the config can't prove (App-ID, FQDN, dynamic groups). Not counted as closed.",
    tone: "conditional",
    glyph: "≈",
  },
  insufficient: {
    key: "insufficient",
    label: "Not enough evidence",
    tip: "Insufficient: the sources don't add up to a verdict (for example no probe was run). Not a proof either way.",
    tone: "insufficient",
    glyph: "?",
  },
};

export function verdictMeta(verdict: string | null | undefined): VerdictMeta {
  const key = String(verdict ?? "").toLowerCase();
  return (
    VERDICTS[key] ?? {
      key,
      label: key ? key.replace(/_/g, " ") : "No verdict",
      tip: `"${key || "(empty)"}" is not a verdict this console recognises; shown as reported and not counted as closed.`,
      tone: "unknown",
      glyph: "·",
    }
  );
}

export const VERDICT_ORDER = ["fail_open", "conditional", "insufficient", "proved_config", "pass"];

export function verdictRank(v: string): number {
  const i = VERDICT_ORDER.indexOf(String(v).toLowerCase());
  return i === -1 ? -1 : i; // unknown first: it needs a human
}

export interface CertStatusMeta {
  label: string;
  tone: VerdictTone;
  tip: string;
}

export function certStatusMeta(status: string, expiresAt: string | null, now = Date.now()): CertStatusMeta {
  const s = String(status).toLowerCase();
  const lapsed = expiresAt ? Date.parse(expiresAt) <= now : false;
  if (s === "contradicted") {
    return {
      label: "Contradicted",
      tone: "open",
      tip: "Real traffic crossed a boundary this certificate proved closed. The signature still verifies, but the claim no longer holds.",
    };
  }
  if (s === "expired" || (s === "valid" && lapsed)) {
    return { label: "Expired", tone: "insufficient", tip: "Past its expiry: re-run the assessment to re-prove the boundary." };
  }
  if (s === "valid") {
    return { label: "Valid", tone: "pass", tip: "Signed, unexpired, and not contradicted by observed traffic." };
  }
  return { label: s || "Unknown", tone: "unknown", tip: `"${s}" is not a status this console recognises.` };
}

/** "in 20 hours" / "3 days ago" — coarse on purpose. */
export function relativeTime(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "no expiry recorded";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const diff = t - now;
  const abs = Math.abs(diff);
  const unit =
    abs < 3_600_000
      ? { n: Math.max(1, Math.round(abs / 60_000)), u: "minute" }
      : abs < 86_400_000 * 2
        ? { n: Math.round(abs / 3_600_000), u: "hour" }
        : { n: Math.round(abs / 86_400_000), u: "day" };
  const s = `${unit.n} ${unit.u}${unit.n === 1 ? "" : "s"}`;
  return diff >= 0 ? `in ${s}` : `${s} ago`;
}

export function assumptionText(a: unknown): { key: string; text: string } {
  if (a && typeof a === "object") {
    const o = a as Record<string, unknown>;
    return { key: String(o.key ?? ""), text: String(o.text ?? o.key ?? "") };
  }
  return { key: "", text: String(a) };
}

/* ------------------------------------------------------------------ */
/* Fix set                                                             */
/* ------------------------------------------------------------------ */

/** Ids of the changes a route could be cut by. */
export function routeFixIds(route: WargameRoute): Set<string> {
  const ids = new Set<string>();
  for (const h of route.hops ?? []) for (const id of h.fix_candidate_ids ?? []) ids.add(id);
  return ids;
}

/** The selected fixes that cut this route (empty = this route stays open). */
export function cuttingFixes(route: WargameRoute, fixSet: WargameFixSet | null | undefined): string[] {
  if (!fixSet) return [];
  const ids = routeFixIds(route);
  return (fixSet.selected ?? []).filter((f) => ids.has(f.id)).map((f) => f.id);
}

/**
 * Routes the fix set does not cut. The engine records these as
 * `uncut_routes` (indices); the persisted fix set may carry them in
 * metadata. Otherwise derive: a route is uncut when none of its cuttable
 * elements is selected.
 */
export function uncutRoutes(routes: WargameRoute[], fixSet: WargameFixSet | null | undefined): WargameRoute[] {
  if (!fixSet) return [];
  const meta = fixSet.metadata?.uncut_routes;
  if (Array.isArray(meta) && meta.length && meta.every((x) => typeof x === "string")) {
    const fp = new Set(meta as string[]);
    const hit = routes.filter((r) => fp.has(r.fingerprint) || fp.has(r.id));
    if (hit.length) return hit;
  }
  return routes.filter((r) => cuttingFixes(r, fixSet).length === 0);
}

/* ------------------------------------------------------------------ */
/* Change gate                                                         */
/* ------------------------------------------------------------------ */

export type ImpactTone = "safe" | "opens" | "breaks" | "both" | "unknown";

export interface ImpactHeadline {
  tone: ImpactTone;
  headline: string;
  /** A second, quieter sentence (e.g. the routes it also closes). */
  sub?: string;
}

function uniq(xs: string[]): string[] {
  return [...new Set(xs)];
}

export function joinList(xs: string[]): string {
  if (xs.length <= 1) return xs.join("");
  if (xs.length === 2) return `${xs[0]} and ${xs[1]}`;
  return `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function impactHeadline(r: WargameChangeImpact): ImpactHeadline {
  const opened = r.routes_opened ?? [];
  const closed = r.routes_closed ?? [];
  const denied = r.newly_denied_flows ?? [];
  const incomplete = r.complete === false;
  const jewels = joinList(uniq(opened.map((p) => p.jewel)));
  const opens = `opens a route to ${jewels || "a crown jewel"}`;
  const breaks = `breaks ${plural(denied.length || 0, "live flow")}`;
  const closesSub = closed.length
    ? `It also closes ${plural(closed.length, "route")} to ${joinList(uniq(closed.map((p) => p.jewel)))}.`
    : undefined;
  const partial = incomplete ? "Part of this plan couldn't be checked against the model, so there may be more; see the warnings." : undefined;
  const join = (...xs: (string | undefined)[]) => xs.filter(Boolean).join(" ") || undefined;
  const v = String(r.verdict ?? "").toLowerCase();
  switch (v) {
    case "safe":
      if (incomplete) {
        return {
          tone: "unknown",
          headline: "Not proved safe: part of this change couldn't be checked",
          sub: join(
            closesSub,
            "In the parts Paddock could model, it opens no route to a crown jewel and breaks none of the flows supplied. Read the warnings before approving.",
          ),
        };
      }
      return {
        tone: "safe",
        headline: "This change looks safe",
        sub: join(closesSub, "It opens no route to a crown jewel and breaks none of the flows supplied."),
      };
    case "opens_route_to_crown_jewel":
      return { tone: "opens", headline: `This change ${opens}`, sub: join(closesSub, partial) };
    case "breaks_live_flows":
      return {
        tone: "breaks",
        headline: denied.length ? `This change ${breaks}` : "This change breaks live flows",
        sub: join(closesSub, partial),
      };
    case "opens_and_breaks":
      return {
        tone: "both",
        headline: `This change ${opens} and ${denied.length ? breaks : "breaks live flows"}`,
        sub: join(closesSub, partial),
      };
    default:
      return {
        tone: "unknown",
        headline: `Needs review: the gate answered "${r.verdict || "nothing"}"`,
        sub: join("This console doesn't recognise that verdict, so it isn't read as safe.", closesSub, partial),
      };
  }
}

export const FLOW_FORMATS: { value: string; label: string }[] = [
  { value: "auto", label: "Detect automatically" },
  { value: "generic", label: "Generic JSON / JSONL" },
  { value: "zeek", label: "Zeek conn.log" },
  { value: "firewall", label: "Firewall allow/deny log" },
];

export const CONFIG_VENDORS: { value: string; label: string }[] = [
  { value: "paloalto", label: "Palo Alto (PAN-OS set format)" },
  { value: "fortinet", label: "Fortinet (FortiGate config)" },
  { value: "cisco_asa", label: "Cisco ASA (running-config)" },
  { value: "aws", label: "AWS (security groups / NACLs JSON)" },
];
