/**
 * Verified findings (schema 026): the exploitability verdict, the evidence the
 * safe check saw, the "Verify now" action and the verification ledger.
 *
 * Claims become proof: a finding is "unverified" until a non-destructive check
 * (GET/HEAD, TLS handshake, TCP connect) reproduces it, and "verified fixed"
 * once a re-check after the fix can no longer reproduce it.
 */

import { ApiError } from "../api/client";
import type { Exploitability, Verification } from "../api/verification";
import type { Finding } from "../api/types";
import { useVerifications, useVerifyFinding } from "../hooks/useVerification";
import Gate from "./Gate";
import "../styles/verification.css";

const LABEL: Record<Exploitability, string> = {
  unverified: "Unverified",
  confirmed: "Verified exploitable",
  not_reproducible: "Not reproducible",
  inconclusive: "Inconclusive",
};

const HINT: Record<Exploitability, string> = {
  unverified: "No safe check has reproduced this finding yet",
  confirmed: "A safe check reproduced this finding",
  not_reproducible: "A safe check could not reproduce this finding (it is not closed automatically)",
  inconclusive: "A safe check could not decide (target unreachable, blocked or ambiguous)",
};

export function ExploitabilityBadge({ value }: { value?: Exploitability | null }) {
  const v: Exploitability = value ?? "unverified";
  return (
    <span className="xbadge" data-state={v} title={HINT[v]}>
      {LABEL[v]}
    </span>
  );
}

export function VerifiedFixedBadge({ at }: { at?: string | null }) {
  if (!at) return null;
  return (
    <span className="xbadge" data-state="verified_fixed" title={`Re-checked after the fix on ${at.slice(0, 16).replace("T", " ")} UTC: no longer reproducible`}>
      Verified fixed
    </span>
  );
}

function day(ts?: string | null): string {
  return ts ? ts.slice(0, 16).replace("T", " ") : "";
}

/** Short, already-redacted, size-capped evidence lines from the worker. */
export function evidenceLines(ev: Record<string, unknown> | undefined): [string, string][] {
  if (!ev) return [];
  const order = ["url", "final_url", "host", "port", "status", "http_status", "state", "service",
    "not_after", "days_remaining", "negotiated_by_default", "negotiated", "title", "banner", "excerpt"];
  const keys = [...order.filter((k) => k in ev), ...Object.keys(ev).filter((k) => !order.includes(k))];
  return keys.slice(0, 8).map((k) => {
    const v = ev[k];
    const s = typeof v === "string" ? v : JSON.stringify(v);
    return [k, (s ?? "").slice(0, 240)] as [string, string];
  });
}

function outcomeText(v: Verification): string {
  if (v.status === "done" && v.verdict) return LABEL[v.verdict];
  if (v.status === "scheduled") return "scheduled";
  if (v.status === "queued") return "running";
  return v.status;
}

function refusalReason(e: unknown): string | null {
  if (!e) return null;
  if (e instanceof ApiError) {
    const d = (e.body as { detail?: unknown } | null)?.detail;
    if (d && typeof d === "object" && "reason" in d) return String((d as { reason: unknown }).reason);
    if (typeof d === "string") return d;
    if (e.status === 403) return "Your role can't run verification.";
  }
  return "Could not queue the check.";
}

export default function VerificationPanel({ finding }: { finding: Finding }) {
  const hist = useVerifications(finding.id);
  const verify = useVerifyFinding();
  const items = hist.data?.items ?? [];
  const inFlight = items.some((v) => v.status === "scheduled" || v.status === "queued");
  const latestDone = items.find((v) => v.status === "done");
  const state: Exploitability = (hist.data?.exploitability ?? finding.exploitability ?? "unverified") as Exploitability;
  const lastAt = hist.data?.last_verified_at ?? finding.last_verified_at;
  const fixedAt = hist.data?.fix_verified_at ?? finding.fix_verified_at;
  const lines = evidenceLines(latestDone?.evidence);
  const refusal = refusalReason(verify.error);
  const isFixed = finding.status === "fixed";

  return (
    <div className="section vpanel" data-testid="verification-panel">
      <h3>Verification</h3>
      <div className="vhead">
        <ExploitabilityBadge value={state} />
        <VerifiedFixedBadge at={fixedAt} />
        {lastAt && <span className="when">checked {day(lastAt)} UTC</span>}
      </div>

      {latestDone && (
        <>
          {latestDone.reason && <div className="vnote" style={{ marginTop: 6 }}>{latestDone.reason}</div>}
          {lines.length > 0 && (
            <div className="vevidence" aria-label="evidence excerpt">
              {lines.map(([k, v]) => (
                <div key={k}><span className="k">{k}</span> {v}</div>
              ))}
            </div>
          )}
        </>
      )}

      <Gate need="triage" title="Read-only — your role can't run verification">
        <div className="vactions">
          <button
            disabled={verify.isPending || inFlight}
            onClick={() => verify.mutate(finding.id)}
            title="Runs a non-destructive check (GET/HEAD, TLS handshake or TCP connect) against the target"
          >
            {inFlight ? "Checking…" : isFixed ? "Verify fix now" : "Verify now"}
          </button>
          <span className="vnote">non-destructive · scope and proof-of-control enforced</span>
        </div>
      </Gate>
      {refusal && <div className="vnote" data-tone="bad" role="alert" style={{ marginTop: 6 }}>{refusal}</div>}

      {items.length > 0 && (
        <ul className="vhist" aria-label="verification history">
          {items.slice(0, 8).map((v) => (
            <li key={v.id} data-status={v.status}>
              <span className="t">{day(v.requested_at)}</span>
              <span className="r" title={v.reason ?? undefined}>
                {v.purpose === "fix" ? "fix check" : "check"} · {v.check_id ?? v.trigger}
                {v.reason ? ` — ${v.reason}` : ""}
              </span>
              <span className="xbadge" data-state={v.verdict ?? (v.status === "done" ? "unverified" : "inconclusive")}>
                {outcomeText(v)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
