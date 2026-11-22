import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import HorseMark from "../brand/HorseMark";
import Wordmark from "../brand/Wordmark";
import { ApiError } from "../api/client";
import { errorDetail, viewTrust, type Grade, type TrustView } from "../api/growth";
import "../styles/check.css";

/**
 * /trust/:token — the shareable posture page for insurers and customers.
 * Public. It renders only what the API returns: aggregates for the sections
 * the sender chose. There is no host, address, asset or finding on this page
 * because the API never sends one.
 */

const SEV_ORDER = ["critical", "high", "medium", "low"] as const;
const SEV_COLOR: Record<string, string> = {
  critical: "var(--sev-crit)", high: "var(--sev-high)", medium: "var(--sev-med)", low: "var(--sev-low)",
};
const STATUS_COLOR: Record<string, string> = {
  satisfied: "var(--ok)", partial: "var(--warn)", gap: "var(--bad)", requires_attestation: "var(--text-3)",
};
const STATUS_LABEL: Record<string, string> = {
  satisfied: "Satisfied", partial: "Partial", gap: "Gap", requires_attestation: "Attestation",
};
const GRADE_TONE: Record<Grade, string> = {
  A: "var(--ok)", B: "var(--ok)", C: "var(--warn)", D: "var(--sev-high)", F: "var(--sev-crit)",
};

export function fmtHours(h: number | null | undefined): string {
  if (h == null) return "n/a";
  if (h < 1) return `${Math.round(h * 60)} min`;
  if (h < 48) return `${Math.round(h * 10) / 10} h`;
  return `${Math.round((h / 24) * 10) / 10} days`;
}
const pct = (v: number | null | undefined) => (v == null ? "n/a" : `${Math.round(v)}%`);
const fmtDate = (iso: string) =>
  new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });

function Shell({ children, title }: { children: ReactNode; title?: string }) {
  useEffect(() => {
    document.title = title ? `${title} · Security posture` : "Security posture";
    // Shared links must not be indexed.
    const m = document.createElement("meta");
    m.name = "robots";
    m.content = "noindex, nofollow";
    document.head.appendChild(m);
    return () => { m.remove(); };
  }, [title]);
  return (
    <div className="ck">
      <nav className="ck-nav">
        <span className="ck-brand" aria-label="Paddock">
          <HorseMark size={28} />
          <Wordmark height={20} />
        </span>
      </nav>
      <main className="ck-main" style={{ width: "min(1040px, 100%)" }}>{children}</main>
      <footer className="ck-foot">
        <span>Aggregate figures only. No hostnames, addresses or findings are shared.</span>
        <Link to="/welcome">About Paddock</Link>
      </footer>
    </div>
  );
}

function SevBars({ counts }: { counts: Record<string, number> }) {
  const max = Math.max(1, ...SEV_ORDER.map((s) => counts[s] ?? 0));
  return (
    <div className="tp-bars" aria-label="Open findings by severity">
      {SEV_ORDER.map((s) => (
        <div className="tp-bar" key={s}>
          <span style={{ textTransform: "capitalize" }}>{s}</span>
          <span className="track"><span className="fill" style={{ width: `${((counts[s] ?? 0) / max) * 100}%`, background: SEV_COLOR[s] }} /></span>
          <span className="n">{counts[s] ?? 0}</span>
        </div>
      ))}
    </div>
  );
}

export function TrustBody({ v }: { v: TrustView }) {
  const d = v.data;
  return (
    <>
      <header className="ck-hero">
        <div className="ck-eyebrow">Security posture</div>
        <h1>{v.organization ?? "Security posture"}</h1>
        <p>
          Prepared {fmtDate(v.generated_at)} over the last {v.period_days} days. This link expires on{" "}
          {fmtDate(v.expires_at)}.
        </p>
      </header>

      <div className="tp-grid">
        {d.grade && (
          <section className="ck-card tp-card" aria-label="Security grade">
            <h2>Security grade</h2>
            <div className="tp-big" style={{ color: GRADE_TONE[d.grade.grade] }} aria-label={`Grade ${d.grade.grade}`}>
              {d.grade.grade}
              <span style={{ fontSize: 22, color: "var(--ck-ink-2)", marginLeft: 12 }}>{d.grade.score} / 100</span>
            </div>
            <div className="tp-sub">
              Exposure is {d.grade.trend} · {d.grade.open_critical_high} critical or high issue
              {d.grade.open_critical_high === 1 ? "" : "s"} open
            </div>
            <SevBars counts={d.grade.open_by_severity} />
          </section>
        )}

        {d.verified_fixes && (
          <section className="ck-card tp-card" aria-label="Verified fixes">
            <h2>Verified fixes</h2>
            <div className="tp-kv">
              <div><div className="v">{d.verified_fixes.fixed}</div><div className="k">Fixed</div></div>
              <div><div className="v">{d.verified_fixes.verified}</div><div className="k">Verified by re-scan</div></div>
              <div><div className="v">{d.verified_fixes.regressed}</div><div className="k">Came back</div></div>
              <div><div className="v">{fmtHours(d.verified_fixes.median_hours_to_fix)}</div><div className="k">Median time to fix</div></div>
            </div>
          </section>
        )}

        {d.sla && (
          <section className="ck-card tp-card wide" aria-label="SLA compliance">
            <h2>Remediation SLA compliance</h2>
            <div className="tp-big">{pct(d.sla.compliance_pct)}</div>
            <div className="tp-sub">
              {d.sla.met} fixed within policy · {d.sla.late} late · {d.sla.breached_open} open past due
            </div>
            <table className="tp-table" style={{ marginTop: 14 }}>
              <thead>
                <tr><th>Severity</th><th className="num">Target</th><th className="num">On time</th><th className="num">Late</th><th className="num">Compliance</th></tr>
              </thead>
              <tbody>
                {d.sla.by_severity.map((r) => (
                  <tr key={r.severity}>
                    <td style={{ textTransform: "capitalize" }}>{r.severity}</td>
                    <td className="num">{r.policy_hours ? fmtHours(r.policy_hours) : "n/a"}</td>
                    <td className="num">{r.met}</td>
                    <td className="num">{r.late + r.breached_open}</td>
                    <td className="num">{pct(r.compliance_pct)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}

        {d.compliance && (
          <section className="ck-card tp-card wide" aria-label="Compliance packs">
            <h2>Compliance pack summary</h2>
            {d.compliance.length === 0 && <p className="ck-muted">No frameworks configured.</p>}
            {d.compliance.map((f) => (
              <div key={f.id} style={{ marginBottom: 14 }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
                  <strong>{f.name} <span style={{ color: "var(--ck-ink-2)", fontWeight: 400 }}>{f.version}</span></strong>
                  <span className="ck-muted" style={{ margin: 0 }}>
                    {Object.entries(f.counts).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${STATUS_LABEL[k] ?? k}`).join(" · ")}
                  </span>
                </div>
                <div className="tp-meter" role="img" aria-label={`${f.name} control status`}>
                  {Object.entries(f.counts).filter(([, n]) => n > 0).map(([k, n]) => (
                    <span key={k} style={{ flexGrow: n, background: STATUS_COLOR[k] ?? "var(--text-3)" }} />
                  ))}
                </div>
              </div>
            ))}
          </section>
        )}

        {d.coverage && (
          <section className="ck-card tp-card wide" aria-label="Coverage">
            <h2>Coverage</h2>
            <div className="tp-kv">
              <div><div className="v">{d.coverage.assets_total}</div><div className="k">Assets monitored</div></div>
              <div><div className="v">{d.coverage.fleet_agents}</div><div className="k">Managed endpoints</div></div>
              <div><div className="v">{d.coverage.sbom_projects}</div><div className="k">Software inventories</div></div>
              <div><div className="v">{d.coverage.tls_graded}</div><div className="k">TLS endpoints graded</div></div>
            </div>
            <table className="tp-table" style={{ marginTop: 14 }}>
              <thead><tr><th>Asset type</th><th className="num">Total</th><th className="num">Seen in 7 days</th><th className="num">Stale</th></tr></thead>
              <tbody>
                {d.coverage.by_kind.map((k) => (
                  <tr key={k.kind}><td>{k.kind}</td><td className="num">{k.total}</td><td className="num">{k.seen_7d}</td><td className="num">{k.stale}</td></tr>
                ))}
              </tbody>
            </table>
            {d.coverage.last_completed_scan && (
              <div className="tp-sub">Last completed scan {fmtDate(d.coverage.last_completed_scan)}</div>
            )}
          </section>
        )}
      </div>
    </>
  );
}

type Phase =
  | { k: "loading" }
  | { k: "ready"; view: TrustView }
  | { k: "locked"; wrong: boolean }
  | { k: "gone" }
  | { k: "throttled" }
  | { k: "error" };

export default function Trust() {
  const { token = "" } = useParams();
  const [phase, setPhase] = useState<Phase>({ k: "loading" });
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);

  async function load(password?: string) {
    setBusy(true);
    try {
      const view = await viewTrust(token, password);
      setPhase({ k: "ready", view });
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setPhase({ k: "locked", wrong: errorDetail(e).code === "password_incorrect" });
      } else if (e instanceof ApiError && e.status === 404) {
        setPhase({ k: "gone" });
      } else if (e instanceof ApiError && e.status === 429) {
        setPhase({ k: "throttled" });
      } else {
        setPhase({ k: "error" });
      }
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  function unlock(e: FormEvent) {
    e.preventDefault();
    if (pw && !busy) void load(pw);
  }

  if (phase.k === "ready") {
    return (
      <Shell title={phase.view.organization ?? undefined}>
        <TrustBody v={phase.view} />
      </Shell>
    );
  }
  return (
    <Shell>
      {phase.k === "loading" && <div className="ck-card tp-lock" role="status">Loading…</div>}
      {phase.k === "locked" && (
        <div className="ck-card tp-lock">
          <div className="ck-eyebrow">Protected</div>
          <p>This page is protected. Enter the password you were given.</p>
          <form onSubmit={unlock} aria-label="Unlock">
            <label htmlFor="tp-pw" className="sr">Password</label>
            <input id="tp-pw" type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="off" autoFocus />
            {phase.wrong && <div className="ck-error" role="alert">That password is not correct.</div>}
            <button className="ck-btn" type="submit" disabled={busy || !pw}>{busy ? "Checking…" : "View"}</button>
          </form>
        </div>
      )}
      {phase.k === "gone" && (
        <div className="ck-card tp-lock" role="alert">
          <div className="ck-eyebrow">Unavailable</div>
          <p>This link is no longer available. It may have expired or been withdrawn. Ask the sender for a new one.</p>
        </div>
      )}
      {phase.k === "throttled" && (
        <div className="ck-card tp-lock" role="alert"><p>Too many attempts. Please try again in a few minutes.</p></div>
      )}
      {phase.k === "error" && (
        <div className="ck-card tp-lock" role="alert"><p>Something went wrong loading this page. Please try again.</p></div>
      )}
    </Shell>
  );
}
