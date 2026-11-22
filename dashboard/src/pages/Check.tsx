import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import HorseMark from "../brand/HorseMark";
import Wordmark from "../brand/Wordmark";
import PixelField from "../brand/PixelField";
import { useAuth } from "../state/auth";
import { ApiError } from "../api/client";
import {
  errorDetail,
  getExposure,
  submitExposure,
  type ExposureReport,
  type ExposureSummary,
  type Sev,
} from "../api/growth";
import "../styles/check.css";

/**
 * /check — the free exposure check. Public, unauthenticated, passive: it only
 * ever reads DNS and certificate-transparency data about the domain, and says
 * so. Result = a graded summary plus a teaser; the full report is the CTA.
 */

/** Forgive what people paste: URLs, www., ports, trailing dots. The server re-validates strictly. */
export function normalizeDomain(raw: string): string {
  let s = raw.trim().toLowerCase();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  s = s.replace(/^[^@/]*@/, "");
  s = s.split(/[/?#]/)[0] ?? "";
  s = s.replace(/:\d+$/, "").replace(/\.$/, "");
  if (s.startsWith("www.")) s = s.slice(4);
  return s;
}

const REASONS: Record<string, string> = {
  ip_literal: "That is an IP address. Enter a domain name such as example.com.",
  internal_name: "That looks like an internal name. Only public domains can be checked.",
  not_registrable: "Enter the main domain (for example example.com), not a sub-domain.",
  public_suffix: "That is a public suffix, not a company domain.",
  invalid_chars: "Enter just the domain, such as example.com.",
  invalid_idn: "That is not a valid domain name.",
  too_long: "That domain name is too long.",
  empty: "Enter a domain such as example.com.",
  invalid: "That does not look like a valid domain name.",
  captcha_failed: "We could not verify you are human. Please try again.",
  invalid_email: "That email address does not look right.",
};

export function describeError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 429) {
      const ra = (e as ApiError & { retryAfter?: number }).retryAfter;
      const mins = ra ? Math.max(1, Math.ceil(ra / 60)) : null;
      return `Too many checks right now${mins ? `. Please try again in about ${mins} minute${mins > 1 ? "s" : ""}` : ""}.`;
    }
    if (e.status === 503) return "The check is busy. Please try again in a minute.";
    const d = errorDetail(e);
    if (d.code && REASONS[d.code]) return REASONS[d.code];
    if (d.message) return d.message;
    if (e.status === 0) return "Could not reach the server.";
  }
  return "Something went wrong. Please try again.";
}

const SEV_LABEL: Record<Sev, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const CHECK_LABEL = { pass: "Looks good", warn: "Needs attention", fail: "Action needed", unknown: "Not checked" } as const;

function Grade({ s }: { s: ExposureSummary }) {
  return (
    <section className={`ck-card ck-grade g-${s.grade}`} aria-label="Exposure grade">
      <div className="ck-letter" aria-label={`Grade ${s.grade}`}>{s.grade}</div>
      <div className="ck-grade-body">
        <div className="ck-eyebrow">Exposure grade</div>
        <div className="ck-score"><b>{s.score}</b><span>/ 100</span></div>
        <ul className="ck-reasons">
          {s.reasons.map((r) => <li key={r}>{r}</li>)}
        </ul>
      </div>
    </section>
  );
}

function Result({ r }: { r: ExposureReport }) {
  const s = r.summary!;
  const t = r.teaser!;
  const email = s.email;
  return (
    <div className="ck-result" data-testid="check-result">
      <Grade s={s} />

      <section className="ck-card" aria-label="Scorecard">
        <div className="ck-eyebrow">What we looked at</div>
        <ul className="ck-checks">
          {s.checks.map((c) => (
            <li key={c.key} className={`st-${c.status}`}>
              <i aria-hidden="true" />
              <span>{c.label}</span>
              <em>{CHECK_LABEL[c.status]}</em>
            </li>
          ))}
        </ul>
      </section>

      <section className="ck-stats" aria-label="Surface">
        {[
          ["Sub-domains found", s.stats.subdomains],
          ["Hosts answering", s.stats.live_hosts],
          ["Valid certificates", s.stats.certificates_valid],
          ["Nameservers", s.stats.nameservers],
        ].map(([k, v]) => (
          <div key={k as string} className="ck-stat">
            <div className="v">{v}</div>
            <div className="k">{k}</div>
          </div>
        ))}
      </section>

      <section className="ck-card" aria-label="Email protection">
        <div className="ck-eyebrow">Email protection</div>
        <div className="ck-chips">
          <span className={`chip ${email.spf === "fail" ? "ok" : "bad"}`}>SPF {email.spf === "fail" ? "strict" : email.spf.replace("_", " ")}</span>
          <span className={`chip ${email.dmarc === "reject" || email.dmarc === "quarantine" ? "ok" : "bad"}`}>DMARC {email.dmarc}</span>
          <span className={`chip ${email.dkim_found ? "ok" : "mute"}`}>DKIM {email.dkim_found ? "found" : "not seen"}</span>
          <span className={`chip ${email.mta_sts ? "ok" : "mute"}`}>MTA-STS {email.mta_sts ? "on" : "off"}</span>
        </div>
      </section>

      <section className="ck-card" aria-label="Findings preview">
        <div className="ck-eyebrow">
          {s.findings_total} finding{s.findings_total === 1 ? "" : "s"}
        </div>
        {t.shown.length === 0 ? (
          <p className="ck-muted">Nothing to report from public data. Nice work.</p>
        ) : (
          <ul className="ck-findings">
            {t.shown.map((f, i) => (
              <li key={i}>
                <span className={`sev sev-${f.severity}`}>{SEV_LABEL[f.severity]}</span>
                <span className="t">{f.title}</span>
                {f.host && <code>{f.host}</code>}
                {f.confidence === "possible" && <em>possible</em>}
              </li>
            ))}
            {Array.from({ length: Math.min(t.hidden, 3) }).map((_, i) => (
              <li key={`h${i}`} className="locked" aria-hidden="true">
                <span className="sev sev-info">Hidden</span>
                <span className="bar" />
              </li>
            ))}
          </ul>
        )}
        {t.hidden > 0 && <p className="ck-muted">+ {t.hidden} more in the full report.</p>}
      </section>

      <section className="ck-cta" aria-label="Next step">
        <p>{r.cta?.text}</p>
        <Link className="ck-btn" to={r.cta?.url ?? "/welcome"}>Get the full report <span aria-hidden="true">→</span></Link>
      </section>

      <p className="ck-notice">{r.passive_notice}</p>
    </div>
  );
}

const STEPS = [
  "Reading certificate-transparency logs",
  "Looking up DNS records",
  "Checking email authentication",
  "Grading what we found",
];

function Working({ status }: { status: string }) {
  const [i, setI] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setI((n) => Math.min(n + 1, STEPS.length - 1)), 2200);
    return () => clearInterval(t);
  }, []);
  return (
    <div className="ck-card ck-working" role="status" aria-live="polite">
      <div className="ck-eyebrow">{status === "queued" ? "In the queue" : "Checking"}</div>
      <ul>
        {STEPS.map((s, n) => (
          <li key={s} className={n < i ? "done" : n === i ? "now" : ""}>{s}</li>
        ))}
      </ul>
      <p className="ck-muted">This usually takes under a minute.</p>
    </div>
  );
}

const MAX_POLL_MS = 4 * 60 * 1000;

export default function Check() {
  const token = useAuth((s) => s.token);
  const [params, setParams] = useSearchParams();
  const id = params.get("id");
  const [domain, setDomain] = useState(params.get("domain") ?? "");
  const [email, setEmail] = useState("");
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(Date.now());

  useEffect(() => {
    started.current = Date.now();
  }, [id]);

  const q = useQuery({
    queryKey: ["exposure-report", id],
    queryFn: () => getExposure(id!),
    enabled: !!id,
    retry: false,
    refetchInterval: (query) => {
      const d = query.state.data;
      if (!d || d.status === "queued" || d.status === "running") {
        return Date.now() - started.current < MAX_POLL_MS ? 2000 : false;
      }
      return false;
    },
  });
  const report = q.data;
  const timedOut = !!id && !report && q.isError;

  useEffect(() => {
    document.title = "Free exposure check · Paddock";
  }, []);

  const normalized = useMemo(() => normalizeDomain(domain), [domain]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setError(null);
    if (!normalized) {
      setError(REASONS.empty);
      return;
    }
    setBusy(true);
    try {
      const res = await submitExposure({
        domain: normalized,
        ...(email.trim() ? { email: email.trim(), consent } : {}),
      });
      setDomain(res.domain);
      setParams({ id: res.id });
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  const working = !!id && (!report || report.status === "queued" || report.status === "running") && !q.isError;

  return (
    <div className="ck">
      <div className="ck-sky" aria-hidden="true">
        <PixelField className="ck-pixels" cell={6} maxDpr={1} animate={false} />
      </div>

      <nav className="ck-nav">
        <Link to="/welcome" className="ck-brand" aria-label="Paddock home">
          <HorseMark size={28} />
          <Wordmark height={20} />
        </Link>
        <Link to={token ? "/" : "/login"} className="ck-signin">
          {token ? "Open console" : "Sign in"} <span aria-hidden="true">→</span>
        </Link>
      </nav>

      <main className="ck-main">
        <header className="ck-hero">
          <div className="ck-eyebrow">Free exposure check</div>
          <h1>How exposed is your domain?</h1>
          <p>
            A passive look from the outside: certificate logs, DNS and email records. We never
            send a single packet to your servers.
          </p>
        </header>

        <form className="ck-form" onSubmit={submit} aria-label="Check a domain">
          <div className="row">
            <label htmlFor="ck-domain" className="sr">Domain</label>
            <input
              id="ck-domain"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="yourcompany.com"
              inputMode="url"
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              maxLength={300}
              aria-invalid={!!error}
            />
            <button className="ck-btn" type="submit" disabled={busy}>
              {busy ? "Starting…" : "Check my domain"}
            </button>
          </div>
          <details className="ck-opt">
            <summary>Email me when anything changes (optional)</summary>
            <div className="opt-body">
              <label htmlFor="ck-email" className="sr">Email</label>
              <input
                id="ck-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@yourcompany.com"
                autoComplete="email"
                maxLength={254}
              />
              <label className="consent">
                <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
                <span>
                  I agree to be contacted about this report. Without this box ticked we do not store
                  your email.
                </span>
              </label>
            </div>
          </details>
          {error && <div className="ck-error" role="alert">{error}</div>}
        </form>

        {working && <Working status={report?.status ?? "queued"} />}

        {timedOut && (
          <div className="ck-card" role="alert">
            <p>We could not load that report. It may have expired. Run the check again.</p>
          </div>
        )}

        {report?.status === "failed" && (
          <div className="ck-card" role="alert">
            <div className="ck-eyebrow">No result</div>
            <p>
              {report.error === "domain_not_found"
                ? `We could not find ${report.domain} in public DNS. Check the spelling and try again.`
                : "The check could not finish. Please try again in a few minutes."}
            </p>
          </div>
        )}

        {report?.status === "done" && report.summary && report.teaser && (
          <>
            <h2 className="ck-domain">{report.domain}</h2>
            <Result r={report} />
          </>
        )}
      </main>

      <footer className="ck-foot">
        <span>Passive checks only. Public DNS and certificate-transparency data.</span>
        <Link to="/welcome">About Paddock</Link>
      </footer>
    </div>
  );
}
