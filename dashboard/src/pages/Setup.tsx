/**
 * First-run wizard (/setup).
 *
 *   workspace → domain → prove ownership → passive discovery → first results
 *   → invite a teammate / connect Slack → done
 *
 * Progress lives server-side (GET/PUT /v1/onboarding, schema 021) so it
 * survives reloads and other admins see the same state. Shown automatically
 * to an admin while the workspace has no verified scope (FirstRunRedirect),
 * and always skippable.
 *
 * Proof-of-control is the legal gate for scanning: the domain step creates a
 * scope entry, the verify step shows the exact DNS TXT / HTTPS file values and
 * checks them live. Nothing is scanned until the orchestrator says the entry
 * is proven (when REQUIRE_SCOPE_PROOF is on).
 */

import PixelField from "../brand/PixelField";
import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import HorseMark from "../brand/HorseMark";
import { ApiError } from "../api/client";
import {
  addScope,
  createInviteKey,
  getOnboarding,
  getServices,
  issueChallenge,
  putOnboarding,
  startScan,
  verifyScope,
  type Challenge,
  type Onboarding,
  type OnboardingPatch,
  type ProofStatus,
  type VerifyResult,
  type WizardStep,
} from "../api/onboarding";
import { useAuth } from "../state/auth";
import "../styles/setup.css";

const STEPS: { id: WizardStep; label: string; hint: string }[] = [
  { id: "workspace", label: "Name your workspace", hint: "What your team calls this" },
  { id: "domain", label: "Add your domain", hint: "The surface you defend" },
  { id: "verify", label: "Prove ownership", hint: "DNS TXT or HTTPS file" },
  { id: "scan", label: "First discovery", hint: "Passive, no packets to you" },
  { id: "results", label: "First results", hint: "Live as they land" },
  { id: "team", label: "Bring your team", hint: "Teammate · Slack" },
  { id: "done", label: "Done", hint: "" },
];

const PASSIVE_KIND = "passive_full";

function errText(e: unknown): string {
  if (e instanceof ApiError) {
    const b = e.body as { detail?: unknown } | undefined;
    const d = b && typeof b === "object" ? b.detail : undefined;
    if (typeof d === "string") return d;
    if (d && typeof d === "object" && "reason" in (d as Record<string, unknown>)) {
      return String((d as Record<string, unknown>).reason);
    }
    return e.message;
  }
  return e instanceof Error ? e.message : String(e);
}

/* ------------------------------------------------------------------ */
/* Small pieces                                                        */
/* ------------------------------------------------------------------ */

export function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard blocked (http / permissions): the value is selectable */
    }
  }
  return (
    <div className="setup-copy">
      <span className="setup-copy-label">{label}</span>
      <code className="setup-copy-value mono" title={value}>{value}</code>
      <button type="button" className="setup-copy-btn" onClick={copy} aria-label={`Copy ${label}`}>
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

const STATUS_TEXT: Record<ProofStatus, string> = {
  pending: "Waiting for proof",
  verified: "Verified",
  attested: "Attested",
  expired: "Proof expired",
};

function ProofPill({ status }: { status: ProofStatus }) {
  return (
    <span className={`setup-pill setup-pill-${status}`} data-testid="proof-status">
      <span className="setup-pill-dot" aria-hidden="true" />
      {STATUS_TEXT[status]}
    </span>
  );
}

function StepShell({ title, lede, children }: { title: string; lede?: ReactNode; children: ReactNode }) {
  return (
    <section className="setup-step" aria-labelledby="setup-step-title">
      <h1 id="setup-step-title" className="setup-title">{title}</h1>
      {lede && <p className="setup-lede">{lede}</p>}
      <div className="setup-body">{children}</div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Steps                                                               */
/* ------------------------------------------------------------------ */

interface StepProps {
  ob: Onboarding;
  save: (patch: OnboardingPatch) => Promise<void>;
}

function WorkspaceStep({ ob, save }: StepProps) {
  const [name, setName] = useState(ob.workspace_name ?? "");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    try {
      await save({ workspace_name: name.trim(), step_done: "workspace", current_step: "domain" });
    } finally {
      setBusy(false);
    }
  }
  return (
    <StepShell title="Name your workspace" lede="This is how Paddock refers to your organisation in reports and alerts.">
      <form onSubmit={submit} className="setup-form">
        <label className="setup-label" htmlFor="setup-ws">Workspace name</label>
        <input id="setup-ws" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Security" maxLength={120} />
        <div className="setup-actions">
          <button type="submit" className="primary" disabled={busy || !name.trim()}>Continue</button>
        </div>
      </form>
    </StepShell>
  );
}

function DomainStep({ ob, save }: StepProps) {
  const user = useAuth((s) => s.user);
  const existing = ob.scope_entry;
  const [domain, setDomain] = useState(existing?.value ?? pendingDomain());
  const [wildcard, setWildcard] = useState(existing ? existing.kind === "subdomain_wildcard" : true);
  const [authRef, setAuthRef] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const value = domain.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
    if (!value) return;
    setBusy(true);
    setError(null);
    try {
      const entry = await addScope({
        kind: wildcard ? "subdomain_wildcard" : "domain",
        value,
        added_by: user?.username ?? "admin",
        auth_doc_ref: authRef.trim() || "first-run wizard: owner of the domain",
      });
      await save({ scope_entry_id: entry.id, step_done: "domain", current_step: "verify" });
    } catch (err) {
      setError(errText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <StepShell
      title="Add your domain"
      lede="Start with the registrable domain you own. Paddock will only ever look at what is in scope."
    >
      <form onSubmit={submit} className="setup-form">
        <label className="setup-label" htmlFor="setup-domain">Domain</label>
        <input id="setup-domain" autoFocus className="mono" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" spellCheck={false} />
        <label className="setup-check">
          <input type="checkbox" checked={wildcard} onChange={(e) => setWildcard(e.target.checked)} />
          <span>
            Include every subdomain
            <span className="setup-muted"> — discovery finds hosts under it; proven via DNS TXT</span>
          </span>
        </label>
        <label className="setup-label" htmlFor="setup-auth">Authorization note <span className="setup-muted">(optional)</span></label>
        <input id="setup-auth" value={authRef} onChange={(e) => setAuthRef(e.target.value)} placeholder="e.g. we own this domain — ticket SEC-142" />
        {error && <div className="setup-error" role="alert">{error}</div>}
        <div className="setup-actions">
          <button type="submit" className="primary" disabled={busy || !domain.trim()}>
            {busy ? "Adding…" : "Add domain"}
          </button>
        </div>
      </form>
    </StepShell>
  );
}

function VerifyStep({ ob, save }: StepProps) {
  const entry = ob.scope_entry;
  const qc = useQueryClient();
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [method, setMethod] = useState<"dns_txt" | "http_file">("dns_txt");
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [auto, setAuto] = useState(true);
  const status: ProofStatus = result?.proof.status ?? entry?.proof.status ?? "pending";
  const proven = status === "verified" || status === "attested";
  const checkingRef = useRef(false);

  useEffect(() => {
    if (!entry) return;
    let live = true;
    issueChallenge(entry.id)
      .then((c) => live && setChallenge(c))
      .catch((e) => live && setError(errText(e)));
    return () => {
      live = false;
    };
  }, [entry?.id]);

  async function checkNow(m?: "dns_txt" | "http_file") {
    if (!entry || checkingRef.current) return;
    checkingRef.current = true;
    setChecking(true);
    setError(null);
    try {
      const r = await verifyScope(entry.id, m ? { method: m } : {});
      setResult(r);
      qc.invalidateQueries({ queryKey: ["onboarding"] });
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 429)) setError(errText(e));
    } finally {
      checkingRef.current = false;
      setChecking(false);
    }
  }

  // "Live" check: while waiting, re-check every 30s (one TXT lookup each).
  useEffect(() => {
    if (!auto || proven || !challenge) return;
    const t = window.setInterval(() => void checkNow(), 30_000);
    return () => window.clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, proven, challenge?.token]);

  if (!entry) {
    return (
      <StepShell title="Prove ownership">
        <p className="setup-muted">Add a domain first.</p>
        <button type="button" onClick={() => save({ current_step: "domain" })}>Back</button>
      </StepShell>
    );
  }

  const hasHttp = Boolean(challenge?.http_file);
  return (
    <StepShell
      title="Prove you control it"
      lede={
        <>
          Scanning is only legal against what you own. Publish <strong>one</strong> of these for{" "}
          <span className="mono">{entry.value}</span>, then check. Your record stays in place: Paddock
          re-checks it daily and pauses scanning if it disappears.
        </>
      }
    >
      <div className="setup-proof-head">
        <ProofPill status={status} />
        {!ob.require_scope_proof && !proven && (
          <span className="setup-muted">Proof isn’t enforced on this deployment, but it’s still recommended.</span>
        )}
      </div>

      {hasHttp && (
        <div className="setup-tabs" role="tablist">
          <button type="button" role="tab" aria-selected={method === "dns_txt"} className={method === "dns_txt" ? "on" : ""} onClick={() => setMethod("dns_txt")}>
            DNS TXT record
          </button>
          <button type="button" role="tab" aria-selected={method === "http_file"} className={method === "http_file" ? "on" : ""} onClick={() => setMethod("http_file")}>
            HTTPS file
          </button>
        </div>
      )}

      {!challenge && !error && <div className="setup-muted">Preparing your challenge…</div>}
      {challenge && method === "dns_txt" && (
        <div className="setup-record">
          <CopyField label="Type" value="TXT" />
          <CopyField label="Name" value={challenge.dns_txt.name} />
          <CopyField label="Value" value={challenge.dns_txt.value} />
          <p className="setup-muted">DNS changes can take a few minutes to propagate.</p>
        </div>
      )}
      {challenge && method === "http_file" && challenge.http_file && (
        <div className="setup-record">
          <CopyField label="URL" value={challenge.http_file.url} />
          <CopyField label="Body" value={challenge.http_file.body} />
          <p className="setup-muted">Serve it over HTTPS with status 200 and exactly this body. Redirects to another host are not followed.</p>
        </div>
      )}

      {result && (
        <div className={`setup-check-result ${result.check.ok ? "ok" : "bad"}`} role="status">
          {result.check.ok ? "✓ " : "✕ "}
          {result.check.detail}
        </div>
      )}
      {error && <div className="setup-error" role="alert">{error}</div>}

      <div className="setup-actions">
        {proven ? (
          <button type="button" className="primary" onClick={() => save({ step_done: "verify", current_step: "scan" })}>
            Continue
          </button>
        ) : (
          <>
            <button type="button" className="primary" disabled={checking || !challenge} onClick={() => checkNow(hasHttp ? method : undefined)}>
              {checking ? "Checking…" : "Check now"}
            </button>
            <label className="setup-check setup-inline">
              <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
              <span>Keep checking every 30s</span>
            </label>
            {!ob.require_scope_proof && (
              <button type="button" className="ghost" onClick={() => save({ current_step: "scan" })}>
                Skip for now
              </button>
            )}
          </>
        )}
      </div>
    </StepShell>
  );
}

function ScanStep({ ob, save }: StepProps) {
  const entry = ob.scope_entry;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const target = entry?.value ?? "";

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const scan = await startScan(PASSIVE_KIND, target);
      await save({ first_scan_id: scan.id, step_done: "scan", current_step: "results" });
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <StepShell
      title="Run your first discovery"
      lede={
        <>
          A <strong>passive</strong> sweep of <span className="mono">{target || "your domain"}</span>: certificate
          transparency logs, DNS and public archives. It reads public sources only — no packet is sent to
          your hosts.
        </>
      }
    >
      <ul className="setup-list">
        <li>Certificate transparency (crt.sh)</li>
        <li>DNS enumeration</li>
        <li>Web archives (Wayback)</li>
      </ul>
      {error && <div className="setup-error" role="alert">{error}</div>}
      <div className="setup-actions">
        <button type="button" className="primary" disabled={busy || !target} onClick={run}>
          {busy ? "Starting…" : "Start passive discovery"}
        </button>
        <button type="button" className="ghost" onClick={() => save({ current_step: "verify" })}>Back</button>
      </div>
    </StepShell>
  );
}

const SCAN_LABEL: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

function ResultsStep({ ob, save }: StepProps) {
  const scan = ob.first_scan;
  const running = !scan || scan.status === "queued" || scan.status === "running";
  return (
    <StepShell
      title="Your first results"
      lede={running ? "Results stream in as each source answers. This usually takes a minute or two." : "Here’s what Paddock found so far."}
    >
      <div className="setup-scan-row">
        <span className={`setup-pill setup-pill-scan-${scan?.status ?? "queued"}`}>
          <span className="setup-pill-dot" aria-hidden="true" />
          {scan ? SCAN_LABEL[scan.status] ?? scan.status : "No scan yet"}
        </span>
        {scan?.error && <span className="setup-muted">{scan.error}</span>}
      </div>
      <div className="setup-stats" aria-live="polite">
        <div className="setup-stat">
          <span className="setup-stat-value" data-testid="count-assets">{ob.counts.domain_assets}</span>
          <span className="setup-stat-label">assets discovered</span>
        </div>
        <div className="setup-stat">
          <span className="setup-stat-value" data-testid="count-findings">{ob.counts.domain_findings}</span>
          <span className="setup-stat-label">findings</span>
        </div>
      </div>
      <div className="setup-links">
        <Link to="/graph">Open the graph →</Link>
        <Link to="/findings">Review findings →</Link>
      </div>
      <div className="setup-actions">
        <button type="button" className="primary" onClick={() => save({ step_done: "results", current_step: "team" })}>
          Continue
        </button>
      </div>
    </StepShell>
  );
}

function TeamStep({ save }: StepProps) {
  const [name, setName] = useState("");
  const [key, setKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function invite(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const res = await createInviteKey(`invite: ${name.trim()}`);
      setKey(res.api_key);
    } catch (err) {
      setError(errText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <StepShell title="Bring your team" lede="Security is a team sport. Both are optional — you can do them later.">
      <div className="setup-cards">
        <form className="setup-card" onSubmit={invite}>
          <div className="setup-card-title">Invite a teammate</div>
          <p className="setup-muted">Creates a <strong>read-only</strong> access key they can sign in with. It is shown once.</p>
          {key ? (
            <CopyField label="Key" value={key} />
          ) : (
            <>
              <input aria-label="Teammate name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Teammate’s name" />
              <button type="submit" disabled={busy || !name.trim()}>{busy ? "Creating…" : "Create access key"}</button>
            </>
          )}
          {error && <div className="setup-error" role="alert">{error}</div>}
        </form>
        <div className="setup-card">
          <div className="setup-card-title">Connect Slack</div>
          <p className="setup-muted">Route new high-severity findings and proof expiries to a channel.</p>
          <Link className="setup-card-link" to="/integrations">Set up integrations →</Link>
        </div>
      </div>
      <div className="setup-actions">
        <button type="button" className="primary" onClick={() => save({ step_done: "team", current_step: "done" })}>
          Continue
        </button>
      </div>
    </StepShell>
  );
}

function DoneStep({ ob, save }: StepProps) {
  const nav = useNavigate();
  const services = useQuery({ queryKey: ["system-services"], queryFn: getServices, staleTime: 30_000 });
  const off = (services.data?.services ?? []).filter((s) => s.status !== "ok");
  async function finish() {
    await save({ completed: true, step_done: "done", current_step: "done" });
    nav("/");
  }
  return (
    <StepShell
      title={`${ob.workspace_name ?? "Your workspace"} is ready`}
      lede="Paddock keeps watching: proofs are re-checked daily and new assets appear as discovery finds them."
    >
      {services.data && off.length > 0 && (
        <div className="setup-services">
          <div className="setup-card-title">
            {services.data.mode === "lite" ? "Lite mode — not enabled on this node" : "Optional services not reachable"}
          </div>
          <ul>
            {off.map((s) => (
              <li key={s.name}>
                <span>{s.feature}</span>
                <span className="setup-muted mono">{s.status === "not_enabled" ? "not enabled" : "down"}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="setup-actions">
        <button type="button" className="primary" onClick={finish}>Go to overview</button>
      </div>
    </StepShell>
  );
}

const STEP_VIEWS: Record<WizardStep, (p: StepProps) => JSX.Element> = {
  workspace: WorkspaceStep,
  domain: DomainStep,
  verify: VerifyStep,
  scan: ScanStep,
  results: ResultsStep,
  team: TeamStep,
  done: DoneStep,
};

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

/** A domain typed into the landing page CTA, handed over through sessionStorage. */
function pendingDomain(): string {
  try { return sessionStorage.getItem("paddock.cta.domain") ?? ""; } catch { return ""; }
}

export default function Setup() {
  const qc = useQueryClient();
  const nav = useNavigate();
  const [view, setView] = useState<WizardStep | null>(null);
  const q = useQuery({
    queryKey: ["onboarding"],
    queryFn: getOnboarding,
    // Live counts while discovery runs.
    refetchInterval: (query) => {
      const d = query.state.data as Onboarding | undefined;
      return (view ?? d?.current_step) === "results" ? 3000 : false;
    },
  });
  const ob = q.data;
  const step: WizardStep = view ?? ob?.current_step ?? "workspace";
  const done = useMemo(() => new Set(ob?.steps_done ?? []), [ob?.steps_done]);

  async function save(patch: OnboardingPatch) {
    const next = await putOnboarding(patch);
    qc.setQueryData(["onboarding"], next);
    setView(null);
  }

  async function skip() {
    try {
      await putOnboarding({ dismissed: true });
    } catch {
      /* non-admins can't record it; leaving is still fine */
    }
    qc.invalidateQueries({ queryKey: ["onboarding"] });
    nav("/");
  }

  return (
    <div className="setup-screen">
      <PixelField className="setup-pixels" cell={5} animate={false} originX={0.1} />
      <header className="setup-top">
        <div className="setup-brand">
          <HorseMark size={24} />
          <span>Paddock</span>
          {ob?.deployment_mode === "lite" && <span className="setup-badge">lite</span>}
        </div>
        <button type="button" className="ghost setup-skip" onClick={skip}>Skip setup</button>
      </header>

      <div className="setup-frame">
        <nav className="setup-rail" aria-label="Setup steps">
          <ol>
            {STEPS.map((s, i) => {
              const isDone = done.has(s.id);
              const isOn = s.id === step;
              const reachable = isDone || isOn || STEPS.findIndex((x) => x.id === ob?.current_step) >= i;
              return (
                <li key={s.id} className={`setup-rail-item${isOn ? " on" : ""}${isDone ? " done" : ""}`}>
                  <button type="button" disabled={!reachable} onClick={() => setView(s.id)} aria-current={isOn ? "step" : undefined}>
                    <span className="setup-rail-num" aria-hidden="true">{isDone ? "✓" : i + 1}</span>
                    <span className="setup-rail-text">
                      <span className="setup-rail-label">{s.label}</span>
                      {s.hint && <span className="setup-rail-hint">{s.hint}</span>}
                    </span>
                  </button>
                </li>
              );
            })}
          </ol>
        </nav>

        <main className="setup-main">
          {q.isLoading && <div className="setup-muted">Loading…</div>}
          {q.isError && (
            <div className="setup-error" role="alert">Couldn’t load setup state: {errText(q.error)}</div>
          )}
          {ob && !ob.available && (
            <div className="setup-error" role="alert">
              Setup isn’t available: the database is missing schema 021 (apply schema/021_scope_proof.sql).
            </div>
          )}
          {ob && ob.available && (() => {
            const View = STEP_VIEWS[step];
            return <View key={step} ob={ob} save={save} />;
          })()}
        </main>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Auto-open for admins                                                */
/* ------------------------------------------------------------------ */

const REDIRECT_FLAG = "paddock.setup.redirected";

function alreadyRedirected(): boolean {
  try {
    return sessionStorage.getItem(REDIRECT_FLAG) === "1";
  } catch {
    return false;
  }
}

function markRedirected(): void {
  try {
    sessionStorage.setItem(REDIRECT_FLAG, "1");
  } catch {
    /* storage blocked: we may redirect again next load, which is harmless */
  }
}

/**
 * Sends an admin to /setup once per session while the workspace has no
 * verified scope (and setup wasn't completed or dismissed). Renders nothing.
 */
export function FirstRunRedirect() {
  const role = useAuth((s) => s.user?.role);
  const loc = useLocation();
  const nav = useNavigate();
  const isAdmin = role === "admin";
  const q = useQuery({
    queryKey: ["onboarding"],
    queryFn: getOnboarding,
    enabled: isAdmin,
    staleTime: 60_000,
    retry: false,
  });
  useEffect(() => {
    if (!isAdmin || !q.data?.needs_setup) return;
    if (loc.pathname === "/setup" || loc.pathname === "/welcome") return;
    if (alreadyRedirected()) return;
    markRedirected();
    nav("/setup");
  }, [isAdmin, q.data?.needs_setup, loc.pathname, nav]);
  return null;
}
