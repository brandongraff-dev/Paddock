/**
 * Wargame: "can anyone reach what you care about, and is the door shut?"
 *
 * Works backward from crown jewels (docs/WARGAME.md §2). One page:
 *   1. scorecard: closure tiles + the engine's board line (coverage caveat
 *      included, verbatim; closure is never shown without it);
 *   2. routes: entry → … → crown jewel, every hop labelled on the evidence
 *      ladder; weak evidence is drawn dashed / dotted, never like proof;
 *   3. the cheapest fix set, and any routes it can't cut;
 *   4. boundary verdicts and signed closed-boundary certificates;
 *   5. the change gate (what a plan would open or break);
 *   6. an empty state that walks a new tenant through loading config.
 *
 * Sample mode (?sample=1) renders a fictional estate, clearly labelled. It is
 * opt-in only and never stands in for a failed or empty API response.
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import StatTile from "../components/StatTile";
import EmptyState from "../components/EmptyState";
import ChangeGate from "../components/wargame/ChangeGate";
import TwinSetup from "../components/wargame/TwinSetup";
import { EvidenceChip, EvidenceLegend, RouteStrip, Tip, ToneChip, VerdictChip } from "../components/wargame/parts";
import { ApiError } from "../api/client";
import {
  getWargameFixSet,
  getWargameTwin,
  listWargameAssessments,
  listWargameBoundaries,
  listWargameCertificates,
  listWargameRoutes,
  recomputeWargame,
} from "../api/wargame";
import type {
  WargameAssessment,
  WargameBoundary,
  WargameCertificate,
  WargameFixSet,
  WargameRoute,
} from "../api/types";
import {
  EVIDENCE_LADDER,
  assumptionText,
  certStatusMeta,
  cuttingFixes,
  evidenceMeta,
  relativeTime,
  routeFixIds,
  routeStrengthSentence,
  uncutRoutes,
  verdictMeta,
  verdictRank,
} from "../lib/wargame";
import { buildWargameSample } from "../lib/wargameSample";
import { useStore } from "../state/store";
import "../styles/wargame.css";

const ROUTE_LIMIT = 500;

function fmtPct(x: number): string {
  const s = (Math.round(x * 10) / 10).toFixed(1);
  return s.endsWith(".0") ? s.slice(0, -2) : s;
}

function errStatus(e: unknown): string {
  if (e instanceof ApiError) return e.status ? `HTTP ${e.status}` : "network error";
  return "error";
}

function short(h: string, n = 12): string {
  const s = String(h);
  const i = s.indexOf(":");
  const body = i >= 0 && i < 10 ? s.slice(i + 1) : s;
  return body.length > n ? `${body.slice(0, n)}…` : body;
}

/* ------------------------------------------------------------------ */
/* 1. Scorecard                                                        */
/* ------------------------------------------------------------------ */

function Scorecard({ a }: { a: WargameAssessment }) {
  const coverage = a.coverage_pct == null ? "coverage not yet measured" : `model explains ${fmtPct(a.coverage_pct)}% of traffic`;
  const fcr =
    a.false_closed_rate == null
      ? "not yet evaluated"
      : `${fmtPct(a.false_closed_rate <= 1 ? a.false_closed_rate * 100 : a.false_closed_rate)}%`;
  const blind = (a.blind_spots ?? []).map((b) => (typeof b === "string" ? b : JSON.stringify(b)));
  return (
    <>
      <div className="stat-row wg-stats" role="group" aria-label="Crown-jewel closure">
        <StatTile label="Crown-jewel closure" value={`${fmtPct(a.closure_pct)}%`} accent="var(--ok)" hint={coverage} />
        <StatTile
          label="Open"
          value={a.crownjewel_open}
          accent="var(--bad)"
          hint={`of ${a.crownjewel_total} entry → jewel pairs`}
        />
        <StatTile label="Closed" value={a.crownjewel_closed} accent="var(--accent)" hint="proved shut in config" />
        <StatTile
          label="Depends on runtime"
          value={a.crownjewel_conditional}
          accent="var(--warn)"
          hint="not counted as closed"
        />
      </div>

      <section className="panel wg-board" aria-labelledby="wg-board-h">
        <div className="panel-h">
          <h2 id="wg-board-h">The board line</h2>
          <span className="wg-muted wg-run-meta">
            {a.label || "Assessment"} · computed {relativeTime(a.computed_at)}
          </span>
        </div>
        <p className="wg-board-line">{a.board_line}</p>
        <dl className="wg-facts">
          <div>
            <dt>Model coverage</dt>
            <dd>{a.coverage_pct == null ? "Not yet measured" : `${fmtPct(a.coverage_pct)}% of observed traffic explained`}</dd>
          </div>
          <div>
            <dt>
              <Tip tip="On Paddock's own test ranges: how often the engine called a pair closed when it was actually open. Lower is better.">
                False-closed rate <span aria-hidden="true">ⓘ</span>
              </Tip>
            </dt>
            <dd>{fcr}</dd>
          </div>
          <div>
            <dt>Pairs assessed</dt>
            <dd>
              {a.crownjewel_total} ({a.crownjewel_open} open · {a.crownjewel_closed} closed · {a.crownjewel_conditional}{" "}
              depend on runtime)
            </dd>
          </div>
        </dl>
        {blind.length > 0 && (
          <div className="wg-blind">
            <h3>Blind spots</h3>
            <ul>
              {blind.map((b, i) => (
                <li key={i}>{b}</li>
              ))}
            </ul>
          </div>
        )}
      </section>
    </>
  );
}

/* ------------------------------------------------------------------ */
/* 2. Routes                                                           */
/* ------------------------------------------------------------------ */

function RouteCard({ r, fixSet }: { r: WargameRoute; fixSet: WargameFixSet | null | undefined }) {
  const weakest = evidenceMeta(r.weakest_label);
  const cuts = cuttingFixes(r, fixSet);
  const fixById = new Map((fixSet?.selected ?? []).map((f) => [f.id, f]));
  return (
    <article className={`wg-route-card wg-tier-${weakest.tier}`} aria-label={`${r.entry} to ${r.jewel}`}>
      <header className="wg-route-head">
        <h3 className="mono">
          {r.entry} <span aria-hidden="true">→</span>
          <span className="wg-sr-only"> to </span> {r.jewel}
        </h3>
        <span className="wg-muted">
          {r.length} {r.length === 1 ? "hop" : "hops"}
        </span>
        <span className="wg-spacer" />
        <EvidenceChip meta={weakest} prefix="Weakest" />
        {fixSet &&
          (cuts.length ? (
            <ToneChip
              tone="pass"
              tip={
                <>
                  <b>Cut by the fix set</b>
                  {cuts.map((c) => (
                    <span key={c}>{fixById.get(c)?.description || c}</span>
                  ))}
                </>
              }
            >
              <span aria-hidden="true">✂</span> Cut by fix set
            </ToneChip>
          ) : (
            <ToneChip
              tone="open"
              tip="None of the selected changes is on this route: there's no control Paddock can model here yet."
            >
              Not cut
            </ToneChip>
          ))}
      </header>
      <RouteStrip route={r} />
      <p className="wg-route-sentence">{routeStrengthSentence(r)}</p>
    </article>
  );
}

function RoutesPanel({
  routes,
  total,
  loading,
  error,
  fixSet,
}: {
  routes: WargameRoute[];
  total: number;
  loading: boolean;
  error: unknown;
  fixSet: WargameFixSet | null | undefined;
}) {
  const [jewel, setJewel] = useState("");
  const [entry, setEntry] = useState("");
  const jewels = useMemo(() => [...new Set(routes.map((r) => r.jewel))].sort(), [routes]);
  const entries = useMemo(() => [...new Set(routes.map((r) => r.entry))].sort(), [routes]);
  const shown = routes.filter((r) => (!jewel || r.jewel === jewel) && (!entry || r.entry === entry));

  return (
    <section className="panel wg-routes" aria-labelledby="wg-routes-h">
      <div className="panel-h">
        <h2 id="wg-routes-h">Who can reach your crown jewels</h2>
        <span className="wg-muted">
          {shown.length === routes.length ? `${routes.length}` : `${shown.length} of ${routes.length}`}{" "}
          {routes.length === 1 ? "route" : "routes"}
        </span>
      </div>

      {routes.length > 0 && (
        <div className="wg-filters" role="group" aria-label="Filter routes">
          <label>
            <span>Crown jewel</span>
            <select value={jewel} onChange={(e) => setJewel(e.target.value)}>
              <option value="">All</option>
              {jewels.map((j) => (
                <option key={j} value={j}>
                  {j}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>Entry point</span>
            <select value={entry} onChange={(e) => setEntry(e.target.value)}>
              <option value="">All</option>
              {entries.map((j) => (
                <option key={j} value={j}>
                  {j}
                </option>
              ))}
            </select>
          </label>
          {(jewel || entry) && (
            <button
              type="button"
              className="ghost"
              onClick={() => {
                setJewel("");
                setEntry("");
              }}
            >
              Clear
            </button>
          )}
        </div>
      )}

      <details className="wg-ladder">
        <summary>How to read the evidence on each hop</summary>
        <p className="wg-muted">
          A route is only as strong as its weakest hop. Solid lines are proved or seen; dashed and dotted lines are
          not proof.
        </p>
        <EvidenceLegend metas={EVIDENCE_LADDER} />
      </details>

      {loading && <p className="wg-muted" role="status">Loading routes…</p>}
      {!!error && <p className="wg-error">Couldn't load routes ({errStatus(error)}).</p>}
      {!loading && !error && routes.length === 0 && (
        <EmptyState
          icon="✓"
          title="No open routes to a crown jewel in this run."
          hint="Read this with the board line above: it holds only as far as the model's coverage."
        />
      )}
      {!loading && !error && routes.length > 0 && shown.length === 0 && (
        <EmptyState title="No routes match these filters." />
      )}
      <div className="wg-route-list">
        {shown.map((r) => (
          <RouteCard key={r.id} r={r} fixSet={fixSet} />
        ))}
      </div>
      {total > routes.length && (
        <p className="wg-muted">
          Showing the first {routes.length} of {total} routes.
        </p>
      )}
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* 3. Fix set                                                          */
/* ------------------------------------------------------------------ */

function FixSetPanel({
  fixSet,
  routes,
  loading,
  error,
}: {
  fixSet: WargameFixSet | null | undefined;
  routes: WargameRoute[];
  loading: boolean;
  error: unknown;
}) {
  const uncut = useMemo(() => uncutRoutes(routes, fixSet), [routes, fixSet]);
  const routeCount = (fixId: string) => routes.filter((r) => routeFixIds(r).has(fixId)).length;
  const exact = String(fixSet?.optimality).toLowerCase() === "exact";

  return (
    <section className="panel wg-fix" aria-labelledby="wg-fix-h">
      <div className="panel-h">
        <h2 id="wg-fix-h">Cheapest fix set</h2>
      </div>
      {loading && <p className="wg-muted" role="status">Loading fix set…</p>}
      {!!error && <p className="wg-error">Couldn't load the fix set ({errStatus(error)}).</p>}
      {!loading && !error && !fixSet && (
        <EmptyState
          title={routes.length ? "No fix set was stored for this run." : "Nothing to cut."}
          hint={routes.length ? "Recompute to work out the cheapest changes." : "There are no open routes in this run."}
        />
      )}
      {fixSet && (
        <div className="wg-fix-body">
          <div>
            <div className={`wg-cuts ${fixSet.cuts_all ? "is-yes" : "is-no"}`}>
              <span className="wg-cuts-q">Cuts every route?</span>
              <span className="wg-cuts-a">
                <span aria-hidden="true">{fixSet.cuts_all ? "✓ " : "✕ "}</span>
                {fixSet.cuts_all ? "Yes" : `No: ${uncut.length || "some"} ${uncut.length === 1 ? "route stays" : "routes stay"} open`}
              </span>
            </div>
            <dl className="wg-facts wg-fix-facts">
              <div>
                <dt>
                  <Tip tip="The sum of the cost classes you set (a rule change is cheap, a device patch is expensive). Paddock doesn't invent risk weights.">
                    Total cost <span aria-hidden="true">ⓘ</span>
                  </Tip>
                </dt>
                <dd className="mono">{fixSet.total_cost}</dd>
              </div>
              <div>
                <dt>
                  <Tip
                    tip={
                      exact
                        ? "Exact: the solver proved no cheaper set of changes cuts these routes."
                        : "Greedy: a good answer for a large estate, but not proved to be the cheapest."
                    }
                  >
                    How sure <span aria-hidden="true">ⓘ</span>
                  </Tip>
                </dt>
                <dd>{exact ? "Proved cheapest" : String(fixSet.optimality) === "greedy" ? "Best found, not proved cheapest" : String(fixSet.optimality)}</dd>
              </div>
            </dl>
          </div>
          <div>
            <h3 className="wg-sub-h">
              {fixSet.selected.length} {fixSet.selected.length === 1 ? "change" : "changes"}
            </h3>
            <ol className="wg-fix-list">
              {fixSet.selected.map((f) => {
                const n = routeCount(f.id);
                return (
                  <li key={f.id}>
                    <p className="wg-fix-desc">{f.description || <span className="mono">{f.id}</span>}</p>
                    <p className="wg-fix-meta">
                      <span className="mono">{f.id}</span>
                      {f.cost_class && <span>{f.cost_class.replace(/_/g, " ")}</span>}
                      <span>cost {f.cost}</span>
                      {routes.length > 0 && <span>cuts {n} {n === 1 ? "route" : "routes"}</span>}
                    </p>
                  </li>
                );
              })}
            </ol>

            {uncut.length > 0 && (
              <div className="wg-uncut">
                <h3 className="wg-sub-h">Routes this can't cut</h3>
                <p className="wg-muted">No change Paddock can model sits on these routes. They need a person to look.</p>
                <ul>
                  {uncut.map((r) => (
                    <li key={r.id}>
                      <span className="mono">
                        {r.entry} → {r.jewel}
                      </span>
                      <EvidenceChip meta={evidenceMeta(r.weakest_label)} prefix="Weakest" quiet />
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {!fixSet.cuts_all && uncut.length === 0 && (
              <p className="wg-muted">
                The engine reports some routes stay uncut, but they aren't among the routes loaded here.
              </p>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* 4. Boundaries + certificates                                        */
/* ------------------------------------------------------------------ */

function BoundariesPanel({ rows, loading, error }: { rows: WargameBoundary[]; loading: boolean; error: unknown }) {
  const sorted = useMemo(
    () => [...rows].sort((a, b) => verdictRank(a.verdict) - verdictRank(b.verdict)),
    [rows],
  );
  const counts = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of rows) m.set(String(r.verdict), (m.get(String(r.verdict)) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => verdictRank(a[0]) - verdictRank(b[0]));
  }, [rows]);

  return (
    <section className="panel wg-bounds" aria-labelledby="wg-bounds-h">
      <div className="panel-h">
        <h2 id="wg-bounds-h">Is the door shut? Boundary by boundary</h2>
        <span className="wg-muted">config proof, probes and observed traffic, reconciled</span>
      </div>
      {counts.length > 0 && (
        <ul className="wg-verdict-counts" aria-label="Verdict counts">
          {counts.map(([v, n]) => (
            <li key={v}>
              <VerdictChip verdict={v} /> <span className="mono">{n}</span>
            </li>
          ))}
        </ul>
      )}
      {loading && <p className="wg-muted" role="status">Loading boundaries…</p>}
      {!!error && <p className="wg-error">Couldn't load boundaries ({errStatus(error)}).</p>}
      {!loading && !error && rows.length === 0 && (
        <EmptyState title="No boundaries assessed in this run." hint="Boundaries appear once the twin has rule sets between segments." />
      )}
      {sorted.length > 0 && (
        <ul className="wg-bnd-list">
          {sorted.map((b) => {
            const m = verdictMeta(b.verdict);
            const dis = (b.disagreements ?? []).map((d) => (typeof d === "string" ? d : JSON.stringify(d)));
            return (
              <li key={b.id} className={`wg-bnd tone-${m.tone}`}>
                <div className="wg-bnd-where">
                  <span className="mono">
                    {b.boundary_src} <span aria-hidden="true">→</span>
                    <span className="wg-sr-only"> to </span> {b.boundary_dst}
                  </span>
                  <span className="wg-bnd-port mono">{b.port || "any"}</span>
                </div>
                <div className="wg-bnd-verdict">
                  <VerdictChip verdict={b.verdict} />
                </div>
                <div className="wg-bnd-note">
                  {b.note && <p>{b.note}</p>}
                  {dis.length > 0 && (
                    <p className="wg-bnd-dis">
                      <span>Where the evidence disagrees:</span> {dis.join("; ")}
                    </p>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

function CertificateCard({ c }: { c: WargameCertificate }) {
  const st = certStatusMeta(c.status, c.expires_at);
  const lapsed = c.expires_at ? Date.parse(c.expires_at) <= Date.now() : false;
  return (
    <li className={`wg-cert tone-${st.tone}`}>
      <div className="wg-cert-head">
        <ToneChip tone={st.tone} tip={st.tip}>
          {st.label}
        </ToneChip>
        <span className="wg-muted">
          {c.expires_at ? (lapsed ? `expired ${relativeTime(c.expires_at)}` : `expires ${relativeTime(c.expires_at)}`) : "no expiry recorded"}
        </span>
      </div>
      <p className="wg-cert-claim">{c.claim}</p>
      {c.key_id === "unsigned-dev" && (
        <p className="wg-error">Signed with the public development key: fine for a demo, not valid as audit evidence.</p>
      )}
      <p className="wg-cert-where mono">
        {c.boundary_src} → {c.boundary_dst} · {c.port || "any"}
      </p>
      <div className="wg-cert-assume">
        <h4>Holds only if</h4>
        {c.assumptions.length ? (
          <ul>
            {c.assumptions.map((a, i) => {
              const t = assumptionText(a);
              return (
                <li key={i} className={t.key === "observation_side" ? "is-caveat" : ""}>
                  {t.text}
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="wg-error">No assumptions recorded. Treat this certificate as invalid.</p>
        )}
      </div>
      <dl className="wg-cert-meta">
        <div>
          <dt>Issued</dt>
          <dd>{c.issued_at ? new Date(c.issued_at).toLocaleString() : "not recorded"}</dd>
        </div>
        <div>
          <dt>
            <Tip tip="Hashes of the exact config snapshots this proof was computed against. An auditor can check them without Paddock.">
              Config proved against <span aria-hidden="true">ⓘ</span>
            </Tip>
          </dt>
          <dd className="mono" title={c.config_hashes.join("\n")}>
            {c.config_hashes.length ? `${short(c.config_hashes[0])}${c.config_hashes.length > 1 ? ` +${c.config_hashes.length - 1}` : ""}` : "none"}
          </dd>
        </div>
        <div>
          <dt>
            <Tip tip="HMAC-SHA256 signature over the claim, boundary, assumptions, config hashes and validity window.">
              Signature <span aria-hidden="true">ⓘ</span>
            </Tip>
          </dt>
          <dd className="mono" title={c.fingerprint}>
            {short(c.fingerprint, 16)}
            {c.key_id && c.key_id !== "unsigned-dev" ? <span className="wg-muted"> · key {c.key_id}</span> : null}
          </dd>
        </div>
      </dl>
    </li>
  );
}

function CertificatesPanel({ rows, loading, error }: { rows: WargameCertificate[]; loading: boolean; error: unknown }) {
  return (
    <section className="panel wg-certs" aria-labelledby="wg-certs-h">
      <div className="panel-h">
        <h2 id="wg-certs-h">Closed-boundary certificates</h2>
        <span className="wg-muted">signed, expiring, and explicit about what they assume</span>
      </div>
      {loading && <p className="wg-muted" role="status">Loading certificates…</p>}
      {!!error && <p className="wg-error">Couldn't load certificates ({errStatus(error)}).</p>}
      {!loading && !error && rows.length === 0 && (
        <EmptyState
          title="No certificates in this run."
          hint="A certificate is only issued for a boundary that config proves shut and a probe confirms (verdict: shut, proved and tested)."
        />
      )}
      {rows.length > 0 && (
        <ul className="wg-cert-list">
          {rows.map((c) => (
            <CertificateCard key={c.id} c={c} />
          ))}
        </ul>
      )}
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

export default function WargamePage() {
  const [params, setParams] = useSearchParams();
  const sample = params.get("sample") === "1";
  const sampleData = useMemo(() => (sample ? buildWargameSample() : null), [sample]);
  const [runId, setRunId] = useState<string | null>(null);
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);

  const setSample = (on: boolean) => {
    const next = new URLSearchParams(params);
    if (on) next.set("sample", "1");
    else next.delete("sample");
    setRunId(null);
    setParams(next, { replace: true });
  };

  const twinQ = useQuery({ queryKey: ["wargame", "twin"], queryFn: getWargameTwin, enabled: !sample, staleTime: 15_000 });
  const listQ = useQuery({
    queryKey: ["wargame", "assessments"],
    queryFn: () => listWargameAssessments({ limit: 20 }),
    enabled: !sample,
    staleTime: 15_000,
  });

  const assessments = sample ? sampleData!.assessments : listQ.data?.items ?? [];
  const current = assessments.find((a) => a.id === runId) ?? assessments[0];
  const id = current?.id ?? "";
  const live = !sample && !!id;

  const routesQ = useQuery({
    queryKey: ["wargame", id, "routes"],
    queryFn: () => listWargameRoutes(id, { limit: ROUTE_LIMIT }),
    enabled: live,
  });
  const boundsQ = useQuery({ queryKey: ["wargame", id, "boundaries"], queryFn: () => listWargameBoundaries(id), enabled: live });
  const certsQ = useQuery({ queryKey: ["wargame", id, "certificates"], queryFn: () => listWargameCertificates(id), enabled: live });
  const fixQ = useQuery({
    queryKey: ["wargame", id, "fix-set"],
    queryFn: async () => {
      try {
        return await getWargameFixSet(id);
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) return null; // no fix set for this run
        throw e;
      }
    },
    enabled: live,
  });

  const recompute = useMutation({
    mutationFn: recomputeWargame,
    onSuccess: (r) => {
      if (r.status === "unavailable") {
        pushToast({ text: r.detail || "The analysis service is unreachable; nothing was recomputed.", severity: "high" });
      } else {
        pushToast({ text: r.status === "queued" ? "Wargame recompute queued." : r.detail || "Wargame recomputed." });
      }
      setRunId(null);
      qc.invalidateQueries({ queryKey: ["wargame"] });
    },
    onError: () => pushToast({ text: "Recompute failed.", severity: "high" }),
  });

  const routes = sample ? sampleData!.routes : routesQ.data?.items ?? [];
  const routeTotal = sample ? routes.length : routesQ.data?.total ?? routes.length;
  const boundaries = sample ? sampleData!.boundaries : boundsQ.data ?? [];
  const certificates = sample ? sampleData!.certificates : certsQ.data ?? [];
  const fixSet = sample ? sampleData!.fixSet : fixQ.data;
  const twin = sample ? sampleData!.twin : twinQ.data;

  const loading = !sample && listQ.isLoading;
  const listError = !sample && listQ.isError;
  const empty = !loading && !listError && assessments.length === 0;
  const showGate = !!current || !!twin?.has_twin;

  return (
    <div className="page wargame">
      <div className="page-header">
        <div>
          <h1>Wargame</h1>
          <div className="subtitle">
            Can anyone reach what you care about, and is the door shut? Paddock works backward from your crown jewels
            over your own config. It never runs exploits.
          </div>
        </div>
        <div className="wg-header-actions">
          {assessments.length > 1 && (
            <label className="wg-run-pick">
              <span>Run</span>
              <select value={current?.id ?? ""} onChange={(e) => setRunId(e.target.value)}>
                {assessments.map((a, i) => (
                  <option key={a.id} value={a.id}>
                    {i === 0 ? "Latest · " : ""}
                    {new Date(a.computed_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}
                  </option>
                ))}
              </select>
            </label>
          )}
          {!sample && !empty && (
            <button type="button" className="primary" disabled={recompute.isPending} onClick={() => recompute.mutate()}>
              {recompute.isPending ? "Recomputing…" : "Recompute"}
            </button>
          )}
        </div>
      </div>

      {sample && (
        <div className="wg-sample-banner" role="status">
          <span className="wg-sample-tag">Sample data</span>
          <span>
            A fictional estate (guest Wi-Fi → smart fridge → POS → payment database), not your network.
          </span>
          <button type="button" onClick={() => setSample(false)}>
            Leave sample
          </button>
        </div>
      )}

      {loading && (
        <p className="wg-muted" role="status">
          Loading Wargame…
        </p>
      )}

      {listError && (
        <section className="panel" aria-labelledby="wg-err-h">
          <div className="panel-h">
            <h2 id="wg-err-h">Couldn't load Wargame</h2>
          </div>
          <EmptyState
            icon="!"
            title={`The assessments didn't load (${errStatus(listQ.error)}).`}
            hint="Nothing is shown rather than a guess. Try again, or look at the sample to see what Wargame does."
          />
          <div className="wg-center-actions">
            <button type="button" onClick={() => listQ.refetch()}>
              Try again
            </button>
            <button type="button" className="ghost" onClick={() => setSample(true)}>
              Preview with sample data
            </button>
          </div>
        </section>
      )}

      {empty && (
        <TwinSetup
          twin={twin}
          twinError={twinQ.isError}
          onRecompute={() => recompute.mutate()}
          recomputing={recompute.isPending}
          onSample={() => setSample(true)}
        />
      )}

      {current && (
        <>
          <Scorecard a={current} />
          <div className="wg-main">
            <RoutesPanel
              routes={routes}
              total={routeTotal}
              loading={!sample && routesQ.isLoading}
              error={!sample && routesQ.error}
              fixSet={fixSet}
            />
            <FixSetPanel
              fixSet={fixSet}
              routes={routes}
              loading={!sample && fixQ.isLoading}
              error={!sample && fixQ.error}
            />
          </div>
          <BoundariesPanel rows={boundaries} loading={!sample && boundsQ.isLoading} error={!sample && boundsQ.error} />
          <CertificatesPanel rows={certificates} loading={!sample && certsQ.isLoading} error={!sample && certsQ.error} />
        </>
      )}

      {showGate && (
        <section className="panel wg-gate-panel" aria-labelledby="wg-gate-h">
          <div className="panel-h">
            <h2 id="wg-gate-h">Change gate: check a change before it ships</h2>
          </div>
          <ChangeGate key={sample ? "sample" : "live"} sample={sample} />
        </section>
      )}
    </div>
  );
}
