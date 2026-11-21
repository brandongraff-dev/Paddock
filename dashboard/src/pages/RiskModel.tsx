import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import StatTile from "../components/StatTile";
import SeverityChip from "../components/Severity";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import {
  ackAnomaly,
  getMlModel,
  listAnomalies,
  listMlRisk,
  retrainModel,
  type AnomalyFilter,
} from "../api/ml";
import type { AnomalyPage, MlRationaleSignal, MlRiskRow } from "../api/types";
import {
  contributionColor,
  featureLabel,
  kindColor,
  mlRiskColor,
  mlRiskPct,
  severityColor,
} from "../lib/color";
import { useStore } from "../state/store";

/* ------------------------------- helpers ------------------------------- */

function relPast(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

/* ------------------------------- tiles --------------------------------- */

function HeaderTiles() {
  const modelQ = useQuery({ queryKey: ["ml-model"], queryFn: getMlModel, staleTime: 20_000 });
  const openQ = useQuery({
    queryKey: ["anomalies-open-count"],
    queryFn: () => listAnomalies({ acknowledged: false, limit: 1 }),
    staleTime: 15_000,
  });

  const ranker = modelQ.data?.risk_ranker;
  const cold = ranker?.cold_start ?? false;
  const openAnoms = openQ.data?.total ?? openQ.data?.items?.length ?? 0;

  return (
    <div className="stat-row">
      <StatTile label="Model version" value={ranker?.version ?? "—"} accent="#c084fc" />
      <StatTile label="Samples trained" value={ranker?.n_samples ?? 0} accent="#4ea3ff" />
      <StatTile
        label="Cold start"
        value={ranker ? (cold ? "yes" : "no") : "—"}
        accent={cold ? "#f0b429" : "#58d68d"}
      />
      <StatTile label="Anomalies open" value={openAnoms} accent="#ff7a45" />
    </div>
  );
}

/* --------------------------- risk rank table --------------------------- */

/** Big band-colored risk number with a thin 0–100 meter under it. */
function RiskScore({ score }: { score: number }) {
  const pct = mlRiskPct(score);
  const color = mlRiskColor(score);
  return (
    <div className="ml-score" title={`adaptive risk ${Math.round(pct)} / 100`}>
      <span className="ml-score-val mono" style={{ color }}>
        {Math.round(pct)}
      </span>
      <span className="ml-score-track">
        <span style={{ width: `${pct}%`, background: color }} />
      </span>
    </div>
  );
}

/** A signed contribution chip: "reachable +22", "dismissed-pattern -8". */
function RationaleChip({ sig }: { sig: MlRationaleSignal }) {
  const color = contributionColor(sig.contribution);
  const n = Math.round(sig.contribution);
  const sign = n > 0 ? "+" : n < 0 ? "-" : "";
  return (
    <span className="rationale-chip mono" style={{ borderColor: color }}>
      <span className="rationale-feat">{featureLabel(sig.feature)}</span>
      <span className="rationale-val" style={{ color }}>
        {sign}
        {Math.abs(n)}
      </span>
    </span>
  );
}

function RiskRankRow({ row }: { row: MlRiskRow }) {
  const [open, setOpen] = useState(false);
  const signals = useMemo(
    () => [...(row.rationale ?? [])].sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution)),
    [row.rationale],
  );
  const top = signals.slice(0, 3);
  const asset = row.asset;

  return (
    <div className={`ml-rank-item${open ? " open" : ""}`}>
      <button
        type="button"
        className="ml-rank-row"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <div>
          <RiskScore score={row.ml_risk} />
        </div>
        <div className="ml-rank-title" title={row.finding?.title}>
          {row.finding?.title ?? "—"}
        </div>
        <div>
          <SeverityChip severity={row.finding?.severity ?? "info"} compact />
        </div>
        <div className="ml-rank-asset mono" title={asset?.value}>
          {asset?.kind && (
            <span className="ml-asset-kind" style={{ color: kindColor(asset.kind) }}>
              {asset.kind}
            </span>
          )}
          <span className="ml-asset-val">{asset?.value ?? "—"}</span>
        </div>
        <div className="ml-rank-why">
          {top.map((s, i) => (
            <RationaleChip key={i} sig={s} />
          ))}
          {signals.length > top.length && (
            <span className="ml-why-more">+{signals.length - top.length}</span>
          )}
          <span className="ml-why-caret mono" aria-hidden>
            {open ? "▾" : "▸"}
          </span>
        </div>
      </button>
      {open && (
        <div className="ml-rationale-full">
          <div className="ml-rationale-chips">
            {signals.length === 0 ? (
              <span className="muted" style={{ fontSize: 12 }}>
                No rationale recorded for this score.
              </span>
            ) : (
              signals.map((s, i) => <RationaleChip key={i} sig={s} />)
            )}
          </div>
          <div className="ml-rationale-note">
            Scored by model <span className="mono">{row.model_version}</span>. Each chip is a signed
            contribution (feature weight × value): positive signals raise the score, negative ones
            lower it. The model ranks and explains — an analyst decides.
          </div>
        </div>
      )}
    </div>
  );
}

function RiskRankPanel() {
  const q = useQuery({
    queryKey: ["ml-risk", { limit: 100 }],
    queryFn: () => listMlRisk({ limit: 100 }),
    staleTime: 10_000,
  });
  const rows = useMemo(
    () => [...(q.data?.items ?? [])].sort((a, b) => b.ml_risk - a.ml_risk),
    [q.data],
  );

  return (
    <div className="panel" style={{ padding: 0, display: "flex", flexDirection: "column", minHeight: 0 }}>
      <div className="panel-h" style={{ padding: "12px 14px 8px", marginBottom: 0 }}>
        <h2>Top adaptive-risk findings</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>
          ranked by learned risk · click a row for the full rationale
        </span>
      </div>

      <div className="ml-rank-list">
        <div className="ml-rank-row ml-rank-head">
          <div>Risk</div>
          <div>Finding</div>
          <div>Sev</div>
          <div>Asset</div>
          <div>Why (top signals)</div>
        </div>
        {q.isLoading && <div style={{ padding: 12, color: "var(--text-2)" }}>Loading risk scores…</div>}
        {q.isError && <div style={{ padding: 12, color: "var(--bad)" }}>Failed to load risk scores.</div>}
        {!q.isLoading && !q.isError && rows.length === 0 && (
          <EmptyState
            title="No scored findings yet."
            hint="The risk ranker scores every open finding on each sweep and re-train."
          />
        )}
        {rows.map((r) => (
          <RiskRankRow key={r.finding_id} row={r} />
        ))}
      </div>
    </div>
  );
}

/* --------------------------- model insights ---------------------------- */

function ModelInsights() {
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);
  const q = useQuery({ queryKey: ["ml-model"], queryFn: getMlModel, staleTime: 20_000 });

  const ranker = q.data?.risk_ranker;
  const fi = ranker?.feature_importance ?? {};
  const entries = useMemo(
    () => Object.entries(fi).sort((a, b) => b[1] - a[1]),
    [fi],
  );
  const maxFi = entries.reduce((m, [, v]) => Math.max(m, v), 0) || 1;
  const metrics = ranker?.metrics ? Object.entries(ranker.metrics) : [];

  const retrain = useMutation({
    mutationFn: retrainModel,
    onSuccess: (res) => {
      if (res && res.available === false) {
        pushToast({
          text: res.note || "Retrain unavailable — the ML service is offline.",
          severity: "medium",
        });
        return;
      }
      pushToast({
        text: res?.note || `Retrain started${res?.version ? ` · ${res.version}` : ""}.`,
      });
      qc.invalidateQueries({ queryKey: ["ml-model"] });
      qc.invalidateQueries({ queryKey: ["ml-risk"] });
      qc.invalidateQueries({ queryKey: ["anomalies"] });
      qc.invalidateQueries({ queryKey: ["anomalies-open-count"] });
    },
    onError: () =>
      pushToast({ text: "Retrain failed — the ML service is unreachable.", severity: "high" }),
  });

  return (
    <div className="panel ml-insights">
      <div className="panel-h">
        <h2>Model insights</h2>
        <span className="mono" style={{ color: "var(--text-2)", fontSize: 11 }}>
          {ranker?.algo ?? "—"}
        </span>
      </div>

      <div className="ml-meta mono">
        trained {relPast(ranker?.trained_at)} · {ranker?.n_samples ?? 0} labeled samples ·{" "}
        <span style={{ color: "var(--text-1)" }}>{ranker?.version ?? "—"}</span>
      </div>

      {metrics.length > 0 && (
        <div className="ml-metrics">
          {metrics.map(([k, v]) => (
            <span key={k} className="ml-metric mono">
              <span className="ml-metric-k">{k}</span>
              <span className="ml-metric-v">{typeof v === "number" ? v.toFixed(3) : String(v)}</span>
            </span>
          ))}
        </div>
      )}

      <div className="fi-head">Feature importance</div>
      <div className="fi-list">
        {entries.length === 0 ? (
          <div className="muted" style={{ fontSize: 11.5, padding: "2px 0" }}>
            Feature importances appear once the ranker has trained on labeled triage.
          </div>
        ) : (
          entries.map(([k, v]) => (
            <div key={k} className="fi-row">
              <span className="fi-label" title={k}>
                {featureLabel(k)}
              </span>
              <span className="fi-track">
                <span className="fi-bar" style={{ width: `${(v / maxFi) * 100}%` }} />
              </span>
              <span className="fi-val mono">{v.toFixed(2)}</span>
            </div>
          ))
        )}
      </div>

      <p className="ml-learn-note">
        This ranker learns from your team's triage — which findings analysts act on versus dismiss
        (ticket and finding outcomes) — and re-trains on a schedule as new labels arrive. It surfaces
        and explains; it never acts on its own.
      </p>

      <div className="ml-insights-foot">
        <Gate need="triage">
          <button className="primary" disabled={retrain.isPending} onClick={() => retrain.mutate()}>
            {retrain.isPending ? "Retraining…" : "Retrain now"}
          </button>
        </Gate>
        {q.isError && <span className="muted" style={{ fontSize: 11 }}>model service unavailable</span>}
      </div>
    </div>
  );
}

/* ----------------------------- anomalies ------------------------------- */

function AnomalyScore({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.max(5, Math.min(100, (value / max) * 100)) : 0;
  const label = Number.isFinite(value) ? Math.round(value * 100) / 100 : value;
  return (
    <div className="blast-meter" style={{ width: 120 }} title={`anomaly score ${label}`}>
      <div className="blast-meter-track">
        <span style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="blast-meter-val mono" style={{ color }}>
        {label}
      </span>
    </div>
  );
}

function AnomaliesFeed() {
  const qc = useQueryClient();
  const [unackedOnly, setUnackedOnly] = useState(true);

  const filter = useMemo<AnomalyFilter>(
    () => ({ acknowledged: unackedOnly ? false : undefined, limit: 100 }),
    [unackedOnly],
  );

  const q = useQuery({
    queryKey: ["anomalies", filter],
    queryFn: () => listAnomalies(filter),
    staleTime: 10_000,
  });

  const ack = useMutation({
    mutationFn: (id: string) => ackAnomaly(id),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: ["anomalies"] });
      qc.setQueriesData<AnomalyPage>({ queryKey: ["anomalies"] }, (old) =>
        old
          ? { ...old, items: old.items.map((a) => (a.id === id ? { ...a, acknowledged: true } : a)) }
          : old,
      );
    },
    onError: () => qc.invalidateQueries({ queryKey: ["anomalies"] }),
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ["anomalies"] });
      qc.invalidateQueries({ queryKey: ["anomalies-open-count"] });
    },
  });

  const rows = useMemo(() => {
    const items = q.data?.items ?? [];
    const visible = unackedOnly ? items.filter((a) => !a.acknowledged) : items;
    return [...visible].sort((a, b) => b.score - a.score);
  }, [q.data, unackedOnly]);

  const maxScore = useMemo(() => rows.reduce((m, a) => Math.max(m, a.score), 0), [rows]);

  return (
    <div className="panel" style={{ padding: 0, display: "flex", flexDirection: "column", minHeight: 0 }}>
      <div className="panel-h" style={{ padding: "12px 14px 8px", marginBottom: 0 }}>
        <h2>Anomalies</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>
          outliers rules don't encode — surfaced, not auto-actioned
        </span>
      </div>

      <div className="filterbar" style={{ borderRadius: 0, border: 0, borderBottom: "1px solid var(--border)" }}>
        <label
          className={`checkchip ${unackedOnly ? "on" : ""}`}
          style={unackedOnly ? { borderColor: "#ff7a45", color: "#ff7a45" } : undefined}
        >
          <input
            type="checkbox"
            checked={unackedOnly}
            onChange={(e) => setUnackedOnly(e.target.checked)}
          />
          Unacknowledged only
        </label>
        <span className="sep" />
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>{rows.length} shown</span>
      </div>

      <div className="anomaly-list">
        <div className="anomaly-row anomaly-head">
          <div>Sev</div>
          <div>Subject</div>
          <div>Score</div>
          <div>Reason</div>
          <div>Detected</div>
          <div />
        </div>
        {q.isLoading && <div style={{ padding: 12, color: "var(--text-2)" }}>Loading anomalies…</div>}
        {q.isError && <div style={{ padding: 12, color: "var(--bad)" }}>Failed to load anomalies.</div>}
        {!q.isLoading && !q.isError && rows.length === 0 && (
          <EmptyState
            title={unackedOnly ? "No open anomalies." : "No anomalies detected."}
            hint="The detector flags assets/hosts whose feature vectors deviate from their peers."
          />
        )}
        {rows.map((a) => (
          <div key={a.id} className={`anomaly-row${a.acknowledged ? " acked" : ""}`}>
            <div>
              <SeverityChip severity={a.severity} compact />
            </div>
            <div className="anomaly-subject">
              <span className="anomaly-label mono" title={a.subject_label}>
                {a.subject_label}
              </span>
              <span className="anomaly-type">{a.subject_type}</span>
            </div>
            <div>
              <AnomalyScore value={a.score} max={maxScore} color={severityColor(a.severity)} />
            </div>
            <div className="anomaly-reason" title={a.reason}>
              {a.reason}
            </div>
            <div className="anomaly-ago mono" title={a.detected_at}>
              {relPast(a.detected_at)}
            </div>
            <div className="anomaly-ack">
              {a.acknowledged ? (
                <span className="acked-tag">acked</span>
              ) : (
                <Gate need="triage">
                  <button disabled={ack.isPending} onClick={() => ack.mutate(a.id)}>
                    ack
                  </button>
                </Gate>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------- page ---------------------------------- */

export default function RiskModelPage() {
  const modelQ = useQuery({ queryKey: ["ml-model"], queryFn: getMlModel, staleTime: 20_000 });
  const coldStart = modelQ.data?.risk_ranker?.cold_start ?? false;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Risk Model</h1>
          <div className="subtitle">
            An adaptive, explainable aid: the model learns from your triage to rank open findings and
            flag anomalies, and shows the signals behind every score. It surfaces and explains —
            analysts decide. Not a black box, not an autonomous actor.
          </div>
        </div>
      </div>

      <HeaderTiles />

      {coldStart && (
        <div className="ml-coldstart" role="note">
          <span className="ml-coldstart-tag mono">COLD START</span>
          <span className="ml-coldstart-text">
            Too little analyst triage so far — scores use a transparent heuristic prior, not a trained
            model. They sharpen as findings get acted on or dismissed and the ranker re-trains.
          </span>
        </div>
      )}

      <div className="rm-grid">
        <RiskRankPanel />
        <div className="rm-side">
          <ModelInsights />
        </div>
      </div>

      <AnomaliesFeed />
    </div>
  );
}
