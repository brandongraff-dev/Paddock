import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import SeverityChip from "../components/Severity";
import EmptyState from "../components/EmptyState";
import { getTlsGradeSummary, listTakeoverFindings, listTlsGrades } from "../api/posture";
import type { Finding, Grade, TlsGrade } from "../api/types";
import { GRADE_ORDER, gradeColor } from "../lib/color";
import { useStore } from "../state/store";

/* ------------------------------- helpers ------------------------------- */

/** Whole days between now and an ISO timestamp (negative = already past). */
function daysUntil(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((t - Date.now()) / 86_400_000);
}

/** "expires in 15d" / "expired 3d ago" / "—"; red when inside 30 days. */
function certLabel(iso: string | null | undefined): { text: string; danger: boolean } {
  const d = daysUntil(iso);
  if (d == null) return { text: "—", danger: false };
  if (d < 0) return { text: `expired ${Math.abs(d)}d ago`, danger: true };
  if (d === 0) return { text: "expires today", danger: true };
  return { text: `expires in ${d}d`, danger: d < 30 };
}

/** Pull the dangling-CNAME narrative out of a takeover finding's evidence. */
function takeoverParts(f: Finding): { target: string | null; service: string | null } {
  const ev = (f.evidence ?? {}) as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" && v ? v : null);
  return {
    target: str(ev.cname_target) ?? str(ev.target) ?? str(ev.cname),
    service: str(ev.service) ?? str(ev.fingerprint) ?? str(ev.provider),
  };
}

/* ------------------------------ sub-views ------------------------------ */

function GradeBadge({ grade, size = 34 }: { grade: Grade | string; size?: number }) {
  const color = gradeColor(grade);
  return (
    <span
      className="grade-badge"
      style={{ color, borderColor: color, width: size, height: size, fontSize: size * 0.44 }}
      title={`grade ${grade}`}
    >
      {grade}
    </span>
  );
}

/** Horizontal 0–100 TLS-score meter, coloured by grade (higher = better). */
function ScoreMeter({ score, grade }: { score: number; grade: Grade | string }) {
  const pct = Math.max(0, Math.min(100, score));
  const color = gradeColor(grade);
  return (
    <div className="blast-meter" style={{ width: 120 }} title={`score ${score}`}>
      <div className="blast-meter-track">
        <span style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="blast-meter-val mono" style={{ color }}>
        {Math.round(score)}
      </span>
    </div>
  );
}

function GradeStrip() {
  const q = useQuery({
    queryKey: ["tls-grade-summary"],
    queryFn: getTlsGradeSummary,
    staleTime: 30_000,
  });
  const summary = q.data ?? {};
  return (
    <div className="grade-strip">
      {GRADE_ORDER.map((g) => {
        const color = gradeColor(g);
        const n = summary[g] ?? 0;
        return (
          <div key={g} className="grade-cell" style={{ borderTopColor: color }}>
            <span className="grade-cell-g" style={{ color }}>{g}</span>
            <span className="grade-cell-n mono">{n}</span>
          </div>
        );
      })}
    </div>
  );
}

function TakeoverRisk() {
  const q = useQuery({
    queryKey: ["takeover-findings"],
    queryFn: listTakeoverFindings,
    staleTime: 20_000,
  });
  const openDrawer = useStore((s) => s.openDrawer);
  const rows = q.data ?? [];

  return (
    <div className="panel" style={{ padding: 0 }}>
      <div className="panel-h" style={{ padding: "12px 14px 8px", marginBottom: 0 }}>
        <h2>Takeover risk</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>
          {rows.length} dangling record{rows.length === 1 ? "" : "s"}
        </span>
      </div>
      <div style={{ padding: 12 }}>
        {q.isLoading && <div style={{ color: "var(--text-2)", fontSize: 12 }}>Loading takeover findings…</div>}
        {!q.isLoading && rows.length === 0 && (
          <EmptyState
            title="No dangling DNS detected."
            hint="Takeover findings appear when a subdomain's CNAME points at an unclaimed third-party host."
          />
        )}
        <div className="takeover-grid">
          {rows.map((f) => {
            const { target, service } = takeoverParts(f);
            return (
              <article key={f.id} className={`takeover-card sev-${f.severity}`}>
                <div className="takeover-head">
                  <SeverityChip severity={f.severity} />
                  {service && <span className="takeover-service mono">{service}</span>}
                </div>
                <div className="takeover-flow mono">
                  <button
                    type="button"
                    className="takeover-node sub"
                    title={f.asset_value ?? ""}
                    onClick={() => f.asset_id && openDrawer({ kind: "asset", id: f.asset_id })}
                  >
                    {f.asset_value ?? "subdomain"}
                  </button>
                  <span className="takeover-arrow">→</span>
                  <span className="takeover-node tgt" title={target ?? "dangling target"}>
                    {target ?? "dangling CNAME"}
                  </span>
                </div>
                <button
                  type="button"
                  className="takeover-title"
                  onClick={() => openDrawer({ kind: "finding", id: f.id })}
                >
                  {f.title}
                </button>
                {f.remediation && <p className="takeover-rem">{f.remediation}</p>}
              </article>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------- page ---------------------------------- */

export default function PosturePage() {
  const [grades, setGrades] = useState<Grade[]>([]);
  const openDrawer = useStore((s) => s.openDrawer);

  const filter = useMemo(
    () => ({ grade: grades.length === 1 ? grades[0] : undefined, limit: 200 }),
    [grades],
  );

  const q = useQuery({
    queryKey: ["tls-grades", filter],
    queryFn: () => listTlsGrades(filter),
    staleTime: 15_000,
  });

  const rows = useMemo<TlsGrade[]>(() => {
    const list = q.data ?? [];
    const narrowed = grades.length > 1 ? list.filter((r) => grades.includes(r.grade)) : list;
    // Worst grades first (score ascending).
    return [...narrowed].sort((a, b) => a.score - b.score);
  }, [q.data, grades]);

  const toggleGrade = (g: Grade) =>
    setGrades((cur) => (cur.includes(g) ? cur.filter((x) => x !== g) : [...cur, g]));

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Posture</h1>
          <div className="subtitle">TLS report-card across the surface, plus dangling-DNS takeover risk.</div>
        </div>
      </div>

      <GradeStrip />

      <div className="filterbar">
        <label>Grade</label>
        {GRADE_ORDER.map((g) => {
          const on = grades.includes(g);
          const c = gradeColor(g);
          return (
            <label key={g} className={`checkchip ${on ? "on" : ""}`} style={on ? { borderColor: c, color: c } : undefined}>
              <input type="checkbox" checked={on} onChange={() => toggleGrade(g)} />
              {g}
            </label>
          );
        })}
      </div>

      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        <div className="tls-row tls-head">
          <div>Grade</div>
          <div>Host</div>
          <div>Score</div>
          <div>Issues</div>
          <div>Certificate</div>
        </div>
        <div className="tls-list">
          {q.isLoading && <div style={{ padding: 12, color: "var(--text-2)" }}>Loading TLS grades…</div>}
          {q.isError && <div style={{ padding: 12, color: "var(--bad)" }}>Failed to load TLS grades.</div>}
          {!q.isLoading && rows.length === 0 && <EmptyState title="No graded hosts match these filters." />}
          {rows.map((g) => {
            const cert = certLabel(g.cert_expires);
            return (
              <div key={g.id} className="tls-row">
                <div><GradeBadge grade={g.grade} /></div>
                <div className="tls-host">
                  <button
                    type="button"
                    className="tls-host-btn mono"
                    title={g.host}
                    onClick={() => openDrawer({ kind: "asset", id: g.asset_id })}
                  >
                    {g.host}
                  </button>
                  {g.protocols.length > 0 && (
                    <div className="tls-protos mono">{g.protocols.join(" · ")}</div>
                  )}
                </div>
                <div><ScoreMeter score={g.score} grade={g.grade} /></div>
                <div className="tls-issues">
                  {g.issues.length === 0 && g.weak_ciphers.length === 0 ? (
                    <span className="tls-clean mono">clean</span>
                  ) : (
                    <>
                      {g.issues.map((i, idx) => (
                        <span key={`i${idx}`} className="tls-issue">{i}</span>
                      ))}
                      {g.weak_ciphers.map((c, idx) => (
                        <span key={`c${idx}`} className="tls-issue weak">{c}</span>
                      ))}
                    </>
                  )}
                </div>
                <div className={`tls-cert mono ${cert.danger ? "danger" : ""}`}>{cert.text}</div>
              </div>
            );
          })}
        </div>
      </div>

      <TakeoverRisk />
    </div>
  );
}
