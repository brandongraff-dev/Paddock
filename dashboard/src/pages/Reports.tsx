import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import StatTile from "../components/StatTile";
import TrendArea from "../components/charts/TrendArea";
import RankBars from "../components/charts/RankBars";
import { fmtNum } from "../components/charts/kit";
import { SEV_COLOR } from "../lib/color";
import {
  compliancePackDocPath,
  executiveDocPath,
  getCompliancePack,
  getExecutiveReport,
  listFrameworks,
  openDocument,
  type Control,
  type ControlStatus,
  type ExecutiveReport,
  type FrameworkSummary,
} from "../api/reports";
import { useStore } from "../state/store";
import type { Severity } from "../api/types";
import "../styles/reports.css";

const PERIODS = [
  { key: 7, label: "7D" },
  { key: 30, label: "30D" },
  { key: 90, label: "90D" },
] as const;

export const STATUS_ORDER: ControlStatus[] = ["satisfied", "partial", "gap", "requires_attestation"];
export const STATUS_LABEL: Record<ControlStatus, string> = {
  satisfied: "Satisfied",
  partial: "Partial",
  gap: "Gap",
  requires_attestation: "Attestation",
};
const STATUS_COLOR: Record<ControlStatus, string> = {
  satisfied: "var(--ok)",
  partial: "var(--warn)",
  gap: "var(--bad)",
  requires_attestation: "var(--text-3)",
};

/** "3.5d" / "29h" / "40m" — compact durations from hours. */
export function fmtHours(h: number | null | undefined): string {
  if (h == null) return "—";
  if (h < 1) return `${Math.round(h * 60)}m`;
  if (h < 48) return `${Math.round(h * 10) / 10}h`;
  return `${Math.round((h / 24) * 10) / 10}d`;
}

function shortDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { day: "numeric", month: "short", timeZone: "UTC" });
}

function useDocAction() {
  const pushToast = useStore((s) => s.pushToast);
  const [busy, setBusy] = useState<string | null>(null);
  const run = async (key: string, fn: () => Promise<void>) => {
    setBusy(key);
    try {
      await fn();
    } catch (e) {
      pushToast({ text: `Report failed: ${(e as Error).message}`, severity: "high" });
    } finally {
      setBusy(null);
    }
  };
  return { busy, run };
}

/** satisfied / partial / gap / attestation as one 100% strip with 2px gaps. */
export function StatusMeter({ counts, total }: { counts: Record<ControlStatus, number>; total: number }) {
  return (
    <div className="rp-meter" role="img" aria-label={STATUS_ORDER.map((s) => `${STATUS_LABEL[s]} ${counts[s]}`).join(", ")}>
      {total === 0 ? (
        <span className="rp-meter-empty" />
      ) : (
        STATUS_ORDER.filter((s) => counts[s] > 0).map((s) => (
          <span key={s} style={{ flexGrow: counts[s], background: STATUS_COLOR[s] }} title={`${STATUS_LABEL[s]}: ${counts[s]}`} />
        ))
      )}
    </div>
  );
}

function StatusChip({ status }: { status: ControlStatus }) {
  return (
    <span className={`rp-status rp-st-${status}`}>
      <i style={{ background: STATUS_COLOR[status] }} aria-hidden="true" />
      {STATUS_LABEL[status]}
    </span>
  );
}

function ExecutivePreview({ r }: { r: ExecutiveReport }) {
  const ex = r.exposure;
  const trend = ex.points.map((p) => ({ label: shortDate(p.at), value: p.value }));
  const teams = r.mttr.by_team.slice(0, 6).map((m) => ({ label: m.key, value: Math.round(m.median_hours) }));
  const critMttr = r.mttr.by_severity.find((m) => m.key === "critical");
  return (
    <>
      {r.highlights.length > 0 && (
        <ul className="rp-highlights" aria-label="Highlights">
          {r.highlights.map((h) => (
            <li key={h}>{h}</li>
          ))}
        </ul>
      )}
      <div className="stat-row">
        <StatTile
          label="Exposure index"
          value={fmtNum(ex.end_value)}
          spark={ex.points.map((p) => p.value)}
          delta={{
            // No up/down colouring: for exposure a rise is bad, the opposite of the tile's convention.
            value: `${ex.delta > 0 ? "▲ +" : ex.delta < 0 ? "▼ " : ""}${ex.delta}${ex.delta_pct != null ? ` (${Math.round(ex.delta_pct)}%)` : ""}`,
          }}
          hint="lower is better"
        />
        <StatTile
          label="New critical · high"
          value={`${r.new_findings.critical} · ${r.new_findings.high}`}
          accent={SEV_COLOR.critical}
          hint={`prev ${r.new_findings.previous_critical_high}`}
        />
        <StatTile label="Fixed" value={r.resolutions.fixed} hint={`${r.resolutions.verified} verified`} />
        <StatTile
          label="Median time to fix"
          value={fmtHours(r.mttr.overall?.median_hours)}
          hint={critMttr ? `critical ${fmtHours(critMttr.median_hours)}` : "no criticals fixed"}
        />
        <StatTile
          label="SLA compliance"
          value={r.sla.compliance_pct == null ? "—" : `${Math.round(r.sla.compliance_pct)}%`}
          hint={`${r.sla.late + r.sla.breached_open} breached`}
        />
      </div>
      <div className="rp-grid">
        <section className="panel span-2">
          <div className="panel-h">
            <h2>Exposure index</h2>
            <span className="panel-meta mono">Σ open findings × severity weight · {r.window.label}</span>
          </div>
          <TrendArea data={trend} caption="Exposure index" />
        </section>
        <section className="panel">
          <div className="panel-h">
            <h2>Attack paths to crown jewels</h2>
          </div>
          <div className="rp-big3">
            <div><b>{r.attack_paths.closed}</b><span>closed</span></div>
            <div><b>{r.attack_paths.opened}</b><span>opened</span></div>
            <div><b>{r.attack_paths.open_end}</b><span>remaining</span></div>
          </div>
          {r.attack_paths.top_closed.length > 0 ? (
            <ul className="rp-list">
              {r.attack_paths.top_closed.slice(0, 4).map((p) => (
                <li key={p.fingerprint}>
                  <i className="dot" style={{ background: SEV_COLOR[p.severity] }} aria-hidden="true" />
                  <span className="t" title={p.title}>{p.title}</span>
                  <span className="m mono">{p.open_days}d</span>
                </li>
              ))}
            </ul>
          ) : (
            <div className="empty">No paths closed in this period.</div>
          )}
        </section>
        <section className="panel">
          <div className="panel-h">
            <h2>Time to fix by team</h2>
            <span className="panel-meta mono">median hours</span>
          </div>
          {teams.length ? <RankBars data={teams} caption="Median hours to fix by team" /> : <div className="empty">Nothing fixed in this period.</div>}
        </section>
        <section className="panel span-2">
          <div className="panel-h">
            <h2>SLA by severity</h2>
            <span className="panel-meta mono">{r.sla.overdue_end} overdue now</span>
          </div>
          {r.sla.by_severity.length ? (
            <table className="table rp-table">
              <thead>
                <tr><th>Severity</th><th className="n">Policy</th><th className="n">Met</th><th className="n">Late</th><th className="n">Breached, open</th><th className="n">Compliance</th></tr>
              </thead>
              <tbody>
                {r.sla.by_severity.map((s) => (
                  <tr key={s.severity}>
                    <td><i className="dot" style={{ background: SEV_COLOR[s.severity as Severity] }} aria-hidden="true" />{s.severity}</td>
                    <td className="n mono">{s.policy_hours ? fmtHours(s.policy_hours) : "—"}</td>
                    <td className="n mono">{s.met}</td>
                    <td className="n mono">{s.late}</td>
                    <td className="n mono">{s.breached_open}</td>
                    <td className="n mono">{s.compliance_pct == null ? "—" : `${Math.round(s.compliance_pct)}%`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="empty">No findings reached an SLA outcome in this period.</div>
          )}
        </section>
      </div>
    </>
  );
}

function FrameworkCard({ f, active, onOpen }: { f: FrameworkSummary; active: boolean; onOpen: () => void }) {
  return (
    <button className={`rp-fw ${active ? "on" : ""}`} onClick={onOpen} aria-pressed={active} aria-label={`${f.name} ${f.version}`}>
      <div className="rp-fw-h">
        <span className="rp-fw-name">{f.name}</span>
        <span className="rp-fw-ver mono">{f.version}</span>
      </div>
      <div className="rp-fw-pub">{f.publisher}</div>
      <StatusMeter counts={f.counts} total={f.total} />
      <dl className="rp-fw-counts">
        {STATUS_ORDER.map((s) => (
          <div key={s}>
            <dt><i style={{ background: STATUS_COLOR[s] }} aria-hidden="true" />{STATUS_LABEL[s]}</dt>
            <dd className="mono">{f.counts[s]}</dd>
          </div>
        ))}
      </dl>
    </button>
  );
}

function ControlRow({ c }: { c: Control }) {
  const [open, setOpen] = useState(false);
  return (
    <li className={`rp-ctl ${open ? "open" : ""}`}>
      <button className="rp-ctl-h ghost" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        <span className="rp-ctl-id mono">{c.id}</span>
        <span className="rp-ctl-t">{c.title}</span>
        <StatusChip status={c.status} />
      </button>
      {open && (
        <div className="rp-ctl-b">
          <p>{c.summary}</p>
          <p className="rp-why"><b>How Paddock evidences this.</b> {c.rationale}</p>
          {c.evidence.length > 0 && (
            <ul className="rp-ev">
              {c.evidence.map((e) => (
                <li key={e.key}>
                  <span className={`rp-es rp-es-${e.status} mono`}>{e.status}</span>
                  <b>{e.title}.</b> {e.detail}
                </li>
              ))}
            </ul>
          )}
          {c.attestation && c.status !== "satisfied" && <p className="rp-att">Needs from you: {c.attestation}</p>}
        </div>
      )}
    </li>
  );
}

function FrameworkDetail({ id }: { id: string }) {
  const pack = useQuery({ queryKey: ["compliance-pack", id], queryFn: () => getCompliancePack(id) });
  const [filter, setFilter] = useState<ControlStatus | "all">("all");
  const { busy, run } = useDocAction();
  const families = useMemo(() => {
    const m = new Map<string, Control[]>();
    for (const c of pack.data?.controls ?? []) {
      if (filter !== "all" && c.status !== filter) continue;
      m.set(c.family, [...(m.get(c.family) ?? []), c]);
    }
    return [...m.entries()];
  }, [pack.data, filter]);

  if (pack.isLoading) return <div className="empty">Mapping evidence…</div>;
  if (pack.isError || !pack.data) return <div className="empty">Could not load this framework.</div>;
  const f = pack.data.framework;
  return (
    <section className="panel rp-detail" aria-label={`${f.name} controls`}>
      <div className="panel-h">
        <h2>
          {f.name} <span className="rp-fw-ver mono">{f.version}</span>
        </h2>
        <div className="rp-actions">
          <button
            className="ghost"
            disabled={busy != null}
            onClick={() => run("html", () => openDocument(compliancePackDocPath(id, "html"), `${id}.html`, "open"))}
          >
            Open HTML
          </button>
          <button
            className="primary"
            disabled={busy != null}
            onClick={() => run("pdf", () => openDocument(compliancePackDocPath(id, "pdf"), `paddock-${id}-evidence.pdf`, "download"))}
          >
            {busy === "pdf" ? "Rendering…" : "Download evidence pack"}
          </button>
        </div>
      </div>
      <p className="rp-desc">{f.description}</p>
      <p className="rp-disclaimer">{pack.data.disclaimer}</p>
      <div className="seg rp-filter" role="radiogroup" aria-label="Filter controls by status">
        {(["all", ...STATUS_ORDER] as const).map((s) => (
          <button key={s} role="radio" aria-checked={filter === s} className={filter === s ? "on" : ""} onClick={() => setFilter(s)}>
            {s === "all" ? `All ${f.total}` : `${STATUS_LABEL[s]} ${f.counts[s]}`}
          </button>
        ))}
      </div>
      {families.length === 0 && <div className="empty">No controls with this status.</div>}
      {families.map(([fam, controls]) => (
        <div key={fam} className="rp-fam">
          <h3>{fam}</h3>
          <ul className="rp-ctls">
            {controls.map((c) => (
              <ControlRow key={c.id} c={c} />
            ))}
          </ul>
        </div>
      ))}
    </section>
  );
}

export default function Reports() {
  const [days, setDays] = useState<number>(30);
  const [fw, setFw] = useState<string | null>(null);
  const exec = useQuery({ queryKey: ["report-exec", days], queryFn: () => getExecutiveReport(days) });
  const frameworks = useQuery({ queryKey: ["report-frameworks"], queryFn: listFrameworks });
  const { busy, run } = useDocAction();

  return (
    <div className="page reports">
      <div className="page-header">
        <div>
          <h1>Reports</h1>
          <div className="subtitle">Executive summary, weekly digest and compliance evidence — ready to forward.</div>
        </div>
        <div className="rp-head-actions">
          <div className="seg" role="radiogroup" aria-label="Report period">
            {PERIODS.map((p) => (
              <button key={p.key} role="radio" aria-checked={days === p.key} className={days === p.key ? "on" : ""} onClick={() => setDays(p.key)}>
                {p.label}
              </button>
            ))}
          </div>
          <button
            className="ghost"
            disabled={busy != null}
            onClick={() => run("html", () => openDocument(executiveDocPath(days, "html"), `paddock-executive-${days}d.html`, "open"))}
          >
            Open HTML
          </button>
          <button
            className="primary"
            disabled={busy != null}
            onClick={() => run("pdf", () => openDocument(executiveDocPath(days, "pdf"), `paddock-executive-${days}d.pdf`, "download"))}
          >
            {busy === "pdf" ? "Rendering…" : "Download PDF"}
          </button>
        </div>
      </div>

      <section aria-label="Executive summary preview" className="rp-section">
        <div className="rp-section-h">
          <h2>Executive summary</h2>
          {exec.data && <span className="panel-meta mono">{exec.data.window.label} · data up to {exec.data.clearance}</span>}
        </div>
        {exec.isLoading && <div className="empty">Building the report…</div>}
        {exec.isError && <div className="empty">The report could not be built.</div>}
        {exec.data && <ExecutivePreview r={exec.data} />}
      </section>

      <section aria-label="Compliance evidence" className="rp-section">
        <div className="rp-section-h">
          <h2>Compliance evidence</h2>
          <span className="panel-meta">Paddock evidence mapped to controls. Manual controls need your attestation.</span>
        </div>
        {frameworks.isLoading && <div className="empty">Mapping evidence…</div>}
        {frameworks.isError && <div className="empty">Compliance packs are unavailable.</div>}
        <div className="rp-fws">
          {(frameworks.data ?? []).map((f) => (
            <FrameworkCard key={f.id} f={f} active={fw === f.id} onOpen={() => setFw(fw === f.id ? null : f.id)} />
          ))}
        </div>
        {fw && <FrameworkDetail id={fw} />}
      </section>
    </div>
  );
}
