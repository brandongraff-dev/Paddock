import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import StatTile from "../components/StatTile";
import SeverityChip from "../components/Severity";
import FilterBar from "../components/FilterBar";
import EmptyState from "../components/EmptyState";
import AttackPathStrip from "../components/path/AttackPathStrip";
import { listAttackPaths, recomputeAttackPaths } from "../api/attackpaths";
import type { AttackPath, Severity } from "../api/types";
import { severityColor } from "../lib/color";
import { useStore } from "../state/store";

/** Horizontal exploitability meter (0–100), coloured by the path severity. */
function ExploitMeter({ value, severity }: { value: number; severity: Severity }) {
  const pct = Math.max(0, Math.min(100, value));
  const color = severityColor(severity);
  return (
    <div className="expl-meter" title={`exploitability ${value}`}>
      <span className="expl-meter-val mono" style={{ color }}>
        {value.toFixed(value % 1 === 0 ? 0 : 1)}
      </span>
      <div className="expl-meter-track">
        <span style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

export default function AttackPathsPage() {
  const [sev, setSev] = useState<Severity[]>([]);
  const [kevOnly, setKevOnly] = useState(false);
  const qc = useQueryClient();

  // Server takes a single severity; the chip multiselect is applied client-side
  // (the engine keeps only the top 50 paths, so the set is small). Same shape
  // as the Findings page.
  const filter = useMemo(
    () => ({
      severity: sev.length === 1 ? sev[0] : undefined,
      kev: kevOnly || undefined,
      limit: 50,
    }),
    [sev, kevOnly],
  );

  const q = useQuery({
    queryKey: ["attack-paths", filter],
    queryFn: () => listAttackPaths(filter),
    staleTime: 15_000,
  });

  const pushToast = useStore((s) => s.pushToast);
  const recompute = useMutation({
    mutationFn: recomputeAttackPaths,
    onSuccess: () => {
      pushToast({ text: "Attack-path recompute queued." });
      qc.invalidateQueries({ queryKey: ["attack-paths"] });
    },
    onError: () => pushToast({ text: "Recompute failed.", severity: "high" }),
  });

  const paths = useMemo<AttackPath[]>(() => {
    const rows = q.data ?? [];
    const filtered = sev.length > 1 ? rows.filter((p) => sev.includes(p.severity)) : rows;
    return [...filtered].sort((a, b) => b.exploitability - a.exploitability);
  }, [q.data, sev]);

  const stats = useMemo(() => {
    const rows = q.data ?? [];
    const kev = rows.filter((p) => p.kev_on_path).length;
    const shortest = rows.length ? Math.min(...rows.map((p) => p.length)) : 0;
    const topExploit = rows.length ? Math.max(...rows.map((p) => p.exploitability)) : 0;
    return { total: rows.length, kev, shortest, topExploit };
  }, [q.data]);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Attack Paths</h1>
          <div className="subtitle">
            Node-weighted routes from internet-facing assets to crown jewels, ranked by exploitability.
          </div>
        </div>
      </div>

      <div className="stat-row">
        <StatTile label="Total paths" value={stats.total} accent="#b9a3d6" />
        <StatTile
          label="Paths with KEV"
          value={stats.kev}
          accent={severityColor("critical")}
        />
        <StatTile
          label="Shortest length"
          value={stats.shortest || "—"}
          delta={{ value: "hops", dir: undefined }}
          accent="#9fc2d8"
        />
        <StatTile
          label="Highest exploitability"
          value={stats.topExploit ? stats.topExploit.toFixed(1) : "—"}
          accent={severityColor("high")}
        />
      </div>

      <FilterBar
        severity={sev}
        onSeverity={setSev}
        kevOnly={kevOnly}
        onKev={setKevOnly}
        extra={
          <>
            <span className="sep" />
            <button
              className="primary"
              disabled={recompute.isPending}
              onClick={() => recompute.mutate()}
            >
              {recompute.isPending ? "Recomputing…" : "Recompute"}
            </button>
          </>
        }
      />

      {q.isLoading && <div style={{ color: "var(--text-2)" }}>Loading attack paths…</div>}
      {q.isError && <div style={{ color: "var(--bad)" }}>Failed to load attack paths.</div>}
      {!q.isLoading && !q.isError && paths.length === 0 && (
        <EmptyState
          title="No attack paths computed yet — run Recompute."
          hint="Paths appear once the correlation engine finds a route from an internet-facing source to a crown-jewel target."
        />
      )}

      <div>
        {paths.map((p) => (
          <article key={p.id} className={`path-card sev-${p.severity}`}>
            <div className="path-card-head">
              <div className="path-card-title">
                <SeverityChip severity={p.severity} />
                <h2>{p.title}</h2>
                {p.kev_on_path && <span className="kev-badge">KEV</span>}
              </div>
              <div className="path-card-stats">
                <span className="path-meta mono">
                  {p.length} hops · cost {p.total_cost}
                </span>
                <ExploitMeter value={p.exploitability} severity={p.severity} />
              </div>
            </div>

            {/* internet-facing source → hops (by severity) → crown jewel. */}
            <AttackPathStrip path={p} />

            {p.narrative && <p className="path-narrative">{p.narrative}</p>}
          </article>
        ))}
      </div>
    </div>
  );
}
