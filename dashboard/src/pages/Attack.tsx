import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import StatTile from "../components/StatTile";
import EmptyState from "../components/EmptyState";
import { getAttackCoverage } from "../api/attack";
import type { AttackTechnique } from "../api/types";
import { attackHeat } from "../lib/color";

/* MITRE ATT&CK enterprise tactics in kill-chain order (contract §F). Only the
   tactics actually present are rendered; unknown tactics fall to the end. */
const TACTIC_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Exfiltration",
  "Impact",
];

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
const ORDER_INDEX = new Map(TACTIC_ORDER.map((t, i) => [norm(t), i]));

/* --------------------------- technique popover ------------------------- */

interface Popover {
  tech: AttackTechnique;
  x: number;
  y: number;
}

function TechniquePopover({ pop, onClose }: { pop: Popover; onClose: () => void }) {
  const navigate = useNavigate();
  return (
    <>
      <div className="atk-pop-backdrop" onClick={onClose} />
      <div
        className="atk-pop"
        style={{ left: pop.x, top: pop.y }}
        role="dialog"
        aria-label={`${pop.tech.technique_id} detail`}
      >
        <div className="atk-pop-h">
          <span className="atk-pop-id mono">{pop.tech.technique_id}</span>
          <button className="ghost" onClick={onClose} aria-label="close" style={{ padding: "0 6px" }}>✕</button>
        </div>
        <div className="atk-pop-name">{pop.tech.technique}</div>
        <div className="atk-pop-meta mono">{pop.tech.tactic}</div>
        <div className="atk-pop-count">
          <span className="mono" style={{ fontSize: 18, color: "var(--text-0)" }}>{pop.tech.count}</span>{" "}
          finding{pop.tech.count === 1 ? "" : "s"} mapped
        </div>
        <button
          className="primary"
          style={{ width: "100%", marginTop: 10 }}
          onClick={() => {
            // Deep-link into Findings with the technique id as a free-text hint.
            navigate(`/findings?q=${encodeURIComponent(pop.tech.technique_id)}`);
          }}
        >
          View in Findings →
        </button>
      </div>
    </>
  );
}

/* ------------------------------- page ---------------------------------- */

export default function AttackPage() {
  const q = useQuery({
    queryKey: ["attack-coverage"],
    queryFn: getAttackCoverage,
    staleTime: 20_000,
  });
  const [pop, setPop] = useState<Popover | null>(null);

  const cov = q.data;

  const { columns, maxCount, techniqueCount, tacticCount } = useMemo(() => {
    const techniques = cov?.by_technique ?? [];
    const byTactic = cov?.by_tactic ?? {};

    // Group techniques by their tactic string.
    const groups = new Map<string, AttackTechnique[]>();
    for (const t of techniques) {
      const k = t.tactic || "Unknown";
      (groups.get(k) ?? groups.set(k, []).get(k)!).push(t);
    }

    // Tactic columns = union of technique tactics and by_tactic keys.
    const keys = new Set<string>([...groups.keys(), ...Object.keys(byTactic)]);
    const cols = [...keys]
      .map((tactic) => {
        const techs = (groups.get(tactic) ?? []).slice().sort((a, b) => b.count - a.count);
        const headerCount = byTactic[tactic] ?? techs.reduce((s, t) => s + t.count, 0);
        return { tactic, techs, headerCount };
      })
      // Drop empty columns (no techniques AND no count).
      .filter((c) => c.techs.length > 0 || c.headerCount > 0)
      .sort((a, b) => {
        const ia = ORDER_INDEX.get(norm(a.tactic)) ?? 999;
        const ib = ORDER_INDEX.get(norm(b.tactic)) ?? 999;
        return ia - ib || a.tactic.localeCompare(b.tactic);
      });

    const max = techniques.reduce((m, t) => Math.max(m, t.count), 0);
    return {
      columns: cols,
      maxCount: max,
      techniqueCount: techniques.length,
      tacticCount: cols.length,
    };
  }, [cov]);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>ATT&amp;CK coverage</h1>
          <div className="subtitle">
            Open findings mapped onto MITRE ATT&amp;CK, laid out by tactic in kill-chain order.
            Tile intensity scales with the number of findings mapped to each technique.
          </div>
        </div>
      </div>

      <div className="stat-row">
        <StatTile label="Techniques covered" value={techniqueCount} accent="#9fc2d8" />
        <StatTile label="Tactics touched" value={tacticCount} accent="#b9a3d6" />
        <StatTile label="Findings mapped" value={cov?.total_findings_mapped ?? 0} accent="#8fbf8a" />
      </div>

      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        {q.isLoading && <div style={{ padding: 12, color: "var(--text-2)" }}>Loading coverage…</div>}
        {q.isError && <div style={{ padding: 12, color: "var(--bad)" }}>Failed to load ATT&amp;CK coverage.</div>}
        {!q.isLoading && !q.isError && columns.length === 0 && (
          <EmptyState
            title="No findings mapped to ATT&CK yet."
            hint="The correlation service maps findings to techniques on each sweep."
          />
        )}
        {columns.length > 0 && (
          <div className="atk-board">
            {columns.map((col) => (
              <div key={col.tactic} className="atk-col">
                <div className="atk-col-h">
                  <span className="atk-col-name">{col.tactic}</span>
                  <span className="atk-col-n mono">{col.headerCount}</span>
                </div>
                <div className="atk-col-body">
                  {col.techs.length === 0 ? (
                    <div className="atk-col-empty mono">—</div>
                  ) : (
                    col.techs.map((t) => {
                      const heat = attackHeat(t.count, maxCount);
                      return (
                        <button
                          key={t.technique_id}
                          type="button"
                          className="atk-tile"
                          style={{ background: heat.bg, borderColor: heat.border, color: heat.text }}
                          title={`${t.technique_id} — ${t.technique} · ${t.count} finding${t.count === 1 ? "" : "s"}`}
                          onClick={(e) => {
                            const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
                            const x = Math.min(r.left, window.innerWidth - 268);
                            const y = Math.min(r.bottom + 6, window.innerHeight - 180);
                            setPop({ tech: t, x: Math.max(8, x), y: Math.max(8, y) });
                          }}
                        >
                          <span className="atk-tile-id mono">{t.technique_id}</span>
                          <span className="atk-tile-name">{t.technique}</span>
                          <span className="atk-tile-n mono">{t.count}</span>
                        </button>
                      );
                    })
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {pop && <TechniquePopover pop={pop} onClose={() => setPop(null)} />}
    </div>
  );
}
