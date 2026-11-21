import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import StatTile from "../components/StatTile";
import SeverityChip from "../components/Severity";
import EmptyState from "../components/EmptyState";
import {
  getSbomComponent,
  getSbomSummary,
  listSbomComponents,
  listSbomProjects,
  listSupplyChainRisks,
  type SbomComponentFilter,
} from "../api/sbom";
import { listCodeFindings, type CodeFindingFilter } from "../api/code";
import type {
  CodeFinding,
  Ecosystem,
  ReachabilityGrade,
  SbomComponent,
  Severity,
  SupplyChainRisk,
} from "../api/types";
import {
  SEV_COLOR,
  SEV_RANK,
  ecosystemColor,
  reachabilityColor,
  reachabilityLabel,
  riskTypeLabel,
  RISK_TYPE_ORDER,
} from "../lib/color";

/* ------------------------------ constants ------------------------------ */

const COMPONENT_LIMIT = 500;

/* ------------------------------- helpers ------------------------------- */

/** Vuln-count badge colored by the component's worst severity. */
function VulnBadge({ component }: { component: SbomComponent }) {
  if (!component.vuln_count || component.vuln_count <= 0) {
    return <span className="dep-vuln dep-vuln-clean mono">clean</span>;
  }
  const color = SEV_COLOR[component.max_vuln_severity ?? "medium"] ?? SEV_COLOR.medium;
  return (
    <span
      className="dep-vuln mono"
      style={{ color, borderColor: color, background: "transparent" }}
      title={`${component.vuln_count} vuln${component.vuln_count === 1 ? "" : "s"}, max ${component.max_vuln_severity ?? "?"}`}
    >
      {component.vuln_count} {component.vuln_count === 1 ? "vuln" : "vulns"}
    </span>
  );
}

/**
 * Reachability badge for a component or a single vuln. reachable → red,
 * potential → amber, unreachable → muted "not reached", unknown → faint "—".
 */
function ReachabilityBadge({
  grade,
  count,
  compact,
}: {
  grade: ReachabilityGrade | undefined | null;
  count?: number;
  compact?: boolean;
}) {
  const g = (grade ?? "unknown") as ReachabilityGrade;
  const color = reachabilityColor(g);
  const faint = g === "unknown";
  return (
    <span
      className={`reach-badge mono reach-${g}${compact ? " compact" : ""}`}
      style={{ color, borderColor: faint ? "var(--border)" : color }}
      title={
        g === "reachable"
          ? `vulnerable symbol reachable from an entrypoint${count ? ` · ${count} reachable vuln${count === 1 ? "" : "s"}` : ""}`
          : g === "potential"
            ? "module imported; no direct call path proven"
            : g === "unreachable"
              ? "not referenced from any entrypoint"
              : "no symbol in advisory, or source absent — not graded"
      }
    >
      {reachabilityLabel(g)}
      {g === "reachable" && count != null && count > 0 && (
        <span className="reach-badge-n">{count}</span>
      )}
    </span>
  );
}

/** Mono call path source → … → vulnerable symbol, when the grader resolved one. */
function CallPath({ path }: { path?: string[] | null }) {
  if (!path || path.length === 0) return null;
  return (
    <div className="call-path mono" aria-label="call path to vulnerable symbol">
      {path.map((sym, i) => (
        <span key={i} className="call-path-seg">
          {i > 0 && <span className="call-path-arrow">→</span>}
          <span className={`call-path-node${i === path.length - 1 ? " sink" : ""}`}>{sym}</span>
        </span>
      ))}
    </div>
  );
}

function detailText(d: SupplyChainRisk["detail"]): string {
  if (d == null) return "";
  if (typeof d === "string") return d;
  try {
    return Object.entries(d)
      .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
      .join(" · ");
  } catch {
    return "";
  }
}

/* ------------------------------- tiles --------------------------------- */

function HeaderTiles({ ecosystemsFallback }: { ecosystemsFallback: number }) {
  const q = useQuery({ queryKey: ["sbom-summary"], queryFn: getSbomSummary, staleTime: 20_000 });
  const s = q.data ?? {};
  const risks: number = s.by_risk_type
    ? Object.values(s.by_risk_type).reduce((a: number, b) => a + (b ?? 0), 0)
    : 0;
  const ecosystems: number =
    s.ecosystems ?? (s.by_ecosystem ? Object.keys(s.by_ecosystem).length : ecosystemsFallback);
  return (
    <div className="stat-row">
      <StatTile label="Components" value={s.components ?? 0} accent="#9fc2d8" />
      <StatTile label="Vulnerable" value={s.vulnerable_components ?? 0} accent={SEV_COLOR.high} />
      <StatTile label="Supply-chain risks" value={risks} accent={SEV_COLOR.critical} />
      <StatTile label="Ecosystems" value={ecosystems} accent="#c9b5e0" />
    </div>
  );
}

/* --------------------------- component drawer -------------------------- */

function ComponentDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({
    queryKey: ["sbom-component", id],
    queryFn: () => getSbomComponent(id),
    staleTime: 15_000,
  });
  const c = q.data;

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" aria-label="component detail">
        <header>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className="mono" style={{ color: "var(--text-2)", fontSize: 11, textTransform: "uppercase" }}>
              component
            </span>
            <strong style={{ fontSize: 13 }}>Dependency</strong>
          </div>
          <button className="ghost" onClick={onClose} aria-label="close">✕</button>
        </header>
        <div className="body">
          {q.isLoading && <div style={{ padding: 4, color: "var(--text-2)" }}>Loading component…</div>}
          {q.isError && <div style={{ padding: 4, color: "var(--bad)" }}>Failed to load component.</div>}
          {c && (
            <>
              <div className="section">
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <span
                    className="eco-chip mono"
                    style={{ color: ecosystemColor(c.ecosystem), borderColor: ecosystemColor(c.ecosystem) }}
                  >
                    {c.ecosystem}
                  </span>
                  <span className={`dep-tag mono ${c.direct ? "direct" : "transitive"}`}>
                    {c.direct ? "direct" : `transitive · d${c.depth}`}
                  </span>
                </div>
                <div className="mono" style={{ marginTop: 8, fontSize: 14, color: "var(--text-0)", wordBreak: "break-all" }}>
                  {c.name}
                  <span style={{ color: "var(--text-2)" }}>@{c.version}</span>
                </div>
                {c.purl && (
                  <div className="mono" style={{ marginTop: 4, fontSize: 11, color: "var(--text-2)", wordBreak: "break-all" }}>
                    {c.purl}
                  </div>
                )}
              </div>

              {c.paths && c.paths.length > 0 && (
                <div className="section">
                  <h3>Dependency paths</h3>
                  <ul style={{ margin: "6px 0 0", padding: 0, listStyle: "none", display: "flex", flexDirection: "column", gap: 4 }}>
                    {c.paths.slice(0, 8).map((p, i) => (
                      <li key={i} className="mono" style={{ fontSize: 11, color: "var(--text-1)", wordBreak: "break-all" }}>
                        {p}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="section">
                <h3>Vulnerabilities ({c.vulns?.length ?? 0})</h3>
                {(c.vulns ?? []).length === 0 ? (
                  <div style={{ color: "var(--text-2)", fontSize: 12, marginTop: 6 }}>
                    No known vulnerabilities for this version.
                  </div>
                ) : (
                  <div className="vuln-list">
                    {(c.vulns ?? []).map((v) => (
                      <div key={v.osv_id} className="vuln-card">
                        <div className="vuln-head">
                          <SeverityChip severity={v.severity} compact />
                          <span className="vuln-osv mono">{v.osv_id}</span>
                          {v.cve_id && (
                            <a
                              className="vuln-cve mono"
                              href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve_id)}`}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              {v.cve_id}
                            </a>
                          )}
                          {v.cvss != null && <span className="vuln-cvss mono">CVSS {v.cvss}</span>}
                        </div>
                        {v.reachability && (
                          <div className="vuln-reach">
                            <ReachabilityBadge grade={v.reachability} compact />
                            {v.reachable_symbol && (
                              <span className="vuln-reach-sym mono" title="affected symbol">
                                {v.reachable_symbol}
                              </span>
                            )}
                          </div>
                        )}
                        <CallPath path={v.call_path} />
                        {v.summary && <p className="vuln-summary">{v.summary}</p>}
                        {v.fixed_version ? (
                          <div className="vuln-fix mono">
                            upgrade to <strong>{v.fixed_version}</strong>
                          </div>
                        ) : (
                          <div className="vuln-fix mono none">no fixed version published</div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </aside>
    </>
  );
}

/* ----------------------------- sbom table ------------------------------ */

function SbomTable({ project }: { project: string | undefined }) {
  const [vulnOnly, setVulnOnly] = useState(false);
  const [reachableOnly, setReachableOnly] = useState(false);
  const [eco, setEco] = useState<string>("");
  const [text, setText] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const filter = useMemo<SbomComponentFilter>(
    () => ({
      project: project || undefined,
      vulnerable: vulnOnly || undefined,
      ecosystem: (eco || undefined) as Ecosystem | undefined,
      limit: COMPONENT_LIMIT,
    }),
    [project, vulnOnly, eco],
  );

  const q = useQuery({
    queryKey: ["sbom-components", filter],
    queryFn: () => listSbomComponents(filter),
    staleTime: 10_000,
  });

  const all = q.data?.items ?? [];

  // Ecosystem options derived from the loaded set (stable across text filter).
  const ecosystems = useMemo(() => {
    const set = new Set<string>();
    for (const c of all) set.add(c.ecosystem);
    return [...set].sort();
  }, [all]);

  const rows = useMemo(() => {
    const t = text.trim().toLowerCase();
    let narrowed = t
      ? all.filter(
          (c) =>
            c.name.toLowerCase().includes(t) ||
            c.version.toLowerCase().includes(t) ||
            (c.purl ?? "").toLowerCase().includes(t),
        )
      : all;
    // "Reachable only" — code-reachable vulns (client-side; drops the noise).
    if (reachableOnly) {
      narrowed = narrowed.filter(
        (c) => c.reachability === "reachable" || (c.reachable_vuln_count ?? 0) > 0,
      );
    }
    // Vulnerable first, then by vuln count desc, then name.
    return [...narrowed].sort(
      (a, b) => b.vuln_count - a.vuln_count || a.name.localeCompare(b.name),
    );
  }, [all, text, reachableOnly]);

  return (
    <div className="panel" style={{ padding: 0, display: "flex", flexDirection: "column", minHeight: 0 }}>
      <div className="panel-h" style={{ padding: "12px 14px 8px", marginBottom: 0 }}>
        <h2>SBOM</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>
          {rows.length} of {q.data?.total ?? all.length} components
        </span>
      </div>

      <div className="filterbar" style={{ borderRadius: 0, border: 0, borderBottom: "1px solid var(--border)" }}>
        <label
          className={`checkchip ${vulnOnly ? "on" : ""}`}
          style={vulnOnly ? { borderColor: SEV_COLOR.high, color: SEV_COLOR.high } : undefined}
        >
          <input type="checkbox" checked={vulnOnly} onChange={(e) => setVulnOnly(e.target.checked)} />
          Vulnerable only
        </label>
        <label
          className={`checkchip ${reachableOnly ? "on" : ""}`}
          style={reachableOnly ? { borderColor: SEV_COLOR.critical, color: SEV_COLOR.critical } : undefined}
          title="Only components with a code-reachable vulnerability"
        >
          <input
            type="checkbox"
            checked={reachableOnly}
            onChange={(e) => setReachableOnly(e.target.checked)}
          />
          Reachable only
        </label>
        <span className="sep" />
        <label>Ecosystem</label>
        <select value={eco} onChange={(e) => setEco(e.target.value)}>
          <option value="">Any</option>
          {ecosystems.map((x) => (
            <option key={x} value={x}>{x}</option>
          ))}
        </select>
        <span className="sep" />
        <input
          className="mono"
          style={{ flex: 1, minWidth: 140 }}
          value={text}
          placeholder="filter by name / version / purl…"
          onChange={(e) => setText(e.target.value)}
        />
      </div>

      <div className="dep-list">
        <div className="dep-row dep-row-r4 dep-head">
          <div>Ecosystem</div>
          <div>Package</div>
          <div>Scope</div>
          <div>Reachability</div>
          <div>Vulns</div>
        </div>
        {q.isLoading && <div style={{ padding: 12, color: "var(--text-2)" }}>Loading components…</div>}
        {q.isError && <div style={{ padding: 12, color: "var(--bad)" }}>Failed to load components.</div>}
        {!q.isLoading && rows.length === 0 && (
          <EmptyState title="No components match these filters." />
        )}
        {rows.map((c) => (
          <button
            key={c.id}
            type="button"
            className="dep-row dep-row-r4"
            onClick={() => setSelected(c.id)}
          >
            <div>
              <span
                className="eco-chip mono"
                style={{ color: ecosystemColor(c.ecosystem), borderColor: ecosystemColor(c.ecosystem) }}
              >
                {c.ecosystem}
              </span>
            </div>
            <div className="dep-pkg mono" title={`${c.name}@${c.version}`}>
              {c.name}
              <span style={{ color: "var(--text-2)" }}>@{c.version}</span>
            </div>
            <div>
              <span className={`dep-tag mono ${c.direct ? "direct" : "transitive"}`}>
                {c.direct ? "direct" : `transitive · d${c.depth}`}
              </span>
            </div>
            <div>
              {c.vuln_count > 0 || c.reachability ? (
                <ReachabilityBadge grade={c.reachability} count={c.reachable_vuln_count} />
              ) : (
                <span className="reach-badge mono reach-unknown" style={{ borderColor: "var(--border)" }}>
                  —
                </span>
              )}
            </div>
            <div>
              <VulnBadge component={c} />
            </div>
          </button>
        ))}
      </div>

      {selected && <ComponentDrawer id={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

/* ------------------------- supply-chain risks -------------------------- */

function SupplyChainPanel() {
  const q = useQuery({
    queryKey: ["supply-chain-risks"],
    queryFn: () => listSupplyChainRisks({ limit: 300 }),
    staleTime: 15_000,
  });
  const risks = q.data ?? [];

  const byType = useMemo(() => {
    const m = new Map<string, SupplyChainRisk[]>();
    for (const r of risks) {
      const k = r.risk_type;
      (m.get(k) ?? m.set(k, []).get(k)!).push(r);
    }
    return m;
  }, [risks]);

  // Known categories first (canonical order), then any extras seen.
  const types = useMemo(() => {
    const extras = [...byType.keys()].filter((t) => !RISK_TYPE_ORDER.includes(t));
    return [...RISK_TYPE_ORDER, ...extras];
  }, [byType]);

  return (
    <div className="panel">
      <div className="panel-h">
        <h2>Supply-chain risk</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>
          {risks.length} exposure{risks.length === 1 ? "" : "s"} · detection only
        </span>
      </div>

      {q.isLoading && <div style={{ color: "var(--text-2)", fontSize: 12 }}>Loading supply-chain risks…</div>}

      <div className="risk-groups">
        {types.map((t) => {
          const list = (byType.get(t) ?? []).slice().sort(
            (a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.summary.localeCompare(b.summary),
          );
          return (
            <section key={t} className="risk-group">
              <div className="risk-group-h">
                <span className="risk-group-name">{riskTypeLabel(t)}</span>
                <span className="risk-group-n mono">{list.length}</span>
              </div>
              {list.length === 0 ? (
                <div className="risk-empty mono">none detected</div>
              ) : (
                <div className="risk-cards">
                  {list.map((r) => {
                    const detail = detailText(r.detail);
                    const color = SEV_COLOR[r.severity] ?? SEV_COLOR.info;
                    return (
                      <article key={r.id} className="risk-card" style={{ borderLeftColor: color }}>
                        <div className="risk-card-h">
                          <SeverityChip severity={r.severity} compact />
                          <span className="risk-summary">{r.summary}</span>
                        </div>
                        {detail && <p className="risk-detail">{detail}</p>}
                      </article>
                    );
                  })}
                </div>
              )}
            </section>
          );
        })}
      </div>
    </div>
  );
}

/* --------------------------- code (SAST) ------------------------------- */

const CODE_SEV_LIST: Severity[] = ["critical", "high", "medium", "low", "info"];

/** One expandable SAST finding row with its source→sink dataflow trace. */
function CodeFindingRow({ f }: { f: CodeFinding }) {
  const [open, setOpen] = useState(false);
  const steps = f.dataflow ?? [];
  const lineLabel =
    f.end_line && f.end_line !== f.start_line
      ? `${f.file}:${f.start_line}-${f.end_line}`
      : `${f.file}:${f.start_line}`;
  return (
    <div className={`sast-item${open ? " open" : ""}`}>
      <button type="button" className="sast-row" onClick={() => setOpen((o) => !o)}>
        <div>
          <SeverityChip severity={f.severity} compact />
        </div>
        <div className="sast-rule mono" title={f.rule}>
          {f.rule}
          {f.cwe && <span className="sast-cwe">{f.cwe}</span>}
        </div>
        <div className="sast-loc mono" title={lineLabel}>
          {lineLabel}
        </div>
        <div className="sast-msg" title={f.message}>
          {f.message}
        </div>
        <div className="sast-exp mono" aria-hidden>
          {steps.length > 0 ? (open ? "▾" : `▸ ${steps.length}`) : ""}
        </div>
      </button>
      {open && (
        <div className="sast-detail">
          {(f.source || f.sink) && (
            <div className="sast-ss mono">
              {f.source && <span className="sast-ss-node source">{f.source}</span>}
              <span className="sast-ss-arrow">→</span>
              {f.sink && <span className="sast-ss-node sink">{f.sink}</span>}
            </div>
          )}
          {steps.length === 0 ? (
            <div className="sast-noflow">No dataflow trace recorded for this finding.</div>
          ) : (
            <ol className="dataflow">
              {steps.map((s, i) => {
                const role = s.kind ?? (i === 0 ? "source" : i === steps.length - 1 ? "sink" : "propagation");
                return (
                  <li key={i} className={`dataflow-step role-${role}`}>
                    <span className="dataflow-dot" aria-hidden />
                    <div className="dataflow-body">
                      <div className="dataflow-head">
                        <span className="dataflow-loc mono">
                          {s.file}:{s.line}
                        </span>
                        <span className="dataflow-role">{role}</span>
                      </div>
                      {s.note && <div className="dataflow-note">{s.note}</div>}
                      {s.code && <pre className="dataflow-code mono">{s.code}</pre>}
                    </div>
                  </li>
                );
              })}
            </ol>
          )}
        </div>
      )}
    </div>
  );
}

function CodeFindingsPanel({ project }: { project: string | undefined }) {
  const [sev, setSev] = useState<Severity | "">("");

  const filter = useMemo<CodeFindingFilter>(
    () => ({ project: project || undefined, severity: sev || undefined, limit: 300 }),
    [project, sev],
  );

  const q = useQuery({
    queryKey: ["code-findings", filter],
    queryFn: () => listCodeFindings(filter),
    staleTime: 10_000,
  });

  const rows = useMemo(() => {
    const items = q.data?.items ?? [];
    return [...items].sort(
      (a, b) =>
        SEV_RANK[b.severity] - SEV_RANK[a.severity] ||
        a.file.localeCompare(b.file) ||
        a.start_line - b.start_line,
    );
  }, [q.data]);

  return (
    <div className="panel" style={{ padding: 0, display: "flex", flexDirection: "column", minHeight: 0 }}>
      <div className="panel-h" style={{ padding: "12px 14px 8px", marginBottom: 0 }}>
        <h2>Code (SAST)</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>
          {q.data?.total ?? rows.length} finding{(q.data?.total ?? rows.length) === 1 ? "" : "s"} · source→sink taint traces
        </span>
      </div>

      <div className="filterbar" style={{ borderRadius: 0, border: 0, borderBottom: "1px solid var(--border)" }}>
        <label>Severity</label>
        <select value={sev} onChange={(e) => setSev(e.target.value as Severity | "")}>
          <option value="">Any</option>
          {CODE_SEV_LIST.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <span className="sep" />
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>
          static analysis — click a row to expand its dataflow
        </span>
      </div>

      <div className="sast-list">
        <div className="sast-row sast-head">
          <div>Sev</div>
          <div>Rule</div>
          <div>Location</div>
          <div>Message</div>
          <div />
        </div>
        {q.isLoading && <div style={{ padding: 12, color: "var(--text-2)" }}>Loading code findings…</div>}
        {q.isError && <div style={{ padding: 12, color: "var(--bad)" }}>Failed to load code findings.</div>}
        {!q.isLoading && !q.isError && rows.length === 0 && (
          <EmptyState
            title="No SAST findings."
            hint="The codeanalysis service runs Semgrep (or a bundled taint scanner) over first-party source on each sweep."
          />
        )}
        {rows.map((f) => (
          <CodeFindingRow key={f.id} f={f} />
        ))}
      </div>
    </div>
  );
}

/* ------------------------------- page ---------------------------------- */

export default function DependenciesPage() {
  const projectsQ = useQuery({
    queryKey: ["sbom-projects"],
    queryFn: listSbomProjects,
    staleTime: 30_000,
  });
  const projects = projectsQ.data ?? [];
  const [project, setProject] = useState<string>("");

  // Fallback ecosystem count for the header tile when the summary omits it:
  // union across project.ecosystems (cheap, already loaded).
  const ecosystemsFallback = useMemo(() => {
    const set = new Set<string>();
    for (const p of projects) for (const e of p.ecosystems ?? []) set.add(e);
    return set.size;
  }, [projects]);

  const selectedProject = project || (projects.length === 1 ? projects[0].id : "");

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Dependencies</h1>
          <div className="subtitle">
            Software composition — the SBOM, its known-vulnerable components, and defensive
            supply-chain exposures. Read-only; detection, not attack tooling.
          </div>
        </div>
      </div>

      <HeaderTiles ecosystemsFallback={ecosystemsFallback} />

      {projects.length > 1 && (
        <div className="filterbar">
          <label>Project</label>
          <select value={selectedProject} onChange={(e) => setProject(e.target.value)}>
            <option value="">All projects</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
                {p.component_count != null ? ` · ${p.component_count} comp` : ""}
              </option>
            ))}
          </select>
        </div>
      )}

      <div className="deps-grid">
        <SbomTable project={selectedProject || undefined} />
        <SupplyChainPanel />
      </div>

      <CodeFindingsPanel project={selectedProject || undefined} />
    </div>
  );
}
