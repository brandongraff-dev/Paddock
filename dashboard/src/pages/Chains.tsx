import { useChains } from "../hooks/useFindings";
import SeverityChip from "../components/Severity";
import EmptyState from "../components/EmptyState";
import ChainMiniGraph from "../components/chain/ChainMiniGraph";

export default function ChainsPage() {
  const q = useChains();

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Chains</h1>
          <div className="subtitle">Correlated multi-finding narratives produced by the correlation service.</div>
        </div>
      </div>

      {q.isLoading && <div style={{ color: "var(--text-2)" }}>Loading chains…</div>}
      {q.isError && <div style={{ color: "var(--bad)" }}>Failed to load chains.</div>}
      {q.data?.length === 0 && (
        <EmptyState title="No chains correlated yet." hint="Chains appear once the correlation service finds multiple findings that compose into a higher-severity narrative." />
      )}

      <div>
        {(q.data ?? []).map((c) => (
          <article key={c.id} className={`chain-card sev-${c.severity}`}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <SeverityChip severity={c.severity} />
              <h2>{c.title}</h2>
            </div>
            <div className="meta">
              <span className="mono">{c.chain_rule_id}</span>
              {c.blast_radius_score != null && (
                <span>blast <strong className="mono" style={{ color: "var(--sev-high)" }}>{c.blast_radius_score}</strong></span>
              )}
              <span>based on <strong>{c.finding_ids.length}</strong> findings</span>
              <span className="mono">{new Date(c.created_at).toISOString().slice(0, 16).replace("T", " ")}</span>
            </div>
            <p style={{ color: "var(--text-1)", marginTop: 8 }}>{c.description}</p>

            {/* Inline finding-sequence graph: anchor → findings, click opens drawer. */}
            <ChainMiniGraph chain={c} />

            {c.impact_narrative && (
              <blockquote>{c.impact_narrative}</blockquote>
            )}
            {c.findings && c.findings.length > 0 && (
              <details>
                <summary>Component findings ({c.findings.length})</summary>
                <ul>
                  {c.findings.map((f) => (
                    <li key={f.id} style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 0" }}>
                      <SeverityChip severity={f.severity} compact />
                      <span style={{ fontSize: 12 }}>{f.title}</span>
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </article>
        ))}
      </div>
    </div>
  );
}
