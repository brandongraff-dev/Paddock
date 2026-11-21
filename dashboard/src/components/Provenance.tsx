/**
 * Provenance / lineage section (governance §B) for the finding & asset detail
 * drawers. Answers "where did this fact come from": source service, method,
 * evidence, confidence, recorded time — one card per record, newest first.
 */

import { useQuery } from "@tanstack/react-query";
import { listProvenance } from "../api/provenance";
import type { ProvenanceRecord } from "../api/types";

function fmtConfidence(c: number | null | undefined): string | null {
  if (c == null || Number.isNaN(c)) return null;
  // Accept either 0–1 or 0–100 and render as a percentage.
  const pct = c <= 1 ? c * 100 : c;
  return `${Math.round(pct)}%`;
}

function evidenceText(ev: ProvenanceRecord["evidence"]): string | null {
  if (ev == null) return null;
  if (typeof ev === "string") return ev;
  try {
    const s = JSON.stringify(ev);
    return s === "{}" ? null : s;
  } catch {
    return null;
  }
}

function Record({ p }: { p: ProvenanceRecord }) {
  const conf = fmtConfidence(p.confidence);
  const ev = evidenceText(p.evidence);
  return (
    <div className="prov-card">
      <div className="prov-head">
        <span className="prov-service mono">{p.source_service}</span>
        <span className="prov-method mono">{p.method}</span>
        {conf && <span className="prov-conf mono" title="confidence">{conf}</span>}
      </div>
      {p.source_detail && <div className="prov-detail">{p.source_detail}</div>}
      {ev && <div className="prov-evidence mono">{ev}</div>}
      <div className="prov-time mono" title={p.recorded_at}>
        recorded {p.recorded_at}
      </div>
    </div>
  );
}

export default function ProvenanceSection({
  subjectType,
  subjectId,
}: {
  subjectType: "finding" | "asset";
  subjectId: string;
}) {
  const q = useQuery({
    queryKey: ["provenance", subjectType, subjectId],
    queryFn: () => listProvenance(subjectType, subjectId),
    enabled: !!subjectId,
    staleTime: 30_000,
  });

  return (
    <div className="section">
      <h3>Provenance / lineage</h3>
      {q.isLoading && (
        <div style={{ color: "var(--text-2)", fontSize: 12, marginTop: 6 }}>Loading lineage…</div>
      )}
      {q.isError && (
        <div style={{ color: "var(--text-2)", fontSize: 12, marginTop: 6 }}>
          No provenance available.
        </div>
      )}
      {!q.isLoading && !q.isError && (q.data ?? []).length === 0 && (
        <div style={{ color: "var(--text-2)", fontSize: 12, marginTop: 6 }}>
          No recorded lineage for this item.
        </div>
      )}
      {(q.data ?? []).length > 0 && (
        <div className="prov-list">
          {(q.data ?? []).map((p, i) => (
            <Record key={p.id ?? `${p.source_service}-${p.recorded_at}-${i}`} p={p} />
          ))}
        </div>
      )}
    </div>
  );
}
