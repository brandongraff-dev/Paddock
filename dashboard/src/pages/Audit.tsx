/**
 * Audit log (governance §B) — auditor/admin only. The hash-chained,
 * tamper-evident record of every mutating + denied request and every read of
 * restricted data. The "Verify chain integrity" action is the centerpiece: it
 * walks the chain server-side and reports a crisp intact / broken verdict.
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { listAudit, verifyAudit, type AuditFilter } from "../api/audit";
import type { AuditEntry } from "../api/types";
import { ClassificationChip } from "../components/Classification";
import EmptyState from "../components/EmptyState";

const PAGE = 100;

function ResourceCell({ e }: { e: AuditEntry }) {
  return (
    <span className="audit-resource mono" title={`${e.resource_type}${e.resource_id ? ` / ${e.resource_id}` : ""}`}>
      <span className="audit-rtype">{e.resource_type}</span>
      {e.resource_id && <span className="audit-rid">{e.resource_id}</span>}
    </span>
  );
}

function VerifyPanel() {
  const verify = useMutation({ mutationFn: verifyAudit });
  const r = verify.data;
  return (
    <div className="audit-verify">
      <button className="primary audit-verify-btn" disabled={verify.isPending} onClick={() => verify.mutate()}>
        {verify.isPending ? "Verifying…" : "Verify chain integrity"}
      </button>
      {verify.isError && (
        <span className="audit-verdict err">Verification call failed.</span>
      )}
      {r && r.ok && (
        <span className="audit-verdict ok" role="status">
          <span className="audit-verdict-dot" />
          chain intact · {r.checked} entr{r.checked === 1 ? "y" : "ies"} verified
        </span>
      )}
      {r && !r.ok && (
        <span className="audit-verdict bad" role="status">
          <span className="audit-verdict-dot" />
          chain broken at #{String(r.first_broken_id ?? "?")} · {r.checked} verified before the break
        </span>
      )}
    </div>
  );
}

export default function AuditPage() {
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [applied, setApplied] = useState<AuditFilter>({});
  const [offset, setOffset] = useState(0);

  const filter = useMemo<AuditFilter>(
    () => ({ ...applied, limit: PAGE, offset }),
    [applied, offset],
  );

  const q = useQuery({
    queryKey: ["audit", filter],
    queryFn: () => listAudit(filter),
    staleTime: 10_000,
  });

  const apply = () => {
    setOffset(0);
    setApplied({
      actor: actor.trim() || undefined,
      action: action.trim() || undefined,
      from: from.trim() || undefined,
      to: to.trim() || undefined,
    });
  };

  const rows = q.data?.items ?? [];
  const total = q.data?.total ?? rows.length;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Audit log</h1>
          <div className="subtitle">
            Tamper-evident, hash-chained record of every governed action. Each entry is
            sealed by <code className="mono">sha256(prev_hash ‖ row)</code>.
          </div>
        </div>
      </div>

      <div className="panel audit-verify-panel">
        <VerifyPanel />
      </div>

      <div className="filterbar">
        <label>Actor</label>
        <input value={actor} onChange={(e) => setActor(e.target.value)} placeholder="username / key" style={{ width: 150 }} />
        <label>Action</label>
        <input value={action} onChange={(e) => setAction(e.target.value)} placeholder="e.g. finding.patch" style={{ width: 160 }} />
        <label>From</label>
        <input className="mono" value={from} onChange={(e) => setFrom(e.target.value)} placeholder="2026-01-01" style={{ width: 120 }} />
        <label>To</label>
        <input className="mono" value={to} onChange={(e) => setTo(e.target.value)} placeholder="2026-12-31" style={{ width: 120 }} />
        <span className="sep" />
        <button onClick={apply} disabled={q.isFetching}>Apply</button>
      </div>

      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        <div className="audit-list">
          <div className="audit-row audit-head">
            <div>Time</div>
            <div>Actor</div>
            <div>Role</div>
            <div>Action</div>
            <div>Resource</div>
            <div>Class.</div>
            <div>Justification</div>
          </div>
          {q.isLoading && <div style={{ padding: 12, color: "var(--text-2)" }}>Loading audit log…</div>}
          {q.isError && <div style={{ padding: 12, color: "var(--bad)" }}>Failed to load the audit log.</div>}
          {!q.isLoading && !q.isError && rows.length === 0 && (
            <EmptyState title="No audit entries match these filters." />
          )}
          {rows.map((e) => (
            <div className="audit-row" key={String(e.id)}>
              <div className="audit-ts mono" title={e.ts}>{e.ts}</div>
              <div className="audit-actor mono" title={e.actor}>{e.actor}</div>
              <div><span className="audit-role mono">{e.role}</span></div>
              <div className="audit-action mono" title={e.action}>{e.action}</div>
              <div><ResourceCell e={e} /></div>
              <div>{e.classification ? <ClassificationChip c={e.classification} compact /> : <span className="muted">—</span>}</div>
              <div className="audit-just" title={e.justification ?? ""}>
                {e.justification ?? <span className="muted">—</span>}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="audit-pager">
        <span className="muted mono">
          {rows.length === 0 ? "0" : `${offset + 1}–${offset + rows.length}`} of {total}
        </span>
        <span className="sp" />
        <button disabled={offset === 0 || q.isFetching} onClick={() => setOffset((o) => Math.max(0, o - PAGE))}>Prev</button>
        <button disabled={offset + rows.length >= total || q.isFetching} onClick={() => setOffset((o) => o + PAGE)}>Next</button>
      </div>
    </div>
  );
}
