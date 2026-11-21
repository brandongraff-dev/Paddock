/**
 * Scope admin — defensive UX:
 *   - Audit log is prominent (expandable row per entry).
 *   - Creating a wildcard entry (kind === "subdomain_wildcard" or a "*." value)
 *     requires an explicit confirm modal that spells out the blast impact.
 *   - Proof-of-control: each entry shows whether ownership is proven, and
 *     domains can be proven inline (DNS TXT / HTTPS file); IP ranges and ASNs
 *     are attested (LOA reference + approver).
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  addScopeEntry,
  deactivateScopeEntry,
  entryDecisions,
  listScope,
} from "../api/scope";
import { issueChallenge, verifyScope } from "../api/onboarding";
import type { ScopeEntry, ScopeKind } from "../api/types";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";

const KINDS: ScopeKind[] = ["domain", "subdomain_wildcard", "ipv4_cidr", "ipv6_cidr", "asn"];

const PLACEHOLDER: Record<ScopeKind, string> = {
  domain: "app.example.com",
  subdomain_wildcard: "example.com (covers *.example.com)",
  ipv4_cidr: "203.0.113.0/24",
  ipv6_cidr: "2001:db8::/48",
  asn: "AS64500",
};

const PROOF_TONE: Record<string, string> = {
  verified: "var(--ok)", attested: "var(--ok)", pending: "var(--warn)", expired: "var(--bad)",
};

function ProofBadge({ e }: { e: ScopeEntry }) {
  const p = e.proof;
  if (!p) return <span className="mono" style={{ color: "var(--text-2)" }}>—</span>;
  const failing = p.status === "verified" && p.failing_since;
  const label = failing ? "verified · failing" : p.status;
  const tone = failing ? "var(--warn)" : PROOF_TONE[p.status] ?? "var(--text-2)";
  return (
    <span
      className="chip"
      style={{ color: tone, borderColor: tone }}
      title={
        p.required && !p.effective
          ? "Not authorising scans until ownership is proven"
          : p.last_error ?? (p.method ? `via ${p.method}` : "")
      }
    >
      {label}
      {p.required && !p.effective ? " · blocked" : ""}
    </span>
  );
}

function ProofPanel({ e, onDone }: { e: ScopeEntry; onDone: () => void }) {
  const id = Number(e.id);
  const isDomain = e.kind === "domain" || e.kind === "subdomain_wildcard";
  const [loa, setLoa] = useState("");
  const [approver, setApprover] = useState("");
  const challenge = useQuery({
    queryKey: ["scope-challenge", e.id],
    queryFn: () => issueChallenge(id),
    enabled: isDomain,
    staleTime: Infinity,
  });
  const verify = useMutation({
    mutationFn: () =>
      verifyScope(id, isDomain ? {} : { method: "attestation", loa_ref: loa, approver }),
    onSuccess: onDone,
  });
  const copy = (t: string) => {
    try { void navigator.clipboard?.writeText(t); } catch { /* clipboard unavailable */ }
  };
  return (
    <div className="proof-panel" onClick={(ev) => ev.stopPropagation()}>
      {isDomain ? (
        challenge.data ? (
          <>
            <p>Publish <b>one</b> of these, then check:</p>
            <div className="proof-row">
              <span className="label">DNS TXT</span>
              <code>{challenge.data.dns_txt.name}</code>
              <code>{challenge.data.dns_txt.value}</code>
              <button className="ghost" onClick={() => copy(challenge.data!.dns_txt.value)}>copy</button>
            </div>
            {challenge.data.http_file && (
              <div className="proof-row">
                <span className="label">HTTPS file</span>
                <code>{challenge.data.http_file.url}</code>
                <code>{challenge.data.http_file.body}</code>
                <button className="ghost" onClick={() => copy(challenge.data!.http_file!.body)}>copy</button>
              </div>
            )}
          </>
        ) : (
          <p>{challenge.isError ? "Could not issue a challenge." : "Issuing challenge…"}</p>
        )
      ) : (
        <div className="proof-row">
          <span className="label">Attest</span>
          <input placeholder="LOA / contract reference" value={loa} onChange={(ev) => setLoa(ev.target.value)} />
          <input placeholder="Approver (name, role)" value={approver} onChange={(ev) => setApprover(ev.target.value)} />
        </div>
      )}
      <div className="proof-actions">
        <button
          className="primary"
          disabled={verify.isPending || (!isDomain && (!loa.trim() || !approver.trim()))}
          onClick={() => verify.mutate()}
        >
          {isDomain ? "Check now" : "Record attestation"}
        </button>
        {verify.data && (
          <span style={{ color: verify.data.check.ok ? "var(--ok)" : "var(--bad)" }}>
            {verify.data.check.ok ? "Proven" : verify.data.check.detail}
          </span>
        )}
      </div>
    </div>
  );
}

function ConfirmWildcard({
  entry,
  onConfirm,
  onCancel,
}: {
  entry: { kind: ScopeKind; value: string };
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const [typed, setTyped] = useState("");
  const required = `ALLOW ${entry.value}`;
  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <header style={{ borderColor: "var(--bad)", color: "var(--bad)" }}>
          Confirm broad scope entry
        </header>
        <div className="body">
          <div style={{ color: "var(--text-1)" }}>
            You're about to add a <strong>{entry.kind}</strong> entry with value{" "}
            <code className="mono" style={{ color: "var(--bad)" }}>{entry.value}</code>.
          </div>
          <div style={{ color: "var(--text-1)" }}>
            Impact: workers will treat this as permission to probe any target
            matching this pattern. Scope decisions are logged, but a broad
            entry significantly widens the blast radius of every scan.
          </div>
          <div style={{ color: "var(--text-1)" }}>
            To proceed, type <code className="mono">{required}</code> exactly:
          </div>
          <input
            autoFocus
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder={required}
          />
        </div>
        <div className="foot">
          <button onClick={onCancel}>Cancel</button>
          <button
            className="danger"
            disabled={typed !== required}
            onClick={onConfirm}
          >
            Add anyway
          </button>
        </div>
      </div>
    </div>
  );
}

function AuditLog({ entryId }: { entryId: string }) {
  const q = useQuery({
    queryKey: ["scope-decisions", entryId],
    queryFn: () => entryDecisions(entryId, 10),
  });
  if (q.isLoading) return <div style={{ color: "var(--text-2)", padding: 8 }}>Loading audit…</div>;
  if (q.isError) return <div style={{ color: "var(--text-2)", padding: 8 }}>No audit available.</div>;
  if (!q.data?.length) return <div style={{ color: "var(--text-2)", padding: 8 }}>No recent decisions.</div>;
  return (
    <table className="table" style={{ background: "var(--bg-1)" }}>
      <thead>
        <tr>
          <th>decided_at</th>
          <th>allow</th>
          <th>target</th>
          <th>normalized</th>
          <th>reason</th>
          <th>worker</th>
        </tr>
      </thead>
      <tbody>
        {q.data.map((d) => (
          <tr key={d.id} style={{ cursor: "default" }}>
            <td className="mono">{d.decided_at}</td>
            <td>
              <span
                className="chip"
                style={{
                  color: d.allow ? "var(--ok)" : "var(--bad)",
                  borderColor: d.allow ? "var(--ok)" : "var(--bad)",
                }}
              >
                {d.allow ? "allow" : "deny"}
              </span>
            </td>
            <td className="mono">{d.target}</td>
            <td className="mono">{d.normalized}</td>
            <td>{d.reason}</td>
            <td className="mono">{d.worker_id ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function ScopePage() {
  const qc = useQueryClient();
  const scope = useQuery({ queryKey: ["scope"], queryFn: listScope });
  const [kind, setKind] = useState<ScopeKind>("domain");
  const [value, setValue] = useState("");
  const [authRef, setAuthRef] = useState("");
  const [notes, setNotes] = useState("");
  const [addedBy] = useState("analyst@localhost");
  const [pendingWild, setPendingWild] = useState<
    | { kind: ScopeKind; value: string; auth_doc_ref?: string; notes?: string }
    | null
  >(null);

  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [proving, setProving] = useState<string | null>(null);

  const add = useMutation({
    mutationFn: addScopeEntry,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scope"] });
      setValue("");
      setAuthRef("");
      setNotes("");
      setPendingWild(null);
    },
  });

  const deactivate = useMutation({
    mutationFn: (id: string) => deactivateScopeEntry(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scope"] }),
  });

  const submit = (ev: React.FormEvent) => {
    ev.preventDefault();
    if (!value.trim()) return;
    const payload = {
      kind,
      value: value.trim(),
      added_by: addedBy,
      auth_doc_ref: authRef || undefined,
      notes: notes || undefined,
    };
    const broad = kind === "subdomain_wildcard" || value.trim() === "*" || value.trim().startsWith("*.");
    if (broad) {
      setPendingWild(payload);
      return;
    }
    add.mutate(payload);
  };

  const entries = scope.data ?? [];

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Scope</h1>
          <div className="subtitle">
            Authorizations and the audit log of every scope decision. Every outbound
            worker request passes through this allowlist.
          </div>
        </div>
      </div>

      <form className="panel" onSubmit={submit}>
        <div className="panel-h">
          <h2>Add entry</h2>
          <span style={{ color: "var(--text-2)", fontSize: 11 }}>
            All additions are audit-logged. Broad entries require confirmation.
          </span>
        </div>
        <Gate need="admin">
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "140px 1fr 1fr 1fr auto",
            gap: 8,
            alignItems: "end",
          }}
        >
          <div className="field">
            <label>Kind</label>
            <select value={kind} onChange={(e) => setKind(e.target.value as ScopeKind)}>
              {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
            </select>
          </div>
          <div className="field">
            <label>Value</label>
            <input value={value} onChange={(e) => setValue(e.target.value)} placeholder={PLACEHOLDER[kind]} required />
          </div>
          <div className="field">
            <label>Auth doc ref</label>
            <input value={authRef} onChange={(e) => setAuthRef(e.target.value)} placeholder="ticket:AUTH-123" />
          </div>
          <div className="field">
            <label>Notes</label>
            <input value={notes} onChange={(e) => setNotes(e.target.value)} />
          </div>
          <button type="submit" className="primary" disabled={add.isPending}>Add</button>
        </div>
        </Gate>
      </form>

      <div className="panel" style={{ padding: 0 }}>
        <div className="panel-h" style={{ padding: "10px 14px" }}>
          <h2>Active entries</h2>
          <span style={{ color: "var(--text-2)", fontSize: 11 }}>
            click a row to view its last 10 decisions
          </span>
        </div>
        {entries.length === 0 ? (
          <EmptyState title="No scope entries yet." hint="Add one above to authorize workers to probe a target." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>kind</th>
                <th>value</th>
                <th>added_by</th>
                <th>added_at</th>
                <th>auth_doc_ref</th>
                <th>expires_at</th>
                <th>ownership</th>
                <th>active</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {entries.flatMap((e: ScopeEntry) => {
                const isOpen = expanded.has(e.id);
                const mainRow = (
                  <tr
                    key={e.id}
                    className={isOpen ? "focused" : ""}
                    onClick={() =>
                      setExpanded((prev) => {
                        const next = new Set(prev);
                        if (next.has(e.id)) next.delete(e.id);
                        else next.add(e.id);
                        return next;
                      })
                    }
                  >
                    <td className="mono">{e.kind}</td>
                    <td
                      className="mono"
                      style={{ color: e.value === "*" ? "var(--bad)" : "var(--text-0)" }}
                    >
                      {e.value}
                    </td>
                    <td className="mono">{e.added_by}</td>
                    <td className="mono">{e.added_at}</td>
                    <td className="mono">{e.auth_doc_ref ?? "—"}</td>
                    <td className="mono">{e.expires_at ?? "—"}</td>
                    <td><ProofBadge e={e} /></td>
                    <td>
                      <span
                        className="chip"
                        style={{
                          color: e.active ? "var(--ok)" : "var(--text-2)",
                          borderColor: e.active ? "var(--ok)" : "var(--text-2)",
                        }}
                      >
                        {e.active ? "active" : "inactive"}
                      </span>
                    </td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      <Gate need="admin">
                        {e.active && e.proof && !["verified", "attested"].includes(e.proof.status) && (
                          <button
                            className="ghost"
                            onClick={(ev) => {
                              ev.stopPropagation();
                              setProving(proving === e.id ? null : e.id);
                            }}
                          >
                            {e.kind === "domain" || e.kind === "subdomain_wildcard" ? "prove ownership" : "attest"}
                          </button>
                        )}
                        <button
                          className="danger"
                          disabled={!e.active}
                          onClick={(ev) => {
                            ev.stopPropagation();
                            if (confirm(`Deactivate scope entry ${e.value}?`)) {
                              deactivate.mutate(e.id);
                            }
                          }}
                        >
                          deactivate
                        </button>
                      </Gate>
                    </td>
                  </tr>
                );
                const proofRow = proving === e.id ? (
                  <tr key={`${e.id}-proof`} style={{ cursor: "default" }}>
                    <td colSpan={9}>
                      <ProofPanel
                        e={e}
                        onDone={() => qc.invalidateQueries({ queryKey: ["scope"] })}
                      />
                    </td>
                  </tr>
                ) : null;
                const auditRow = isOpen ? (
                  <tr key={`${e.id}-audit`} style={{ cursor: "default" }}>
                    <td colSpan={9} style={{ padding: 0 }}>
                      <AuditLog entryId={e.id} />
                    </td>
                  </tr>
                ) : null;
                return [mainRow, proofRow, auditRow].filter(Boolean) as JSX.Element[];
              })}
            </tbody>
          </table>
        )}
      </div>

      {pendingWild && (
        <ConfirmWildcard
          entry={pendingWild}
          onConfirm={() => add.mutate({ ...pendingWild, added_by: addedBy })}
          onCancel={() => setPendingWild(null)}
        />
      )}
    </div>
  );
}
