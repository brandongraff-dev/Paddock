import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import StatTile from "../components/StatTile";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import {
  approveAction,
  denyAction,
  listActions,
  listAgents,
  proposeAction,
  revertAction,
  type Action,
  type ActionStatus,
  type ActionType,
  type Agent,
} from "../api/fleet";
import { useStore } from "../state/store";
import "../styles/fleet.css";

/* ------------------------------- helpers ------------------------------- */

const PROPOSABLE: Exclude<ActionType, "revert">[] = [
  "block_ip",
  "block_domain",
  "quarantine_file",
  "firewall_rule",
];

const STATUS_COLOR: Record<ActionStatus, string> = {
  proposed: "#e3b265",
  approved: "#9fc2d8",
  applied: "#8fbf8a",
  failed: "#e67350",
  reverted: "#b9a3d6",
  denied: "#7d7468",
};

const AGENT_DOT: Record<string, string> = {
  online: "#8fbf8a",
  enrolled: "#9fc2d8",
  stale: "#e3b265",
  offline: "#7d7468",
  revoked: "#e67350",
};

function relTime(iso: string | null): string {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 60) return `${Math.max(s, 0)}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

/* ------------------------------- agents -------------------------------- */

function AgentCard({ agent, onSelect, selected }: {
  agent: Agent;
  onSelect: (id: string) => void;
  selected: boolean;
}) {
  const dot = AGENT_DOT[agent.status] ?? "#7d7468";
  return (
    <button
      type="button"
      className={`fl-agent${selected ? " selected" : ""}`}
      onClick={() => onSelect(agent.id)}
    >
      <div className="fl-agent-top">
        <span className="fl-dot" style={{ background: dot, boxShadow: `0 0 6px ${dot}` }} />
        <span className="fl-agent-host mono">{agent.hostname}</span>
        <span className="fl-agent-platform">{agent.platform ?? "?"}</span>
      </div>
      <div className="fl-agent-meta">
        <span className={`fl-agent-status s-${agent.status}`}>{agent.status}</span>
        <span className="fl-muted">seen {relTime(agent.last_seen)}</span>
      </div>
      <div className="fl-caps">
        {agent.capabilities.map((c) => (
          <span key={c} className="fl-cap mono">{c}</span>
        ))}
      </div>
    </button>
  );
}

function AgentsPanel({ agents, selected, onSelect }: {
  agents: Agent[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="panel fl-agents">
      <div className="panel-h">
        <h2>Agents</h2>
        <span className="panel-sub">{agents.length} enrolled · host-local only</span>
      </div>
      {agents.length === 0 ? (
        <EmptyState
          title="No agents enrolled."
          hint="The agent runs ON a host (opt-in). Enroll with `paddock enroll --server … --token …`."
        />
      ) : (
        <div className="fl-agent-list">
          {agents.map((a) => (
            <AgentCard key={a.id} agent={a} selected={a.id === selected} onSelect={onSelect} />
          ))}
        </div>
      )}
    </div>
  );
}

/* --------------------------- propose (operator) ------------------------ */

function ProposePanel({ agents }: { agents: Agent[] }) {
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);
  const [agentId, setAgentId] = useState("");
  const [type, setType] = useState<Exclude<ActionType, "revert">>("block_ip");
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");

  const propose = useMutation({
    mutationFn: () =>
      proposeAction({ agent_id: agentId, action_type: type, target: target.trim(), reason: reason.trim() || undefined }),
    onSuccess: () => {
      pushToast({ text: "Action proposed (dry-run, awaiting approval)." });
      setTarget("");
      setReason("");
      qc.invalidateQueries({ queryKey: ["fleet-actions"] });
    },
    onError: (e: unknown) =>
      pushToast({ text: `Propose refused: ${(e as Error)?.message ?? "error"}`, severity: "high" }),
  });

  const placeholder: Record<string, string> = {
    block_ip: "203.0.113.10 (a single IP to drop on THIS host)",
    block_domain: "evil.example (sinkholed in /etc/hosts on THIS host)",
    quarantine_file: "/var/tmp/suspicious.bin (moved, never deleted)",
    firewall_rule: "in:tcp:3389 (local port rule)",
  };
  const canPropose = agentId && target.trim().length > 0;

  return (
    <div className="panel fl-propose">
      <div className="panel-h">
        <h2>Propose action</h2>
        <span className="panel-sub">host-local · dry-run · needs approval</span>
      </div>
      <form
        className="fl-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (canPropose) propose.mutate();
        }}
      >
        <div className="field">
          <label>Agent (host)</label>
          <select value={agentId} onChange={(e) => setAgentId(e.target.value)}>
            <option value="">select a host…</option>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>{a.hostname}</option>
            ))}
          </select>
        </div>
        <div className="fl-form-grid">
          <div className="field">
            <label>Action</label>
            <select value={type} onChange={(e) => setType(e.target.value as typeof type)}>
              {PROPOSABLE.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label>Target (on that host)</label>
            <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={placeholder[type]} />
          </div>
        </div>
        <div className="field">
          <label>Reason</label>
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. matches threat-intel indicator X" />
        </div>
        <div className="fl-form-foot">
          <span className="fl-note">
            Proposing never changes a host. It creates a dry-run request an admin must approve.
          </span>
          <button type="submit" className="primary" disabled={!canPropose || propose.isPending}>
            {propose.isPending ? "Proposing…" : "Propose (dry-run)"}
          </button>
        </div>
      </form>
    </div>
  );
}

/* ------------------------------ actions queue -------------------------- */

function DryRunBadge({ dry }: { dry: boolean }) {
  return (
    <span className={`fl-badge ${dry ? "dry" : "real"}`} title={dry ? "simulation only" : "real host change"}>
      {dry ? "DRY-RUN" : "REAL"}
    </span>
  );
}

function ActionRow({ a, agents }: { a: Action; agents: Agent[] }) {
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);
  const host = agents.find((g) => g.id === a.agent_id)?.hostname ?? a.agent_id.slice(0, 8);
  const color = STATUS_COLOR[a.status];

  const invalidate = () => qc.invalidateQueries({ queryKey: ["fleet-actions"] });
  const onErr = (e: unknown) =>
    pushToast({ text: `Refused: ${(e as Error)?.message ?? "error"}`, severity: "high" });

  const approveDry = useMutation({
    mutationFn: () => approveAction(a.id, false),
    onSuccess: () => { pushToast({ text: "Approved (dry-run)." }); invalidate(); },
    onError: onErr,
  });
  const approveReal = useMutation({
    mutationFn: () => approveAction(a.id, true),
    onSuccess: () => { pushToast({ text: "Approved for REAL apply." }); invalidate(); },
    onError: onErr,
  });
  const deny = useMutation({
    mutationFn: () => denyAction(a.id),
    onSuccess: () => { pushToast({ text: "Denied." }); invalidate(); },
    onError: onErr,
  });
  const revert = useMutation({
    mutationFn: () => revertAction(a.id),
    onSuccess: () => { pushToast({ text: "Revert action queued." }); invalidate(); },
    onError: onErr,
  });

  return (
    <div className="fl-action-row">
      <div className="fl-action-main">
        <div className="fl-action-head">
          <span className="fl-status-chip" style={{ color, borderColor: color }}>{a.status}</span>
          <span className="fl-action-type mono">{a.action_type}</span>
          <span className="fl-action-target mono">{a.target}</span>
          <DryRunBadge dry={a.dry_run} />
          <span className="fl-action-host mono" title="host-local target">@{host}</span>
        </div>
        <div className="fl-action-meta">
          {a.reason && <span className="fl-reason">{a.reason}</span>}
          <span className="fl-muted">req {a.requested_by ?? "—"}</span>
          {a.approved_by && <span className="fl-muted">· appr {a.approved_by}</span>}
          <span className="fl-muted">· {relTime(a.created_at)}</span>
        </div>
      </div>
      <div className="fl-action-controls">
        {a.status === "proposed" && (
          <Gate need="admin" title="Admin-only — approve/deny is gated">
            <button className="ghost ok" onClick={() => approveDry.mutate()}
                    title="approve as a dry-run simulation">
              approve (dry-run)
            </button>
            <button className="primary" onClick={() => approveReal.mutate()}
                    title="approve a REAL host change (four-eyes: you must not be the requester)">
              approve · real
            </button>
            <button className="ghost danger" onClick={() => deny.mutate()}>deny</button>
          </Gate>
        )}
        {a.status === "approved" && (
          <span className="fl-muted">awaiting agent{a.dry_run ? " (dry-run)" : " (real)"}</span>
        )}
        {a.status === "applied" && (
          <Gate need="admin" title="Admin-only — revert is gated">
            <button className="ghost" onClick={() => revert.mutate()} title="undo this block (reversible)">
              revert
            </button>
          </Gate>
        )}
      </div>
    </div>
  );
}

function ActionsPanel({ agents, selected }: { agents: Agent[]; selected: string | null }) {
  const [status, setStatus] = useState<ActionStatus | "">("");
  const filter = useMemo(
    () => ({ agent: selected || undefined, status: status || undefined }),
    [selected, status],
  );
  const q = useQuery({
    queryKey: ["fleet-actions", filter],
    queryFn: () => listActions(filter),
    staleTime: 8_000,
    refetchInterval: 15_000,
  });
  const items = q.data?.items ?? [];

  return (
    <div className="panel fl-actions">
      <div className="panel-h">
        <h2>Enforcement queue</h2>
        <span className="panel-sub">
          proposed → approved → applied · {q.data?.total ?? 0} total
        </span>
      </div>
      <div className="fl-filterbar">
        <select value={status} onChange={(e) => setStatus(e.target.value as ActionStatus | "")}>
          <option value="">all statuses</option>
          {(["proposed", "approved", "applied", "failed", "reverted", "denied"] as ActionStatus[]).map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        {selected && <span className="fl-muted">filtered to selected host</span>}
      </div>
      <div className="fl-action-list">
        {q.isLoading && <div className="fl-muted">Loading actions…</div>}
        {!q.isLoading && items.length === 0 && (
          <EmptyState title="No actions." hint="Propose a host-local block above; it starts as a dry-run awaiting approval." />
        )}
        {items.map((a) => (
          <ActionRow key={a.id} a={a} agents={agents} />
        ))}
      </div>
    </div>
  );
}

/* -------------------------------- page --------------------------------- */

export default function FleetPage() {
  const [selected, setSelected] = useState<string | null>(null);
  const agentsQ = useQuery({
    queryKey: ["fleet-agents"],
    queryFn: listAgents,
    staleTime: 10_000,
    refetchInterval: 20_000,
  });
  const agents = agentsQ.data ?? [];

  const counts = useMemo(() => {
    const online = agents.filter((a) => a.status === "online").length;
    const stale = agents.filter((a) => a.status === "stale").length;
    return { total: agents.length, online, stale };
  }, [agents]);

  return (
    <div className="page fl-page">
      <div className="page-header">
        <div>
          <h1>Fleet &amp; Enforcement</h1>
          <div className="subtitle">
            Host agents report inventory and can apply <strong>host-local, defensive</strong> blocks —
            but only through <strong>propose → approve → apply</strong>: dry-run by default, nothing
            applies without an admin approval (four-eyes), every block is reversible, and every
            transition is written to the tamper-evident audit log. Agents act only on the host they
            run on; nothing here scans or touches a remote machine.
          </div>
        </div>
      </div>

      <div className="stat-row">
        <StatTile label="Agents" value={counts.total} accent="#9fc2d8" />
        <StatTile label="Online" value={counts.online} accent="#8fbf8a" />
        <StatTile label="Stale" value={counts.stale} accent="#e3b265" />
      </div>

      <div className="fl-grid">
        <AgentsPanel agents={agents} selected={selected} onSelect={(id) => setSelected((p) => (p === id ? null : id))} />
        <ProposePanel agents={agents} />
      </div>

      <ActionsPanel agents={agents} selected={selected} />
    </div>
  );
}
