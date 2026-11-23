/**
 * Settings → System (admin). What this install is made of: the Paddock
 * version, edition and profile, and one row per component with its health.
 * Services left out of a lite install show as "Not installed", which is
 * normal and not an error.
 */
import { useQuery } from "@tanstack/react-query";
import { getSystem, type ComponentStatus, type SystemComponent, type SystemInfo } from "../api/system";
import StatTile from "../components/StatTile";
import "../styles/system.css";

const EDITION_LABEL: Record<string, string> = {
  community: "Community",
  team: "Team",
  enterprise: "Enterprise",
  edge: "Edge",
};

const STATUS_LABEL: Record<ComponentStatus, string> = {
  up: "Running",
  down: "Not responding",
  not_installed: "Not installed",
};

export function StatusDot({ status }: { status: ComponentStatus }) {
  return (
    <span className="sys-status" data-status={status}>
      <i className="sys-dot" aria-hidden="true" />
      {STATUS_LABEL[status]}
    </span>
  );
}

function Rows({ rows }: { rows: SystemComponent[] }) {
  return (
    <table className="table sys-table">
      <thead>
        <tr><th>Component</th><th>What it does</th><th>Status</th></tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.key} data-key={r.key}>
            <td>{r.label}</td>
            <td className="sys-desc">{r.description}</td>
            <td><StatusDot status={r.status} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function headline(s: SystemInfo): { tone: "ok" | "warn" | "bad"; title: string; body: string } | null {
  const down = [...s.core, ...s.services].filter((c) => c.status === "down");
  if (down.length === 0) return null;
  return {
    tone: s.core.some((c) => c.status === "down") ? "bad" : "warn",
    title: `${down.length} ${down.length === 1 ? "component is" : "components are"} not responding`,
    body: `${down.map((c) => c.label).join(", ")}. Check the container logs with: docker compose logs --tail=100`,
  };
}

export default function SystemPage() {
  const q = useQuery({ queryKey: ["system"], queryFn: getSystem, refetchInterval: 15000 });
  const s = q.data;
  const note = s ? headline(s) : null;

  return (
    <div className="page system-page">
      <div className="page-header">
        <div>
          <h1>System</h1>
          <div className="subtitle">What this install is made of and whether each part is running.</div>
        </div>
      </div>

      {q.isLoading && <div className="empty">Loading…</div>}
      {q.isError && <div className="empty">System details are unavailable right now.</div>}

      {note && (
        <div className={`sys-notice tone-${note.tone}`} role="status">
          <div className="sys-notice-title">{note.title}</div>
          <div className="sys-notice-body">{note.body}</div>
        </div>
      )}

      {s && (
        <>
          <div className="sys-tiles">
            <StatTile label="Version" value={s.version} />
            <StatTile label="Edition" value={EDITION_LABEL[s.edition] ?? s.edition} hint={s.license_status} />
            <StatTile
              label="Running"
              value={`${s.counts.up} / ${s.counts.up + s.counts.down + s.counts.not_installed}`}
              hint={s.counts.not_installed ? `${s.counts.not_installed} not installed` : undefined}
            />
            <StatTile
              label="Sign-in"
              value={s.auth_mode === "dev" ? "Open (dev)" : "Required"}
              hint={s.auth_mode === "dev" ? "Do not expose this install" : undefined}
            />
          </div>

          <section className="panel">
            <div className="panel-h"><h2>Core</h2></div>
            <Rows rows={s.core} />
          </section>

          <section className="panel">
            <div className="panel-h"><h2>Services</h2></div>
            <Rows rows={s.services} />
            {s.counts.not_installed > 0 && (
              <p className="sys-foot">
                Services marked Not installed are not part of this install (the lite stack runs a smaller set).
                Everything that is installed keeps working without them.
              </p>
            )}
          </section>
        </>
      )}
    </div>
  );
}
