import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import StatTile from "../components/StatTile";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import {
  bootFile,
  createToken,
  enrollCommand,
  listSensors,
  listTokens,
  revokeSensor,
  revokeToken,
  type EnrollToken,
  type Sensor,
  type SensorState,
  type TokenCreated,
} from "../api/sensors";
import { useStore } from "../state/store";
import "../styles/sensors.css";

/* ------------------------------- helpers ------------------------------- */

const STATE_LABEL: Record<SensorState, string> = {
  online: "online",
  degraded: "needs attention",
  offline: "silent",
  revoked: "revoked",
};

const EXPIRY: { label: string; minutes: number }[] = [
  { label: "15 minutes", minutes: 15 },
  { label: "1 hour", minutes: 60 },
  { label: "24 hours", minutes: 1440 },
  { label: "7 days", minutes: 10080 },
];

export function relTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function until(iso: string, now: number = Date.now()): string {
  const s = Math.round((Date.parse(iso) - now) / 1000);
  if (Number.isNaN(s) || s <= 0) return "expired";
  if (s < 3600) return `in ${Math.max(1, Math.round(s / 60))}m`;
  if (s < 86400) return `in ${Math.floor(s / 3600)}h`;
  return `in ${Math.floor(s / 86400)}d`;
}

function defaultServer(): string {
  try {
    const saved = localStorage.getItem("paddock.sensors.server");
    if (saved) return saved;
  } catch {
    /* storage can be blocked */
  }
  const { protocol, hostname } = window.location;
  return `${protocol}//${hostname}:8101`;
}

function StateChip({ state }: { state: SensorState }) {
  return <span className={`sn-chip sn-${state}`}>{STATE_LABEL[state]}</span>;
}

function bytes(n: number | undefined): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

/* ------------------------------ sensor list ---------------------------- */

function SensorsPanel({ sensors, selected, onSelect }: {
  sensors: Sensor[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="panel sn-list">
      <div className="panel-h">
        <h2>Sensors</h2>
        <span className="panel-sub">{sensors.length} enrolled · listen-only</span>
      </div>
      {sensors.length === 0 ? (
        <EmptyState
          title="No sensors yet."
          hint="Add a sensor to see every device on a network segment. It takes one token and a mirror port."
        />
      ) : (
        <table className="table sn-table">
          <thead>
            <tr>
              <th>Sensor</th>
              <th>Site</th>
              <th>State</th>
              <th>Last seen</th>
              <th>Last upload</th>
              <th>Version</th>
            </tr>
          </thead>
          <tbody>
            {sensors.map((s) => (
              <tr key={s.id} className={s.id === selected ? "focused" : ""} onClick={() => onSelect(s.id)}>
                <td>
                  <button type="button" className="sn-link mono">{s.name}</button>
                </td>
                <td>{s.site}</td>
                <td><StateChip state={s.state} /></td>
                <td>{relTime(s.last_seen_at)}</td>
                <td>{relTime(s.last_upload_at)}</td>
                <td className="mono">{s.version ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

/* ------------------------------ sensor detail -------------------------- */

function Metric({ label, value, warn }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className={`sn-metric${warn ? " warn" : ""}`}>
      <span className="sn-metric-l">{label}</span>
      <span className="sn-metric-v mono">{value}</span>
    </div>
  );
}

function SensorDetail({ sensor, onRevoke }: { sensor: Sensor; onRevoke: (s: Sensor) => void }) {
  const h = sensor.health ?? {};
  const skew = h.clock_skew_s;
  return (
    <div className="panel sn-detail">
      <div className="panel-h">
        <h2>{sensor.name}</h2>
        <StateChip state={sensor.state} />
      </div>
      <div className="sn-detail-body">
        {sensor.warnings.length > 0 && (
          <ul className="sn-warnings" aria-label="warnings">
            {sensor.warnings.map((w) => <li key={w}>{w}</li>)}
          </ul>
        )}
        {sensor.state === "offline" && (
          <div className="sn-note">
            No contact since {relTime(sensor.last_seen_at)} (alerts after {Math.round(sensor.silent_after_s / 60)} min of
            silence). Check power, the uplink and the mirror port.
          </div>
        )}
        <div className="sn-metrics">
          <Metric label="Packets seen" value={h.packets_seen != null ? h.packets_seen.toLocaleString() : "—"} />
          <Metric label="Packets dropped" value={h.packets_dropped != null ? h.packets_dropped.toLocaleString() : "—"}
                  warn={(h.packets_dropped ?? 0) > 0} />
          <Metric label="Buffer" value={h.buffer_fill_pct != null ? `${h.buffer_fill_pct.toFixed(0)}% · ${bytes(h.buffer_bytes)}` : "—"}
                  warn={(h.buffer_fill_pct ?? 0) >= 80} />
          <Metric label="Clock skew" value={skew != null ? `${skew > 0 ? "+" : ""}${skew.toFixed(1)}s` : "—"}
                  warn={skew != null && Math.abs(skew) > 30} />
          <Metric label="Flows reported" value={sensor.flows_total.toLocaleString()} />
          <Metric label="Batches" value={`${sensor.batches_total.toLocaleString()} (${sensor.duplicates_total} replays ignored)`} />
          <Metric label="Capture port" value={h.iface ?? "—"} />
          <Metric label="Enrolled" value={relTime(sensor.enrolled_at)} />
        </div>
        {sensor.interfaces.length > 0 && (
          <div className="sn-ifaces">
            {sensor.interfaces.map((i) => (
              <span key={i.name} className="sn-iface mono">
                {i.name}{i.up ? " · up" : " · down"}{i.speed_mbps ? ` · ${i.speed_mbps}M` : ""}
              </span>
            ))}
          </div>
        )}
        {sensor.status === "active" && (
          <Gate need="admin" title="Admin-only: revoking a sensor is gated">
            <div className="sn-actions">
              <button type="button" className="ghost danger" onClick={() => onRevoke(sensor)}>
                Revoke sensor
              </button>
            </div>
          </Gate>
        )}
      </div>
    </div>
  );
}

/* ------------------------------ tokens panel --------------------------- */

function TokensPanel({ tokens }: { tokens: EnrollToken[] }) {
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);
  const revoke = useMutation({
    mutationFn: (id: string) => revokeToken(id),
    onSuccess: () => {
      pushToast({ text: "Enrollment token revoked." });
      qc.invalidateQueries({ queryKey: ["sensor-tokens"] });
    },
    onError: (e: unknown) => pushToast({ text: `Refused: ${(e as Error)?.message ?? "error"}`, severity: "high" }),
  });
  const open = tokens.filter((t) => t.state === "pending");
  return (
    <div className="panel sn-tokens">
      <div className="panel-h">
        <h2>Enrollment tokens</h2>
        <span className="panel-sub">{open.length} waiting · single-use, short-lived</span>
      </div>
      {tokens.length === 0 ? (
        <EmptyState title="No tokens." hint="Add a sensor to create one. A token works once, then it is spent." />
      ) : (
        <table className="table sn-table">
          <thead>
            <tr><th>Token</th><th>Site</th><th>State</th><th>Expires</th><th /></tr>
          </thead>
          <tbody>
            {tokens.slice(0, 20).map((t) => (
              <tr key={t.id}>
                <td className="mono">pet_{t.token_prefix}…</td>
                <td>{t.site}</td>
                <td><span className={`sn-tstate st-${t.state}`}>{t.state}</span></td>
                <td>{t.state === "pending" ? until(t.expires_at) : "—"}</td>
                <td>
                  {t.state === "pending" && (
                    <Gate need="admin">
                      <button type="button" className="ghost" onClick={() => revoke.mutate(t.id)}>Revoke</button>
                    </Gate>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

/* ------------------------------ add-sensor wizard ---------------------- */

function CopyBlock({ label, text }: { label: string; text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked: the text is selectable below */
    }
  };
  return (
    <div className="sn-copy">
      <div className="sn-copy-h">
        <span>{label}</span>
        <button type="button" className="ghost" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
      </div>
      <pre className="sn-pre mono" aria-label={label}>{text}</pre>
    </div>
  );
}

function AddSensorWizard({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);
  const [site, setSite] = useState("");
  const [minutes, setMinutes] = useState(60);
  const [server, setServer] = useState(defaultServer);
  const [created, setCreated] = useState<TokenCreated | null>(null);

  const make = useMutation({
    mutationFn: () => createToken({ site: site.trim(), ttl_minutes: minutes }),
    onSuccess: (t) => {
      try {
        localStorage.setItem("paddock.sensors.server", server.trim());
      } catch {
        /* ignore */
      }
      setCreated(t);
      qc.invalidateQueries({ queryKey: ["sensor-tokens"] });
    },
    onError: (e: unknown) => pushToast({ text: `Could not create token: ${(e as Error)?.message ?? "error"}`, severity: "high" }),
  });

  // Once the token exists, watch for the sensor to use it.
  const watch = useQuery({
    queryKey: ["sensor-tokens", "watch", created?.id],
    queryFn: listTokens,
    enabled: !!created,
    refetchInterval: 4000,
  });
  const mine = watch.data?.find((t) => t.id === created?.id);
  const enrolled = mine?.state === "used";
  useEffect(() => {
    if (enrolled) qc.invalidateQueries({ queryKey: ["sensors"] });
  }, [enrolled, qc]);

  const srv = server.trim().replace(/\/+$/, "");
  const valid = site.trim().length > 0 && /^https?:\/\/\S+$/.test(srv);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal sn-wizard" role="dialog" aria-label="Add sensor" onClick={(e) => e.stopPropagation()}>
        <header>Add sensor</header>
        {!created ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (valid) make.mutate();
            }}
          >
            <div className="body">
              <p className="sn-lead">
                A sensor listens to a mirror (SPAN) port and reports what is on the wire. It never sends a packet to
                your devices. You need a token, then one command (or one file on the SD card).
              </p>
              <div className="field">
                <label htmlFor="sn-site">Site name</label>
                <input id="sn-site" value={site} onChange={(e) => setSite(e.target.value)}
                       placeholder="e.g. Store 42, Plant A" autoFocus />
              </div>
              <div className="field">
                <label htmlFor="sn-expiry">Token expires after</label>
                <select id="sn-expiry" value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
                  {EXPIRY.map((x) => <option key={x.minutes} value={x.minutes}>{x.label}</option>)}
                </select>
              </div>
              <div className="field">
                <label htmlFor="sn-server">Sensor ingest address (the sensor must reach this)</label>
                <input id="sn-server" value={server} onChange={(e) => setServer(e.target.value)} className="mono" />
              </div>
            </div>
            <div className="foot">
              <button type="button" className="ghost" onClick={onClose}>Cancel</button>
              <button type="submit" className="primary" disabled={!valid || make.isPending}>
                {make.isPending ? "Creating…" : "Create token"}
              </button>
            </div>
          </form>
        ) : (
          <>
            <div className="body">
              <div className="sn-warn-once">
                Copy this now. The token is shown once and works once, until {new Date(created.expires_at).toLocaleString()}.
              </div>
              <CopyBlock label="Run on the sensor" text={enrollCommand(srv, created.token)} />
              <CopyBlock label="Or: file on the SD card's boot partition (paddock-sentry.env)"
                         text={bootFile(srv, created.token, created.site)} />
              <div className={`sn-wait${enrolled ? " done" : ""}`} role="status">
                {enrolled
                  ? "Sensor enrolled. It appears in the list now."
                  : "Waiting for the sensor to enroll…"}
              </div>
            </div>
            <div className="foot">
              <button type="button" className="primary" onClick={onClose}>{enrolled ? "Done" : "Close"}</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function RevokeDialog({ sensor, onClose }: { sensor: Sensor; onClose: () => void }) {
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);
  const revoke = useMutation({
    mutationFn: () => revokeSensor(sensor.id),
    onSuccess: () => {
      pushToast({ text: `Sensor ${sensor.name} revoked.` });
      qc.invalidateQueries({ queryKey: ["sensors"] });
      onClose();
    },
    onError: (e: unknown) => pushToast({ text: `Refused: ${(e as Error)?.message ?? "error"}`, severity: "high" }),
  });
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" role="dialog" aria-label="Revoke sensor" onClick={(e) => e.stopPropagation()}>
        <header>Revoke {sensor.name}?</header>
        <div className="body">
          <p className="sn-lead">
            Its credential stops working on the next request and the sensor can no longer upload. To use the device
            again, enroll it with a new token.
          </p>
        </div>
        <div className="foot">
          <button type="button" className="ghost" onClick={onClose}>Cancel</button>
          <button type="button" className="primary danger" disabled={revoke.isPending} onClick={() => revoke.mutate()}>
            Revoke sensor
          </button>
        </div>
      </div>
    </div>
  );
}

/* -------------------------------- page --------------------------------- */

export default function SensorsPage() {
  const [selected, setSelected] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [revoking, setRevoking] = useState<Sensor | null>(null);

  const sensorsQ = useQuery({ queryKey: ["sensors"], queryFn: listSensors, staleTime: 8_000, refetchInterval: 15_000 });
  const tokensQ = useQuery({ queryKey: ["sensor-tokens"], queryFn: listTokens, staleTime: 8_000, refetchInterval: 30_000 });
  const sensors = sensorsQ.data ?? [];
  const tokens = tokensQ.data ?? [];
  const current = sensors.find((s) => s.id === selected) ?? null;

  const counts = useMemo(() => {
    const live = sensors.filter((s) => s.state !== "revoked");
    return {
      total: live.length,
      online: live.filter((s) => s.state === "online").length,
      silent: live.filter((s) => s.state === "offline").length,
      attention: live.filter((s) => s.state === "degraded").length,
    };
  }, [sensors]);

  return (
    <div className="page sn-page">
      <div className="page-header">
        <div>
          <h1>Sensors</h1>
          <div className="subtitle">
            Sentry sensors watch a mirror port and tell Paddock what is on a network: cameras, printers, controllers,
            anything with an address. They are <strong>listen-only</strong>, send only metadata, and keep a bounded
            buffer if the link drops. Each sensor has its own credential you can revoke at any time.
          </div>
        </div>
        <Gate need="admin" title="Admin-only: adding a sensor creates an enrollment token">
          <button type="button" className="primary" onClick={() => setAdding(true)}>Add sensor</button>
        </Gate>
      </div>

      <div className="stat-row">
        <StatTile label="Sensors" value={counts.total} accent="#9fc2d8" />
        <StatTile label="Online" value={counts.online} accent="#8fbf8a" />
        <StatTile label="Needs attention" value={counts.attention} accent="#e3b265" />
        <StatTile label="Silent" value={counts.silent} accent="#e67350" />
      </div>

      <div className="sn-grid">
        <SensorsPanel sensors={sensors} selected={selected} onSelect={(id) => setSelected((p) => (p === id ? null : id))} />
        {current ? <SensorDetail sensor={current} onRevoke={setRevoking} /> : <TokensPanel tokens={tokens} />}
      </div>
      {current && <TokensPanel tokens={tokens} />}

      {adding && <AddSensorWizard onClose={() => setAdding(false)} />}
      {revoking && <RevokeDialog sensor={revoking} onClose={() => setRevoking(null)} />}
    </div>
  );
}
