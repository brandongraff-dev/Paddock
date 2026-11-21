import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import StatTile from "../components/StatTile";
import SeverityChip from "../components/Severity";
import EmptyState from "../components/EmptyState";
import { SEV_COLOR, severityColor } from "../lib/color";
import {
  getDevice,
  getDeviceSummary,
  listDevices,
  type Device,
  type DeviceFilter,
  type DeviceRole,
} from "../api/devices";
import "../styles/devices.css";

const DEVICE_LIMIT = 500;

/* ------------------------------- icons --------------------------------- */

const OT_TYPES = new Set([
  "plc", "rtu", "hvac_controller", "building_controller", "ot_server", "hmi", "ied",
]);

/** Small glyph per device type; falls back to a role-colored dot. */
function TypeIcon({ type, role }: { type?: string | null; role: DeviceRole }) {
  const t = (type ?? "").toLowerCase();
  const stroke = role === "ot" ? "var(--ot)" : "var(--iot)";
  const common = {
    width: 18, height: 18, viewBox: "0 0 24 24", fill: "none",
    stroke, strokeWidth: 1.6,
  } as const;
  let path: JSX.Element;
  if (t === "camera") {
    path = (<><rect x="3" y="7" width="13" height="11" rx="2" /><path d="M16 11 L21 8 L21 17 L16 14 Z" /></>);
  } else if (t === "printer") {
    path = (<><rect x="6" y="3" width="12" height="6" /><rect x="4" y="9" width="16" height="7" rx="1.5" /><rect x="7" y="15" width="10" height="5" /></>);
  } else if (t === "plc" || t === "rtu" || t === "ied") {
    path = (<><rect x="4" y="5" width="16" height="14" rx="1.5" /><path d="M8 5 L8 19 M12 9 L16 9 M12 12 L16 12 M12 15 L16 15" /></>);
  } else if (t === "hvac_controller" || t === "thermostat") {
    path = (<><circle cx="12" cy="12" r="8" /><path d="M12 7 L12 12 L15 14" /></>);
  } else if (t === "ot_server" || t === "building_controller" || t === "file_server") {
    path = (<><rect x="4" y="4" width="16" height="7" rx="1.5" /><rect x="4" y="13" width="16" height="7" rx="1.5" /><circle cx="8" cy="7.5" r="0.8" fill={stroke} /><circle cx="8" cy="16.5" r="0.8" fill={stroke} /></>);
  } else if (t === "router") {
    path = (<><rect x="3" y="12" width="18" height="7" rx="1.5" /><path d="M12 12 L12 6 M12 6 L8 9 M12 6 L16 9" /></>);
  } else {
    path = (<><rect x="5" y="5" width="14" height="14" rx="3" /><circle cx="12" cy="12" r="2.4" /></>);
  }
  return <svg {...common} aria-hidden>{path}</svg>;
}

function RoleChip({ role }: { role: DeviceRole }) {
  return (
    <span className={`dev-role dev-role-${role}`}>{role.toUpperCase()}</span>
  );
}

function ExposureBadge({ device }: { device: Device }) {
  if (!device.exposed) {
    return <span className="dev-exposure clean mono">isolated</span>;
  }
  return <span className="dev-exposure bad mono" title="OT exposed to IT / internet">exposed</span>;
}

function ProtocolChips({ protocols }: { protocols: string[] }) {
  if (!protocols || protocols.length === 0) return <span className="dev-proto-none">—</span>;
  return (
    <span className="dev-protos">
      {protocols.map((p) => (
        <span key={p} className="dev-proto mono">{p}</span>
      ))}
    </span>
  );
}

/* --------------------------------- tiles ------------------------------- */

function HeaderTiles() {
  const q = useQuery({ queryKey: ["device-summary"], queryFn: getDeviceSummary, staleTime: 15_000 });
  const s = q.data;
  return (
    <div className="stat-row">
      <StatTile label="Devices" value={s?.total ?? 0} accent="var(--iot)" />
      <StatTile label="OT devices" value={s?.ot_total ?? 0} accent="var(--ot)" />
      <StatTile label="Exposed OT" value={s?.exposed_ot ?? 0} accent={SEV_COLOR.high} />
      <StatTile label="IT/OT violations" value={s?.it_ot_violations ?? 0} accent={SEV_COLOR.critical} />
    </div>
  );
}

/* ---------------------------- exposure panel --------------------------- */

function ExposurePanel({
  devices,
  onSelect,
}: {
  devices: Device[];
  onSelect: (id: string) => void;
}) {
  const exposed = useMemo(
    () => devices.filter((d) => d.role === "ot" && d.exposed),
    [devices],
  );
  return (
    <div className="panel dev-exposure-panel">
      <div className="panel-h">
        <h2>OT exposed to IT / internet</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>
          {exposed.length} at-risk OT device{exposed.length === 1 ? "" : "s"} · passive detection
        </span>
      </div>
      {exposed.length === 0 ? (
        <div className="dev-exposure-ok">
          No OT device is reachable from an IT segment or a public address. Segmentation holds.
        </div>
      ) : (
        <div className="dev-exposure-cards">
          {exposed.map((d) => (
            <button key={d.id} type="button" className="dev-exposure-card" onClick={() => onSelect(d.id)}>
              <div className="dev-exposure-card-h">
                <TypeIcon type={d.type} role={d.role} />
                <span className="dev-exposure-card-name mono">{d.vendor ?? "OT device"} {d.model ?? d.type}</span>
                <span className="dev-exposure-card-flag mono">{d.open_finding_count} finding{d.open_finding_count === 1 ? "" : "s"}</span>
              </div>
              <div className="dev-exposure-card-meta mono">
                <span>{d.value}</span>
                {d.segment && <span className="dev-exposure-card-seg">seg {d.segment}</span>}
                <ProtocolChips protocols={d.protocols} />
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/* ------------------------------- drawer -------------------------------- */

function evidenceRows(evidence: unknown): [string, string][] {
  if (!evidence || typeof evidence !== "object") return [];
  const out: [string, string][] = [];
  for (const [k, v] of Object.entries(evidence as Record<string, unknown>)) {
    out.push([k, typeof v === "object" ? JSON.stringify(v) : String(v)]);
  }
  return out;
}

function DeviceDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ["device", id], queryFn: () => getDevice(id), staleTime: 10_000 });
  const detail = q.data;
  const d = detail?.device;

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" aria-label="device detail">
        <header>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className="mono" style={{ color: "var(--text-2)", fontSize: 11, textTransform: "uppercase" }}>
              {d ? d.kind.replace("_", " ") : "device"}
            </span>
            <strong style={{ fontSize: 13 }}>{d?.vendor ?? "Device"}</strong>
          </div>
          <button className="ghost" onClick={onClose} aria-label="close">✕</button>
        </header>
        <div className="body">
          {q.isLoading && <div style={{ padding: 4, color: "var(--text-2)" }}>Loading device…</div>}
          {q.isError && <div style={{ padding: 4, color: "var(--bad)" }}>Failed to load device.</div>}
          {d && (
            <>
              <div className="section">
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <TypeIcon type={d.type} role={d.role} />
                  <RoleChip role={d.role} />
                  <span className="dev-type-tag mono">{d.type ?? "unknown"}</span>
                  <ExposureBadge device={d} />
                </div>
                <div className="mono" style={{ marginTop: 8, fontSize: 14, color: "var(--text-0)" }}>
                  {d.value}
                </div>
                <div className="dev-kv">
                  {d.model && <div><span>Model</span><b className="mono">{d.model}</b></div>}
                  {d.mac && <div><span>MAC</span><b className="mono">{d.mac}</b></div>}
                  {d.os && <div><span>OS</span><b className="mono">{d.os}</b></div>}
                  <div><span>Confidence</span><b className="mono">{d.confidence}</b></div>
                  {d.segment && <div><span>Segment</span><b className="mono">{d.segment}</b></div>}
                </div>
              </div>

              <div className="section">
                <h3>Protocols</h3>
                <ProtocolChips protocols={d.protocols} />
              </div>

              <div className="section">
                <h3>Fingerprint evidence</h3>
                <div className="dev-evidence mono">
                  {evidenceRows(d.metadata.evidence).length === 0 ? (
                    <div style={{ color: "var(--text-2)" }}>No structured evidence recorded.</div>
                  ) : (
                    evidenceRows(d.metadata.evidence).map(([k, v]) => (
                      <div key={k} className="dev-evidence-row">
                        <span className="dev-evidence-k">{k}</span>
                        <span className="dev-evidence-v">{v}</span>
                      </div>
                    ))
                  )}
                </div>
                <div className="dev-passive-note">Passively derived — no probe sent to this device.</div>
              </div>

              {detail?.segment && (
                <div className="section">
                  <h3>Segment</h3>
                  <div className="dev-seg-card">
                    <span className="mono">{detail.segment.value}</span>
                    <span className={`dev-seg-class dev-seg-${detail.segment.classification ?? "unknown"}`}>
                      {detail.segment.classification ?? "unknown"}
                    </span>
                    {detail.segment.internet_facing && (
                      <span className="dev-seg-inet mono">internet-facing</span>
                    )}
                  </div>
                </div>
              )}

              <div className="section">
                <h3>Findings ({detail?.findings.length ?? 0})</h3>
                {(detail?.findings ?? []).length === 0 ? (
                  <div style={{ color: "var(--text-2)", fontSize: 12 }}>No findings on this device.</div>
                ) : (
                  <div className="dev-finding-list">
                    {(detail?.findings ?? []).map((f) => (
                      <div key={f.id} className="dev-finding" style={{ borderLeftColor: severityColor(f.severity) }}>
                        <div className="dev-finding-h">
                          <SeverityChip severity={f.severity} compact />
                          <span className="dev-finding-rule mono">{f.rule_id}</span>
                          <span className="dev-finding-src mono">{f.rule_source}</span>
                          {f.cvss != null && <span className="dev-finding-cvss mono">CVSS {f.cvss}</span>}
                        </div>
                        <div className="dev-finding-title">{f.title}</div>
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

/* --------------------------------- page -------------------------------- */

export default function DevicesPage() {
  const [role, setRole] = useState<DeviceRole | "">("");
  const [type, setType] = useState("");
  const [vendor, setVendor] = useState("");
  const [exposedOnly, setExposedOnly] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  const filter = useMemo<DeviceFilter>(
    () => ({
      role: (role || undefined) as DeviceRole | undefined,
      type: type || undefined,
      vendor: vendor || undefined,
      limit: DEVICE_LIMIT,
    }),
    [role, type, vendor],
  );

  const q = useQuery({
    queryKey: ["devices", filter],
    queryFn: () => listDevices(filter),
    staleTime: 10_000,
  });

  const all = q.data?.items ?? [];

  const types = useMemo(() => {
    const set = new Set<string>();
    for (const d of all) if (d.type) set.add(d.type);
    return [...set].sort();
  }, [all]);

  const rows = useMemo(() => {
    const narrowed = exposedOnly ? all.filter((d) => d.exposed) : all;
    return [...narrowed].sort(
      (a, b) =>
        Number(b.exposed) - Number(a.exposed) ||
        (a.role === b.role ? 0 : a.role === "ot" ? -1 : 1) ||
        (a.vendor ?? "").localeCompare(b.vendor ?? ""),
    );
  }, [all, exposedOnly]);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Devices</h1>
          <div className="subtitle">
            Passive IoT &amp; OT inventory — fingerprinted from captures, announcements and
            flows. The platform never probes these devices (OT-safe, passive-first).
          </div>
        </div>
      </div>

      <HeaderTiles />

      <ExposurePanel devices={all} onSelect={setSelected} />

      <div className="panel" style={{ padding: 0, display: "flex", flexDirection: "column", minHeight: 0 }}>
        <div className="panel-h" style={{ padding: "12px 14px 8px", marginBottom: 0 }}>
          <h2>Inventory</h2>
          <span style={{ color: "var(--text-2)", fontSize: 11 }}>
            {rows.length} of {q.data?.total ?? all.length} devices
          </span>
        </div>

        <div className="filterbar" style={{ borderRadius: 0, border: 0, borderBottom: "1px solid var(--border)" }}>
          <div className="dev-role-tabs">
            {([["", "All"], ["ot", "OT"], ["iot", "IoT"]] as const).map(([val, label]) => (
              <button
                key={val}
                type="button"
                className={`dev-role-tab ${role === val ? "on" : ""}`}
                onClick={() => setRole(val as DeviceRole | "")}
              >
                {label}
              </button>
            ))}
          </div>
          <span className="sep" />
          <label>Type</label>
          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="">Any</option>
            {types.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <span className="sep" />
          <input
            className="mono"
            style={{ minWidth: 140 }}
            value={vendor}
            placeholder="vendor…"
            onChange={(e) => setVendor(e.target.value)}
          />
          <span className="sep" />
          <label
            className={`checkchip ${exposedOnly ? "on" : ""}`}
            style={exposedOnly ? { borderColor: SEV_COLOR.high, color: SEV_COLOR.high } : undefined}
          >
            <input type="checkbox" checked={exposedOnly} onChange={(e) => setExposedOnly(e.target.checked)} />
            Exposed only
          </label>
        </div>

        <div className="dev-list">
          <div className="dev-row dev-head">
            <div>Type</div>
            <div>Vendor / model</div>
            <div>Role</div>
            <div>Address</div>
            <div>Protocols</div>
            <div>Exposure</div>
          </div>
          {q.isLoading && <div style={{ padding: 12, color: "var(--text-2)" }}>Loading devices…</div>}
          {q.isError && <div style={{ padding: 12, color: "var(--bad)" }}>Failed to load devices.</div>}
          {!q.isLoading && !q.isError && rows.length === 0 && (
            <EmptyState
              title="No devices discovered yet."
              hint="Ingest a capture or observations through the otdiscovery service (POST /ingest)."
            />
          )}
          {rows.map((d) => (
            <button key={d.id} type="button" className="dev-row" onClick={() => setSelected(d.id)}>
              <div className="dev-cell-type"><TypeIcon type={d.type} role={d.role} /><span className="dev-type-label">{d.type ?? "—"}</span></div>
              <div className="dev-pkg mono" title={`${d.vendor ?? ""} ${d.model ?? ""}`}>
                {d.vendor ?? "unknown"}
                {d.model && <span style={{ color: "var(--text-2)" }}> · {d.model}</span>}
              </div>
              <div><RoleChip role={d.role} /></div>
              <div className="mono dev-addr">{d.value}</div>
              <div><ProtocolChips protocols={d.protocols} /></div>
              <div><ExposureBadge device={d} /></div>
            </button>
          ))}
        </div>
      </div>

      {selected && <DeviceDrawer id={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
