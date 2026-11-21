/**
 * Shell — three-zone chrome.
 *   .rail   : 72px icon nav
 *   .topbar : 44px global filters + event ticker
 *   .main   : page outlet
 * DetailDrawer renders itself when drawer.id is set.
 */

import { useEffect, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useStore } from "../state/store";
import { useAuth, canViewAudit } from "../state/auth";
import DetailDrawer from "./DetailDrawer";
import CommandPalette from "./CommandPalette";
import { ClassificationBanner } from "./Classification";

interface NavEntry {
  to: string;
  label: string;
  icon: ReactNode;
}

const Icon = {
  Overview: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <rect x="3" y="3" width="8" height="8" rx="1.5" />
      <rect x="13" y="3" width="8" height="5" rx="1.5" />
      <rect x="13" y="10" width="8" height="11" rx="1.5" />
      <rect x="3" y="13" width="8" height="8" rx="1.5" />
    </svg>
  ),
  Graph: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <circle cx="5" cy="5" r="2.2" />
      <circle cx="19" cy="6" r="2.2" />
      <circle cx="6" cy="18" r="2.2" />
      <circle cx="18" cy="18" r="2.2" />
      <path d="M7 6 L17 7 M6 7 L6 16 M8 18 L16 18 M7 16 L17 8" />
    </svg>
  ),
  Findings: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M12 2 L22 20 L2 20 Z" />
      <path d="M12 9 L12 14" />
      <circle cx="12" cy="17" r="0.8" fill="currentColor" />
    </svg>
  ),
  Chains: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M9 7 L15 7 M9 17 L15 17" />
      <rect x="4" y="4" width="6" height="6" rx="1.5" />
      <rect x="14" y="4" width="6" height="6" rx="1.5" />
      <rect x="4" y="14" width="6" height="6" rx="1.5" />
      <rect x="14" y="14" width="6" height="6" rx="1.5" />
    </svg>
  ),
  AttackPaths: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <circle cx="5" cy="6" r="2.2" />
      <circle cx="19" cy="18" r="2.2" />
      <path d="M5 8.2 L5 13 Q5 15 7 15 L15 15 Q17 15 17 17 L17 17.8" />
      <path d="M14.5 12.5 L17 15 L19.5 12.5" />
    </svg>
  ),
  Changes: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M3 14 L7 14 L10 6 L14 19 L16.5 11 L18 14 L21 14" />
    </svg>
  ),
  Posture: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M12 3 L19 6 L19 11 Q19 18 12 21 Q5 18 5 11 L5 6 Z" />
      <path d="M9 12 L11 14 L15 10" />
    </svg>
  ),
  Tickets: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M4 7 Q4 6 5 6 L19 6 Q20 6 20 7 L20 10 Q18.5 10.5 18.5 12 Q18.5 13.5 20 14 L20 17 Q20 18 19 18 L5 18 Q4 18 4 17 L4 14 Q5.5 13.5 5.5 12 Q5.5 10.5 4 10 Z" />
      <path d="M13 6 L13 18" strokeDasharray="2 2" />
    </svg>
  ),
  Dependencies: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M12 3 L20 7 L20 17 L12 21 L4 17 L4 7 Z" />
      <path d="M4 7 L12 11 L20 7 M12 11 L12 21" />
    </svg>
  ),
  RiskModel: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <circle cx="12" cy="12" r="3" />
      <circle cx="5" cy="6" r="1.4" />
      <circle cx="19" cy="7" r="1.4" />
      <circle cx="6" cy="18" r="1.4" />
      <circle cx="18" cy="18" r="1.4" />
      <path d="M9.6 10.2 L6.2 6.9 M14.4 10.3 L17.7 7.4 M9.8 14 L7 16.8 M14.2 14 L17 16.8" />
    </svg>
  ),
  Attack: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <rect x="3" y="3" width="5" height="5" rx="1" />
      <rect x="9.5" y="3" width="5" height="5" rx="1" />
      <rect x="16" y="3" width="5" height="5" rx="1" />
      <rect x="3" y="9.5" width="5" height="5" rx="1" />
      <rect x="9.5" y="9.5" width="5" height="5" rx="1" />
      <rect x="16" y="9.5" width="5" height="5" rx="1" />
      <rect x="3" y="16" width="5" height="5" rx="1" />
      <rect x="9.5" y="16" width="5" height="5" rx="1" />
      <rect x="16" y="16" width="5" height="5" rx="1" />
    </svg>
  ),
  Ask: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M4 5 Q4 4 5 4 L19 4 Q20 4 20 5 L20 15 Q20 16 19 16 L9 16 L5 20 L5 16 Q4 16 4 15 Z" />
      <path d="M9 10 L15 10" />
    </svg>
  ),
  Monitoring: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <circle cx="12" cy="12" r="8" />
      <path d="M12 7 L12 12 L15.5 14" />
    </svg>
  ),
  Timeline: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M3 12 L21 12" />
      <circle cx="6" cy="12" r="1.5" />
      <circle cx="12" cy="12" r="1.5" />
      <circle cx="18" cy="12" r="1.5" />
    </svg>
  ),
  Scope: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="3.5" />
      <path d="M12 2 L12 6 M12 18 L12 22 M2 12 L6 12 M18 12 L22 12" />
    </svg>
  ),
  Scans: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M4 6 L20 6 M4 12 L14 12 M4 18 L18 18" />
      <circle cx="19" cy="12" r="1.6" />
    </svg>
  ),
  Audit: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M12 3 L19 6 L19 11 Q19 18 12 21 Q5 18 5 11 L5 6 Z" />
      <path d="M9 9 L15 9 M9 12 L15 12 M9 15 L13 15" />
    </svg>
  ),
  Explore: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <circle cx="6" cy="6" r="2.4" /><circle cx="18" cy="8" r="2.4" /><circle cx="10" cy="18" r="2.4" />
      <path d="M8 7 L16 8 M7.5 8 L9 16" />
    </svg>
  ),
  ThreatIntel: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M12 3 L19 6 L19 11 Q19 18 12 21 Q5 18 5 11 L5 6 Z" />
      <circle cx="12" cy="11" r="2.2" /><path d="M12 3.5 L12 6 M12 16 L12 18.5 M6 11 L8 11 M16 11 L18 11" />
    </svg>
  ),
  Devices: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <rect x="7" y="7" width="10" height="10" rx="1.5" /><rect x="10" y="10" width="4" height="4" />
      <path d="M9 4 L9 7 M12 4 L12 7 M15 4 L15 7 M9 17 L9 20 M12 17 L12 20 M15 17 L15 20 M4 9 L7 9 M4 12 L7 12 M4 15 L7 15 M17 9 L20 9 M17 12 L20 12 M17 15 L20 15" />
    </svg>
  ),
  Fleet: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <rect x="4" y="4" width="16" height="6" rx="1.2" /><rect x="4" y="14" width="16" height="6" rx="1.2" />
      <circle cx="7" cy="7" r="0.8" /><circle cx="7" cy="17" r="0.8" />
    </svg>
  ),
  Remediation: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M14 6 a3 3 0 1 0 4 4 L21 13 L13 21 L3 11 L11 3 Z" /><path d="M9 11 L13 15" />
    </svg>
  ),
};

const navEntries: NavEntry[] = [
  { to: "/", label: "Overview", icon: Icon.Overview },
  { to: "/graph", label: "Graph", icon: Icon.Graph },
  { to: "/explore", label: "Explore", icon: Icon.Explore },
  { to: "/devices", label: "Devices", icon: Icon.Devices },
  { to: "/findings", label: "Findings", icon: Icon.Findings },
  { to: "/chains", label: "Chains", icon: Icon.Chains },
  { to: "/attack-paths", label: "Attack Paths", icon: Icon.AttackPaths },
  { to: "/changes", label: "Changes", icon: Icon.Changes },
  { to: "/posture", label: "Posture", icon: Icon.Posture },
  { to: "/tickets", label: "Tickets", icon: Icon.Tickets },
  { to: "/dependencies", label: "Dependencies", icon: Icon.Dependencies },
  { to: "/risk-model", label: "Risk Model", icon: Icon.RiskModel },
  { to: "/attack", label: "ATT&CK", icon: Icon.Attack },
  { to: "/threat-intel", label: "Threat Intel", icon: Icon.ThreatIntel },
  { to: "/ask", label: "Ask", icon: Icon.Ask },
  { to: "/monitoring", label: "Monitoring", icon: Icon.Monitoring },
  { to: "/timeline", label: "Timeline", icon: Icon.Timeline },
  { to: "/scope", label: "Scope", icon: Icon.Scope },
  { to: "/scans", label: "Scans", icon: Icon.Scans },
  { to: "/fleet", label: "Fleet", icon: Icon.Fleet },
  { to: "/remediation", label: "Remediation", icon: Icon.Remediation },
];

/** Audit log — appended to the rail only for auditor/admin. */
const auditEntry: NavEntry = { to: "/audit", label: "Audit", icon: Icon.Audit };

function ToastStack() {
  const toasts = useStore((s) => s.toasts);
  const dismiss = useStore((s) => s.dismissToast);
  if (toasts.length === 0) return null;
  return (
    <div className="toast-stack" role="status" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={`toast ${t.severity ? `sev-${t.severity}` : ""}`}>
          <button
            className="ghost"
            style={{ float: "right", padding: "0 4px" }}
            onClick={() => dismiss(t.id)}
            aria-label="dismiss"
          >
            ✕
          </button>
          {t.text}
        </div>
      ))}
    </div>
  );
}

function Ticker() {
  const events = useStore((s) => s.events);
  const connected = useStore((s) => s.connected);
  const latest = events[0];
  const text = latest
    ? `${latest.event}${"severity" in latest && latest.severity ? ` · ${latest.severity}` : ""}${"value" in latest && latest.value ? ` · ${latest.value}` : ""}`
    : "awaiting events…";
  return (
    <span className="ticker" title="live event stream" style={latest?.seeded ? { color: "var(--text-2)" } : undefined}>
      <span
        className="dot"
        style={{
          background: connected ? "var(--ok)" : "var(--text-2)",
          boxShadow: connected ? "0 0 8px var(--ok)" : "none",
        }}
      />
      {text}
      {latest?.seeded && <span style={{ marginLeft: 6, opacity: 0.7 }}>· recent</span>}
    </span>
  );
}

const ROLE_CLEARANCE_COLOR: Record<string, string> = {
  public: "#58d68d",
  internal: "#4ea3ff",
  confidential: "#f0b429",
  restricted: "#ff4d6d",
};

/** Current principal + logout, in the top bar. */
function UserMenu() {
  const user = useAuth((s) => s.user);
  const token = useAuth((s) => s.token);
  const logout = useAuth((s) => s.logout);
  if (!token) return null;
  const clr = user?.clearance ?? "public";
  return (
    <div className="usermenu">
      <div className="usermenu-id">
        <span className="usermenu-name mono">{user?.username ?? "—"}</span>
        <span className="usermenu-role">{user?.role ?? "unknown"}</span>
      </div>
      <span
        className="usermenu-clearance mono"
        title={`Clearance: ${clr}`}
        style={{ color: ROLE_CLEARANCE_COLOR[clr], borderColor: ROLE_CLEARANCE_COLOR[clr] }}
      >
        {clr}
      </span>
      <button className="ghost usermenu-logout" onClick={logout} title="Sign out">
        Logout
      </button>
    </div>
  );
}

function CmdkButton() {
  const openCmdk = useStore((s) => s.openCmdk);
  const isMac =
    typeof navigator !== "undefined" && /mac/i.test(navigator.platform || navigator.userAgent || "");
  return (
    <button className="cmdk-trigger" onClick={openCmdk} title="Command palette" aria-keyshortcuts="Meta+K Control+K">
      <span>Search</span>
      <span className="keys">{isMac ? "⌘K" : "Ctrl K"}</span>
    </button>
  );
}

interface Props {
  children: ReactNode;
  noScroll?: boolean;
}

export default function Shell({ children, noScroll }: Props) {
  const loc = useLocation();
  const role = useAuth((s) => s.user?.role);
  const resetClassification = useStore((s) => s.resetClassification);

  // Audit is appended to the rail only for roles that may open it.
  const entries = canViewAudit(role) ? [...navEntries, auditEntry] : navEntries;

  const title =
    entries.find((n) => (n.to === "/" ? loc.pathname === "/" : loc.pathname.startsWith(n.to)))
      ?.label ?? "palantir-asm";

  // The classification banner tracks the page you're on: clear the on-screen
  // max when the route changes so a drawer/page's data re-notes afresh.
  useEffect(() => {
    resetClassification();
  }, [loc.pathname, resetClassification]);

  return (
    <div className="shell">
      <nav className="rail" aria-label="primary">
        <div className="brand" title="palantir-asm">pa</div>
        {entries.map((e) => (
          <NavLink
            key={e.to}
            to={e.to}
            end={e.to === "/"}
            className={({ isActive }) => `rail-item ${isActive ? "active" : ""}`}
            aria-label={e.label}
          >
            {e.icon}
            <span className="hover-label">{e.label}</span>
          </NavLink>
        ))}
      </nav>

      <header className="topbar">
        <div className="title mono">{title.toUpperCase()}</div>
        <div className="spacer" />
        <CmdkButton />
        <Ticker />
        <span className="topbar-sep" />
        <UserMenu />
      </header>

      <main className={`main${noScroll ? " no-scroll" : ""}`}>
        <ClassificationBanner />
        {children}
      </main>

      <ToastStack />
      <DetailDrawer />
      <CommandPalette />
    </div>
  );
}
