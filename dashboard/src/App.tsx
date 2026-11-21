import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import Shell from "./components/Shell";
import Overview from "./pages/Overview";
import GraphPage from "./pages/Graph";
import FindingsPage from "./pages/Findings";
import ChainsPage from "./pages/Chains";
import AttackPathsPage from "./pages/AttackPaths";
import ChangesPage from "./pages/Changes";
import PosturePage from "./pages/Posture";
import TicketsPage from "./pages/Tickets";
import DependenciesPage from "./pages/Dependencies";
import RiskModelPage from "./pages/RiskModel";
import AttackPage from "./pages/Attack";
import AskPage from "./pages/Ask";
import MonitoringPage from "./pages/Monitoring";
import TimelinePage from "./pages/Timeline";
import ScopePage from "./pages/Scope";
import ScansPage from "./pages/Scans";
import AuditPage from "./pages/Audit";
import ExplorePage from "./pages/Explore";
import ThreatIntelPage from "./pages/ThreatIntel";
import DevicesPage from "./pages/Devices";
import FleetPage from "./pages/Fleet";
import RemediationPage from "./pages/Remediation";
import IntegrationsPage from "./pages/Integrations";
import Login from "./pages/Login";
import Landing from "./pages/Landing";
import { useLiveEvents } from "./hooks/useLiveEvents";
import { useAuth, canViewAudit } from "./state/auth";
import type { ReactNode } from "react";

const qc = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 10_000,
    },
  },
});

function LiveEvents() {
  useLiveEvents();
  return null;
}

/** Route guard: audit log is auditor/admin only. Others bounce to Overview. */
function RequireAudit({ children }: { children: ReactNode }) {
  const role = useAuth((s) => s.user?.role);
  if (!canViewAudit(role)) return <Navigate to="/" replace />;
  return <>{children}</>;
}

/** Everything behind auth: the router, live events, and the governed pages. */
function AuthedApp() {
  return (
    <BrowserRouter>
      <LiveEvents />
      <Routes>
        <Route path="/welcome" element={<Landing />} />
        <Route path="/" element={<Shell><Overview /></Shell>} />
        <Route path="/graph" element={<Shell noScroll><GraphPage /></Shell>} />
        <Route path="/findings" element={<Shell><FindingsPage /></Shell>} />
        <Route path="/chains" element={<Shell><ChainsPage /></Shell>} />
        <Route path="/attack-paths" element={<Shell><AttackPathsPage /></Shell>} />
        <Route path="/changes" element={<Shell><ChangesPage /></Shell>} />
        <Route path="/posture" element={<Shell><PosturePage /></Shell>} />
        <Route path="/tickets" element={<Shell><TicketsPage /></Shell>} />
        <Route path="/dependencies" element={<Shell><DependenciesPage /></Shell>} />
        <Route path="/risk-model" element={<Shell><RiskModelPage /></Shell>} />
        <Route path="/attack" element={<Shell><AttackPage /></Shell>} />
        <Route path="/ask" element={<Shell><AskPage /></Shell>} />
        <Route path="/monitoring" element={<Shell><MonitoringPage /></Shell>} />
        <Route path="/timeline" element={<Shell><TimelinePage /></Shell>} />
        <Route path="/scope" element={<Shell><ScopePage /></Shell>} />
        <Route path="/scans" element={<Shell><ScansPage /></Shell>} />
        <Route path="/explore" element={<Shell><ExplorePage /></Shell>} />
        <Route path="/threat-intel" element={<Shell><ThreatIntelPage /></Shell>} />
        <Route path="/devices" element={<Shell><DevicesPage /></Shell>} />
        <Route path="/fleet" element={<Shell><FleetPage /></Shell>} />
        <Route path="/remediation" element={<Shell><RemediationPage /></Shell>} />
        <Route path="/integrations" element={<Shell><IntegrationsPage /></Shell>} />
        <Route path="/audit" element={<Shell><RequireAudit><AuditPage /></RequireAudit></Shell>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

/** Signed-out surface: the public landing page and the sign-in screen. */
function PublicApp() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/welcome" element={<Landing />} />
        <Route path="*" element={<Login />} />
      </Routes>
    </BrowserRouter>
  );
}

/** Top-level gate: no token → landing / Login; otherwise the authenticated app. */
function Gate() {
  const token = useAuth((s) => s.token);
  if (!token) return <PublicApp />;
  return <AuthedApp />;
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <Gate />
    </QueryClientProvider>
  );
}
