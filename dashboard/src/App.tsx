import { lazy, Suspense } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import Login from "./pages/Login";
import SsoCallback from "./pages/SsoCallback";
import Landing from "./pages/Landing";
import NotFound from "./pages/NotFound";
import { useAuth } from "./state/auth";

const AuthedApp = lazy(() => import("./AuthedApp"));

const qc = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 10_000,
    },
  },
});

const APP_SEGMENTS = new Set(["ask", "attack", "attack-paths", "audit", "chains", "changes", "dependencies", "devices", "explore", "findings", "fleet", "graph", "integrations", "monitoring", "posture", "remediation", "reports", "risk-model", "scans", "scope", "settings", "setup", "sso", "suppressions", "threat-intel", "tickets", "timeline"]);

function SignedOutDeepLink() {
  const seg = window.location.pathname.split("/")[1] ?? "";
  return APP_SEGMENTS.has(seg) ? <Login /> : <NotFound />;
}

/** Signed-out surface: the public landing page and the sign-in screen. */
function PublicApp() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/welcome" element={<Landing />} />
        <Route path="/sso/callback" element={<SsoCallback />} />
        <Route path="/login" element={<Login />} />
        {/* app routes the sign-in screen should catch (deep links): everything else is a real 404 */}
        <Route path={`/:seg/*`} element={<SignedOutDeepLink />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </BrowserRouter>
  );
}

/** Top-level gate: no token → landing / Login; otherwise the authenticated app. */
function Gate() {
  const token = useAuth((s) => s.token);
  if (!token) return <PublicApp />;
  return (
    <Suspense fallback={<div style={{ minHeight: "100vh", background: "#0e0c0a" }} />}>
      <AuthedApp />
    </Suspense>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <Gate />
    </QueryClientProvider>
  );
}
