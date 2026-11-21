/**
 * Login screen (governance §B). The top-level gate in App.tsx renders this
 * whenever there's no session token. Two ways in:
 *   - username + password → POST /v1/auth/login → JWT
 *   - an API key, used directly as the bearer
 * Either way we then call GET /v1/auth/me to resolve role + clearance, so the
 * rest of the app knows what the principal may do.
 *
 * Enterprise SSO: enabled identity providers (GET /v1/auth/sso/providers) are
 * offered as "Continue with <IdP>" buttons above the form. When the admin has
 * made SSO required, the password / API-key form folds behind a break-glass
 * disclosure (the server enforces it either way).
 *
 * Dark, dense, serious — not a marketing page. One column, mono accents.
 */

import HorseMark from "../brand/HorseMark";
import { useEffect, useState, type FormEvent } from "react";
import { login as loginReq, me } from "../api/auth";
import {
  beginSso,
  listSsoProviders,
  normalizeProviders,
  type PublicProvider,
  type PublicProviders,
} from "../api/sso";
import { ApiError } from "../api/client";
import { useAuth } from "../state/auth";
import "../styles/identity.css";

type Mode = "password" | "apikey";

/** Where to land after SSO: the deep link the user was trying to open. */
function currentReturnTo(): string {
  try {
    const { pathname, search } = window.location;
    if (pathname.startsWith("/sso/") || pathname === "/login") return "/";
    return pathname + search;
  } catch {
    return "/";
  }
}

const PRESET_TINT: Record<string, string> = {
  okta: "#9fc2d8",
  entra: "#8fbf8a",
  google: "#e3b265",
  auth0: "#e67350",
  keycloak: "#b9a3d6",
};

function ProviderGlyph({ p }: { p: PublicProvider }) {
  const letter = (p.display_name.trim()[0] ?? "?").toUpperCase();
  return (
    <span
      className="sso-glyph"
      aria-hidden="true"
      style={{ color: PRESET_TINT[p.preset] ?? "var(--text-1)" }}
    >
      {letter}
    </span>
  );
}

export default function Login() {
  const setAuth = useAuth((s) => s.setAuth);
  const setUser = useAuth((s) => s.setUser);
  const logout = useAuth((s) => s.logout);

  const [mode, setMode] = useState<Mode>("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sso, setSso] = useState<PublicProviders>({ providers: [], sso_required: false });
  const [breakGlass, setBreakGlass] = useState(false);
  const [ssoBusy, setSsoBusy] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    listSsoProviders()
      .then((r) => { if (alive) setSso(normalizeProviders(r)); })
      .catch(() => { /* SSO list is optional; the form still works */ });
    return () => { alive = false; };
  }, []);

  const hasSso = sso.providers.length > 0;
  const showLocal = !hasSso || !sso.sso_required || breakGlass;

  async function startSso(p: PublicProvider) {
    if (ssoBusy) return;
    setError(null);
    setSsoBusy(p.slug);
    try {
      await beginSso(p, currentReturnTo());
    } catch {
      setSsoBusy(null);
      setError("Couldn't start single sign-on.");
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setError(null);
    setBusy(true);
    try {
      if (mode === "password") {
        const res = await loginReq(username.trim(), password);
        // Seed a provisional principal from the login response so gating works
        // even if /v1/auth/me is briefly unavailable; refresh it right after.
        setAuth(res.access_token, {
          username: username.trim(),
          role: res.role,
          clearance: res.clearance,
        });
        try {
          setUser(await me());
        } catch {
          /* keep the provisional principal from the login response */
        }
      } else {
        const key = apiKey.trim();
        if (!key) {
          setError("Enter an API key.");
          setBusy(false);
          return;
        }
        // Store the key as the bearer, then resolve the principal behind it.
        setAuth(key, null);
        try {
          setUser(await me());
        } catch (err) {
          logout();
          throw err;
        }
      }
    } catch (err) {
      const msg =
        err instanceof ApiError && err.status === 401
          ? "Invalid credentials."
          : err instanceof Error
            ? err.message
            : "Sign-in failed.";
      setError(msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <span className="login-mark"><HorseMark size={40} title="" /></span>
          <div>
            <div className="login-title">Paddock</div>
            <div className="login-sub mono">attack surface management</div>
          </div>
        </div>

        {hasSso && (
          <div className="sso-list" aria-label="Single sign-on">
            {sso.providers.map((p) => (
              <button
                key={p.slug}
                type="button"
                className="sso-btn"
                disabled={ssoBusy !== null}
                onClick={() => startSso(p)}
              >
                <ProviderGlyph p={p} />
                <span className="sso-btn-label">
                  {ssoBusy === p.slug ? "Redirecting…" : `Continue with ${p.display_name}`}
                </span>
                <span className="sso-btn-kind mono">{p.kind}</span>
              </button>
            ))}
          </div>
        )}

        {hasSso && showLocal && (
          <div className="login-divider" role="separator"><span>or</span></div>
        )}

        {!showLocal && (
          <>
            {error && <div className="login-error" role="alert">{error}</div>}
            <button type="button" className="ghost login-breakglass" onClick={() => setBreakGlass(true)}>
              Break-glass access
            </button>
            <div className="field-note">
              Single sign-on is required. Local credentials are for designated break-glass accounts only.
            </div>
          </>
        )}

        {showLocal && (<>
        <div className="login-tabs" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={mode === "password"}
            className={`login-tab ${mode === "password" ? "on" : ""}`}
            onClick={() => { setMode("password"); setError(null); }}
          >
            Password
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === "apikey"}
            className={`login-tab ${mode === "apikey" ? "on" : ""}`}
            onClick={() => { setMode("apikey"); setError(null); }}
          >
            API key
          </button>
        </div>

        {mode === "password" ? (
          <>
            <div className="field">
              <label htmlFor="login-username">Username</label>
              <input
                id="login-username"
                autoFocus
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="analyst"
              />
            </div>
            <div className="field">
              <label htmlFor="login-password">Password</label>
              <input
                id="login-password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
              />
            </div>
          </>
        ) : (
          <div className="field">
            <label htmlFor="login-apikey">API key</label>
            <input
              id="login-apikey"
              className="mono"
              autoFocus
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="pak_…"
            />
            <div className="field-note">Used directly as the bearer token.</div>
          </div>
        )}

        {error && <div className="login-error" role="alert">{error}</div>}

        <button type="submit" className="primary login-submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
        </>)}

        <div className="login-foot mono">
          Access is governed, classified, and audited. Authorized use only.
        </div>
      </form>
    </div>
  );
}
