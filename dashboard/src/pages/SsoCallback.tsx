/**
 * /sso/callback — where the orchestrator sends the browser after an IdP
 * round-trip. The URL carries either ?error=<code> or a one-time ?code=
 * (never a token). We immediately scrub it from the address bar/history,
 * exchange code + the verifier this tab stored before leaving for a JWT,
 * resolve the principal, and land on the page the user originally wanted.
 */

import { useEffect, useRef, useState } from "react";
import HorseMark from "../brand/HorseMark";
import { me } from "../api/auth";
import { exchangeSsoCode, safeNext, ssoErrorMessage, takeVerifier } from "../api/sso";
import { useAuth } from "../state/auth";
import "../styles/identity.css";

/** Codes already being exchanged — guards StrictMode's double effect. */
const inFlight = new Set<string>();

function readParams(): { code: string | null; error: string | null; next: string } {
  try {
    const q = new URLSearchParams(window.location.search);
    return { code: q.get("code"), error: q.get("error"), next: safeNext(q.get("next")) };
  } catch {
    return { code: null, error: "state_mismatch", next: "/" };
  }
}

function replaceUrl(path: string) {
  try {
    window.history.replaceState(null, "", path);
  } catch {
    /* ignore */
  }
}

export default function SsoCallback() {
  const setAuth = useAuth((s) => s.setAuth);
  const setUser = useAuth((s) => s.setUser);
  const [params] = useState(readParams);
  const [error, setError] = useState<string | null>(params.error);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    // Scrub the one-time code from the address bar + history right away.
    replaceUrl("/sso/callback");
    const { code, next } = params;
    if (params.error || !code) {
      setError(params.error ?? "state_mismatch");
      return;
    }
    if (inFlight.has(code)) return;
    inFlight.add(code);
    const verifier = takeVerifier();
    (async () => {
      try {
        const res = await exchangeSsoCode(code, verifier);
        // Land on the deep link once the authed router mounts.
        replaceUrl(next);
        setAuth(res.access_token, { username: res.username, role: res.role, clearance: res.clearance });
        try {
          setUser(await me());
        } catch {
          /* keep the provisional principal */
        }
      } catch {
        replaceUrl("/sso/callback");
        setError("state_mismatch");
      }
    })();
  }, [params, setAuth, setUser]);

  return (
    <div className="login-screen">
      <div className="login-card" aria-live="polite">
        <div className="login-brand">
          <span className="login-mark"><HorseMark size={40} title="" /></span>
          <div>
            <div className="login-title">Paddock</div>
            <div className="login-sub mono">single sign-on</div>
          </div>
        </div>
        {error ? (
          <>
            <div className="login-error" role="alert">{ssoErrorMessage(error)}</div>
            <a className="sso-back" href="/login">Back to sign-in</a>
            <div className="login-foot mono">reference: {error}</div>
          </>
        ) : (
          <div className="sso-pending">
            <span className="sso-spinner" aria-hidden="true" />
            Completing sign-in…
          </div>
        )}
      </div>
    </div>
  );
}
