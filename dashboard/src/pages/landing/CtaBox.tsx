import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../state/auth";
import { BRAND_ICONS } from "../../brand/brandIcons";

const DOCS = "https://docs.openpaddock.dev";
const CMD = "make quickstart";
export const PENDING_DOMAIN_KEY = "paddock.cta.domain";

/**
 * The main call to action: a domain pill with its button inside, a
 * copy-the-install-command pill, a docs link and a one-line promise.
 * The domain is handed to the setup wizard, which asks for proof of
 * ownership before anything is ever scanned.
 */
export default function CtaBox({ className }: { className?: string }) {
  const nav = useNavigate();
  const token = useAuth((s) => s.token);
  const [domain, setDomain] = useState("");
  const [copied, setCopied] = useState(false);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const v = domain.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
    try { if (v) sessionStorage.setItem(PENDING_DOMAIN_KEY, v); } catch { /* storage unavailable */ }
    nav(token ? "/setup" : "/login");
  };

  const copy = async () => {
    try { await navigator.clipboard.writeText(CMD); } catch { /* clipboard unavailable */ }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className={`cta ${className ?? ""}`}>
      <form className="cta-pill" onSubmit={submit}>
        <input
          type="text"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          placeholder="Enter a domain you own"
          aria-label="Domain you own"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
        />
        <button type="submit">Start mapping</button>
      </form>
      <div className="cta-row">
        <button type="button" className="cta-cmd" onClick={copy} aria-label={`Copy command: ${CMD}`}>
          <span className="cta-dots" aria-hidden="true">
            {(["cursor", "openai", "claude"] as const).map((k) => (
              <i key={k} className={`cta-${k}`}>
                <svg viewBox="0 0 24 24" width="13" height="13"><path d={BRAND_ICONS[k]} fill="currentColor" /></svg>
              </i>
            ))}
          </span>
          <span>{copied ? "Copied to clipboard" : "Self-host in one command"}</span>
          <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
            {copied ? <path d="M3 8.5l3.2 3L13 4.5" /> : (<><rect x="5.5" y="5.5" width="8" height="8" rx="1.8" /><path d="M10.5 5.5V4A1.5 1.5 0 0 0 9 2.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></>)}
          </svg>
        </button>
        <a className="cta-link" href="https://docs.openpaddock.dev" target="_blank" rel="noreferrer">Read the docs</a>
      </div>
      <p className="cta-note">Open source. Self-hosted. Your data and keys stay on your own infrastructure.</p>
    </div>
  );
}
