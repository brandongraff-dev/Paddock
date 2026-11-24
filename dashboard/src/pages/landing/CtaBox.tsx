import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../state/auth";
import { BRAND_ICONS } from "../../brand/brandIcons";
import { DOWNLOAD_NOTE, DOWNLOAD_URL } from "./download";

const DOCS = "https://paddock-docs.vercel.app";
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
        <a className="cta-cmd cta-download" href={DOWNLOAD_URL} target="_blank" rel="noreferrer" title={DOWNLOAD_NOTE}>
          <svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor" aria-hidden="true">
            <path d="M0 2.3l6.5-.9v6.1H0zM7.4 1.3L16 0v7.5H7.4zM0 8.4h6.5v6.1L0 13.7zM7.4 8.4H16V16l-8.6-1.2z" />
          </svg>
          <span>Download for Windows</span>
        </a>
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
        <a className="cta-link" href="https://paddock-docs.vercel.app" target="_blank" rel="noreferrer">Read the docs</a>
      </div>
      <p className="cta-note">Open source. Self-hosted. Your data and keys stay on your own infrastructure.</p>
      <p className="cta-note cta-dl-note">{DOWNLOAD_NOTE}</p>
    </div>
  );
}
