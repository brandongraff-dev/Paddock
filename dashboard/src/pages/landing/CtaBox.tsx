import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../state/auth";

const REPO = "https://github.com/brandongraff-dev/cybersec";
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
            <i className="cta-cursor"><svg viewBox="0 0 24 24" width="13" height="13"><path d="M12 2.5 20.5 7.5v9L12 21.5 3.5 16.5v-9Z" fill="none" stroke="#14110e" strokeWidth="1.8" strokeLinejoin="round" /><path d="M3.5 7.5 12 12.5l8.5-5M12 12.5v9" fill="none" stroke="#14110e" strokeWidth="1.8" strokeLinejoin="round" /></svg></i>
            <i className="cta-gpt"><svg viewBox="0 0 24 24" width="13" height="13"><path d="M12 3.2a4.2 4.2 0 0 1 3.6 2.1M18.9 8.6a4.2 4.2 0 0 1-.2 4.2M18 17.2a4.2 4.2 0 0 1-3.6 2.4M12 20.8a4.2 4.2 0 0 1-3.6-2.1M5.1 15.4a4.2 4.2 0 0 1 .2-4.2M6 6.8a4.2 4.2 0 0 1 3.6-2.4" fill="none" stroke="#14110e" strokeWidth="1.8" strokeLinecap="round" /><path d="m12 7.6 3.9 2.2v4.4L12 16.4l-3.9-2.2V9.8Z" fill="none" stroke="#14110e" strokeWidth="1.8" strokeLinejoin="round" /></svg></i>
            <i className="cta-claude"><svg viewBox="0 0 24 24" width="13" height="13"><path d="M12 2v20M2 12h20M5 5l14 14M19 5 5 19" stroke="#14110e" strokeWidth="2.2" strokeLinecap="round" /></svg></i>
          </span>
          <span>{copied ? "Copied to clipboard" : "Self-host in one command"}</span>
          <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
            {copied ? <path d="M3 8.5l3.2 3L13 4.5" /> : (<><rect x="5.5" y="5.5" width="8" height="8" rx="1.8" /><path d="M10.5 5.5V4A1.5 1.5 0 0 0 9 2.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></>)}
          </svg>
        </button>
        <a className="cta-link" href={`${REPO}/tree/main/docs`} target="_blank" rel="noreferrer">Read the docs</a>
      </div>
      <p className="cta-note">Open source. Self-hosted. Your data and keys stay on your own infrastructure.</p>
    </div>
  );
}
