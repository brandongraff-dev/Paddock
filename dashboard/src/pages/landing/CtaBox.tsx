import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../state/auth";
import { BRAND_ICONS } from "../../brand/brandIcons";
import { DOWNLOAD_NOTE, DOWNLOAD_URL } from "./download";

const DOCS = "https://docs.openpaddock.dev";
const REPO_URL = "https://github.com/brandongraff-dev/Paddock";
/** What the "Paste into your agent" pill copies: a self-contained setup brief for a coding agent. */
export const AGENT_PROMPT = `Set up Paddock (open-source, self-hosted attack surface management) on this machine and walk me through it.

1. Check that Docker and Docker Compose are installed and running. If not, tell me and stop.
2. Clone ${REPO_URL} and cd into it.
3. Run \`make quickstart\`. It creates .env, builds and starts the stack, and seeds a demo graph. It can take a few minutes the first time.
4. When it finishes, confirm the dashboard answers at http://localhost:3000 and the API docs at http://localhost:8080/docs, then tell me to open the Graph page.
5. Read docs/getting-started.md in the repo. Do not point Paddock at anything yet.

Rules you must follow:
- Paddock is defensive only. Never scan, probe or add as scope anything I have not told you I own or am explicitly authorised to assess.
- Do not change .env secrets or commit anything.
- If a step fails, show me the exact error and the fix you propose before you try it.

When the demo works, ask me which domain I own and want to map. Then use the "Point it at your own surface" steps in docs/getting-started.md (paddockctl scope add, then a scan), and remind me that ownership has to be proven before it counts as in scope.`;
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
    try { await navigator.clipboard.writeText(AGENT_PROMPT); } catch { /* clipboard unavailable */ }
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
        <button type="button" className="cta-cmd" onClick={copy} aria-label="Copy a setup prompt to paste into your coding agent" title="Copies a setup prompt for Cursor, ChatGPT or Claude">
          <span className="cta-dots" aria-hidden="true">
            {(["cursor", "openai", "claude"] as const).map((k) => (
              <i key={k} className={`cta-${k}`}>
                <svg viewBox="0 0 24 24" width="13" height="13"><path d={BRAND_ICONS[k]} fill="currentColor" /></svg>
              </i>
            ))}
          </span>
          <span>{copied ? "Copied. Paste it into your agent" : "Paste into your agent to set up"}</span>
          <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
            {copied ? <path d="M3 8.5l3.2 3L13 4.5" /> : (<><rect x="5.5" y="5.5" width="8" height="8" rx="1.8" /><path d="M10.5 5.5V4A1.5 1.5 0 0 0 9 2.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></>)}
          </svg>
        </button>
        <a className="cta-link" href="https://docs.openpaddock.dev" target="_blank" rel="noreferrer">Read the docs</a>
      </div>
      <p className="cta-note">Open source. Self-hosted. Your data and keys stay on your own infrastructure.</p>
      <p className="cta-note cta-dl-note">{DOWNLOAD_NOTE}</p>
    </div>
  );
}
