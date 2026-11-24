import { useEffect, useRef, useState, type ReactNode } from "react";
import HorseMark from "@dash/brand/HorseMark";
import { DOCKER_URL, WSL_URL } from "./bridge";
import type { Check } from "./protocol";

export function Brand({ version }: { version?: string }) {
  return (
    <header className="setup-top">
      <div className="setup-brand">
        <HorseMark size={24} />
        <span>Paddock</span>
        <span className="setup-badge">setup{version ? ` ${version}` : ""}</span>
      </div>
    </header>
  );
}

export const RAIL = [
  { id: "welcome", label: "Welcome", hint: "What this does" },
  { id: "pc", label: "Your PC", hint: "A quick check" },
  { id: "options", label: "Options", hint: "Where it goes" },
  { id: "install", label: "Install", hint: "About 5 minutes" },
  { id: "done", label: "Done", hint: "Sign in" },
] as const;
export type RailId = (typeof RAIL)[number]["id"];

export function Rail({ current }: { current: RailId }) {
  const at = RAIL.findIndex((r) => r.id === current);
  return (
    <nav className="setup-rail" aria-label="Setup steps">
      <ol>
        {RAIL.map((r, i) => (
          <li key={r.id} className={`setup-rail-item${i === at ? " on" : ""}${i < at ? " done" : ""}`}>
            <div className="inst-rail-row" aria-current={i === at ? "step" : undefined}>
              <span className="setup-rail-num" aria-hidden="true">{i < at ? "✓" : i + 1}</span>
              <span className="setup-rail-text">
                <span className="setup-rail-label">{r.label}</span>
                <span className="setup-rail-hint">{r.hint}</span>
              </span>
            </div>
          </li>
        ))}
      </ol>
    </nav>
  );
}

const ICON: Record<Check["status"], { glyph: string; label: string }> = {
  ok: { glyph: "✓", label: "Passed" },
  warn: { glyph: "!", label: "Warning" },
  fail: { glyph: "✕", label: "Needs fixing" },
};

/** Which "get it" link, if any, helps with this failing check. */
function helpLink(c: Check): { label: string; url: string } | null {
  if (c.status === "ok") return null;
  if (c.name === "Docker Desktop") return { label: "Get Docker Desktop", url: DOCKER_URL };
  if (c.name === "WSL 2") return { label: "How to install WSL", url: WSL_URL };
  return null;
}

export function CheckList({ checks, onOpen, onlyProblems = false }: { checks: Check[]; onOpen: (url: string) => void; onlyProblems?: boolean }) {
  const rows = onlyProblems ? checks.filter((c) => c.status !== "ok") : checks;
  return (
    <ul className="inst-checks" aria-label="Checks">
      {rows.map((c, i) => {
        const link = helpLink(c);
        return (
          <li key={`${c.name}-${i}`} className="inst-check" data-status={c.status}>
            <span className="inst-check-icon" role="img" aria-label={ICON[c.status].label}>{ICON[c.status].glyph}</span>
            <div className="inst-check-body">
              <div className="inst-check-head"><strong>{c.name}</strong><span>{c.detail}</span></div>
              {c.status !== "ok" && c.fix && (
                <div className="inst-fix">
                  {c.fix.split("\n").map((l, j) => <div key={j}>{l}</div>)}
                </div>
              )}
              {link && <button type="button" className="inst-link" onClick={() => onOpen(link.url)}>{link.label}</button>}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

export function Spinner({ label }: { label: string }) {
  return <span className="inst-spinner" role="status" aria-label={label} />;
}

/** One labelled value with a Copy button, in the same style as the web setup's DNS records. */
export function CopyRow({ label, value, secret = false }: { label: string; value: string; secret?: boolean }) {
  const [shown, setShown] = useState(!secret);
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => () => clearTimeout(timer.current), []);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1600);
    } catch {
      setShown(true); // clipboard blocked: show it so it can be selected by hand
    }
  }
  return (
    <div className="setup-copy">
      <span className="setup-copy-label">{label}</span>
      <code className="setup-copy-value mono" data-testid={`value-${label}`}>{shown ? value : "•".repeat(Math.min(value.length, 16))}</code>
      <span className="inst-copy-actions">
        {secret && (
          <button type="button" className="ghost setup-copy-btn" onClick={() => setShown((v) => !v)} aria-pressed={shown}>
            {shown ? "Hide" : "Show"}
          </button>
        )}
        <button type="button" className="setup-copy-btn" onClick={copy} aria-label={copied ? `${label} copied` : `Copy ${label}`}>{copied ? "Copied" : "Copy"}</button>
      </span>
    </div>
  );
}

export function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="panel inst-panel">
      <div className="panel-h"><h2>{title}</h2></div>
      {children}
    </section>
  );
}
