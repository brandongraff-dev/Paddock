import { useEffect, useRef, useState, type ReactNode } from "react";
import Wordmark from "@dash/brand/Wordmark";
import { DOCKER_URL, WSL_URL } from "./bridge";
import { capitalize, friendlyCheck, tidyFix } from "./humanize";
import type { Check } from "./protocol";

/** Window chrome: the wordmark, and where you are in the three steps. */
export function Header({ step }: { step?: string }) {
  return (
    <header className="inst-header">
      <Wordmark height={17} mono />
      {step && <span className="inst-step">{step}</span>}
    </header>
  );
}

/** One screen: a title, one sentence, the content, and the button bar that never scrolls away. */
export function Screen({ title, lede, children, left, actions }: {
  title: string; lede?: ReactNode; children?: ReactNode; left?: ReactNode; actions: ReactNode;
}) {
  return (
    <section className="inst-screen">
      <div className="inst-body">
        <h1 className="inst-title">{title}</h1>
        {lede && <p className="inst-lede">{lede}</p>}
        {children}
      </div>
      <footer className="inst-footer">
        <div className="inst-footer-left">{left}</div>
        <div className="inst-footer-right">{actions}</div>
      </footer>
    </section>
  );
}

const ICON: Record<Check["status"], { glyph: string; label: string }> = {
  ok: { glyph: "✓", label: "Passed" },
  warn: { glyph: "!", label: "Note" },
  fail: { glyph: "✕", label: "Needs fixing" },
};

function helpLink(c: Check): { label: string; url: string } | null {
  if (c.status === "ok") return null;
  if (c.name === "Docker Desktop") return { label: "Get Docker Desktop", url: DOCKER_URL };
  if (c.name === "WSL 2") return { label: "How to install WSL", url: WSL_URL };
  return null;
}

/** Problems: what is wrong, how to fix it, and a link when one helps. */
export function Problems({ checks, onOpen }: { checks: Check[]; onOpen: (url: string) => void }) {
  const rows = checks.filter((c) => c.status !== "ok");
  if (!rows.length) return null;
  return (
    <ul className="inst-problems" aria-label="Things to fix">
      {rows.map((c, i) => {
        const f = friendlyCheck(c);
        const link = helpLink(c);
        const fix = tidyFix(c.fix);
        return (
          <li key={`${c.name}-${i}`} data-status={c.status}>
            <span className="inst-mark" role="img" aria-label={ICON[c.status].label}>{ICON[c.status].glyph}</span>
            <div>
              <div className="inst-problem-head"><strong>{f.name}</strong> <span>{f.detail}</span></div>
              {fix.paragraphs.map((p, j) => <p key={j} className="inst-fix">{p}</p>)}
              {fix.steps.length > 0 && <ol className="inst-steps">{fix.steps.map((s, j) => <li key={j}>{s}</li>)}</ol>}
              {link && <button type="button" className="inst-linkbtn" onClick={() => onOpen(link.url)}>{link.label}</button>}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

/** Every check, compact, for people who want to see them. */
export function CheckTable({ checks }: { checks: Check[] }) {
  return (
    <table className="inst-table" aria-label="All checks">
      <tbody>
        {checks.map((c, i) => {
          const f = friendlyCheck(c);
          return (
            <tr key={`${c.name}-${i}`} data-status={c.status}>
              <td className="inst-table-mark"><span className="inst-mark" role="img" aria-label={ICON[c.status].label}>{ICON[c.status].glyph}</span></td>
              <th scope="row">{f.name}</th>
              <td>{capitalize(f.detail)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

export function Spinner({ label }: { label: string }) {
  return <span className="inst-spinner" role="status" aria-label={label} />;
}

export function Disclosure({ summary, children }: { summary: string; children: ReactNode }) {
  return (
    <details className="inst-details">
      <summary>{summary}</summary>
      {children}
    </details>
  );
}

/** A label, a value, and a Copy button. The value can start hidden. */
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
    <div className="inst-copyrow">
      <span className="inst-copy-label">{label}</span>
      <code className="inst-copy-value" data-testid={`value-${label}`}>{shown ? value : "•".repeat(Math.min(value.length, 16))}</code>
      <span className="inst-copy-actions">
        {secret && (
          <button type="button" className="inst-linkbtn" onClick={() => setShown((v) => !v)} aria-pressed={shown}>
            {shown ? "Hide" : "Show"}
          </button>
        )}
        <button type="button" className="inst-small" onClick={copy} aria-label={copied ? `${label} copied` : `Copy ${label}`}>{copied ? "Copied" : "Copy"}</button>
      </span>
    </div>
  );
}
