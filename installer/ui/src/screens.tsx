import { useState } from "react";
import { PADDOCK_URL, type AppState } from "./bridge";
import { CANCELLED } from "./useRun";
import { CheckList, CopyRow, Panel, Spinner } from "./components";
import { hasBlocker, percent, PHASES, phaseState, type Check, type RunState } from "./protocol";

type Open = (url: string) => void;

/* ------------------------------ welcome ------------------------------ */

export function Welcome({ onStart }: { onStart: () => void }) {
  return (
    <div className="setup-step">
      <h1 className="setup-title">Install Paddock</h1>
      <p className="setup-lede">
        Paddock keeps watch over the websites and servers you put on the internet and tells you what to fix first.
        This sets it up on this PC in about five minutes. You do not need any accounts or keys.
      </p>
      <ul className="setup-list">
        <li>Runs privately on this PC, inside Docker Desktop. Nothing is sent anywhere.</li>
        <li>Takes about 1.5 GB of disk space and 2 GB of memory while it is running.</li>
        <li>Strong passwords are created for you. You will see the login at the end.</li>
        <li>AI summaries are optional and can be switched on later, in Settings.</li>
      </ul>
      <div className="setup-actions">
        <button type="button" className="primary" onClick={onStart}>Get started</button>
      </div>
    </div>
  );
}

/* ------------------------------ PC check ------------------------------ */

export function PcCheck({ run, onOpen, onAgain, onBack, onNext }: {
  run: RunState | null; onOpen: Open; onAgain: () => void; onBack: () => void; onNext: () => void;
}) {
  const checking = !run || run.status === "running";
  const blocked = !!run && hasBlocker(run.checks);
  const warns = run?.checks.filter((c) => c.status === "warn").length ?? 0;
  const crashed = !!run && run.status === "failed" && run.checks.length === 0;
  return (
    <div className="setup-step">
      <h1 className="setup-title">Checking your PC</h1>
      <p className="setup-lede">
        {checking
          ? "Making sure Docker Desktop and your PC are ready. This takes a few seconds."
          : blocked
            ? "A few things need your attention before Paddock can run. Each one says how to fix it."
            : warns > 0
              ? "You can continue. Keep an eye on the notes below."
              : "Everything looks good."}
      </p>
      {checking && !run?.checks.length && <div className="inst-wait"><Spinner label="Checking" /> Checking…</div>}
      {run && run.checks.length > 0 && (
        <Panel title="This PC">
          <CheckList checks={run.checks} onOpen={onOpen} />
        </Panel>
      )}
      {crashed && run?.error && <div className="setup-error" role="alert">{run.error}</div>}
      <div className="setup-actions">
        <button type="button" className="ghost" onClick={onBack}>Back</button>
        <button type="button" onClick={onAgain} disabled={checking}>Check again</button>
        <button type="button" className="primary" onClick={onNext} disabled={checking || blocked || crashed}>Continue</button>
      </div>
    </div>
  );
}

/* ------------------------------ options ------------------------------ */

export function Options({ dir, active, error, onDir, onActive, onBack, onInstall }: {
  dir: string; active: boolean; error: string | null;
  onDir: (v: string) => void; onActive: (v: boolean) => void; onBack: () => void; onInstall: () => void;
}) {
  return (
    <form className="setup-step" onSubmit={(e) => { e.preventDefault(); onInstall(); }}>
      <h1 className="setup-title">Where should it go?</h1>
      <p className="setup-lede">
        Paddock keeps its settings and passwords in one folder. The default is fine for almost everyone.
      </p>
      <div className="setup-form">
        <label className="setup-label" htmlFor="inst-dir">Install folder</label>
        <input id="inst-dir" className="mono" value={dir} onChange={(e) => onDir(e.target.value)} spellCheck={false} autoComplete="off" />
        <label className="setup-check">
          <input type="checkbox" checked={active} onChange={(e) => onActive(e.target.checked)} />
          <span>
            Also install the active scanner
            <span className="setup-muted"> Probes your own sites for open ports and weak TLS. Adds about 3.5 GB. You can add it later.</span>
          </span>
        </label>
      </div>
      {error && <div className="setup-error" role="alert">{error}</div>}
      <div className="setup-actions">
        <button type="button" className="ghost" onClick={onBack}>Back</button>
        <button type="submit" className="primary" disabled={!dir.trim()}>Install</button>
      </div>
    </form>
  );
}

/* ------------------------------ installing ------------------------------ */

function Log({ lines }: { lines: string[] }) {
  return (
    <details className="inst-details">
      <summary>Show details</summary>
      <pre className="inst-log" tabIndex={0} aria-label="Installer output">{lines.slice(-200).join("\n") || "Nothing yet."}</pre>
    </details>
  );
}

export function ProblemList({ checks, onOpen }: { checks: Check[]; onOpen: Open }) {
  const problems = checks.filter((c) => c.status !== "ok");
  if (!problems.length) return null;
  return <Panel title="What to fix"><CheckList checks={problems} onOpen={onOpen} /></Panel>;
}

export function Installing({ run, onCancel }: { run: RunState; onCancel: () => void }) {
  const pct = percent(run);
  return (
    <div className="setup-step">
      <h1 className="setup-title">Installing Paddock</h1>
      <p className="setup-lede" aria-live="polite">{run.stepText || "Getting ready…"}</p>
      <div className="inst-progress" role="progressbar" aria-label="Install progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} data-busy={run.step === "images"}>
        <i style={{ width: `${pct}%` }} />
      </div>
      <ol className="inst-phases">
        {PHASES.map((p) => {
          const st = phaseState(run, p.id);
          return (
            <li key={p.id} data-state={st}>
              <span className="inst-phase-dot" aria-hidden="true">{st === "done" ? "✓" : ""}</span>
              <span>{p.label}</span>
              <span className="sr-only">{st === "done" ? " (done)" : st === "active" ? " (in progress)" : ""}</span>
            </li>
          );
        })}
      </ol>
      {run.step === "images" && (
        <p className="setup-muted">This is the longest part: about 1.5 GB to download, usually one to two minutes. It is safe to leave this window open in the background.</p>
      )}
      {run.warnings.length > 0 && <div className="inst-warn" role="status">{run.warnings[run.warnings.length - 1]}</div>}
      <Log lines={run.log} />
      <div className="setup-actions">
        <button type="button" className="ghost" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}

export function Failed({ title, run, onOpen, onRetry, onBack, backLabel, onCopy }: {
  title: string; run: RunState; onOpen: Open; onRetry: () => void; onBack?: () => void; backLabel?: string; onCopy: () => void;
}) {
  const cancelled = run.error === CANCELLED;
  return (
    <div className="setup-step">
      <h1 className="setup-title">{cancelled ? "Setup stopped" : title}</h1>
      <div className={cancelled ? "inst-warn" : "setup-error"} role="alert">{run.error}</div>
      <ProblemList checks={run.checks} onOpen={onOpen} />
      {!cancelled && <p className="setup-muted">If Docker Desktop was only just installed, restart your PC and try again. Nothing here is lost: Setup picks up where it left off.</p>}
      <Log lines={run.log} />
      <div className="setup-actions">
        {onBack && <button type="button" className="ghost" onClick={onBack}>{backLabel ?? "Back"}</button>}
        <button type="button" onClick={onCopy}>Copy details</button>
        <button type="button" className="primary" onClick={onRetry}>Try again</button>
      </div>
    </div>
  );
}

/* ------------------------------ done ------------------------------ */

export function Done({ run, onOpen, onRetry, onClose }: { run: RunState; onOpen: Open; onRetry: () => void; onClose: () => void }) {
  const r = run.result;
  if (!r) return null;
  return (
    <div className="setup-step">
      <div className={`inst-badge ${r.healthy ? "ok" : "warn"}`} aria-hidden="true">{r.healthy ? "✓" : "!"}</div>
      <h1 className="setup-title">{r.healthy ? "Paddock is running" : "Paddock is starting"}</h1>
      <p className="setup-lede">
        {r.healthy
          ? "Open it in your browser and sign in with the login below. A short guide then helps you add your first domain."
          : "It started, but is not answering yet. Give it a minute, then open it. If it still does not load, choose Check again."}
      </p>
      <Panel title="Your login">
        <div className="inst-creds">
          <CopyRow label="Address" value={r.url} />
          <CopyRow label="User" value={r.username} />
          <CopyRow label="Password" value={r.password} secret />
        </div>
        <p className="setup-muted inst-creds-note">
          Saved in {r.dir ? <code className="mono">{r.dir}\.env</code> : "your install folder"} if you need it again.
        </p>
      </Panel>
      <div className="setup-actions">
        {!r.healthy && <button type="button" onClick={onRetry}>Check again</button>}
        <button type="button" onClick={onClose}>Close</button>
        <button type="button" className="primary" onClick={() => onOpen(r.url || PADDOCK_URL)}>Open Paddock</button>
      </div>
    </div>
  );
}

/* ------------------------------ manage (already installed) ------------------------------ */

export function Manage({ app, onOpen, onStart, onStop, onRemove, onClose }: {
  app: AppState; onOpen: Open; onStart: () => void; onStop: () => void; onRemove: () => void; onClose: () => void;
}) {
  const [confirm, setConfirm] = useState(false);
  return (
    <div className="setup-step">
      <h1 className="setup-title">Paddock is installed</h1>
      <p className="setup-lede">
        {app.running ? "It is running on this PC." : "It is installed but not running right now."}
        {app.version ? ` Version ${app.version}.` : ""}
      </p>
      <Panel title="This install">
        <div className="inst-status">
          <span className="inst-dot" data-on={app.running} aria-hidden="true" />
          <strong>{app.running ? "Running" : "Stopped"}</strong>
          <code className="mono inst-dir">{app.dir}</code>
        </div>
      </Panel>
      {!confirm ? (
        <div className="setup-actions">
          <button type="button" className="primary" onClick={() => (app.running ? onOpen(PADDOCK_URL) : onStart())}>
            {app.running ? "Open Paddock" : "Start Paddock"}
          </button>
          {app.running && <button type="button" onClick={onStart}>Update or repair</button>}
          {app.running && <button type="button" onClick={onStop}>Stop</button>}
          <button type="button" className="danger" onClick={() => setConfirm(true)}>Remove…</button>
          <button type="button" className="ghost" onClick={onClose}>Close</button>
        </div>
      ) : (
        <div className="inst-confirm" role="alertdialog" aria-labelledby="inst-confirm-h">
          <h2 id="inst-confirm-h">Remove Paddock and all its data?</h2>
          <p className="setup-muted">
            This deletes your findings, scan history, settings and passwords from this PC. It cannot be undone.
            To keep your data, choose Stop instead.
          </p>
          <div className="setup-actions">
            <button type="button" className="ghost" onClick={() => setConfirm(false)}>Keep it</button>
            <button type="button" className="danger" onClick={onRemove}>Delete everything</button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ------------------------------ stop / remove ------------------------------ */

export function Work({ action, run, onBack, onRetry, onCopy, onOpen }: {
  action: "stop" | "remove"; run: RunState; onBack: () => void; onRetry: () => void; onCopy: () => void; onOpen: Open;
}) {
  const verb = action === "stop" ? "Stopping" : "Removing";
  if (run.status === "failed") {
    return <Failed title={`${verb} did not finish`} run={run} onOpen={onOpen} onRetry={onRetry} onBack={onBack} onCopy={onCopy} />;
  }
  if (run.status === "succeeded") {
    return (
      <div className="setup-step">
        <div className="inst-badge ok" aria-hidden="true">✓</div>
        <h1 className="setup-title">{action === "stop" ? "Paddock is stopped" : "Paddock was removed"}</h1>
        <p className="setup-lede">
          {action === "stop" ? "Your data is kept. Start it again any time from this window." : "Its containers, data and folder are gone from this PC."}
        </p>
        <div className="setup-actions"><button type="button" className="primary" onClick={onBack}>Done</button></div>
      </div>
    );
  }
  return (
    <div className="setup-step">
      <h1 className="setup-title">{verb} Paddock</h1>
      <p className="setup-lede" aria-live="polite"><Spinner label={verb} /> {run.stepText || "Working…"}</p>
      <Log lines={run.log} />
    </div>
  );
}
