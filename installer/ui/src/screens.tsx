import { useState } from "react";
import { helpUrl, PADDOCK_URL, type AppState } from "./bridge";
import { CheckTable, CopyRow, Disclosure, Problems, Screen, Spinner } from "./components";
import { explainError, friendlyStep, friendlyWarning } from "./humanize";
import { hasBlocker, percent, type RunState } from "./protocol";
import { CANCELLED } from "./useRun";

type Open = (url: string) => void;

/* ------------------------------ 1. ready ------------------------------ */

/** The PC check runs by itself; this only interrupts when something needs fixing. */
export function Ready({ pc, dir, active, shortcut, dirError, onDir, onActive, onShortcut, onBrowse, onOpen, onAgain, onInstall, onClose }: {
  pc: RunState | null; dir: string; active: boolean; shortcut: boolean; dirError: string | null;
  onDir: (v: string) => void; onActive: (v: boolean) => void; onShortcut: (v: boolean) => void; onBrowse: () => void;
  onOpen: Open; onAgain: () => void; onInstall: () => void; onClose: () => void;
}) {
  const checking = !pc || pc.status === "running";
  const blocked = !!pc && hasBlocker(pc.checks);
  const crashed = !!pc && pc.status === "failed" && pc.checks.length === 0;
  const notes = pc ? pc.checks.filter((c) => c.status === "warn").length : 0;
  const ready = !checking && !blocked && !crashed;
  const canInstall = ready && dir.trim().length > 0;

  return (
    <Screen
      title="Install Paddock"
      lede="Paddock runs privately on this PC, inside Docker Desktop. Setup takes about five minutes."
      left={<button type="button" onClick={onClose}>Cancel</button>}
      actions={<button type="submit" form="inst-ready" className="primary" disabled={!canInstall}>Install</button>}
    >
      <section className="inst-section" aria-labelledby="inst-pc-h">
        <h2 id="inst-pc-h" className="inst-h2">Your PC</h2>
        {checking && <p className="inst-status"><Spinner label="Checking" /> Checking your PC</p>}
        {ready && (
          <p className="inst-status" data-tone="ok"><span className="inst-mark" aria-hidden="true">✓</span> {notes > 0 ? `Ready to install, with ${notes === 1 ? "a note" : `${notes} notes`}` : "Your PC is ready"}</p>
        )}
        {blocked && <p className="inst-status" data-tone="bad"><span className="inst-mark" aria-hidden="true">✕</span> {pc!.checks.filter((c) => c.status === "fail").length === 1 ? "One thing needs fixing first" : "A few things need fixing first"}</p>}
        {crashed && pc?.error && <p className="inst-error" role="alert">{explainError(pc.error).headline} {explainError(pc.error).hint}</p>}
        {pc && <Problems checks={pc.checks} onOpen={onOpen} />}
        {pc && pc.checks.length > 0 && !checking && (
          <Disclosure summary="Show all checks"><CheckTable checks={pc.checks} /></Disclosure>
        )}
        {!checking && (blocked || crashed) && (
          <p><button type="button" onClick={onAgain}>Check again</button></p>
        )}
      </section>

      <form id="inst-ready" className="inst-section" onSubmit={(e) => { e.preventDefault(); if (canInstall) onInstall(); }}>
        <label className="inst-h2" htmlFor="inst-dir">Install location</label>
        <div className="inst-field">
          <input id="inst-dir" className="inst-input" value={dir} onChange={(e) => onDir(e.target.value)} spellCheck={false} autoComplete="off" aria-invalid={!!dirError} aria-describedby={dirError ? "inst-dir-err" : undefined} />
          <button type="button" onClick={onBrowse}>Browse…</button>
        </div>
        {dirError && <p id="inst-dir-err" className="inst-error" role="alert">{dirError}</p>}
        <Disclosure summary="More options">
          <label className="inst-check">
            <input type="checkbox" checked={shortcut} onChange={(e) => onShortcut(e.target.checked)} />
            <span>Add a shortcut to the Start menu
              <span className="inst-hint">So you can open Paddock like any other app.</span>
            </span>
          </label>
          <label className="inst-check">
            <input type="checkbox" checked={active} onChange={(e) => onActive(e.target.checked)} />
            <span>Include the active scanner
              <span className="inst-hint">Probes your own sites for open ports and weak TLS. Adds about 3.5 GB; you can add it later.</span>
            </span>
          </label>
        </Disclosure>
      </form>
    </Screen>
  );
}

/* ------------------------------ 2. installing ------------------------------ */

export function Installing({ run, action = "install", onCancel }: { run: RunState; action?: "install" | "stop" | "remove"; onCancel?: () => void }) {
  const pct = percent(run);
  const slow = run.warnings.length > 0 ? friendlyWarning(run.warnings[run.warnings.length - 1]) : null;
  const verb = action === "install" ? "Installing Paddock" : action === "stop" ? "Stopping Paddock" : "Removing Paddock";
  return (
    <Screen
      title={verb}
      lede={<span aria-live="polite">{friendlyStep(run.step, action)}</span>}
      actions={onCancel ? <button type="button" onClick={onCancel}>Cancel</button> : <span />}
    >
      {action === "install" ? (
        <div className="inst-progress-row">
          <div className="inst-progress" role="progressbar" aria-label="Install progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} data-busy={run.step === "images"}>
            <i style={{ width: `${pct}%` }} />
          </div>
          <span className="inst-pct">{pct}%</span>
        </div>
      ) : (
        <p className="inst-status"><Spinner label={verb} /> {friendlyStep(run.step, action)}</p>
      )}
      {run.step === "images" && <p className="inst-hint">This is the longest part. It usually takes one to two minutes, and you can leave this window open in the background.</p>}
      {slow && <p className="inst-note" role="status">{slow}</p>}
      <Details run={run} />
    </Screen>
  );
}

function Details({ run, label = "Details" }: { run: RunState; label?: string }) {
  return (
    <Disclosure summary={label}>
      <pre className="inst-log" tabIndex={0} aria-label="Installer output">{run.log.slice(-200).join("\n") || "Nothing yet."}</pre>
    </Disclosure>
  );
}

/* ------------------------------ failure ------------------------------ */

export function Failed({ run, onOpen, onRetry, onBack, backLabel = "Back", onCopy }: {
  run: RunState; onOpen: Open; onRetry: () => void; onBack: () => void; backLabel?: string; onCopy: () => void;
}) {
  const help = () => onOpen(helpUrl(explainError(run.error ?? "").headline));
  const cancelled = run.error === CANCELLED;
  const e = explainError(run.error ?? "");
  return (
    <Screen
      title={cancelled ? "Setup stopped" : e.headline}
      lede={cancelled ? "Run it again whenever you like. It picks up where it left off." : e.hint || undefined}
      left={!cancelled ? <><button type="button" onClick={onCopy}>Copy details</button><button type="button" className="inst-linkbtn" onClick={help}>Get help</button></> : undefined}
      actions={<><button type="button" onClick={onBack}>{backLabel}</button><button type="button" className="primary" onClick={onRetry}>Try again</button></>}
    >
      {!cancelled && <Problems checks={run.checks} onOpen={onOpen} />}
      {!cancelled && (
        <Disclosure summary="Technical details">
          <pre className="inst-log" tabIndex={0} aria-label="Technical details">{[run.error, "", ...run.log.slice(-200)].join("\n")}</pre>
        </Disclosure>
      )}
    </Screen>
  );
}

/* ------------------------------ 3. done ------------------------------ */

export function Done({ run, onOpen, onRetry, onClose }: { run: RunState; onOpen: Open; onRetry: () => void; onClose: () => void }) {
  const r = run.result;
  if (!r) return null;
  return (
    <Screen
      title={r.healthy ? "Paddock is running" : "Paddock is still starting"}
      lede={r.healthy
        ? "Open it in your browser and sign in with the details below."
        : "It is installed but is not answering yet. Give it a minute, then open it. If it still does not load, choose Check again."}
      actions={
        <>
          {!r.healthy && <button type="button" onClick={onRetry}>Check again</button>}
          <button type="button" onClick={onClose}>Close</button>
          <button type="button" className="primary" onClick={() => onOpen(r.url || PADDOCK_URL)}>Open Paddock</button>
        </>
      }
    >
      <section className="inst-section" aria-label="Sign-in details">
        <CopyRow label="Address" value={r.url} />
        <CopyRow label="User" value={r.username} />
        <CopyRow label="Password" value={r.password} secret />
        <p className="inst-hint">Saved in {r.dir ? <code>{r.dir}\.env</code> : "your install folder"} if you need it again.</p>
      </section>
    </Screen>
  );
}

/* ------------------------------ manage ------------------------------ */

export function Manage({ app, onOpen, onStart, onStop, onRemove, onClose }: {
  app: AppState; onOpen: Open; onStart: () => void; onStop: () => void; onRemove: () => void; onClose: () => void;
}) {
  const [confirm, setConfirm] = useState(false);
  if (confirm) {
    return (
      <Screen
        title="Remove Paddock and all its data?"
        lede="This deletes your findings, scan history, settings and passwords from this PC. It cannot be undone. To keep your data, choose Stop instead."
        actions={<><button type="button" onClick={() => setConfirm(false)}>Keep it</button><button type="button" className="danger" onClick={onRemove}>Delete everything</button></>}
      />
    );
  }
  return (
    <Screen
      title="Paddock is installed"
      lede={app.version ? `Version ${app.version}.` : undefined}
      left={<button type="button" className="inst-linkbtn danger" onClick={() => setConfirm(true)}>Remove…</button>}
      actions={
        <>
          <button type="button" onClick={onClose}>Close</button>
          {app.running && <button type="button" onClick={onStop}>Stop</button>}
          {app.running && <button type="button" onClick={onStart}>Update or repair</button>}
          <button type="button" className="primary" onClick={() => (app.running ? onOpen(PADDOCK_URL) : onStart())}>{app.running ? "Open Paddock" : "Start Paddock"}</button>
        </>
      }
    >
      <section className="inst-section">
        <p className="inst-status" data-tone={app.running ? "ok" : undefined}>
          <span className="inst-dot" data-on={app.running} aria-hidden="true" /> {app.running ? "Running" : "Stopped"}
        </p>
        <p className="inst-hint">Installed in <code>{app.dir}</code></p>
      </section>
    </Screen>
  );
}

/* ------------------------------ stop / remove finished ------------------------------ */

export function WorkDone({ action, onBack }: { action: "stop" | "remove"; onBack: () => void }) {
  return (
    <Screen
      title={action === "stop" ? "Paddock is stopped" : "Paddock was removed"}
      lede={action === "stop" ? "Your data is kept. Start it again any time from this window." : "Its containers, data and folder are gone from this PC."}
      actions={<button type="button" className="primary" onClick={onBack}>Done</button>}
    />
  );
}
