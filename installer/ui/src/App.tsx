import { useCallback, useEffect, useState } from "react";
import PixelField from "@dash/brand/PixelField";
import type { AppState, Bridge } from "./bridge";
import { Brand, Rail, type RailId } from "./components";
import type { RunState } from "./protocol";
import { Done, Failed, Installing, Manage, Options, PcCheck, Welcome, Work } from "./screens";
import { CANCELLED, useRun } from "./useRun";

type Screen = "welcome" | "pc" | "options" | "install" | "manage" | "work";

const msg = (e: unknown) => String((e as Error)?.message ?? e);

/** Everything worth pasting into a support request. Never the login. */
export function detailsText(run: RunState | null): string {
  if (!run) return "";
  const checks = run.checks.map((c) => `[${c.status}] ${c.name}: ${c.detail}`);
  return [run.error ? `error: ${run.error}` : "", ...checks, "", ...run.log].filter((l, i) => l !== "" || i > 0).join("\n");
}

export default function App({ bridge }: { bridge: Bridge }) {
  const [app, setApp] = useState<AppState | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [screen, setScreen] = useState<Screen>("welcome");
  const [dir, setDir] = useState("");
  const [active, setActive] = useState(false);
  const [work, setWork] = useState<"stop" | "remove">("stop");
  const [optionsError, setOptionsError] = useState<string | null>(null);
  const run = useRun(bridge);
  const st = run.state;

  const refresh = useCallback(async () => {
    const s = await bridge.getState();
    setApp(s);
    return s;
  }, [bridge]);

  useEffect(() => {
    refresh().then(
      (s) => {
        setDir(s.dir);
        setScreen(s.installed ? "manage" : "welcome");
      },
      (e) => setLoadError(msg(e)),
    );
  }, [refresh]);

  // The script never started (a bad folder, PowerShell missing): that is a mistake in the
  // options, not an install failure, so say so where it can be fixed.
  useEffect(() => {
    if (screen === "install" && st && st.status === "failed" && st.seen.length === 0 && st.exitCode === null && st.error !== CANCELLED) {
      setOptionsError(st.error);
      setScreen("options");
      run.reset();
    }
  }, [screen, st, run]);

  const open = (url: string) => void bridge.openUrl(url).catch(() => undefined);
  const copyDetails = () => void navigator.clipboard?.writeText(detailsText(st)).catch(() => undefined);

  const check = () => { setScreen("pc"); run.start("doctor", { dir }); };
  const install = (d = dir, a = active) => { setOptionsError(null); setScreen("install"); run.start("install", { dir: d, active: a }); };
  const doWork = (a: "stop" | "remove") => { setWork(a); setScreen("work"); run.start(a, { dir: app?.dir ?? dir }); };
  const backFromWork = async () => {
    run.reset();
    try {
      const s = await refresh();
      setDir(s.dir);
      setScreen(s.installed ? "manage" : "welcome");
    } catch {
      setScreen("welcome");
    }
  };
  const goto = (s: Screen) => { run.reset(); setScreen(s); };

  if (loadError) {
    return (
      <Shell rail={null}>
        <div className="setup-step">
          <h1 className="setup-title">Setup could not start</h1>
          <div className="setup-error" role="alert">{loadError}</div>
        </div>
      </Shell>
    );
  }
  if (!app) return <Shell rail={null}><div className="setup-muted">Loading…</div></Shell>;
  if (!app.resourcesReady) {
    return (
      <Shell rail={null} version={app.appVersion}>
        <div className="setup-step">
          <h1 className="setup-title">This copy of Setup is incomplete</h1>
          <div className="setup-error" role="alert">
            The installer files that should be inside it are missing. Download Paddock Setup again from the Paddock releases page.
          </div>
        </div>
      </Shell>
    );
  }

  let view: JSX.Element;
  let rail: RailId | null = null;
  const finished = screen === "install" && st?.status === "succeeded";

  switch (screen) {
    case "welcome":
      rail = "welcome";
      view = <Welcome onStart={check} />;
      break;
    case "pc":
      rail = "pc";
      view = <PcCheck run={st} onOpen={open} onAgain={check} onBack={() => goto("welcome")} onNext={() => { run.reset(); setScreen("options"); }} />;
      break;
    case "options":
      rail = "options";
      view = <Options dir={dir} active={active} error={optionsError} onDir={setDir} onActive={setActive} onBack={() => goto("pc")} onInstall={() => install()} />;
      break;
    case "install": {
      rail = finished && st?.result ? "done" : "install";
      if (!st) {
        view = <div className="setup-muted">Starting…</div>;
      } else if (finished && st.result) {
        view = <Done run={st} onOpen={open} onRetry={() => { void refresh(); install(app.dir || dir, active); }} onClose={() => void bridge.quit()} />;
      } else if (st.status === "failed" || finished) {
        const shown: RunState = finished ? { ...st, status: "failed", error: "Setup finished without confirming that Paddock started." } : st;
        view = (
          <Failed title="Paddock could not be installed" run={shown} onOpen={open} onCopy={copyDetails}
            onRetry={() => install()} onBack={() => goto(app.installed ? "manage" : "pc")} backLabel={app.installed ? "Back" : "Check my PC"} />
        );
      } else {
        view = <Installing run={st} onCancel={run.cancel} />;
      }
      break;
    }
    case "manage":
      view = <Manage app={app} onOpen={open} onStart={() => install(app.dir, false)} onStop={() => doWork("stop")} onRemove={() => doWork("remove")} onClose={() => void bridge.quit()} />;
      break;
    case "work":
      view = st ? <Work action={work} run={st} onBack={backFromWork} onRetry={() => doWork(work)} onCopy={copyDetails} onOpen={open} /> : <div className="setup-muted">Working…</div>;
      break;
  }

  return <Shell rail={rail} version={app.appVersion}>{view}</Shell>;
}

function Shell({ rail, version, children }: { rail: RailId | null; version?: string; children: React.ReactNode }) {
  return (
    <div className="setup-screen">
      <PixelField className="setup-pixels" cell={5} animate={false} originX={0.1} />
      <Brand version={version} />
      {/* One glass window over the aurora: the dashboard's own .panel recipe, so text never sits on bare pixels */}
      <div className={`panel inst-window${rail ? "" : " inst-single"}`}>
        {rail && <Rail current={rail} />}
        <main className="setup-main inst-main">{children}</main>
      </div>
    </div>
  );
}
