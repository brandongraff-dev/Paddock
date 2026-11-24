import { useCallback, useEffect, useState } from "react";
import type { AppState, Bridge } from "./bridge";
import { Header, Screen } from "./components";
import type { RunState } from "./protocol";
import { Done, Failed, Installing, Manage, Ready, WorkDone } from "./screens";
import { CANCELLED, useRun } from "./useRun";

type Screen_ = "ready" | "install" | "manage" | "work";

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
  const [screen, setScreen] = useState<Screen_>("ready");
  const [dir, setDir] = useState("");
  const [active, setActive] = useState(false);
  const [work, setWork] = useState<"stop" | "remove">("stop");
  const [dirError, setDirError] = useState<string | null>(null);
  const pcRun = useRun(bridge);   // the automatic PC check
  const job = useRun(bridge);     // install / stop / remove
  const pc = pcRun.state;
  const st = job.state;

  const refresh = useCallback(async () => {
    const s = await bridge.getState();
    setApp(s);
    return s;
  }, [bridge]);

  const check = useCallback((folder: string) => pcRun.start("doctor", { dir: folder }), [pcRun]);

  // first load: an existing install opens the manage screen; a new one starts checking the PC at once
  useEffect(() => {
    refresh().then(
      (s) => {
        setDir(s.dir);
        if (s.installed) setScreen("manage");
        else if (s.resourcesReady) check(s.dir);
      },
      (e) => setLoadError(msg(e)),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refresh]);

  // the script never started (a bad folder, PowerShell missing): that is a mistake in the options
  useEffect(() => {
    if (screen === "install" && st && st.status === "failed" && st.seen.length === 0 && st.exitCode === null && st.error !== CANCELLED) {
      setDirError(st.error);
      setScreen("ready");
      job.reset();
    }
  }, [screen, st, job]);

  const open = (url: string) => void bridge.openUrl(url).catch(() => undefined);
  const quit = () => void bridge.quit();
  const copyDetails = () => void navigator.clipboard?.writeText(detailsText(st)).catch(() => undefined);

  const install = (d = dir, a = active) => { setDirError(null); setScreen("install"); job.start("install", { dir: d, active: a }); };
  const doWork = (a: "stop" | "remove") => { setWork(a); setScreen("work"); job.start(a, { dir: app?.dir ?? dir }); };
  const backToReady = () => { job.reset(); setScreen("ready"); check(dir); };
  const backFromWork = async () => {
    job.reset();
    try {
      const s = await refresh();
      setDir(s.dir);
      if (s.installed) setScreen("manage");
      else { setScreen("ready"); check(s.dir); }
    } catch {
      setScreen("ready");
    }
  };

  if (loadError) {
    return <Frame><Screen title="Setup could not start" lede={loadError} actions={<button type="button" onClick={quit}>Close</button>} /></Frame>;
  }
  if (!app) return <Frame><p className="inst-body inst-hint">Loading…</p></Frame>;
  if (!app.resourcesReady) {
    return (
      <Frame>
        <Screen
          title="This copy of Setup is incomplete"
          lede="The installer files that should be inside it are missing. Download Paddock Setup again from the Paddock releases page."
          actions={<button type="button" onClick={quit}>Close</button>}
        />
      </Frame>
    );
  }

  let view: JSX.Element;
  let step: string | undefined;
  const finished = screen === "install" && st?.status === "succeeded";

  switch (screen) {
    case "ready":
      step = "Step 1 of 3";
      view = <Ready pc={pc} dir={dir} active={active} dirError={dirError} onDir={setDir} onActive={setActive} onOpen={open} onAgain={() => check(dir)} onInstall={() => install()} onClose={quit} />;
      break;
    case "install":
      step = finished && st?.result ? "Step 3 of 3" : "Step 2 of 3";
      if (!st) view = <p className="inst-body inst-hint">Starting…</p>;
      else if (finished && st.result) view = <Done run={st} onOpen={open} onRetry={() => { void refresh(); install(app.dir || dir, active); }} onClose={quit} />;
      else if (st.status === "failed" || finished) {
        const shown: RunState = finished ? { ...st, status: "failed", error: "Setup finished without confirming that Paddock started." } : st;
        view = <Failed run={shown} onOpen={open} onCopy={copyDetails} onRetry={() => install()} onBack={app.installed ? () => { job.reset(); setScreen("manage"); } : backToReady} backLabel={app.installed ? "Back" : "Check my PC"} />;
      } else view = <Installing run={st} onCancel={job.cancel} />;
      break;
    case "manage":
      view = <Manage app={app} onOpen={open} onStart={() => install(app.dir, false)} onStop={() => doWork("stop")} onRemove={() => doWork("remove")} onClose={quit} />;
      break;
    case "work":
      if (!st) view = <p className="inst-body inst-hint">Working…</p>;
      else if (st.status === "failed") view = <Failed run={st} onOpen={open} onCopy={copyDetails} onRetry={() => doWork(work)} onBack={backFromWork} />;
      else if (st.status === "succeeded") view = <WorkDone action={work} onBack={backFromWork} />;
      else view = <Installing run={st} action={work} />;
      break;
  }

  return <Frame step={step}>{view}</Frame>;
}

function Frame({ step, children }: { step?: string; children: React.ReactNode }) {
  return (
    <div className="inst">
      <Header step={step} />
      <main className="inst-main">{children}</main>
    </div>
  );
}
