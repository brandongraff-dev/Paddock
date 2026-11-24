/**
 * A scripted stand-in for the Tauri shell, for looking at the wizard in a normal
 * browser (`npm run demo`) and for screenshots. Only built when VITE_DEMO is set;
 * a real build never contains it.
 *
 * ?scenario=fresh            clean PC, everything passes, install succeeds   (default)
 * ?scenario=docker-missing   Docker Desktop is not installed (blocks)
 * ?scenario=ports            port 3000 is in use (blocks)
 * ?scenario=fail             PC check passes, the install itself fails
 * ?scenario=installed        Paddock is already installed and running
 * ?scenario=stopped          Paddock is installed but stopped
 * &speed=0.2                 play faster (default 1)
 */
import type { AppState, Bridge, RunHandle } from "./bridge";

const q = new URLSearchParams(typeof location === "undefined" ? "" : location.search);
const scenario = q.get("scenario") ?? "fresh";
const speed = Number(q.get("speed") ?? "1") || 1;

const line = (o: unknown) => JSON.stringify(o);
const check = (name: string, status: string, detail: string, fix = "") => line({ type: "check", name, status, detail, fix });
const step = (id: string, text: string) => line({ type: "step", id, text });

function pcChecks(): string[] {
  const common = [check("Windows version", "ok", "Windows 11 Home (build 22631)"), check("Memory", "ok", "16384 MB"), check("Disk space", "ok", "212004 MB free on the system drive")];
  if (scenario === "docker-missing") {
    return [...common, check("Docker Desktop", "fail", "is not installed",
      "1. Install Docker Desktop (free) from https://www.docker.com/products/docker-desktop/ and choose the WSL 2 option\n2. Restart Windows if it asks, start Docker Desktop, and wait until it says 'Engine running'\n3. Run this installer again"),
      check("Port 3000", "ok", "free"), check("Port 8080", "ok", "free"), line({ type: "summary", fail: 1, warn: 0 })];
  }
  if (scenario === "ports") {
    return [...common, check("Docker engine", "ok", "running (docker 26.1.0), Compose v2, Linux containers"),
      check("Port 3000", "fail", "already in use by node", "Paddock needs this port. Close that program (or stop its container) and run this installer again.\nTo see what holds it, run:  netstat -ano | findstr :3000   (the last number is the process ID in Task Manager > Details)"),
      check("Port 8080", "ok", "free"), line({ type: "summary", fail: 1, warn: 0 })];
  }
  return [...common, check("Docker engine", "ok", "running (docker 26.1.0), Compose v2, Linux containers"), check("Port 3000", "ok", "free"), check("Port 8080", "ok", "free"), line({ type: "summary", fail: 0, warn: 0 })];
}

function installScript(): { t: number; l: string }[] {
  const s: { t: number; l: string }[] = [];
  let t = 400;
  const add = (l: string, dt = 500) => { t += dt; s.push({ t, l }); };
  add(step("checks", "checking prerequisites"));
  for (const c of pcChecks()) add(c, 120);
  add(step("files", "installing into C:\\Users\\Ada\\paddock"));
  add(step("secrets", "generating secrets (existing values are never overwritten)"));
  add(step("images", "downloading the Paddock images (release 1.2.3, about 1-2 minutes)"), 700);
  for (const l of ["orchestrator Pulling", "dashboard Pulling", "worker-passive Pulling", "brain Pulling", "orchestrator Pulled", "dashboard Pulled", "brain Pulled"]) add(l, 900);
  if (scenario === "fail") {
    add(line({ type: "error", text: "docker compose pull failed: could not reach ghcr.io. Check your internet connection and any proxy or firewall." }), 600);
    return s;
  }
  add(step("start", "starting Paddock"), 600);
  add(step("health", "waiting for Paddock to become healthy (up to 600s)"), 1500);
  add(line({ type: "result", healthy: true, url: "http://localhost:3000", username: "admin", password: "k3J9xQ2mTzP7vW4nLb8sYd1A", dir: "C:\\Users\\Ada\\paddock", version: "1.2.3" }), 2500);
  return s;
}

export const demoBridge: Bridge = {
  async getState(): Promise<AppState> {
    const installed = scenario === "installed" || scenario === "stopped";
    return { installed, version: installed ? "1.2.3" : null, running: scenario === "installed", dir: "C:\\Users\\Ada\\paddock", resourcesReady: true, appVersion: "0.1.0" };
  },
  run(action, _opts, onLine): RunHandle {
    const timers: ReturnType<typeof setTimeout>[] = [];
    let end!: (n: number) => void;
    const done = new Promise<number>((res) => { end = res; });
    const play = (script: { t: number; l: string }[], code: number) => {
      script.forEach(({ t, l }) => timers.push(setTimeout(() => onLine(l), t * speed)));
      const last = script.length ? script[script.length - 1].t : 0;
      timers.push(setTimeout(() => end(code), (last + 200) * speed));
    };
    if (action === "doctor") {
      const lines = pcChecks();
      play(lines.map((l, i) => ({ t: 600 + i * 220, l })), scenario === "docker-missing" || scenario === "ports" ? 1 : 0);
    } else if (action === "install") {
      play(installScript(), scenario === "fail" ? 1 : 0);
    } else {
      play([
        { t: 300, l: step("remove", action === "stop" ? "stopping Paddock" : "uninstalling Paddock from C:\\Users\\Ada\\paddock") },
        { t: 1400, l: line({ type: "done", action }) },
      ], 0);
    }
    return { done, cancel: () => { timers.forEach(clearTimeout); end(1); } };
  },
  openUrl: async (url) => { console.info("open", url); },
  quit: async () => { console.info("quit"); },
};
