import { vi } from "vitest";
import type { AppState, Bridge, RunHandle, RunOptions } from "../src/bridge";
import type { Action } from "../src/protocol";

export interface FakeRun {
  action: Action;
  opts: RunOptions;
  cancelled: boolean;
  emit(ev: unknown): void;
  finish(code: number): void;
  fail(message: string): void;
}

export function makeBridge(state: Partial<AppState> = {}) {
  const runs: FakeRun[] = [];
  const base: AppState = { installed: false, version: null, running: false, dir: "C:\\Users\\Ada\\paddock", resourcesReady: true, appVersion: "0.1.0", ...state };
  let current = base;
  const bridge: Bridge = {
    getState: vi.fn(async () => current),
    run(action, opts, onLine): RunHandle {
      let resolve!: (n: number) => void;
      let reject!: (e: Error) => void;
      const done = new Promise<number>((res, rej) => { resolve = res; reject = rej; });
      const r: FakeRun = {
        action, opts, cancelled: false,
        emit: (ev) => onLine(typeof ev === "string" ? ev : JSON.stringify(ev)),
        finish: (c) => resolve(c),
        fail: (m) => reject(new Error(m)),
      };
      runs.push(r);
      return { done, cancel: () => { r.cancelled = true; resolve(1); } };
    },
    openUrl: vi.fn(async () => undefined),
    pickFolder: vi.fn(async () => null as string | null),
    quit: vi.fn(async () => undefined),
  };
  return { bridge, runs, last: () => runs[runs.length - 1], setState: (s: Partial<AppState>) => { current = { ...current, ...s }; } };
}

export const check = (name: string, status: "ok" | "warn" | "fail", detail = "", fix = "") => ({ type: "check", name, status, detail, fix });
export const step = (id: string, text: string) => ({ type: "step", id, text });
export const RESULT = { type: "result", healthy: true, url: "http://localhost:3000", username: "admin", password: "s3cret-Passw0rd-xyz", dir: "C:\\Users\\Ada\\paddock", version: "1.2.3" };
