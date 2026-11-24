/**
 * The conversation with scripts/install.ps1 -Json: one JSON object per line.
 *
 * Everything the wizard shows is derived from these events by `reduce`, a pure
 * function, so the screens are plain views of a state that can be tested
 * without Windows, Docker or a window.
 */

export type Action = "doctor" | "install" | "stop" | "remove";
export type CheckStatus = "ok" | "warn" | "fail";

export interface Check {
  name: string;
  status: CheckStatus;
  detail: string;
  /** Plain-English fix, possibly several lines. */
  fix: string;
}

export interface InstallResult {
  healthy: boolean;
  url: string;
  username: string;
  password: string;
  dir: string;
  version: string;
}

export type InstallerEvent =
  | { type: "step"; id: string; text: string }
  | ({ type: "check" } & Check)
  | { type: "summary"; fail: number; warn: number }
  | { type: "log" | "warn" | "error"; text: string }
  | ({ type: "result" } & InstallResult)
  | { type: "done"; action: "stop" | "remove" };

const isStr = (v: unknown): v is string => typeof v === "string";
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

/**
 * One output line -> one event. Blank lines are ignored; anything that is not a
 * recognised event (a stray message from PowerShell, a half-written line) is
 * kept as a log line instead of being lost or crashing the wizard.
 */
export function parseLine(raw: string): InstallerEvent | null {
  const line = raw.replace(/^\uFEFF/, "").trim();
  if (!line) return null;
  let o: unknown;
  try {
    o = JSON.parse(line);
  } catch {
    return { type: "log", text: line };
  }
  if (typeof o !== "object" || o === null) return { type: "log", text: line };
  const e = o as Record<string, unknown>;
  switch (e.type) {
    case "step":
      if (isStr(e.text)) return { type: "step", id: isStr(e.id) ? e.id : "", text: e.text };
      break;
    case "check":
      if (isStr(e.name) && (e.status === "ok" || e.status === "warn" || e.status === "fail")) {
        return { type: "check", name: e.name, status: e.status, detail: isStr(e.detail) ? e.detail : "", fix: isStr(e.fix) ? e.fix : "" };
      }
      break;
    case "summary":
      if (isNum(e.fail) && isNum(e.warn)) return { type: "summary", fail: e.fail, warn: e.warn };
      break;
    case "log":
    case "warn":
    case "error":
      if (isStr(e.text)) return { type: e.type, text: e.text };
      break;
    case "result":
      if (isStr(e.url) && isStr(e.password)) {
        return {
          type: "result",
          healthy: e.healthy === true,
          url: e.url,
          username: isStr(e.username) ? e.username : "admin",
          password: e.password,
          dir: isStr(e.dir) ? e.dir : "",
          version: isStr(e.version) ? e.version : "",
        };
      }
      break;
    case "done":
      if (e.action === "stop" || e.action === "remove") return { type: "done", action: e.action };
      break;
  }
  return { type: "log", text: line };
}

/** The phases an install goes through, in order. `images` is the long one. */
export const PHASES = [
  { id: "checks", label: "Checking your PC" },
  { id: "files", label: "Preparing files" },
  { id: "secrets", label: "Creating your passwords" },
  { id: "images", label: "Downloading Paddock" },
  { id: "start", label: "Starting Paddock" },
  { id: "health", label: "Waiting until it is ready" },
] as const;
export type PhaseId = (typeof PHASES)[number]["id"];

export interface RunState {
  status: "running" | "succeeded" | "failed";
  step: string | null;
  stepText: string;
  seen: string[];
  checks: Check[];
  summary: { fail: number; warn: number } | null;
  log: string[];
  warnings: string[];
  error: string | null;
  result: InstallResult | null;
  done: "stop" | "remove" | null;
  exitCode: number | null;
}

export const LOG_LIMIT = 400;

export function initialRun(): RunState {
  return { status: "running", step: null, stepText: "", seen: [], checks: [], summary: null, log: [], warnings: [], error: null, result: null, done: null, exitCode: null };
}

export type RunInput = InstallerEvent | { type: "exit"; code: number } | { type: "crash"; message: string };

function pushLog(log: string[], text: string): string[] {
  const next = log.length >= LOG_LIMIT ? log.slice(log.length - LOG_LIMIT + 1) : log.slice();
  next.push(text);
  return next;
}

export function reduce(s: RunState, ev: RunInput): RunState {
  switch (ev.type) {
    case "step":
      return { ...s, step: ev.id || s.step, stepText: ev.text, seen: ev.id && !s.seen.includes(ev.id) ? [...s.seen, ev.id] : s.seen, log: pushLog(s.log, ev.text) };
    case "check":
      return { ...s, checks: [...s.checks, { name: ev.name, status: ev.status, detail: ev.detail, fix: ev.fix }] };
    case "summary":
      return { ...s, summary: { fail: ev.fail, warn: ev.warn } };
    case "log":
      return { ...s, log: pushLog(s.log, ev.text) };
    case "warn":
      return { ...s, warnings: [...s.warnings, ev.text], log: pushLog(s.log, `warning: ${ev.text}`) };
    case "error":
      return { ...s, error: ev.text, log: pushLog(s.log, `error: ${ev.text}`) };
    case "result": {
      const { type: _t, ...result } = ev;
      return { ...s, result };
    }
    case "done":
      return { ...s, done: ev.action };
    case "crash":
      return { ...s, status: "failed", error: s.error ?? ev.message };
    case "exit": {
      // A non-zero exit WITH a result is "installed, but not answering yet": the script
      // reports the login first and then exits 1 on purpose. Show it, do not hide it.
      const ok = !s.error && (ev.code === 0 || s.result !== null);
      return {
        ...s,
        exitCode: ev.code,
        status: ok ? "succeeded" : "failed",
        error: ok ? null : (s.error ?? unexpectedStop(s, ev.code)),
      };
    }
  }
}

function unexpectedStop(s: RunState, code: number): string {
  const failing = s.checks.find((c) => c.status === "fail");
  if (failing) return `${failing.name}: ${failing.detail}`;
  return `The installer stopped unexpectedly (code ${code}).`;
}

/** 0-100 for the progress bar. Phases are weighted by how long they really take. */
const WEIGHTS: Record<PhaseId, number> = { checks: 6, files: 6, secrets: 4, images: 58, start: 14, health: 12 };

export function percent(s: RunState): number {
  if (s.status === "succeeded") return 100;
  let acc = 0;
  for (const p of PHASES) {
    if (s.step === p.id) return Math.min(99, Math.round(acc + WEIGHTS[p.id] * 0.35));
    if (s.seen.includes(p.id)) acc += WEIGHTS[p.id];
  }
  return Math.min(99, Math.round(acc));
}

export function phaseState(s: RunState, id: PhaseId): "done" | "active" | "pending" {
  if (s.status === "succeeded") return "done";
  if (s.step === id) return "active";
  return s.seen.includes(id) ? "done" : "pending";
}

export const hasBlocker = (checks: Check[]): boolean => checks.some((c) => c.status === "fail");
