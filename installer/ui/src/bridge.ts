/**
 * What the wizard needs from the outside world. The real implementation talks
 * to the Tauri shell (tauriBridge.ts); tests pass a fake, so every screen can
 * be exercised without Windows, Docker or a window.
 */
import type { Action } from "./protocol";

export interface AppState {
  installed: boolean;
  /** Version pinned in the existing install's .env, if any. */
  version: string | null;
  /** Is something listening on Paddock's port right now? */
  running: boolean;
  /** Where Paddock is (or will be) installed. */
  dir: string;
  /** The bundled installer files are present (always true in a real build). */
  resourcesReady: boolean;
  /** This setup's own version. */
  appVersion: string;
}

export interface RunOptions {
  dir?: string | null;
  active?: boolean;
  /** Add a Start menu shortcut (installing only). Default true. */
  shortcut?: boolean;
}

export interface RunHandle {
  /** Resolves with the script's exit code; rejects if it could not be started. */
  done: Promise<number>;
  cancel(): void;
}

export interface Bridge {
  getState(): Promise<AppState>;
  run(action: Action, opts: RunOptions, onLine: (line: string) => void): RunHandle;
  openUrl(url: string): Promise<void>;
  /** The native "choose a folder" dialog. Resolves with the chosen folder, or null if cancelled. */
  pickFolder(current: string): Promise<string | null>;
  quit(): Promise<void>;
}

export const PADDOCK_URL = "http://localhost:3000";
export const DOCKER_URL = "https://www.docker.com/products/docker-desktop/";
export const WSL_URL = "https://learn.microsoft.com/windows/wsl/install";

/**
 * A pre-filled "new issue" page. Only the headline travels in the address: the technical details can be
 * long and may name folders or machines, so the person pastes them in themselves (Copy details).
 */
export function helpUrl(headline: string): string {
  const title = `Setup problem: ${headline}`.slice(0, 120);
  const body = "**What happened**\n\n\n**Technical details** (in Setup, choose Copy details, then paste here)\n\n";
  return `https://github.com/brandongraff-dev/paddock/issues/new?title=${encodeURIComponent(title)}&body=${encodeURIComponent(body)}`;
}
