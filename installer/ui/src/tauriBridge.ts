import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { AppState, Bridge, RunHandle } from "./bridge";

interface LineEvent {
  run_id: string;
  line: string;
}

/** The real bridge: thin wrappers over the commands in src-tauri/src/main.rs. */
export const tauriBridge: Bridge = {
  getState: () => invoke<AppState>("get_state"),

  run(action, opts, onLine): RunHandle {
    const runId = crypto.randomUUID();
    let unlisten: (() => void) | null = null;
    const ready = listen<LineEvent>("installer-line", (e) => {
      if (e.payload.run_id === runId) onLine(e.payload.line);
    }).then((u) => {
      unlisten = u;
    });
    const done = ready
      .then(() => invoke<number>("run_script", { runId, action, dir: opts.dir ?? null, active: !!opts.active }))
      .finally(() => unlisten?.());
    return { done, cancel: () => void invoke("cancel_run", { runId }) };
  },

  openUrl: (url) => invoke("open_url", { url }),
  quit: () => invoke("quit_app"),
};
