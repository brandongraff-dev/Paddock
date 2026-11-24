import { useCallback, useEffect, useRef, useState } from "react";
import type { Bridge, RunHandle, RunOptions } from "./bridge";
import { initialRun, parseLine, reduce, type Action, type RunInput, type RunState } from "./protocol";

export const CANCELLED = "Setup was cancelled. Run it again whenever you like: it picks up where it left off.";

/** Runs one installer action and exposes the evolving RunState. One run at a time. */
export function useRun(bridge: Bridge) {
  const [state, setState] = useState<RunState | null>(null);
  const handle = useRef<RunHandle | null>(null);
  const generation = useRef(0);
  const cancelled = useRef(false);

  const start = useCallback(
    (action: Action, opts: RunOptions = {}) => {
      const id = ++generation.current;
      cancelled.current = false;
      setState(initialRun());
      const apply = (input: RunInput) => {
        if (generation.current === id) setState((s) => (s ? reduce(s, input) : s));
      };
      let h: RunHandle;
      try {
        h = bridge.run(action, opts, (line) => {
          const ev = parseLine(line);
          if (ev) apply(ev);
        });
      } catch (e) {
        apply({ type: "crash", message: String((e as Error)?.message ?? e) });
        return;
      }
      handle.current = h;
      h.done.then(
        (code) => (cancelled.current ? apply({ type: "crash", message: CANCELLED }) : apply({ type: "exit", code })),
        (err) => apply({ type: "crash", message: cancelled.current ? CANCELLED : String(err?.message ?? err) }),
      );
    },
    [bridge],
  );

  const cancel = useCallback(() => {
    cancelled.current = true;
    handle.current?.cancel();
  }, []);

  const reset = useCallback(() => {
    generation.current++;
    handle.current = null;
    setState(null);
  }, []);

  // leaving the wizard mid-run must not leave a script running or a late event landing
  useEffect(() => () => {
    generation.current++;
    handle.current?.cancel();
  }, []);

  return { state, start, cancel, reset };
}
