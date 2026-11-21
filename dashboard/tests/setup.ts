import "@testing-library/jest-dom/vitest";

// EventSource is not in jsdom; stub it so hooks that open SSE don't crash.
class StubEventSource {
  url: string;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  constructor(url: string) { this.url = url; }
  close() { /* noop */ }
}

(globalThis as any).EventSource ??= StubEventSource;

// ResizeObserver is missing from jsdom; recharts probes it on mount.
class StubResizeObserver {
  observe() { /* noop */ }
  unobserve() { /* noop */ }
  disconnect() { /* noop */ }
}
(globalThis as any).ResizeObserver ??= StubResizeObserver;

// jsdom doesn't implement IntersectionObserver (findings infinite-scroll uses it).
class StubIntersectionObserver {
  observe() { /* noop */ }
  unobserve() { /* noop */ }
  disconnect() { /* noop */ }
  takeRecords() { return []; }
}
(globalThis as any).IntersectionObserver ??= StubIntersectionObserver;

// matchMedia stub for recharts' ResponsiveContainer sometimes probing it.
if (typeof window !== "undefined" && !window.matchMedia) {
  Object.defineProperty(window, "matchMedia", {
    value: (q: string) => ({
      matches: false,
      media: q,
      onchange: null,
      addListener: () => undefined,
      removeListener: () => undefined,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      dispatchEvent: () => false,
    }),
  });
}

// jsdom has no canvas backend and logs "Not implemented" on getContext; the
// brand canvases already treat a null context as "render nothing".
if (typeof HTMLCanvasElement !== "undefined") {
  HTMLCanvasElement.prototype.getContext = (() => null) as typeof HTMLCanvasElement.prototype.getContext;
}
