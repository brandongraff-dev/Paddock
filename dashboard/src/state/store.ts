/**
 * App-wide store (zustand).
 *
 * We deliberately keep server state in react-query and only put *UI* /
 * *ephemeral* state here:
 *   - live event ring buffer (populated by /v1/events)
 *   - drawer selection
 *   - toast stack
 *   - global filter: date, severity, free-text
 */

import { create } from "zustand";
import type { Classification, LiveEvent, Severity } from "../api/types";
import { classificationRank } from "../lib/color";

const EVENT_RING_SIZE = 200;
const TOAST_LIFETIME_MS = 6000;

export interface Toast {
  id: string;
  text: string;
  severity?: Severity;
  createdAt: number;
}

export interface DrawerTarget {
  kind: "asset" | "finding" | "chain" | "scan" | null;
  id?: string;
}

export interface FilterState {
  severity: Severity[]; // empty = any
  text: string;
  date?: string;
  kevOnly: boolean;
}

export interface AppState {
  /* Event stream */
  events: LiveEvent[];
  connected: boolean;
  /** True once the ticker has been seeded with historical events (one-shot). */
  seeded: boolean;
  pushEvent: (e: LiveEvent) => void;
  setConnected: (b: boolean) => void;
  /**
   * Seed the event ring with historical (dimmer, "past") events fetched on
   * mount. Live events already received stay on top; seeded events fill in
   * below them. Idempotent — runs at most once.
   */
  seedEvents: (events: LiveEvent[]) => void;

  /* Right-side drawer */
  drawer: DrawerTarget;
  openDrawer: (t: DrawerTarget) => void;
  closeDrawer: () => void;

  /* Command palette (cmd-K / ctrl-K) */
  cmdkOpen: boolean;
  openCmdk: () => void;
  closeCmdk: () => void;
  toggleCmdk: () => void;

  /* Toasts */
  toasts: Toast[];
  pushToast: (t: Omit<Toast, "id" | "createdAt">) => void;
  dismissToast: (id: string) => void;

  /* Global filter bar */
  filter: FilterState;
  setFilter: (patch: Partial<FilterState>) => void;

  /**
   * Highest classification among data currently rendered (governance §B).
   * Rows and drawers call noteClassification() as they mount; the top banner
   * reads `seenClassification`. Shell resets it on route change so the banner
   * tracks the page you're on, not everything ever loaded.
   */
  seenClassification: Classification | null;
  noteClassification: (c: Classification | null | undefined) => void;
  resetClassification: () => void;
}

function makeId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `tst-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
}

/** Stable identity for an event, so seeding doesn't duplicate a live row. */
function eventKey(e: LiveEvent): string {
  const r = e as unknown as Record<string, unknown>;
  if (typeof r.finding_id === "string") return `finding:${r.finding_id}:${e.event}`;
  if (typeof r.scan_id === "string") return `scan:${r.scan_id}:${e.event}`;
  if (typeof r.cve_id === "string") return `cve:${r.cve_id}`;
  if (typeof r.asset_id === "string") return `asset:${r.asset_id}`;
  return `${e.event}:${e.ts}`;
}

export const useStore = create<AppState>((set, get) => ({
  events: [],
  connected: false,
  seeded: false,
  pushEvent: (e) =>
    set((s) => {
      const next = [e, ...s.events].slice(0, EVENT_RING_SIZE);

      // Side effects: raise a toast for notable events.
      if (e.event === "finding_opened" && (e.severity === "high" || e.severity === "critical")) {
        const label =
          e.title ??
          `New ${e.severity} finding${e.asset_value ? ` on ${e.asset_value}` : ""}`;
        queueMicrotask(() =>
          get().pushToast({ text: label, severity: e.severity }),
        );
      }
      return { events: next };
    }),
  setConnected: (b) => set({ connected: b }),
  seedEvents: (seed) =>
    set((s) => {
      if (s.seeded) return {};
      const seen = new Set(s.events.map(eventKey));
      const historical = seed
        .filter((e) => !seen.has(eventKey(e)))
        .map((e) => ({ ...e, seeded: true as const }));
      // Live events (already received) stay newest-first on top; seeded rows
      // fill in below, ordered newest-first by their real timestamp.
      historical.sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
      return {
        seeded: true,
        events: [...s.events, ...historical].slice(0, EVENT_RING_SIZE),
      };
    }),

  drawer: { kind: null },
  openDrawer: (t) => set({ drawer: t }),
  closeDrawer: () => set({ drawer: { kind: null } }),

  cmdkOpen: false,
  openCmdk: () => set({ cmdkOpen: true }),
  closeCmdk: () => set({ cmdkOpen: false }),
  toggleCmdk: () => set((s) => ({ cmdkOpen: !s.cmdkOpen })),

  toasts: [],
  pushToast: (t) => {
    const id = makeId();
    const toast: Toast = { id, createdAt: Date.now(), ...t };
    set((s) => ({ toasts: [...s.toasts, toast] }));
    setTimeout(() => {
      // Only auto-dismiss if still present.
      set((s) => ({ toasts: s.toasts.filter((x) => x.id !== id) }));
    }, TOAST_LIFETIME_MS);
  },
  dismissToast: (id) =>
    set((s) => ({ toasts: s.toasts.filter((x) => x.id !== id) })),

  filter: { severity: [], text: "", kevOnly: false },
  setFilter: (patch) => set((s) => ({ filter: { ...s.filter, ...patch } })),

  seenClassification: null,
  noteClassification: (c) =>
    set((s) => {
      if (!c) return {};
      if (s.seenClassification && classificationRank(s.seenClassification) >= classificationRank(c)) {
        return {};
      }
      return { seenClassification: c };
    }),
  resetClassification: () => set({ seenClassification: null }),
}));

/* ----- selectors (so components only rerender on relevant slices) ----- */
export const selectConnected = (s: AppState) => s.connected;
export const selectEvents = (s: AppState) => s.events;
export const selectToasts = (s: AppState) => s.toasts;
export const selectFilter = (s: AppState) => s.filter;
export const selectDrawer = (s: AppState) => s.drawer;
export const selectSeenClassification = (s: AppState) => s.seenClassification;
