/**
 * useLiveEvents — mount once at the App root. Does two things:
 *
 *   1. Seeds the event ring once with a *historical backlog* — the SSE stream
 *      only emits on new activity, so a freshly-loaded dashboard would sit on
 *      "awaiting events…". We fetch the most recent findings / assets / scans,
 *      synthesize matching LiveEvents (flagged `seeded`, rendered dimmer with
 *      their real timestamps), and fill the ring below any live events.
 *   2. Opens the SSE channel to /v1/events and pushes each payload into the
 *      store. Live events always land newest-first on top of the backlog.
 *
 * Idempotent: safe under StrictMode double-mount (we close on cleanup, and the
 * store's seedEvents() only runs once).
 */

import { useEffect } from "react";
import { openEventStream } from "../api/client";
import { listFindings } from "../api/findings";
import { listAssets } from "../api/assets";
import { listScans } from "../api/scans";
import { useStore } from "../state/store";
import type { LiveEvent, Scan } from "../api/types";

const SEED_PER_SOURCE = 12;
const SEED_TOTAL = 18;

type ScanEventName = "scan_started" | "scan_completed" | "scan_failed";

function scanEventName(status: Scan["status"]): ScanEventName {
  if (status === "done") return "scan_completed";
  if (status === "failed" || status === "scope_denied") return "scan_failed";
  return "scan_started";
}

/** Pull recent rows from the three list endpoints and shape them as events. */
async function fetchBacklog(): Promise<LiveEvent[]> {
  const [findings, assets, scans] = await Promise.all([
    listFindings({ status: "open", limit: SEED_PER_SOURCE }).catch(() => []),
    listAssets({ limit: SEED_PER_SOURCE }).catch(() => []),
    listScans({ limit: SEED_PER_SOURCE }).catch(() => []),
  ]);

  const events: LiveEvent[] = [];

  for (const f of findings) {
    if (!f.first_seen) continue;
    events.push({
      event: "finding_opened",
      ts: f.first_seen,
      finding_id: f.id,
      severity: f.severity,
      asset_id: f.asset_id,
      title: f.title,
      asset_value: f.asset_value ?? f.asset?.value ?? undefined,
    });
  }
  for (const a of assets) {
    if (!a.first_seen) continue;
    events.push({
      event: "asset_added",
      ts: a.first_seen,
      asset_id: a.id,
      kind: a.kind,
      value: a.value,
    });
  }
  for (const s of scans) {
    const ts = s.finished_at ?? s.started_at ?? s.queued_at;
    if (!ts) continue;
    events.push({
      event: scanEventName(s.status),
      ts,
      scan_id: s.id,
      kind: s.kind,
      target: s.target,
      status: s.status,
    });
  }

  events.sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
  return events.slice(0, SEED_TOTAL);
}

export function useLiveEvents(): void {
  const pushEvent = useStore((s) => s.pushEvent);
  const setConnected = useStore((s) => s.setConnected);
  const seedEvents = useStore((s) => s.seedEvents);

  // Seed the backlog once, before/alongside the live stream.
  useEffect(() => {
    let alive = true;
    fetchBacklog()
      .then((backlog) => {
        if (alive && backlog.length) seedEvents(backlog);
      })
      .catch(() => {
        /* seeding is best-effort; the live stream still works */
      });
    return () => {
      alive = false;
    };
  }, [seedEvents]);

  useEffect(() => {
    let alive = true;
    const handle = openEventStream(
      (e) => {
        if (!alive) return;
        pushEvent(e);
        setConnected(true);
      },
      () => {
        if (!alive) return;
        setConnected(false);
      },
    );
    setConnected(true);
    return () => {
      alive = false;
      handle.close();
      setConnected(false);
    };
  }, [pushEvent, setConnected]);
}
