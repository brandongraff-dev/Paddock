/**
 * Smoke tests. Vitest + jsdom.
 * Covers:
 *   1  App renders
 *   2  shell title updates with route
 *   3  api client URL composition (base + path + query)
 *   4  api client throws ApiError on non-2xx
 *   5  store mutation: pushEvent updates events slice
 *   6  store toast auto-raise for high-severity finding_opened
 *   7  openEventStream wires parsed JSON to the handler
 *   8  severity color helper + maxSeverity reduction
 *   9  splitEvidence masks exploit excerpts
 *  10  layoutGraph produces one node per asset w/ deterministic positions
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import React from "react";
import App from "../src/App";
import { ApiError, apiFetch, buildUrl } from "../src/api/client";
import { useStore } from "../src/state/store";
import { useAuth } from "../src/state/auth";
import type { LiveEvent } from "../src/api/types";
import { SEV_COLOR, maxSeverity, severityColor } from "../src/lib/color";
import { splitEvidence } from "../src/components/DetailDrawer";
import { layoutGraph } from "../src/lib/graph";

beforeEach(() => {
  // The app is gated behind auth; seed an admin session so <App/> renders the
  // authenticated shell (not the Login screen) for these UI smoke tests.
  useAuth.setState({
    token: "test-token",
    user: { username: "tester", role: "admin", clearance: "restricted" },
  });
});

afterEach(() => {
  cleanup();
  // reset store between tests
  useStore.setState({
    events: [],
    connected: false,
    seeded: false,
    toasts: [],
    drawer: { kind: null },
    cmdkOpen: false,
    filter: { severity: [], text: "", kevOnly: false },
    seenClassification: null,
  });
  useAuth.setState({ token: null, user: null });
});

describe("App renders", () => {
  it("mounts without throwing and shows the brand mark", () => {
    render(React.createElement(App));
    expect(screen.getAllByText(/pa/i).length).toBeGreaterThan(0);
  });

  it("shows the Overview page title by default", () => {
    render(React.createElement(App));
    // Shell renders uppercased route title in the topbar.
    expect(screen.getByText("OVERVIEW")).toBeInTheDocument();
  });
});

describe("api client", () => {
  it("buildUrl composes base + path + query", () => {
    const u = buildUrl("/v1/findings", { severity: "high", limit: 50, empty: "" });
    expect(u).toMatch(/\/v1\/findings\?/);
    expect(u).toContain("severity=high");
    expect(u).toContain("limit=50");
    expect(u).not.toContain("empty=");
  });

  it("throws ApiError on non-2xx with the response body attached", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ error: "nope" }), {
        status: 403,
        headers: { "content-type": "application/json" },
      }),
    );
    await expect(apiFetch("/v1/findings")).rejects.toMatchObject({
      name: "ApiError",
      status: 403,
      body: { error: "nope" },
    });
    fetchMock.mockRestore();
  });

  it("returns parsed JSON on success", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify([{ id: "a" }]), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const res = await apiFetch<Array<{ id: string }>>("/v1/assets");
    expect(res).toEqual([{ id: "a" }]);
    fetchMock.mockRestore();
  });
});

describe("store", () => {
  it("pushEvent appends to the ring buffer newest-first", () => {
    const e1: LiveEvent = { event: "asset_added", ts: "t1", asset_id: "a", kind: "domain", value: "ex.com" };
    const e2: LiveEvent = { event: "asset_added", ts: "t2", asset_id: "b", kind: "domain", value: "ex2.com" };
    useStore.getState().pushEvent(e1);
    useStore.getState().pushEvent(e2);
    const events = useStore.getState().events;
    expect(events[0]).toMatchObject({ ts: "t2" });
    expect(events[1]).toMatchObject({ ts: "t1" });
  });

  it("auto-raises a toast when a high-severity finding_opened event arrives", async () => {
    const e: LiveEvent = {
      event: "finding_opened",
      ts: "now",
      finding_id: "f1",
      severity: "high",
      asset_id: "a1",
      title: "Exposed .git on example.com",
    };
    await act(async () => {
      useStore.getState().pushEvent(e);
      // microtask flush
      await Promise.resolve();
    });
    const toasts = useStore.getState().toasts;
    expect(toasts.length).toBe(1);
    expect(toasts[0].text).toContain("Exposed .git");
    expect(toasts[0].severity).toBe("high");
  });
});

describe("color helpers", () => {
  it("severityColor returns the token hex", () => {
    expect(severityColor("critical")).toBe(SEV_COLOR.critical);
    expect(severityColor(undefined)).toBe(SEV_COLOR.info);
  });

  it("maxSeverity folds to the highest", () => {
    expect(maxSeverity(["low", "high", "medium"])).toBe("high");
    expect(maxSeverity(["info"])).toBe("info");
    expect(maxSeverity([])).toBe("info");
  });
});

describe("exploit excerpt hard rule", () => {
  it("passes benign text through as a single text block", () => {
    const out = splitEvidence("This asset exposes /README which contains the string TODO.");
    expect(out).toHaveLength(1);
    expect(out[0].kind).toBe("text");
  });

  it("flags paragraphs containing payload: / exploit: as evidence excerpts", () => {
    const text = [
      "Finding summary: outdated lib.",
      "payload: curl -X POST 'https://target/boom' --data '\\x00'",
    ].join("\n\n");
    const out = splitEvidence(text);
    expect(out).toHaveLength(2);
    expect(out[0].kind).toBe("text");
    expect(out[1].kind).toBe("excerpt");
  });
});

describe("graph layout", () => {
  it("emits one node per asset and positions them", () => {
    const assets = [
      { id: "d1", kind: "domain", value: "example.com", canonical: "example.com", first_seen: "", last_seen: "", confidence: 100, source: "test", metadata: {} },
      { id: "s1", kind: "subdomain", value: "www.example.com", canonical: "www.example.com", first_seen: "", last_seen: "", confidence: 100, source: "test", metadata: {} },
      { id: "i1", kind: "ipv4", value: "1.2.3.4", canonical: "1.2.3.4", first_seen: "", last_seen: "", confidence: 100, source: "test", metadata: {} },
    ] as const;
    const edges = [
      { id: "e1", src_id: "d1", dst_id: "s1", kind: "contains", first_seen: "", last_seen: "", metadata: {} },
      { id: "e2", src_id: "s1", dst_id: "i1", kind: "resolves_to", first_seen: "", last_seen: "", metadata: {} },
    ];
    const out = layoutGraph({ assets: assets as any, edges });
    expect(out.nodes).toHaveLength(3);
    expect(out.edges).toHaveLength(2);
    const [d, s, i] = out.nodes;
    expect(d.position.x).toBeLessThan(s.position.x);
    expect(s.position.x).toBeLessThan(i.position.x);
    // reactflow node metadata shape sanity check
    expect(d.type).toBe("assetNode");
    expect(d.data).toHaveProperty("asset");
  });
});

describe("command palette", () => {
  it("opens on ctrl-K, filters the Navigate section, and closes on Esc", () => {
    render(React.createElement(App));

    // Not open initially.
    expect(screen.queryByRole("dialog")).toBeNull();

    // ctrl-K opens it (listener is on window; dispatch bubbles up from body).
    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });

    const dialog = screen.getByRole("dialog");
    const input = within(dialog).getByRole("combobox") as HTMLInputElement;
    expect(input).toBeInTheDocument();

    // All 7 pages present before filtering.
    const listbox = within(dialog).getByRole("listbox");
    expect(within(listbox).getByText("Overview")).toBeInTheDocument();
    expect(within(listbox).getByText("Timeline")).toBeInTheDocument();

    // Typing narrows the Navigate section immediately (not debounced).
    fireEvent.change(input, { target: { value: "timeline" } });
    expect(within(listbox).getByText("Timeline")).toBeInTheDocument();
    expect(within(listbox).queryByText("Overview")).toBeNull();

    // Esc closes it.
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("toggles closed on a second ctrl-K", () => {
    render(React.createElement(App));
    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
