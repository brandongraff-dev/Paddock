/**
 * Tier 2 smoke tests — Posture + Tickets pages.
 *   1  Posture renders its heading, grade strip, and empty TLS state.
 *   2  Tickets renders its queue scaffold + ownership/SLA side panels.
 *
 * Both pull from the orchestrator via react-query, so we wrap them in a
 * QueryClientProvider and stub fetch with an envelope that satisfies every
 * endpoint they hit ({items:[]} / empty summary objects).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import PosturePage from "../src/pages/Posture";
import TicketsPage from "../src/pages/Tickets";
import { useStore } from "../src/state/store";

function mockEmptyFetch() {
  const body = JSON.stringify({ items: [], total: 0, limit: 200, offset: 0 });
  return vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(body, { status: 200, headers: { "content-type": "application/json" } }),
  );
}

function renderWithClient(node: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(React.createElement(QueryClientProvider, { client: qc }, node));
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useStore.setState({ events: [], toasts: [], drawer: { kind: null } });
});

describe("Posture page", () => {
  it("renders the report-card scaffold and empty TLS state", async () => {
    mockEmptyFetch();
    renderWithClient(React.createElement(PosturePage));
    expect(screen.getByRole("heading", { name: "Posture" })).toBeInTheDocument();
    expect(screen.getByText("Takeover risk")).toBeInTheDocument();
    expect(await screen.findByText(/No graded hosts match these filters/i)).toBeInTheDocument();
  });
});

describe("Tickets page", () => {
  it("renders the queue, ownership rules, and SLA policy panels", async () => {
    mockEmptyFetch();
    renderWithClient(React.createElement(TicketsPage));
    expect(screen.getByRole("heading", { name: "Tickets" })).toBeInTheDocument();
    expect(screen.getByText("Queue")).toBeInTheDocument();
    expect(screen.getByText("Ownership rules")).toBeInTheDocument();
    expect(screen.getByText("SLA policies")).toBeInTheDocument();
    expect(await screen.findByText(/No tickets match these filters/i)).toBeInTheDocument();
  });
});
