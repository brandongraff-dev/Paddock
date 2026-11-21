/**
 * Tier 1 smoke tests — Attack Paths + Changes pages.
 *   1  AttackPaths renders its empty state when no paths are computed.
 *   2  Changes renders its scaffold (velocity chart + alert rules panel).
 *
 * Both pages pull from the orchestrator via react-query, so we wrap them in a
 * QueryClientProvider and stub fetch with an envelope that satisfies every
 * endpoint they hit ({items:[]} / summary shape).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import AttackPathsPage from "../src/pages/AttackPaths";
import ChangesPage from "../src/pages/Changes";
import { useStore } from "../src/state/store";

function mockEmptyFetch() {
  const body = JSON.stringify({
    items: [],
    total: 0,
    limit: 50,
    offset: 0,
    by_day: [],
    by_type: {},
  });
  return vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(body, { status: 200, headers: { "content-type": "application/json" } }),
  );
}

function renderWithClient(node: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    React.createElement(QueryClientProvider, { client: qc }, node),
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useStore.setState({ events: [], toasts: [], drawer: { kind: null } });
});

describe("AttackPaths page", () => {
  it("renders the empty state when the engine has no paths", async () => {
    mockEmptyFetch();
    renderWithClient(React.createElement(AttackPathsPage));
    expect(screen.getByRole("heading", { name: "Attack Paths" })).toBeInTheDocument();
    expect(
      await screen.findByText(/No attack paths computed yet/i),
    ).toBeInTheDocument();
  });
});

describe("Changes page", () => {
  it("renders the feed scaffold, velocity chart, and alert-rules panel", () => {
    mockEmptyFetch();
    renderWithClient(React.createElement(ChangesPage));
    expect(screen.getByRole("heading", { name: "Changes" })).toBeInTheDocument();
    expect(screen.getByText("Change velocity")).toBeInTheDocument();
    expect(screen.getByText("Change feed")).toBeInTheDocument();
    expect(screen.getByText("Alert rules")).toBeInTheDocument();
  });
});
