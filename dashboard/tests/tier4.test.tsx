/**
 * Tier 4 smoke tests — Risk Model + Dependencies reachability.
 *   1  RiskModel renders its scaffold and the COLD START banner when the
 *      active ranker reports cold_start=true.
 *   2  Dependencies' "Reachable only" toggle filters the SBOM table down to
 *      code-reachable components (the "not reached" row drops out).
 *
 * Both pull from the orchestrator via react-query, so we wrap them in a
 * QueryClientProvider and use URL-aware fetch mocks: the endpoint under test
 * returns real rows while every other endpoint returns the empty envelope.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import RiskModelPage from "../src/pages/RiskModel";
import DependenciesPage from "../src/pages/Dependencies";
import { useStore } from "../src/state/store";

function emptyBody() {
  return JSON.stringify({ items: [], total: 0, limit: 500, offset: 0 });
}

function jsonResponse(body: string) {
  return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
}

function renderWithClient(node: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(React.createElement(QueryClientProvider, { client: qc }, node));
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  try {
    localStorage.clear();
  } catch {
    /* ignore */
  }
  useStore.setState({ events: [], toasts: [], drawer: { kind: null } });
});

describe("Risk Model page", () => {
  it("renders the scaffold and a COLD START banner when the ranker is cold", async () => {
    const now = new Date().toISOString();
    const model = {
      risk_ranker: {
        version: "rr-2026.11.0",
        algo: "gradient-boosting",
        trained_at: now,
        n_samples: 5,
        cold_start: true,
        metrics: { auc: 0.5 },
        feature_importance: { reachability: 0.31, cvss: 0.22, on_kev_path: 0.18 },
      },
      anomaly_detector: {
        version: "ad-2026.11.0",
        algo: "isolation-forest",
        trained_at: now,
        n_samples: 5,
        cold_start: true,
      },
    };
    vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/v1/ml/model")) return Promise.resolve(jsonResponse(JSON.stringify(model)));
      return Promise.resolve(jsonResponse(emptyBody()));
    });

    renderWithClient(React.createElement(RiskModelPage));
    expect(screen.getByRole("heading", { name: "Risk Model" })).toBeInTheDocument();
    expect(screen.getByText("Top adaptive-risk findings")).toBeInTheDocument();
    expect(screen.getByText("Model insights")).toBeInTheDocument();
    expect(await screen.findByText(/COLD START/)).toBeInTheDocument();
    // feature-importance bars render from the model payload
    expect(await screen.findByText("on KEV path")).toBeInTheDocument();
  });
});

describe("Dependencies — reachability filter", () => {
  it("drops non-reachable components when 'Reachable only' is toggled on", async () => {
    const comps = [
      {
        id: "a",
        ecosystem: "npm",
        name: "reachable-pkg",
        version: "1.0.0",
        direct: true,
        depth: 0,
        vuln_count: 2,
        max_vuln_severity: "high",
        reachability: "reachable",
        reachable_vuln_count: 2,
      },
      {
        id: "b",
        ecosystem: "pypi",
        name: "safe-pkg",
        version: "2.0.0",
        direct: false,
        depth: 1,
        vuln_count: 1,
        max_vuln_severity: "low",
        reachability: "unreachable",
        reachable_vuln_count: 0,
      },
    ];
    vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      // the components LIST endpoint (not the /{id} detail) returns our rows
      if (url.includes("/v1/sbom/components") && !/\/v1\/sbom\/components\/[^?]/.test(url)) {
        return Promise.resolve(
          jsonResponse(JSON.stringify({ items: comps, total: comps.length, limit: 500, offset: 0 })),
        );
      }
      return Promise.resolve(jsonResponse(emptyBody()));
    });

    renderWithClient(React.createElement(DependenciesPage));

    // both grades visible before filtering
    expect(await screen.findByText("not reached")).toBeInTheDocument();
    expect(screen.getByText("reachable")).toBeInTheDocument();

    // toggle "Reachable only" — the unreachable row drops out
    fireEvent.click(screen.getByRole("checkbox", { name: "Reachable only" }));

    expect(screen.queryByText("not reached")).not.toBeInTheDocument();
    expect(screen.getByText("reachable")).toBeInTheDocument();
  });
});
