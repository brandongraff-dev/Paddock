/**
 * Tier 3 smoke tests — Ask + Dependencies pages.
 *   1  Ask renders its query box and, on submit, shows the mocked answer
 *      (engine badge, a result cell, and the validated-SQL block).
 *   2  Dependencies renders its scaffold + empty SBOM state.
 *
 * Both pull from the orchestrator via react-query, so we wrap them in a
 * QueryClientProvider. Ask uses a URL-aware fetch mock so POST /v1/ask returns
 * an AskResult while every other endpoint returns the empty envelope.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import AskPage from "../src/pages/Ask";
import DependenciesPage from "../src/pages/Dependencies";
import { useStore } from "../src/state/store";

function emptyBody() {
  return JSON.stringify({ items: [], total: 0, limit: 500, offset: 0 });
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

describe("Ask page", () => {
  it("renders the query box and shows a mocked answer on submit", async () => {
    const answer = {
      ok: true,
      columns: ["host", "cve"],
      rows: [["api.example.com", "CVE-2024-9999"]],
      generated_sql: "SELECT host, cve FROM ask_findings WHERE kev LIMIT 100",
      engine: "llm",
      note: "matched 1 row",
    };
    vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      const isAsk = url.includes("/v1/ask") && (init?.method ?? "GET").toUpperCase() === "POST";
      const body = isAsk ? JSON.stringify(answer) : emptyBody();
      return Promise.resolve(
        new Response(body, { status: 200, headers: { "content-type": "application/json" } }),
      );
    });

    renderWithClient(React.createElement(AskPage));
    expect(screen.getByRole("heading", { name: "Ask" })).toBeInTheDocument();

    const input = screen.getByPlaceholderText(/internet-facing hosts/i) as HTMLTextAreaElement;
    fireEvent.change(input, { target: { value: "which hosts have a KEV CVE?" } });
    fireEvent.click(screen.getByRole("button", { name: "Ask" }));

    expect(await screen.findByText("api.example.com")).toBeInTheDocument();
    expect(screen.getByText(/engine · llm/i)).toBeInTheDocument();
    expect(screen.getByText(/read-only · validated/i)).toBeInTheDocument();
  });
});

describe("Dependencies page", () => {
  it("renders the SBOM scaffold and empty component state", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(emptyBody(), { status: 200, headers: { "content-type": "application/json" } }),
    );
    renderWithClient(React.createElement(DependenciesPage));
    expect(screen.getByRole("heading", { name: "Dependencies" })).toBeInTheDocument();
    expect(screen.getByText("SBOM")).toBeInTheDocument();
    expect(screen.getByText("Supply-chain risk")).toBeInTheDocument();
    expect(await screen.findByText(/No components match these filters/i)).toBeInTheDocument();
  });
});
