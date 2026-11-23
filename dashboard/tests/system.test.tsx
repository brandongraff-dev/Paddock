/**
 * Settings → System: version/edition tiles, core + service rows with health,
 * "not installed" shown as normal (not an error), and a warning when a
 * component is not responding.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import SystemPage from "../src/pages/System";

function system(over: Record<string, unknown> = {}) {
  return {
    version: "0.1.0", edition: "community", license_status: "community", auth_mode: "enforce", scheduler_enabled: true,
    core: [
      { key: "api", label: "API", description: "Orchestrator", status: "up" },
      { key: "database", label: "Database", description: "PostgreSQL", status: "up" },
    ],
    services: [
      { key: "brain", label: "Brain", description: "Triage", status: "up" },
      { key: "remediation", label: "Remediation", description: "Fixes", status: "not_installed" },
    ],
    counts: { up: 3, down: 0, not_installed: 1 },
    ...over,
  };
}

function renderPage(body: unknown) {
  vi.spyOn(globalThis, "fetch").mockImplementation(
    async () => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } }),
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(React.createElement(QueryClientProvider, { client: qc }, React.createElement(SystemPage)));
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("System page", () => {
  it("shows version, edition and each component's state", async () => {
    renderPage(system());
    await waitFor(() => expect(screen.getByText("0.1.0")).toBeTruthy());
    expect(screen.getByText("Community")).toBeTruthy();
    expect(screen.getByText("3 / 4")).toBeTruthy();
    const brain = document.querySelector('tr[data-key="brain"]') as HTMLElement;
    expect(within(brain).getByText("Running")).toBeTruthy();
    const rem = document.querySelector('tr[data-key="remediation"]') as HTMLElement;
    expect(within(rem).getByText("Not installed")).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull(); // nothing is wrong
    expect(screen.getByText(/lite stack runs a smaller set/)).toBeTruthy();
  });

  it("warns when a component is not responding", async () => {
    renderPage(system({
      services: [{ key: "brain", label: "Brain", description: "Triage", status: "down" }],
      counts: { up: 2, down: 1, not_installed: 0 },
    }));
    const note = await screen.findByRole("status");
    expect(note.textContent).toMatch(/1 component is not responding/);
    expect(note.textContent).toMatch(/Brain/);
  });
});
