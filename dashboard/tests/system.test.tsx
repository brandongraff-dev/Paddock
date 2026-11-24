/**
 * Settings → System: version/edition tiles, core + service rows with health,
 * "not installed" shown as normal (not an error), and a warning when a
 * component is not responding.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import React from "react";
import { MemoryRouter } from "react-router-dom";
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

function aiStatus(over: Record<string, unknown> = {}) {
  return { configured: false, hint: null, updated_at: null, updated_by: null, editable: true, brain: "up", ...over };
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** URL-aware: /v1/system/ai gets `ai`, everything else the system body. Records every call. */
function renderPage(body: unknown, ai: Record<string, unknown> = aiStatus(), onAi?: (req: Request) => Response | undefined) {
  const calls: { url: string; method: string; body: string | null }[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const href = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url;
    const abs = new URL(href, "http://x");
    const req = new Request(abs.href, init);
    const url = abs.pathname;
    const text = req.method === "GET" ? null : await req.text();
    calls.push({ url, method: req.method, body: text });
    if (url === "/v1/system/ai") return onAi?.(req) ?? json(ai);
    return json(body);
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return { calls, ...render(React.createElement(MemoryRouter, null, React.createElement(QueryClientProvider, { client: qc }, React.createElement(SystemPage)))) };
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

describe("AI features panel", () => {
  const KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";

  it("explains the options, says nothing is saved, and offers a password field", async () => {
    renderPage(system());
    expect(await screen.findByText(/No key saved. Using the built-in fallbacks/)).toBeTruthy();
    const input = screen.getByLabelText("Anthropic API key") as HTMLInputElement;
    expect(input.type).toBe("password");
    expect(input.autocomplete).toBe("new-password");
    expect(screen.getByText(/sent to Anthropic/)).toBeTruthy();       // says what leaves the machine
    expect((screen.getByRole("button", { name: "Save key" }) as HTMLButtonElement).disabled).toBe(true); // empty
    expect(screen.queryByRole("button", { name: "Remove key" })).toBeNull();
  });

  it("saves the key, empties the field, and never shows the key again", async () => {
    const { calls } = renderPage(system(), aiStatus(), (req) =>
      req.method === "PUT" ? json(aiStatus({ configured: true, hint: "…wxyz", updated_by: "ada" })) : undefined);
    const input = (await screen.findByLabelText("Anthropic API key")) as HTMLInputElement;
    fireEvent.change(input, { target: { value: KEY } });
    fireEvent.click(screen.getByRole("button", { name: "Save key" }));
    await screen.findByText(/Key saved \(…wxyz\) by ada. AI is on./);
    expect(calls.find((c) => c.method === "PUT")).toMatchObject({ url: "/v1/system/ai", body: JSON.stringify({ api_key: KEY }) });
    expect(input.value).toBe("");
    expect(document.body.textContent).not.toContain(KEY);
    expect(screen.getByRole("button", { name: "Replace key" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Remove key" })).toBeTruthy();
  });

  it("shows the server's plain-English reason when the key is refused", async () => {
    renderPage(system(), aiStatus(), (req) =>
      req.method === "PUT" ? json({ detail: "That does not look like an Anthropic API key." }, 422) : undefined);
    const input = (await screen.findByLabelText("Anthropic API key")) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "nope" } });
    fireEvent.click(screen.getByRole("button", { name: "Save key" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/does not look like an Anthropic API key/);
  });

  it("removes a saved key", async () => {
    const { calls } = renderPage(system(), aiStatus({ configured: true, hint: "…wxyz" }), (req) =>
      req.method === "DELETE" ? json(aiStatus()) : undefined);
    fireEvent.click(await screen.findByRole("button", { name: "Remove key" }));
    await screen.findByText(/No key saved/);
    expect(calls.some((c) => c.method === "DELETE" && c.url === "/v1/system/ai")).toBe(true);
  });

  it("is read-only for a tenant that does not own the install", async () => {
    renderPage(system(), aiStatus({ editable: false }));
    expect(await screen.findByText(/managed by the platform operator/)).toBeTruthy();
    expect((screen.getByLabelText("Anthropic API key") as HTMLInputElement).disabled).toBe(true);
  });

  it("warns when Brain is not part of the install or not up yet", async () => {
    const a = renderPage(system(), aiStatus({ brain: "not_installed" }));
    expect(await screen.findByText(/not part of this install, so a key would have no effect/)).toBeTruthy();
    a.unmount();
    renderPage(system(), aiStatus({ brain: "down" }));
    expect(await screen.findByText(/not responding yet/)).toBeTruthy();
  });
});
