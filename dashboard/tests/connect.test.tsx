/**
 * "Connect anything" panel: create a source (token shown once), snippets that
 * never inline the token, rotate/revoke, role gating, and the pure snippet helpers.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ConnectAnything from "../src/components/ConnectAnything";
import { cleanBase, ingestUrl, mcpConfig, snippetFor, SNIPPET_ORDER } from "../src/lib/connectSnippets";
import { useAuth } from "../src/state/auth";

const SRC = {
  id: "s1", name: "ci-trivy", description: null, token_prefix: "AbC123", default_project: "acme/web",
  allowed_formats: [], rate_limit_per_min: 60, enabled: true, created_by: "admin", created_at: "2026-11-20T10:00:00Z",
  rotated_at: null, revoked_at: null, last_used_at: null, ingest_count: 3, url: "http://x/v1/ingest",
};
const TOKEN = "pdi_0000_1111_SECRETSECRETSECRET";

function mock() {
  const calls: Array<{ url: string; method: string; body: unknown }> = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push({ url, method, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    const json = (b: unknown, status = 200) =>
      new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
    if (method === "POST" && /\/sources$/.test(url)) return json({ ...SRC, id: "s2", name: "new-src", token: TOKEN }, 201);
    if (method === "POST" && /\/rotate$/.test(url)) return json({ ...SRC, token: TOKEN + "2" });
    if (method === "DELETE") return json({ ...SRC, revoked_at: "2026-11-21T00:00:00Z" });
    if (/\/sources/.test(url)) return json({ items: [SRC] });
    if (/\/log/.test(url)) return json({ items: [
      { id: 1, source_id: "s1", source_name: "ci-trivy", actor: "ingest:ci-trivy", format: "trivy", status: "ok", http_status: 200,
        findings_new: 4, findings_updated: 1, components: 2, assets: 1, skipped: 0, duplicates: 0, suppressed: 0, errors: [],
        bytes: 10, project: null, created_at: new Date().toISOString() },
      { id: 2, source_id: "s1", source_name: "ci-trivy", actor: "x", format: null, status: "rejected", http_status: 415, findings_new: 0,
        findings_updated: 0, components: 0, assets: 0, skipped: 0, duplicates: 0, suppressed: 0,
        errors: [{ where: "body", message: "XML is not accepted" }], bytes: 5, project: null, created_at: new Date().toISOString() },
    ] });
    return json({});
  });
  return calls;
}

function renderPanel() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><ConnectAnything /></QueryClientProvider>);
}
const asAdmin = () => useAuth.setState({ token: "t", user: { username: "a", role: "admin", clearance: "restricted" } });
const asViewer = () => useAuth.setState({ token: "t", user: { username: "v", role: "viewer", clearance: "public" } });

afterEach(() => { cleanup(); vi.restoreAllMocks(); useAuth.setState({ token: null, user: null }); });

describe("Connect anything panel", () => {
  it("lists sources without any token and shows recent uploads", async () => {
    asAdmin(); mock(); renderPanel();
    expect(await screen.findByText("pdi_…AbC123")).toBeInTheDocument();
    expect(screen.getByText("pdi_…AbC123")).toBeInTheDocument();
    expect(screen.queryByTestId("ingest-token")).toBeNull();
    expect(await screen.findByText(/4 new, 1 updated, 2 components/)).toBeInTheDocument();
    expect(screen.getByText("rejected (415)")).toBeInTheDocument();
  });

  it("creates a source and reveals the token once", async () => {
    asAdmin(); const calls = mock(); renderPanel();
    fireEvent.change(await screen.findByLabelText("Source name"), { target: { value: "new-src" } });
    fireEvent.change(screen.getByLabelText(/Default project/), { target: { value: "acme/api" } });
    fireEvent.click(screen.getByRole("button", { name: "New source" }));
    expect(await screen.findByTestId("ingest-token")).toHaveTextContent(TOKEN);
    const post = calls.find((c) => c.method === "POST" && /sources$/.test(c.url))!;
    expect(post.body).toEqual({ name: "new-src", default_project: "acme/api" });
    expect(screen.getByLabelText("curl snippet").textContent).not.toContain("SECRETSECRET");
  });

  it("switches snippets and keeps the token out of every one", async () => {
    asAdmin(); mock(); renderPanel();
    await screen.findByText("pdi_…AbC123");
    const cases: Array<[string, string]> = [
      ["GitHub Actions", "secrets.PADDOCK_INGEST_TOKEN"], ["GitLab CI", "CI_PROJECT_PATH"],
      ["Python", "httpx.post"], ["TypeScript", "process.env.PADDOCK_INGEST_TOKEN"],
      ["MCP: Claude Desktop", "paddock-mcp"], ["MCP: Cursor", "mcpServers"],
    ];
    for (const [label, expected] of cases) {
      fireEvent.click(screen.getByRole("tab", { name: label }));
      expect(screen.getByLabelText(`${label} snippet`).textContent).toContain(expected);
    }
  });

  it("rotates and revokes", async () => {
    asAdmin(); const calls = mock(); renderPanel();
    fireEvent.click(await screen.findByRole("button", { name: "Rotate token for ci-trivy" }));
    expect(await screen.findByTestId("ingest-token")).toHaveTextContent(TOKEN + "2");
    fireEvent.click(screen.getByRole("button", { name: "Revoke ci-trivy" }));
    await vi.waitFor(() => expect(calls.some((c) => c.method === "DELETE" && /sources\/s1$/.test(c.url))).toBe(true));
    await vi.waitFor(() => expect(screen.queryByTestId("ingest-token")).toBeNull());
  });

  it("is read-only for non-admins", async () => {
    asViewer(); mock(); renderPanel();
    await screen.findByText("pdi_…AbC123");
    expect(screen.getByRole("button", { name: "New source" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Revoke ci-trivy" })).toBeDisabled();
  });
});

describe("snippet helpers", () => {
  it("never embeds a token and validates the base URL", () => {
    for (const k of SNIPPET_ORDER) {
      const s = snippetFor(k, { baseUrl: "https://paddock.example.com/", project: "a b/c" });
      expect(s).not.toMatch(/pdi_[A-Za-z0-9]/);
      expect(s).toContain("https://paddock.example.com");
    }
    expect(ingestUrl({ baseUrl: "https://p.example.com", project: "a b/c" })).toBe("https://p.example.com/v1/ingest?project=a%20b%2Fc");
    expect(cleanBase("javascript:alert(1)")).toBe("https://paddock.example.com");
    expect(cleanBase("https://x.com'; rm -rf /")).toBe("https://paddock.example.com");
    expect(cleanBase("")).toBe("https://paddock.example.com");
  });

  it("builds the MCP config", () => {
    const c = mcpConfig("https://p.example.com/");
    expect(c.mcpServers.paddock).toMatchObject({ command: "paddock-mcp", env: { PADDOCK_URL: "https://p.example.com" } });
  });
});
