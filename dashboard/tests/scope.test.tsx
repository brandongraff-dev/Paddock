/** Scope page: API-valid kinds, ownership status, inline attestation. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ScopePage from "../src/pages/Scope";
import { useAuth } from "../src/state/auth";

const proof = (status: string, extra: Record<string, unknown> = {}) => ({
  status, method: null, methods: [], token_issued: false, required: true,
  effective: status === "verified" || status === "attested", ...extra,
});
const ENTRIES = [
  { id: "1", kind: "domain", value: "shop.example.com", active: true, added_by: "a", added_at: "2026-11-01", proof: proof("verified") },
  { id: "2", kind: "ipv4_cidr", value: "203.0.113.0/24", active: true, added_by: "a", added_at: "2026-11-01", proof: proof("pending") },
];

function render_() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(React.createElement(QueryClientProvider, { client: qc },
    React.createElement(MemoryRouter, null, React.createElement(ScopePage))));
}

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("Scope page", () => {
  it("offers only the kinds the API accepts and shows ownership status", async () => {
    useAuth.setState({ token: "t", user: { username: "admin", role: "admin", clearance: "restricted" } });
    vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      new Response(JSON.stringify(ENTRIES), { status: 200, headers: { "content-type": "application/json" } }));
    render_();
    const opts = [...(screen.getByRole("combobox") as HTMLSelectElement).options].map((o) => o.value);
    expect(opts).toEqual(["domain", "subdomain_wildcard", "ipv4_cidr", "ipv6_cidr", "asn"]);
    expect(await screen.findByText("verified")).toBeInTheDocument();
    expect(screen.getByText(/pending · blocked/)).toBeInTheDocument();
  });

  it("records an attestation for an IP range", async () => {
    useAuth.setState({ token: "t", user: { username: "admin", role: "admin", clearance: "restricted" } });
    const calls: { url: string; body?: unknown }[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      calls.push({ url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      const body = url.includes("/verify")
        ? { scope_entry_id: 2, check: { ok: true, method: "attestation", detail: "" }, proof: proof("attested") }
        : ENTRIES;
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    });
    render_();
    fireEvent.click(await screen.findByRole("button", { name: "attest" }));
    fireEvent.change(screen.getByPlaceholderText(/LOA/), { target: { value: "MSA-2026-14" } });
    fireEvent.change(screen.getByPlaceholderText(/Approver/), { target: { value: "J. Doe, CISO" } });
    fireEvent.click(screen.getByRole("button", { name: "Record attestation" }));
    await waitFor(() => expect(calls.some((c) => c.url.includes("/v1/scope/2/verify"))).toBe(true));
    const v = calls.find((c) => c.url.includes("/verify"))!;
    expect(v.body).toEqual({ method: "attestation", loa_ref: "MSA-2026-14", approver: "J. Doe, CISO" });
    expect(await screen.findByText("Proven")).toBeInTheDocument();
  });
});
