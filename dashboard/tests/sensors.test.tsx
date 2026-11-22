/**
 * Sensors page: list + health, warnings, silent state, the Add-sensor wizard
 * (token shown once with the enroll command and boot-partition file), token
 * revocation and sensor revocation behind a confirm.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import SensorsPage, { relTime } from "../src/pages/Sensors";
import { bootFile, enrollCommand } from "../src/api/sensors";
import { useAuth } from "../src/state/auth";

const NOW = Date.now();
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString();

function sensor(over: Record<string, unknown> = {}) {
  return {
    id: "s1", name: "lobby-1", site: "Store 42", state: "online", status: "active", version: "0.2.0",
    hostname: "pi-lobby", interfaces: [{ name: "eth1", up: true, speed_mbps: 1000 }],
    enrolled_at: iso(86400e3), last_seen_at: iso(20e3), last_heartbeat_at: iso(20e3), last_upload_at: iso(40e3),
    offline_since: null, silent_after_s: 300, health: { packets_seen: 123456, packets_dropped: 0, buffer_fill_pct: 2, buffer_bytes: 2048, clock_skew_s: 0.4, iface: "eth1" },
    warnings: [], batches_total: 50, flows_total: 4200, duplicates_total: 2, ...over,
  };
}

type Route = { re: RegExp; method?: string; body: unknown; status?: number };

function mockApi(routes: Route[]) {
  const calls: { url: string; method: string; body?: string }[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push({ url, method, body: init?.body as string | undefined });
    const hit = routes.find((r) => r.re.test(url) && (!r.method || r.method === method));
    const status = hit?.status ?? 200;
    return new Response(status === 204 ? null : JSON.stringify(hit?.body ?? []), {
      status, headers: { "content-type": "application/json" },
    });
  });
  return calls;
}

function mount(role: "admin" | "viewer" = "admin") {
  useAuth.setState({ token: "t", user: { username: "u", role, clearance: "restricted" } });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(React.createElement(QueryClientProvider, { client: qc }, React.createElement(SensorsPage)));
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useAuth.setState({ token: null, user: null });
});

describe("helpers", () => {
  it("formats relative times and the enroll artefacts", () => {
    expect(relTime(null)).toBe("never");
    expect(relTime(iso(5e3), NOW)).toBe("just now");
    expect(relTime(iso(10 * 60e3), NOW)).toBe("10m ago");
    expect(relTime(iso(3 * 3600e3), NOW)).toBe("3h ago");
    expect(enrollCommand("https://p.example:8101", "pet_a_b")).toBe("sudo paddock-sentry enroll https://p.example:8101 pet_a_b");
    const f = bootFile("https://p.example:8101", "pet_a_b", "Store 42");
    expect(f).toContain("PADDOCK_SERVER=https://p.example:8101");
    expect(f).toContain("PADDOCK_ENROLL_TOKEN=pet_a_b");
  });
});

describe("Sensors page", () => {
  it("lists sensors with state, site and last seen, and counts them", async () => {
    mockApi([{ re: /\/v1\/sensors$/, body: [
      sensor(),
      sensor({ id: "s2", name: "dock-2", state: "offline", last_seen_at: iso(2 * 3600e3), last_upload_at: iso(2 * 3600e3) }),
      sensor({ id: "s3", name: "plant-3", state: "degraded", warnings: ["12 packets dropped by the kernel"] }),
      sensor({ id: "s4", name: "old-4", state: "revoked", status: "revoked" }),
    ] }, { re: /\/v1\/sensors\/tokens$/, body: [] }]);
    mount();
    expect(await screen.findByText("lobby-1")).toBeInTheDocument();
    expect(screen.getByText("dock-2")).toBeInTheDocument();
    expect(screen.getAllByText("Store 42").length).toBeGreaterThan(0);
    expect(screen.getByText("silent")).toBeInTheDocument();
    expect(screen.getByText("needs attention", { selector: ".sn-chip" })).toBeInTheDocument();
    expect(screen.getAllByText("2h ago", { selector: "td" }).length).toBe(2);
    // tiles ignore revoked sensors: 3 live, 1 online, 1 attention, 1 silent
    const tiles = document.querySelectorAll(".stat-row .stat-tile, .stat-row > *");
    expect(tiles.length).toBeGreaterThanOrEqual(4);
  });

  it("shows health, warnings and the silent explanation for the selected sensor", async () => {
    mockApi([{ re: /\/v1\/sensors$/, body: [sensor({
      state: "degraded", warnings: ["12 packets dropped by the kernel", "clock is +90s off the server (fix NTP)"],
      health: { packets_seen: 1000, packets_dropped: 12, buffer_fill_pct: 91, buffer_bytes: 5e6, clock_skew_s: 90, iface: "eth1" },
    })] }, { re: /\/v1\/sensors\/tokens$/, body: [] }]);
    mount();
    fireEvent.click(await screen.findByRole("button", { name: "lobby-1" }));
    const warnings = await screen.findByLabelText("warnings");
    expect(within(warnings).getByText(/12 packets dropped/)).toBeInTheDocument();
    expect(within(warnings).getByText(/fix NTP/)).toBeInTheDocument();
    expect(screen.getByText("+90.0s")).toBeInTheDocument();
    expect(screen.getByText(/91% · 4\.8 MiB/)).toBeInTheDocument();
    expect(screen.getByText("4,200")).toBeInTheDocument();
  });

  it("empty state points at Add sensor", async () => {
    mockApi([{ re: /\/v1\/sensors$/, body: [] }, { re: /\/v1\/sensors\/tokens$/, body: [] }]);
    mount();
    expect(await screen.findByText("No sensors yet.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add sensor" })).toBeInTheDocument();
  });

  it("Add sensor wizard: creates a token, shows the command and the boot file once, then notices enrollment", async () => {
    let used = false;
    const calls = mockApi([
      { re: /\/v1\/sensors\/tokens$/, method: "POST", status: 201, body: {
        id: "t1", token: "pet_0a1b2c3d_SECRETSECRETSECRETSECRETSECRET", token_prefix: "0a1b2c3d", site: "Store 42", label: null,
        created_by: "admin", created_at: iso(0), expires_at: new Date(NOW + 3600e3).toISOString(), state: "pending", used_by_sensor: null } },
      { re: /\/v1\/sensors\/tokens$/, method: "GET", body: [] },
      { re: /\/v1\/sensors$/, body: [] },
    ]);
    // after the first poll the token flips to "used"
    const base = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
    const wrapped = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (/\/v1\/sensors\/tokens$/.test(url) && (init?.method ?? "GET") === "GET" && used) {
        return new Response(JSON.stringify([{ id: "t1", token_prefix: "0a1b2c3d", site: "Store 42", label: null, created_by: "admin",
          created_at: iso(0), expires_at: new Date(NOW + 3600e3).toISOString(), state: "used", used_by_sensor: "s1" }]),
          { status: 200, headers: { "content-type": "application/json" } });
      }
      return (base as unknown as (i: RequestInfo | URL, n?: RequestInit) => Promise<Response>)(input, init);
    });
    expect(wrapped).toBeDefined();

    mount();
    fireEvent.click(await screen.findByRole("button", { name: "Add sensor" }));
    const dialog = await screen.findByRole("dialog", { name: "Add sensor" });
    const create = within(dialog).getByRole("button", { name: "Create token" });
    expect(create).toBeDisabled(); // site name required
    fireEvent.change(within(dialog).getByLabelText("Site name"), { target: { value: "Store 42" } });
    fireEvent.change(within(dialog).getByLabelText(/Sensor ingest address/), { target: { value: "https://paddock.example:8101/" } });
    fireEvent.change(within(dialog).getByLabelText("Token expires after"), { target: { value: "1440" } });
    fireEvent.click(create);

    const cmd = await within(dialog).findByLabelText("Run on the sensor");
    expect(cmd.textContent).toBe("sudo paddock-sentry enroll https://paddock.example:8101 pet_0a1b2c3d_SECRETSECRETSECRETSECRETSECRET");
    const boot = within(dialog).getByLabelText(/boot partition/);
    expect(boot.textContent).toContain("PADDOCK_SERVER=https://paddock.example:8101");
    expect(boot.textContent).toContain("PADDOCK_ENROLL_TOKEN=pet_0a1b2c3d_SECRETSECRETSECRETSECRETSECRET");
    expect(within(dialog).getByRole("status")).toHaveTextContent(/waiting for the sensor/i);

    const post = calls.find((c) => c.method === "POST" && c.url.endsWith("/v1/sensors/tokens"))!;
    expect(JSON.parse(post.body!)).toEqual({ site: "Store 42", ttl_minutes: 1440 });

    used = true; // the sensor redeems the token
    await waitFor(() => expect(within(dialog).getByRole("status")).toHaveTextContent(/sensor enrolled/i), { timeout: 8000 });
    expect(within(dialog).getByRole("button", { name: "Done" })).toBeInTheDocument();
  }, 15000);

  it("viewers see sensors but cannot add or revoke", async () => {
    mockApi([{ re: /\/v1\/sensors$/, body: [sensor()] }, { re: /\/v1\/sensors\/tokens$/, body: [] }]);
    mount("viewer");
    fireEvent.click(await screen.findByRole("button", { name: "lobby-1" }));
    expect(screen.getByRole("button", { name: "Add sensor" })).toBeDisabled();
    expect(await screen.findByRole("button", { name: "Revoke sensor" })).toBeDisabled();
  });

  it("revokes a pending token", async () => {
    const calls = mockApi([
      { re: /\/v1\/sensors\/tokens\/t9$/, method: "DELETE", status: 204, body: null },
      { re: /\/v1\/sensors\/tokens$/, body: [{ id: "t9", token_prefix: "deadbeef", site: "Plant A", label: null, created_by: "a",
        created_at: iso(1e3), expires_at: new Date(NOW + 30 * 60e3).toISOString(), state: "pending", used_by_sensor: null }] },
      { re: /\/v1\/sensors$/, body: [] },
    ]);
    mount();
    expect(await screen.findByText("pet_deadbeef…")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url.endsWith("/tokens/t9"))).toBe(true));
  });

  it("revoking a sensor asks first and explains the consequence", async () => {
    const calls = mockApi([
      { re: /\/v1\/sensors\/s1\/revoke$/, method: "POST", body: sensor({ state: "revoked", status: "revoked" }) },
      { re: /\/v1\/sensors\/tokens$/, body: [] },
      { re: /\/v1\/sensors$/, body: [sensor()] },
    ]);
    mount();
    fireEvent.click(await screen.findByRole("button", { name: "lobby-1" }));
    fireEvent.click(await screen.findByRole("button", { name: "Revoke sensor" }));
    const dlg = await screen.findByRole("dialog", { name: "Revoke sensor" });
    expect(within(dlg).getByText(/stops working on the next request/i)).toBeInTheDocument();
    expect(calls.some((c) => c.url.endsWith("/revoke"))).toBe(false); // nothing sent before confirming
    fireEvent.click(within(dlg).getByRole("button", { name: "Revoke sensor" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url.endsWith("/v1/sensors/s1/revoke"))).toBe(true));
  });
});
