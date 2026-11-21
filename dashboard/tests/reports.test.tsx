/**
 * Reports page: executive preview, period picker, downloads, compliance
 * framework cards with status meters, and the control drill-down.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ReportsPage, { StatusMeter, fmtHours } from "../src/pages/Reports";
import { useStore } from "../src/state/store";

const sev = (c = 0, h = 0, m = 0, l = 0, i = 0) => ({ critical: c, high: h, medium: m, low: l, info: i });

const REPORT = {
  generated_at: "2026-11-21T12:00:00Z",
  org_name: "Acme",
  clearance: "restricted",
  window: { start: "2026-11-14T12:00:00Z", end: "2026-11-21T12:00:00Z", days: 7, label: "14 – 21 Nov 2026" },
  highlights: ["Exposure fell 12%, from 50 to 44.", "SLA compliance 92% with 1 breach."],
  exposure: {
    points: [50, 52, 49, 47, 46, 45, 44, 44].map((v, i) => ({ at: `2026-11-${14 + i}T12:00:00Z`, value: v })),
    start_value: 50, end_value: 44, delta: -6, delta_pct: -12, open_start: sev(1, 4), open_end: sev(1, 3),
  },
  new_findings: { by_severity: sev(1, 2), critical: 1, high: 2, previous_critical_high: 4, top: [] },
  resolutions: { fixed: 9, verified: 7, regressed: 1, pending_verification: 1, accepted_risk: 0 },
  mttr: {
    overall: { key: "all", count: 9, mean_hours: 50, median_hours: 30, critical_high: 3 },
    by_severity: [{ key: "critical", count: 1, mean_hours: 10, median_hours: 10, critical_high: 1 }],
    by_team: [{ key: "Platform", count: 5, mean_hours: 20, median_hours: 18, critical_high: 2 }],
  },
  sla: {
    met: 11, late: 1, breached_open: 0, overdue_end: 2, compliance_pct: 91.7,
    by_severity: [{ severity: "high", policy_hours: 72, met: 11, late: 1, breached_open: 0, overdue_end: 2, open_within_sla: 1, compliance_pct: 91.7 }],
  },
  attack_paths: {
    opened: 1, closed: 2, open_start: 3, open_end: 2, top_opened: [],
    top_closed: [{ fingerprint: "p", title: "vpn → db", severity: "critical", exploitability: 80, kev_on_path: true, opened_at: "", closed_at: "", open_days: 9 }],
  },
  changes: { total: 4 },
  devices: { iot_total: 2, ot_total: 1, behaviour: [] },
  coverage: { assets_total: 40, last_completed_scan: null, sbom_components: 0 },
};

const FRAMEWORKS = [
  { id: "pci-dss-4.0", name: "PCI DSS", version: "4.0", publisher: "PCI SSC", url: null, description: "Payment card.",
    counts: { satisfied: 2, partial: 10, gap: 4, requires_attestation: 3 }, total: 19, automated: 16 },
  { id: "eu-cra", name: "EU Cyber Resilience Act, Annex I", version: "2024/2847", publisher: "EU", url: null, description: "CRA.",
    counts: { satisfied: 1, partial: 5, gap: 2, requires_attestation: 7 }, total: 15, automated: 8 },
];

const PACK = {
  framework: FRAMEWORKS[0],
  generated_at: "2026-11-21T12:00:00Z",
  clearance: "restricted",
  disclaimer: "Supports, and does not replace, an assessment.",
  controls: [
    { id: "11.4.5", title: "Segmentation controls are tested", family: "11 · Test security regularly", summary: "Pentest segmentation.",
      mode: "automated", status: "partial", max_status: "partial", rationale: "Sentry observes reachability.",
      attestation: "Provide the segmentation penetration-test report.",
      evidence: [{ key: "segmentation_map", title: "Observed segmentation map (Sentry)", status: "pass", detail: "3 segments observed.", metrics: {}, rows: [] }] },
    { id: "12.10.1", title: "Incident response plan exists", family: "12 · Policies", summary: "IR plan.", mode: "manual",
      status: "requires_attestation", max_status: "satisfied", rationale: "Organisational.", attestation: "Provide the plan.", evidence: [] },
  ],
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function mockApi() {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/v1/reports/executive") && url.includes("format=pdf")) {
      return new Response(new Blob(["%PDF-1.7"], { type: "application/pdf" }), { status: 200 });
    }
    if (url.includes("/v1/reports/executive")) return json(REPORT);
    if (url.includes("/v1/reports/compliance/pci-dss-4.0")) return json(PACK);
    if (url.includes("/v1/reports/compliance")) return json(FRAMEWORKS);
    return json({ items: [] });
  });
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(React.createElement(QueryClientProvider, { client: qc }, React.createElement(ReportsPage)));
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useStore.setState({ events: [], toasts: [], drawer: { kind: null } });
});

describe("Reports page", () => {
  it("renders the executive preview with highlights and KPIs", async () => {
    mockApi();
    renderPage();
    expect(screen.getByRole("heading", { name: "Reports" })).toBeInTheDocument();
    expect(await screen.findByText("Exposure fell 12%, from 50 to 44.")).toBeInTheDocument();
    expect(screen.getByText("Exposure index", { selector: ".label" })).toBeInTheDocument();
    expect(screen.getAllByText("92%").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("1 · 2")).toBeInTheDocument();
    expect(screen.getByText("vpn → db")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Exposure index" })).toBeInTheDocument();
  });

  it("refetches when the period changes", async () => {
    const spy = mockApi();
    renderPage();
    await screen.findByText("Exposure fell 12%, from 50 to 44.");
    fireEvent.click(screen.getByRole("radio", { name: "90D" }));
    await waitFor(() =>
      expect(spy.mock.calls.some(([u]) => String(u).includes("/v1/reports/executive?period=90d"))).toBe(true),
    );
  });

  it("downloads the PDF with the auth header path", async () => {
    const spy = mockApi();
    const create = vi.fn(() => "blob:x");
    (URL as unknown as { createObjectURL: unknown }).createObjectURL = create;
    (URL as unknown as { revokeObjectURL: unknown }).revokeObjectURL = vi.fn();
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    renderPage();
    await screen.findByText("Exposure fell 12%, from 50 to 44.");
    fireEvent.click(screen.getByRole("button", { name: "Download PDF" }));
    await waitFor(() => expect(click).toHaveBeenCalled());
    expect(spy.mock.calls.some(([u]) => String(u).includes("format=pdf"))).toBe(true);
    expect(create).toHaveBeenCalled();
  });

  it("shows framework cards with meters and drills into controls", async () => {
    mockApi();
    renderPage();
    const card = await screen.findByRole("button", { name: "PCI DSS 4.0" });
    expect(within(card).getByRole("img").getAttribute("aria-label")).toBe(
      "Satisfied 2, Partial 10, Gap 4, Attestation 3",
    );
    fireEvent.click(card);
    const ctl = await screen.findByText("Segmentation controls are tested");
    expect(screen.getByText("Supports, and does not replace, an assessment.")).toBeInTheDocument();
    fireEvent.click(ctl);
    expect(await screen.findByText(/3 segments observed/)).toBeInTheDocument();
    expect(screen.getByText(/Provide the segmentation penetration-test report/)).toBeInTheDocument();
    // status filter hides partial controls
    fireEvent.click(screen.getByRole("radio", { name: "Attestation 3" }));
    expect(screen.queryByText("Segmentation controls are tested")).not.toBeInTheDocument();
    expect(screen.getByText("Incident response plan exists")).toBeInTheDocument();
  });
});

describe("helpers", () => {
  it("formats hours compactly", () => {
    expect(fmtHours(null)).toBe("—");
    expect(fmtHours(0.5)).toBe("30m");
    expect(fmtHours(29.4)).toBe("29.4h");
    expect(fmtHours(84)).toBe("3.5d");
  });

  it("status meter renders one segment per non-zero status", () => {
    const { container } = render(
      React.createElement(StatusMeter, { counts: { satisfied: 1, partial: 0, gap: 2, requires_attestation: 0 }, total: 3 }),
    );
    expect(container.querySelectorAll(".rp-meter span")).toHaveLength(2);
  });
});
