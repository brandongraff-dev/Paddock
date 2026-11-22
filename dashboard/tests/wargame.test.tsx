/**
 * Wargame page + presentation logic.
 *   - the evidence ladder never upgrades an unknown label, and a hop is styled
 *     by its weakest label (conditional/inferred render as the weak tier);
 *   - boundary verdicts include "proved_config" and render unknown strings
 *     as reported;
 *   - the change gate reads verdicts plainly and never calls an incomplete
 *     check "safe";
 *   - the page: empty state (no twin), the full view (board line verbatim),
 *     an API error (no fabricated data), and a change-impact round trip.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import React from "react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import WargamePage from "../src/pages/Wargame";
import { useStore } from "../src/state/store";
import {
  evidenceMeta,
  hopWeakest,
  impactHeadline,
  routeStrengthSentence,
  uncutRoutes,
  verdictMeta,
} from "../src/lib/wargame";
import { buildWargameSample, sampleImpactFor, SAMPLE_PLANS } from "../src/lib/wargameSample";
import type { WargameChangeImpact } from "../src/api/types";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function renderPage(path = "/wargame") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    React.createElement(
      QueryClientProvider,
      { client: qc },
      React.createElement(MemoryRouter, { initialEntries: [path] }, React.createElement(WargamePage)),
    ),
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useStore.setState({ events: [], toasts: [], drawer: { kind: null } });
});

const baseImpact: WargameChangeImpact = {
  verdict: "safe",
  routes_opened: [],
  routes_closed: [],
  newly_denied_flows: [],
  newly_allowed_flows: [],
  summary: "",
  warnings: [],
};

describe("wargame presentation logic", () => {
  it("treats an unknown evidence label as no proof, shown as reported", () => {
    const m = evidenceMeta("quantum_proof");
    expect(m.strength).toBe(0);
    expect(m.tier).toBe("weak");
    expect(m.label).toBe("quantum proof");
    expect(evidenceMeta("conditional").tier).toBe("weak");
    expect(evidenceMeta("inferred").tier).toBe("weak");
    expect(evidenceMeta("proved_config").tier).toBe("config");
  });

  it("styles a hop by its weakest label", () => {
    expect(hopWeakest({ src: "a", dst: "b", port: null, labels: ["observed", "conditional"] }).key).toBe("conditional");
    expect(hopWeakest({ src: "a", dst: "b", port: null, labels: [] }).key).toBe("unknown");
  });

  it("names the weak hops in the route sentence", () => {
    const s = buildWargameSample();
    expect(routeStrengthSentence(s.routes[1])).toBe("Proved except hop 1 (inferred, not proved).");
    expect(routeStrengthSentence(s.routes[0])).toMatch(/allowed by config/);
  });

  it("knows proved_config and renders unknown verdicts verbatim", () => {
    expect(verdictMeta("proved_config").label).toBe("Shut on paper");
    expect(verdictMeta("pass").tone).toBe("pass");
    const u = verdictMeta("needs_human");
    expect(u.tone).toBe("unknown");
    expect(u.label).toBe("needs human");
  });

  it("derives the routes the fix set can't cut", () => {
    const s = buildWargameSample();
    const uncut = uncutRoutes(s.routes, s.fixSet);
    expect(uncut.map((r) => `${r.entry}>${r.jewel}`)).toEqual(["guest_wifi>phi_store"]);
  });

  it("reads change-impact verdicts plainly", () => {
    expect(
      impactHeadline({ ...baseImpact, verdict: "opens_route_to_crown_jewel", routes_opened: [{ entry: "x", jewel: "payments-db" }] })
        .headline,
    ).toBe("This change opens a route to payments-db");
    const flows = [1, 2, 3].map((i) => ({ src_ip: `10.0.0.${i}`, dst_ip: "10.1.0.1", proto: "tcp", dst_port: 443 }));
    expect(impactHeadline({ ...baseImpact, verdict: "breaks_live_flows", newly_denied_flows: flows }).headline).toBe(
      "This change breaks 3 live flows",
    );
    expect(impactHeadline(baseImpact).tone).toBe("safe");
    // an incomplete check is never called safe
    const partial = impactHeadline({ ...baseImpact, complete: false });
    expect(partial.tone).toBe("unknown");
    expect(partial.headline).toMatch(/Not proved safe/);
    expect(impactHeadline({ ...baseImpact, verdict: "mystery" }).tone).toBe("unknown");
  });

  it("sample mode only answers for its own plans", () => {
    expect(sampleImpactFor(SAMPLE_PLANS[0].plan)?.verdict).toBe("breaks_live_flows");
    expect(sampleImpactFor('{"resource_changes": []}')).toBeNull();
  });
});

describe("Wargame page", () => {
  it("shows the three-step setup when the tenant has no twin", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("/v1/wargame/twin"))
        return json({ ruleset_count: 0, rule_count: 0, segment_count: 0, edge_count: 0, snapshot_count: 0, has_twin: false });
      if (url.includes("/v1/wargame/assessments")) return json({ items: [], total: 0, limit: 20, offset: 0 });
      return json({});
    });
    renderPage();
    expect(await screen.findByText("Set up Wargame")).toBeInTheDocument();
    expect(screen.getByText("Load a firewall or cloud config")).toBeInTheDocument();
    expect(screen.getByText("Run the assessment")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Recompute" }).length).toBeGreaterThan(0);
    // no change gate without a twin
    expect(screen.queryByText(/Change gate/)).not.toBeInTheDocument();
  });

  it("shows an error, not invented data, when the API fails", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => json({ detail: "boom" }, 500));
    renderPage();
    expect(await screen.findByText("Couldn't load Wargame")).toBeInTheDocument();
    expect(screen.queryByText(/payments_db/)).not.toBeInTheDocument();
  });

  it("renders the scorecard, routes, verdicts and certificates from the API", async () => {
    const s = buildWargameSample();
    const a = s.assessments[0];
    const boundaries = [...s.boundaries, { ...s.boundaries[0], id: "bx", verdict: "needs_human", note: "new verdict" }];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/v1/wargame/twin")) return json(s.twin);
      if (url.includes("/routes")) return json({ items: s.routes, total: s.routes.length, limit: 500, offset: 0 });
      if (url.includes("/boundaries")) return json(boundaries);
      if (url.includes("/certificates")) return json(s.certificates);
      if (url.includes("/fix-set")) return json(s.fixSet);
      if (url.includes("/v1/wargame/assessments")) return json({ items: [a], total: 1, limit: 20, offset: 0 });
      return json({});
    });
    const { container } = renderPage();
    // board line verbatim, coverage caveat and all
    expect(await screen.findByText(a.board_line)).toBeInTheDocument();
    expect(await screen.findByText("Who can reach your crown jewels")).toBeInTheDocument();
    await waitFor(() => expect(container.querySelectorAll(".wg-route-card").length).toBe(4));
    // the conditional hop is drawn as weak evidence, never as proof
    expect(container.querySelector(".wg-hop.wg-hop-conditional.wg-tier-weak")).not.toBeNull();
    expect(container.querySelector(".wg-hop.wg-hop-inferred.wg-tier-weak")).not.toBeNull();
    // verdicts incl. proved_config and an unknown string
    const bounds = screen.getByRole("region", { name: /Is the door shut/ });
    expect(within(bounds).getAllByText("Shut on paper").length).toBeGreaterThan(0);
    expect(within(bounds).getAllByText("needs human").length).toBeGreaterThan(0);
    // fix set: does not cut everything, names the uncut route
    expect(screen.getByText(/No: 1 route stays open/)).toBeInTheDocument();
    // certificates: assumptions shown, expired one flagged
    expect(screen.getAllByText("No links outside the modelled topology.").length).toBe(2);
    expect(screen.getAllByText("Expired").length).toBeGreaterThan(0);

    // filter by jewel
    fireEvent.change(screen.getByLabelText("Crown jewel"), { target: { value: "phi_store" } });
    expect(container.querySelectorAll(".wg-route-card").length).toBe(1);
  });

  it("posts a plan to the change gate and reads the verdict out", async () => {
    const s = buildWargameSample();
    const calls: { url: string; body: unknown }[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.includes("/change-impact")) {
        calls.push({ url, body: JSON.parse(String(init?.body)) });
        return json({
          ...baseImpact,
          verdict: "opens_and_breaks",
          routes_opened: [{ entry: "vendor_vpn", jewel: "payments_db" }],
          newly_denied_flows: [{ src_ip: "10.9.0.50", dst_ip: "10.5.0.12", proto: "tcp", dst_port: 8080 }],
          summary: "server summary",
        });
      }
      if (url.endsWith("/v1/wargame/twin")) return json(s.twin);
      if (url.includes("/v1/wargame/assessments") && !url.includes("/assessments/"))
        return json({ items: [], total: 0, limit: 20, offset: 0 });
      return json([]);
    });
    renderPage();
    const box = await screen.findByLabelText("Terraform plan (JSON)");
    fireEvent.change(box, { target: { value: "not json" } });
    fireEvent.click(screen.getByRole("button", { name: "Check this change" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("isn't valid JSON");
    expect(calls.length).toBe(0);

    fireEvent.change(box, { target: { value: '{"resource_changes": []}' } });
    fireEvent.click(screen.getByRole("button", { name: "Check this change" }));
    expect(await screen.findByText("This change opens a route to payments_db and breaks 1 live flow")).toBeInTheDocument();
    expect(calls[0].body).toEqual({ plan: { resource_changes: [] } });
    expect(screen.getByText(/No flow log was supplied/)).toBeInTheDocument();
  });

  it("labels sample mode and keeps it off the API", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockImplementation(async () => json({}));
    renderPage("/wargame?sample=1");
    expect(await screen.findByText("Sample data")).toBeInTheDocument();
    expect(screen.getByText(buildWargameSample().assessments[0].board_line)).toBeInTheDocument();
    expect(f.mock.calls.filter((c) => String(c[0]).includes("/v1/wargame")).length).toBe(0);
  });
});
