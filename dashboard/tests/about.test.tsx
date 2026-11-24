/**
 * Settings → About: the version, the state of each area, and the changelog.
 * The content under test is the real generated CHANGELOG, so these tests also
 * guard that the page says what the file says.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import React from "react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import AboutPage from "../src/pages/About";
import { CHANGELOG } from "../src/pages/about/changelog.generated";

function renderPage(version: string | null) {
  vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
    version
      ? new Response(JSON.stringify({ version, edition: "community" }), { status: 200, headers: { "content-type": "application/json" } })
      : new Response("{}", { status: 500 }),
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(React.createElement(MemoryRouter, null, React.createElement(QueryClientProvider, { client: qc }, React.createElement(AboutPage))));
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("About page", () => {
  it("shows the installed version from the server", async () => {
    renderPage("0.1.0");
    await waitFor(() => expect(screen.getByText("0.1.0")).toBeTruthy());
    expect(screen.getByRole("heading", { name: "About" })).toBeTruthy();
  });

  it("says so when the version cannot be read, instead of showing a blank", async () => {
    renderPage(null);
    expect(await screen.findByText("Unknown")).toBeTruthy();
    expect(screen.getByText(/Could not read it from the server/)).toBeTruthy();
  });

  it("lists every area with a text label for its state (never colour alone) and its notes", () => {
    renderPage("0.1.0");
    const table = screen.getByRole("table");
    for (const row of CHANGELOG.state) {
      const tr = within(table).getByText(row.area).closest("tr") as HTMLElement;
      expect(tr.getAttribute("data-state")).toBe(row.state);
      expect(within(tr).getByText(row.notes)).toBeTruthy();
      expect(tr.textContent).toMatch(/Working|Beta|Not yet verified|Not released/);
    }
  });

  it("is honest about what is not proven: the Windows installer and the missing release are not shown as working", () => {
    renderPage("0.1.0");
    const row = (name: RegExp) => screen.getByText(name).closest("tr") as HTMLElement;
    expect(row(/Install on Windows/).getAttribute("data-state")).toBe("unverified");
    expect(row(/Prebuilt images and release downloads/).getAttribute("data-state")).toBe("not released");
  });

  it("summarises the counts and explains each state", () => {
    renderPage("0.1.0");
    const total = CHANGELOG.state.length;
    const summed = Array.from(document.querySelectorAll(".about-summary strong")).reduce((n, e) => n + Number(e.textContent), 0);
    expect(summed).toBe(total);
    const legend = document.querySelector(".about-legend") as HTMLElement;
    expect(within(legend).getByText(/Tested in CI, never run on the real/)).toBeTruthy();
  });

  it("shows no release as shipped until there is one, and counts what is waiting", () => {
    renderPage("0.1.0");
    const shipped = CHANGELOG.releases.find((r) => r.version !== "Unreleased");
    expect(screen.getByText(shipped ? shipped.version : "None yet")).toBeTruthy();
    const waiting = CHANGELOG.releases.find((r) => r.version === "Unreleased")!.sections.reduce((n, s) => n + s.items.length, 0);
    expect(screen.getByText(String(waiting))).toBeTruthy();
  });

  it("renders each release's sections as lists, with security and known issues labelled", () => {
    renderPage("0.1.0");
    const unreleased = document.querySelector('[data-version="Unreleased"]') as HTMLElement;
    expect(unreleased).toBeTruthy();
    for (const kind of ["Added", "Security", "Known issues"]) {
      const sec = unreleased.querySelector(`[data-kind="${kind}"]`) as HTMLElement;
      expect(sec, kind).toBeTruthy();
      expect(sec.querySelectorAll("li").length).toBeGreaterThan(0);
    }
    expect(screen.getByText("Earlier work (before this changelog)")).toBeTruthy();
  });

  it("links to the System page, and never shows raw markdown", () => {
    renderPage("0.1.0");
    expect(screen.getByRole("link", { name: /System health/ }).getAttribute("href")).toBe("/settings/system");
    expect(document.body.textContent).not.toMatch(/\*\*|`|\]\(http/);
  });
});
