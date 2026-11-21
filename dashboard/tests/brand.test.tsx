/**
 * Brand + chart kit: the landing page renders signed-out, the Muybridge frames
 * decode to the declared grid, and the visx charts render with their
 * screen-reader tables.
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import React from "react";
import { MemoryRouter } from "react-router-dom";
import Landing from "../src/pages/Landing";
import HorseMark from "../src/brand/HorseMark";
import { HORSE_COLS, HORSE_FRAMES, HORSE_ROWS, decodeFrame } from "../src/brand/horseFrames";
import RankBars from "../src/components/charts/RankBars";
import SeverityStream from "../src/components/charts/SeverityStream";
import PixelMatrix from "../src/components/charts/PixelMatrix";
import { useAuth } from "../src/state/auth";

afterEach(() => {
  cleanup();
  useAuth.setState({ token: null, user: null });
});

describe("brand", () => {
  it("decodes every gallop plate to a non-empty grid of the declared size", () => {
    expect(HORSE_FRAMES).toHaveLength(11);
    for (const f of HORSE_FRAMES) {
      const cells = decodeFrame(f);
      expect(cells).toHaveLength(HORSE_COLS * HORSE_ROWS);
      const lit = cells.reduce((s, v) => s + v, 0);
      expect(lit).toBeGreaterThan(cells.length * 0.1);
      expect(lit).toBeLessThan(cells.length * 0.6);
    }
  });

  it("HorseMark is labelled when titled and hidden when decorative", () => {
    const { container } = render(
      React.createElement("div", null,
        React.createElement(HorseMark, { title: "brand" }),
        React.createElement(HorseMark, { title: "" })),
    );
    expect(screen.getByRole("img", { name: "brand" })).toBeInTheDocument();
    expect(container.querySelectorAll('svg[aria-hidden="true"]')).toHaveLength(1);
  });

  it("landing renders signed-out with a sign-in CTA and the four agents", () => {
    render(React.createElement(MemoryRouter, null, React.createElement(Landing)));
    expect(screen.getByRole("link", { name: /sign in/i })).toHaveAttribute("href", "/login");
    for (const a of ["Warden", "Outrider", "Herald", "Farrier"]) {
      expect(screen.getByRole("heading", { name: new RegExp(a) })).toBeInTheDocument();
    }
  });

  it("landing CTA opens the console when signed in", () => {
    useAuth.setState({ token: "t", user: { username: "u", role: "admin", clearance: "restricted" } });
    render(React.createElement(MemoryRouter, null, React.createElement(Landing)));
    expect(screen.getByRole("link", { name: /open console/i })).toHaveAttribute("href", "/");
  });
});

describe("charts", () => {
  it("RankBars renders a row per datum (capped) with an accessible table", () => {
    const data = Array.from({ length: 12 }, (_, i) => ({ label: `k${i}`, value: 12 - i }));
    const { container } = render(React.createElement(RankBars, { data, caption: "Assets by kind", max: 8 }));
    expect(screen.getByRole("img", { name: "Assets by kind" })).toBeInTheDocument();
    expect(container.querySelectorAll("table.sr-only tbody tr")).toHaveLength(8);
  });

  it("SeverityStream renders legend + table for each day", () => {
    const data = ["11-01", "11-02", "11-03"].map((date, i) => ({
      date, info: i, low: 1, medium: 2, high: 0, critical: i,
    }));
    const { container } = render(React.createElement(SeverityStream, { data }));
    // legend entry + sr table header
    expect(screen.getAllByText("Critical")).toHaveLength(2);
    expect(container.querySelectorAll("table.sr-only tbody tr")).toHaveLength(3);
  });

  it("PixelMatrix draws one cell per (row, day)", () => {
    const { container } = render(
      React.createElement(PixelMatrix, {
        rows: [
          { key: "a", label: "A", values: [0, 1, 2, 3] },
          { key: "b", label: "B", values: [4, 0, 0, 1] },
        ],
        columns: ["d1", "d2", "d3", "d4"],
      }),
    );
    expect(container.querySelectorAll("svg rect")).toHaveLength(8);
  });
});
