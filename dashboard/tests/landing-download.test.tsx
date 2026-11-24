/**
 * Landing: the "Download for Windows" button (call-to-action strip and footer)
 * and the nav "Download" link. Until the first release they point at the
 * releases page; the URL lives in one constant.
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import React from "react";
import { MemoryRouter } from "react-router-dom";
import Landing from "../src/pages/Landing";
import { DOWNLOAD_NOTE, DOWNLOAD_URL } from "../src/pages/landing/download";
import { useAuth } from "../src/state/auth";

afterEach(() => {
  cleanup();
  useAuth.setState({ token: null, user: null });
});

describe("landing download button", () => {
  it("is a link to the download in both call-to-action boxes, opening safely in a new tab", () => {
    render(React.createElement(MemoryRouter, null, React.createElement(Landing)));
    const buttons = screen.getAllByRole("link", { name: /Download for Windows/ });
    expect(buttons.length).toBe(2);                                    // the strip and the footer share CtaBox
    for (const a of buttons) {
      expect(a).toHaveAttribute("href", DOWNLOAD_URL);
      expect(a).toHaveAttribute("target", "_blank");
      expect(a.getAttribute("rel")).toContain("noreferrer");
    }
  });

  it("has a Download link in the nav and an honest note about SmartScreen and Docker Desktop", () => {
    render(React.createElement(MemoryRouter, null, React.createElement(Landing)));
    const nav = screen.getAllByRole("link", { name: "Download" });
    expect(nav.length).toBeGreaterThan(0);
    expect(nav[0]).toHaveAttribute("href", DOWNLOAD_URL);
    expect(DOWNLOAD_NOTE).toMatch(/Docker Desktop/);
    expect(DOWNLOAD_NOTE).toMatch(/Run anyway/);
    expect(screen.getAllByText(DOWNLOAD_NOTE).length).toBe(2);
  });

  it("does not disturb the existing calls to action", () => {
    render(React.createElement(MemoryRouter, null, React.createElement(Landing)));
    expect(screen.getAllByText("Start mapping").length).toBe(2);
    expect(screen.getAllByText(/Paste into your agent to set up/).length).toBe(2);
    expect(screen.getAllByRole("link", { name: "Read the docs" }).length).toBe(2);
  });
});

describe("the download URL", () => {
  it("points at this repository's releases", () => {
    expect(DOWNLOAD_URL).toMatch(/^https:\/\/github\.com\/brandongraff-dev\/paddock\/releases\//);
  });
});
