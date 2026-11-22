import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// A signed-out deep link to an app page should land on the sign-in screen, not a
// 404. App.tsx decides that with APP_SEGMENTS, so every authenticated route's
// first path segment must be listed there.
describe("APP_SEGMENTS", () => {
  const src = readFileSync(resolve(__dirname, "../src/App.tsx"), "utf8");
  const listed = new Set(
    [...(src.match(/const APP_SEGMENTS = new Set\(\[([^\]]*)\]\)/)?.[1] ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1]),
  );
  // public, signed-out pages that are routed directly
  const PUBLIC = new Set(["", "welcome", "login", "check", "trust"]);

  it("covers every app route", () => {
    const segs = new Set(
      [...src.matchAll(/path="\/([a-z-]*)/g)].map((m) => m[1]).filter((s) => !PUBLIC.has(s)),
    );
    const missing = [...segs].filter((s) => !listed.has(s));
    expect(missing).toEqual([]);
  });
});
