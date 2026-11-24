import { describe, expect, it } from "vitest";
import { explainError, friendlyCheck, friendlyDetail, friendlyStep, friendlyWarning, humanMb, tidyFix } from "../src/humanize";

describe("numbers", () => {
  it("shows people gigabytes, not megabytes", () => {
    expect(humanMb(16384)).toBe("16 GB");
    expect(humanMb(212004)).toBe("207 GB");
    expect(humanMb(3000)).toBe("2.9 GB");
    expect(humanMb(2048)).toBe("2 GB");
    expect(humanMb(512)).toBe("512 MB");
    expect(friendlyDetail("212004 MB free on the system drive")).toBe("207 GB free on the system drive");
    expect(friendlyDetail("no numbers here")).toBe("no numbers here");
    expect(friendlyDetail("12 MB")).toBe("12 MB");                  // short numbers are not touched
  });
});

describe("checks", () => {
  const c = (name: string, status: "ok" | "warn" | "fail", detail: string) => ({ name, status, detail, fix: "" });
  it("drops version noise and renames the engine", () => {
    expect(friendlyCheck(c("Docker engine", "ok", "running (docker 26.1.0), Compose v2, Linux containers"))).toEqual({ name: "Docker Desktop", detail: "Running" });
    expect(friendlyCheck(c("Windows version", "ok", "Windows 11 Home (build 22631)"))).toEqual({ name: "Windows version", detail: "Windows 11 Home" });
    expect(friendlyCheck(c("Memory", "ok", "16384 MB"))).toEqual({ name: "Memory", detail: "16 GB" });
    expect(friendlyCheck(c("Port 3000", "ok", "free"))).toEqual({ name: "Port 3000", detail: "free" });   // read mid-sentence, so not capitalised here
    expect(friendlyCheck(c("Docker engine", "fail", "running in Windows-containers mode (docker 26.1.0); Paddock needs Linux containers")).detail)
      .toBe("running in Windows-containers mode; Paddock needs Linux containers");
  });
});

describe("fix text", () => {
  it("turns the script's numbered fix into steps, removes links that have a button, and says Setup", () => {
    const t = tidyFix("1. Install Docker Desktop (free) from https://www.docker.com/products/docker-desktop/ and choose the WSL 2 option\n2. Restart Windows if it asks\n3. Run this installer again");
    expect(t.steps).toEqual(["Install Docker Desktop (free) and choose the WSL 2 option", "Restart Windows if it asks", "Run Setup again"]);
    expect(t.paragraphs).toEqual([]);
  });
  it("keeps plain paragraphs and unrelated links", () => {
    const t = tidyFix("Paddock needs this port. Close that program.\nTo see what holds it, run: netstat -ano | findstr :3000");
    expect(t.steps).toEqual([]);
    expect(t.paragraphs).toHaveLength(2);
    expect(tidyFix("Update: https://example.com/x").paragraphs[0]).toContain("https://example.com/x");
    expect(tidyFix("")).toEqual({ steps: [], paragraphs: [] });
  });
});

describe("progress wording", () => {
  it("has a sentence for every phase and never leaks the raw script line", () => {
    for (const id of ["checks", "files", "secrets", "images", "start", "health"]) {
      const s = friendlyStep(id);
      expect(s).toMatch(/^[A-Z]/);
      expect(s).not.toMatch(/\(release|up to \d+s/);
    }
    expect(friendlyStep("images")).toContain("1.5 GB");
    expect(friendlyStep("remove", "stop")).toBe("Stopping Paddock");
    expect(friendlyStep("remove", "remove")).toBe("Removing Paddock");
    expect(friendlyStep(null)).toBe("Getting ready");
  });
  it("softens the health warning", () => {
    expect(friendlyWarning("not healthy after 600s. Inspect with: docker compose -p x logs")).toBe("Paddock is taking longer than usual to start.");
    expect(friendlyWarning("something odd")).toBe("Something odd");
  });
});

describe("errors", () => {
  it("explains the known failures in one sentence each, without tool output", () => {
    const cases: [string, RegExp][] = [
      ["docker compose pull failed: could not reach ghcr.io", /could not download Paddock/],
      ["could not download the Paddock images for release 1.2.3 from ghcr.io/x", /could not download Paddock/],
      ["this PC is not ready yet (see the [FAIL] lines above)", /needs a few things fixed/],
      ["docker compose up failed (see the output above)", /could not start/],
      ["Docker is not installed.", /Docker Desktop is not installed/],
      ["cannot talk to the Docker engine.", /not running/],
      ["a Paddock database volume exists but C:\\x\\.env is missing", /earlier install/],
      ["refusing to delete 'C:\\Users\\Ada'", /cannot be removed safely/],
      ["PowerShell could not be started: not found", /PowerShell/],
      ["The installer stopped unexpectedly (code 3).", /stopped unexpectedly/],
    ];
    for (const [raw, re] of cases) {
      const e = explainError(raw);
      expect(e.headline, raw).toMatch(re);
      expect(e.headline + e.hint, raw).not.toMatch(/docker compose|ghcr\.io|\[FAIL\]|C:\\/);
    }
  });
  it("an unknown error still shows its reason, tidied", () => {
    expect(explainError("paddock-install: disk full")).toEqual({ headline: "Setup could not finish.", hint: "Disk full" });
  });
});
