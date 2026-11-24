import { describe, expect, it } from "vitest";
import { hasBlocker, initialRun, LOG_LIMIT, parseLine, percent, phaseState, reduce, type InstallerEvent, type RunInput } from "../src/protocol";

const run = (...evs: RunInput[]) => evs.reduce(reduce, initialRun());
const ev = (o: unknown) => parseLine(JSON.stringify(o)) as InstallerEvent;

describe("parseLine", () => {
  it("reads every event shape the installer script emits", () => {
    expect(ev({ type: "step", id: "images", text: "downloading" })).toEqual({ type: "step", id: "images", text: "downloading" });
    expect(ev({ type: "check", name: "Memory", status: "warn", detail: "3000 MB", fix: "Close programs" }))
      .toEqual({ type: "check", name: "Memory", status: "warn", detail: "3000 MB", fix: "Close programs" });
    expect(ev({ type: "summary", fail: 1, warn: 2 })).toEqual({ type: "summary", fail: 1, warn: 2 });
    expect(ev({ type: "warn", text: "w" })).toEqual({ type: "warn", text: "w" });
    expect(ev({ type: "error", text: "e" })).toEqual({ type: "error", text: "e" });
    expect(ev({ type: "done", action: "remove" })).toEqual({ type: "done", action: "remove" });
    expect(ev({ type: "result", healthy: true, url: "http://localhost:3000", username: "admin", password: "pw", dir: "C:\\p", version: "1.2.3" }))
      .toEqual({ type: "result", healthy: true, url: "http://localhost:3000", username: "admin", password: "pw", dir: "C:\\p", version: "1.2.3" });
  });

  it("tolerates a BOM, blank lines and CRLF", () => {
    expect(parseLine("")).toBeNull();
    expect(parseLine("  \r\n")).toBeNull();
    expect(parseLine('\uFEFF{"type":"log","text":"x"}\r\n')).toEqual({ type: "log", text: "x" });
  });

  it("keeps anything it does not understand as a log line instead of dropping or crashing", () => {
    expect(parseLine("PowerShell 5.1 says hi")).toEqual({ type: "log", text: "PowerShell 5.1 says hi" });
    expect(parseLine("{broken")).toEqual({ type: "log", text: "{broken" });
    expect(parseLine("42")).toEqual({ type: "log", text: "42" });
    expect(parseLine("null")).toEqual({ type: "log", text: "null" });
    expect(parseLine('{"type":"check","name":"x","status":"great"}')?.type).toBe("log");   // bad status
    expect(parseLine('{"type":"result","url":5}')?.type).toBe("log");
    expect(parseLine('{"type":"done","action":"explode"}')?.type).toBe("log");
    expect(parseLine('{"type":"mystery"}')?.type).toBe("log");
  });

  it("defaults the optional fields", () => {
    expect(ev({ type: "step", text: "t" })).toEqual({ type: "step", id: "", text: "t" });
    expect(ev({ type: "check", name: "n", status: "ok" })).toMatchObject({ detail: "", fix: "" });
    expect(ev({ type: "result", url: "u", password: "p" })).toMatchObject({ healthy: false, username: "admin" });
  });
});

describe("reduce", () => {
  it("collects checks and the summary; blockers are the fail rows", () => {
    const s = run(
      ev({ type: "check", name: "Docker", status: "ok", detail: "running", fix: "" }),
      ev({ type: "check", name: "Port 3000", status: "fail", detail: "in use", fix: "close it" }),
      ev({ type: "summary", fail: 1, warn: 0 }),
      { type: "exit", code: 1 },
    );
    expect(s.checks).toHaveLength(2);
    expect(hasBlocker(s.checks)).toBe(true);
    expect(s.summary).toEqual({ fail: 1, warn: 0 });
    expect(s.status).toBe("failed");
    expect(s.error).toBe("Port 3000: in use");        // a doctor run that found a blocker explains itself
  });

  it("an install that ends cleanly with a result succeeds", () => {
    const s = run(
      ev({ type: "step", id: "checks", text: "a" }), ev({ type: "step", id: "images", text: "b" }),
      ev({ type: "result", healthy: true, url: "u", password: "p" }), { type: "exit", code: 0 },
    );
    expect(s.status).toBe("succeeded");
    expect(s.result?.password).toBe("p");
    expect(percent(s)).toBe(100);
  });

  it("installed but not answering yet: the script reports the login, then exits 1 on purpose", () => {
    const s = run(ev({ type: "result", healthy: false, url: "u", password: "p" }), ev({ type: "warn", text: "not healthy" }), { type: "exit", code: 1 });
    expect(s.status).toBe("succeeded");
    expect(s.result?.healthy).toBe(false);
    // ... but a real error is still a failure even when a result was seen
    expect(run(ev({ type: "result", healthy: true, url: "u", password: "p" }), ev({ type: "error", text: "x" }), { type: "exit", code: 1 }).status).toBe("failed");
  });

  it("an error event wins over a zero exit code, and the message is kept", () => {
    const s = run(ev({ type: "error", text: "docker compose up failed" }), { type: "exit", code: 0 });
    expect(s.status).toBe("failed");
    expect(s.error).toBe("docker compose up failed");
  });

  it("a silent crash still explains itself", () => {
    expect(run({ type: "exit", code: 3 }).error).toMatch(/stopped unexpectedly \(code 3\)/);
    expect(run({ type: "crash", message: "PowerShell was not found" }).error).toBe("PowerShell was not found");
  });

  it("stop and remove finish with their done event", () => {
    expect(run(ev({ type: "done", action: "stop" }), { type: "exit", code: 0 })).toMatchObject({ status: "succeeded", done: "stop" });
  });

  it("warnings are listed and also logged", () => {
    const s = run(ev({ type: "warn", text: "slow" }));
    expect(s.warnings).toEqual(["slow"]);
    expect(s.log).toEqual(["warning: slow"]);
  });

  it("the log is bounded so a chatty pull cannot grow without limit", () => {
    let s = initialRun();
    for (let i = 0; i < LOG_LIMIT + 50; i++) s = reduce(s, { type: "log", text: `l${i}` });
    expect(s.log).toHaveLength(LOG_LIMIT);
    expect(s.log[s.log.length - 1]).toBe(`l${LOG_LIMIT + 49}`);
    expect(s.log[0]).toBe("l50");
  });

  it("is pure: the previous state is never mutated", () => {
    const a = initialRun();
    const b = reduce(a, { type: "log", text: "x" });
    expect(a.log).toEqual([]);
    expect(b).not.toBe(a);
  });
});

describe("progress", () => {
  it("only moves forward through the phases and never reaches 100 before success", () => {
    const steps = ["checks", "files", "secrets", "images", "start", "health"];
    let s = initialRun();
    let last = 0;
    for (const id of steps) {
      s = reduce(s, { type: "step", id, text: id });
      const p = percent(s);
      expect(p).toBeGreaterThanOrEqual(last);
      expect(p).toBeLessThan(100);
      last = p;
    }
    expect(phaseState(s, "checks")).toBe("done");
    expect(phaseState(s, "health")).toBe("active");
    expect(phaseState(initialRun(), "files")).toBe("pending");
    expect(percent(initialRun())).toBe(0);
  });

  it("downloading is the biggest slice, as it is in real life", () => {
    const order = ["checks", "files", "secrets", "images", "start", "health"];
    const at = (id: string) => percent(run(...order.slice(0, order.indexOf(id) + 1).map((i) => ({ type: "step" as const, id: i, text: "" }))));
    expect(at("images") - at("secrets")).toBeGreaterThan(10);
    expect(at("start") - at("images")).toBeGreaterThan(20);
  });
});
