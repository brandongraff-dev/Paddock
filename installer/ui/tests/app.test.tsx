import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import App, { detailsText } from "../src/App";
import { DOCKER_URL } from "../src/bridge";
import { initialRun, reduce } from "../src/protocol";
import { CANCELLED } from "../src/useRun";
import { check, makeBridge, RESULT, step } from "./helpers";

let writeText: ReturnType<typeof vi.fn>;
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const setup = async (state = {}) => {
  const h = makeBridge(state);
  const user = userEvent.setup();               // installs its own navigator.clipboard, so spy AFTER it
  writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined) as unknown as ReturnType<typeof vi.fn>;
  await act(async () => { render(<App bridge={h.bridge} />); });     // lets the initial state load settle
  return { ...h, user };
};

/** Walk a fresh install up to the install run starting. */
async function toInstall(h: Awaited<ReturnType<typeof setup>>, opts: { active?: boolean } = {}) {
  await h.user.click(await screen.findByRole("button", { name: "Get started" }));
  await waitFor(() => expect(h.runs).toHaveLength(1));
  act(() => { h.last().emit(check("Docker engine", "ok", "running")); h.last().emit({ type: "summary", fail: 0, warn: 0 }); h.last().finish(0); });
  await h.user.click(await screen.findByRole("button", { name: "Continue" }));
  if (opts.active) await h.user.click(screen.getByRole("checkbox"));
  await h.user.click(screen.getByRole("button", { name: "Install" }));
  await waitFor(() => expect(h.runs).toHaveLength(2));
}

describe("welcome and PC check", () => {
  it("starts with what will happen, then checks the PC with the chosen folder", async () => {
    const h = await setup();
    expect(await screen.findByRole("heading", { name: "Install Paddock" })).toBeInTheDocument();
    expect(screen.getByText(/do not need any accounts or keys/)).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Setup steps" })).toBeInTheDocument();
    await h.user.click(screen.getByRole("button", { name: "Get started" }));
    await waitFor(() => expect(h.runs).toHaveLength(1));
    expect(h.last().action).toBe("doctor");
    expect(h.last().opts.dir).toBe("C:\\Users\\Ada\\paddock");
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();            // still checking
  });

  it("a failed check explains the fix, offers the download, and blocks Continue until it passes", async () => {
    const h = await setup();
    await h.user.click(await screen.findByRole("button", { name: "Get started" }));
    await waitFor(() => expect(h.runs).toHaveLength(1));
    act(() => {
      h.last().emit(check("Memory", "ok", "16000 MB"));
      h.last().emit(check("Docker Desktop", "fail", "is not installed", "1. Install Docker Desktop (free)\n2. Restart Windows"));
      h.last().emit({ type: "summary", fail: 1, warn: 0 });
      h.last().finish(1);
    });
    expect(await screen.findByText("1. Install Docker Desktop (free)")).toBeInTheDocument();
    expect(screen.getByText("2. Restart Windows")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Needs fixing" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
    await h.user.click(screen.getByRole("button", { name: "Get Docker Desktop" }));
    expect(h.bridge.openUrl).toHaveBeenCalledWith(DOCKER_URL);

    await h.user.click(screen.getByRole("button", { name: "Check again" }));
    await waitFor(() => expect(h.runs).toHaveLength(2));
    act(() => { h.last().emit(check("Docker Desktop", "ok", "running")); h.last().finish(0); });
    await waitFor(() => expect(screen.getByRole("button", { name: "Continue" })).toBeEnabled());
  });

  it("warnings do not block", async () => {
    const h = await setup();
    await h.user.click(await screen.findByRole("button", { name: "Get started" }));
    await waitFor(() => expect(h.runs).toHaveLength(1));
    act(() => { h.last().emit(check("Memory", "warn", "3000 MB", "Close other programs")); h.last().finish(0); });
    expect(await screen.findByText("Close other programs")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Continue" })).toBeEnabled();
  });

  it("a doctor run that cannot even start says why", async () => {
    const h = await setup();
    await h.user.click(await screen.findByRole("button", { name: "Get started" }));
    await waitFor(() => expect(h.runs).toHaveLength(1));
    act(() => h.last().fail("PowerShell was not found on this PC"));
    expect(await screen.findByRole("alert")).toHaveTextContent("PowerShell was not found");
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
  });
});

describe("options and install", () => {
  it("installs into the chosen folder, with the active scanner only if asked", async () => {
    const h = await setup();
    await h.user.click(await screen.findByRole("button", { name: "Get started" }));
    await waitFor(() => expect(h.runs).toHaveLength(1));
    act(() => { h.last().emit(check("Docker engine", "ok")); h.last().finish(0); });
    await h.user.click(await screen.findByRole("button", { name: "Continue" }));
    const dir = screen.getByLabelText("Install folder");
    expect(dir).toHaveValue("C:\\Users\\Ada\\paddock");
    await h.user.clear(dir);
    expect(screen.getByRole("button", { name: "Install" })).toBeDisabled();
    await h.user.type(dir, "D:\\Apps\\Paddock");
    await h.user.click(screen.getByRole("checkbox"));
    await h.user.click(screen.getByRole("button", { name: "Install" }));
    await waitFor(() => expect(h.runs).toHaveLength(2));
    expect(h.last().action).toBe("install");
    expect(h.last().opts).toEqual({ dir: "D:\\Apps\\Paddock", active: true });
  });

  it("shows live progress, the current phase and the details log", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => { h.last().emit(step("checks", "checking prerequisites")); h.last().emit(step("files", "installing into C:\\p")); });
    const bar = await screen.findByRole("progressbar", { name: "Install progress" });
    const first = Number(bar.getAttribute("aria-valuenow"));
    act(() => { h.last().emit(step("images", "downloading the Paddock images")); h.last().emit("postgres Pulling"); });
    await waitFor(() => expect(Number(screen.getByRole("progressbar").getAttribute("aria-valuenow"))).toBeGreaterThan(first));
    expect(screen.getByText("downloading the Paddock images")).toBeInTheDocument();
    expect(screen.getByText(/longest part/)).toBeInTheDocument();
    expect(screen.getByText("Preparing files").closest("li")).toHaveAttribute("data-state", "done");
    expect(screen.getByText("Downloading Paddock").closest("li")).toHaveAttribute("data-state", "active");
    await userEvent.click(screen.getByText("Show details"));
    expect(screen.getByLabelText("Installer output")).toHaveTextContent("postgres Pulling");
  });

  it("finishes on a Done screen with the login, the password hidden until shown, and copy buttons", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => { h.last().emit(step("health", "waiting")); h.last().emit(RESULT); h.last().finish(0); });
    expect(await screen.findByRole("heading", { name: "Paddock is running" })).toBeInTheDocument();
    expect(screen.getByTestId("value-User")).toHaveTextContent("admin");
    expect(screen.getByTestId("value-Password")).not.toHaveTextContent(RESULT.password);
    await h.user.click(screen.getByRole("button", { name: "Show" }));
    expect(screen.getByTestId("value-Password")).toHaveTextContent(RESULT.password);
    await h.user.click(screen.getByRole("button", { name: "Copy Password" }));
    expect(writeText).toHaveBeenCalledWith(RESULT.password);
    expect(await screen.findByRole("button", { name: "Password copied" })).toHaveTextContent("Copied");
    await h.user.click(screen.getByRole("button", { name: "Open Paddock" }));
    expect(h.bridge.openUrl).toHaveBeenCalledWith("http://localhost:3000");
    await h.user.click(screen.getByRole("button", { name: "Close" }));
    expect(h.bridge.quit).toHaveBeenCalled();
  });

  it("an install that started but is not answering yet says so and offers another check", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => { h.last().emit({ ...RESULT, healthy: false }); h.last().emit({ type: "warn", text: "not healthy after 600s" }); h.last().finish(1); });
    // the script exits non-zero when unhealthy but did report a result: still show the login
    expect(await screen.findByRole("heading", { name: "Paddock is starting" })).toBeInTheDocument();
  });

  it("a failed install lists what to fix, can be retried, and copies details without the login", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => {
      h.last().emit(step("checks", "checking prerequisites"));
      h.last().emit(check("Port 3000", "fail", "already in use by node", "Close that program"));
      h.last().emit({ type: "error", text: "this PC is not ready yet" });
      h.last().finish(1);
    });
    expect(await screen.findByRole("heading", { name: "Paddock could not be installed" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("this PC is not ready yet");
    expect(screen.getByText("Close that program")).toBeInTheDocument();
    await h.user.click(screen.getByRole("button", { name: "Copy details" }));
    const copied = String(writeText.mock.calls[0][0]);
    expect(copied).toContain("Port 3000");
    expect(copied).not.toContain(RESULT.password);
    await h.user.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(h.runs).toHaveLength(3));
    expect(h.last().action).toBe("install");
  });

  it("a bad folder sends you back to the options with the reason, not to an install failure", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => h.last().fail("Choose a folder, not a whole drive."));
    expect(await screen.findByRole("heading", { name: "Where should it go?" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("not a whole drive");
    expect(screen.getByLabelText("Install folder")).toBeInTheDocument();
  });

  it("Cancel stops the run and says it can be resumed", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => h.last().emit(step("images", "downloading")));
    await h.user.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(h.last().cancelled).toBe(true);
    expect(await screen.findByRole("heading", { name: "Setup stopped" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(CANCELLED);
  });

  it("an install that ends cleanly without a result is not reported as success", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => { h.last().emit(step("images", "x")); h.last().finish(0); });
    expect(await screen.findByRole("alert")).toHaveTextContent("without confirming that Paddock started");
  });
});

describe("an existing install", () => {
  it("offers to open it when it is running, update it, stop it or remove it", async () => {
    const h = await setup({ installed: true, running: true, version: "1.2.3" });
    expect(await screen.findByRole("heading", { name: "Paddock is installed" })).toBeInTheDocument();
    expect(screen.getByText(/Version 1.2.3/)).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Setup steps" })).toBeNull();
    await h.user.click(screen.getByRole("button", { name: "Open Paddock" }));
    expect(h.bridge.openUrl).toHaveBeenCalledWith("http://localhost:3000");
  });

  it("offers Start when it is stopped, and starts it with the existing folder", async () => {
    const h = await setup({ installed: true, running: false, dir: "E:\\P" });
    await h.user.click(await screen.findByRole("button", { name: "Start Paddock" }));
    await waitFor(() => expect(h.runs).toHaveLength(1));
    expect(h.last()).toMatchObject({ action: "install", opts: { dir: "E:\\P", active: false } });
  });

  it("stop keeps data, then returns to the manage screen with fresh state", async () => {
    const h = await setup({ installed: true, running: true });
    await h.user.click(await screen.findByRole("button", { name: "Stop" }));
    await waitFor(() => expect(h.runs).toHaveLength(1));
    expect(h.last().action).toBe("stop");
    h.setState({ running: false });
    act(() => { h.last().emit({ type: "done", action: "stop" }); h.last().finish(0); });
    expect(await screen.findByRole("heading", { name: "Paddock is stopped" })).toBeInTheDocument();
    await h.user.click(screen.getByRole("button", { name: "Done" }));
    expect(await screen.findByRole("button", { name: "Start Paddock" })).toBeInTheDocument();
  });

  it("remove needs an explicit confirmation and can be backed out of", async () => {
    const h = await setup({ installed: true, running: true });
    await h.user.click(await screen.findByRole("button", { name: "Remove…" }));
    const dialog = screen.getByRole("alertdialog");
    expect(within(dialog).getByText(/cannot be undone/)).toBeInTheDocument();
    expect(h.runs).toHaveLength(0);                                              // nothing ran yet
    await h.user.click(within(dialog).getByRole("button", { name: "Keep it" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    await h.user.click(screen.getByRole("button", { name: "Remove…" }));
    await h.user.click(screen.getByRole("button", { name: "Delete everything" }));
    await waitFor(() => expect(h.runs).toHaveLength(1));
    expect(h.last().action).toBe("remove");
    h.setState({ installed: false, running: false });
    act(() => { h.last().emit({ type: "done", action: "remove" }); h.last().finish(0); });
    expect(await screen.findByRole("heading", { name: "Paddock was removed" })).toBeInTheDocument();
    await h.user.click(screen.getByRole("button", { name: "Done" }));
    expect(await screen.findByRole("heading", { name: "Install Paddock" })).toBeInTheDocument();
  });

  it("a failed stop says so and can be retried", async () => {
    const h = await setup({ installed: true, running: true });
    await h.user.click(await screen.findByRole("button", { name: "Stop" }));
    await waitFor(() => expect(h.runs).toHaveLength(1));
    act(() => { h.last().emit({ type: "error", text: "docker not found" }); h.last().finish(1); });
    expect(await screen.findByRole("heading", { name: "Stopping did not finish" })).toBeInTheDocument();
    await h.user.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(h.runs).toHaveLength(2));
  });
});

describe("when Setup itself is broken", () => {
  it("reports a state it cannot read", async () => {
    const h = makeBridge();
    (h.bridge.getState as any).mockRejectedValueOnce(new Error("backend unavailable"));
    await act(async () => { render(<App bridge={h.bridge} />); });
    expect(await screen.findByRole("alert")).toHaveTextContent("backend unavailable");
  });

  it("refuses to run with missing installer files and says how to fix it", async () => {
    await setup({ resourcesReady: false });
    expect(await screen.findByRole("heading", { name: "This copy of Setup is incomplete" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Get started" })).toBeNull();
  });
});

describe("detailsText", () => {
  it("includes the error, the checks and the log, and never a result's password", () => {
    let s = initialRun();
    s = reduce(s, { type: "check", name: "Memory", status: "warn", detail: "3000 MB", fix: "" });
    s = reduce(s, { type: "log", text: "pulling" });
    s = reduce(s, { type: "error", text: "boom" });
    s = reduce(s, { type: "result", healthy: true, url: "u", username: "admin", password: "TOPSECRET", dir: "", version: "" });
    const t = detailsText(s);
    expect(t).toContain("error: boom");
    expect(t).toContain("[warn] Memory: 3000 MB");
    expect(t).toContain("pulling");
    expect(t).not.toContain("TOPSECRET");
    expect(detailsText(null)).toBe("");
  });
});
