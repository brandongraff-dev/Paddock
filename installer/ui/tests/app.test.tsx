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
type H = Awaited<ReturnType<typeof setup>>;

const GOOD = [
  check("Windows version", "ok", "Windows 11 Home (build 22631)"),
  check("Memory", "ok", "16384 MB"),
  check("Disk space", "ok", "212004 MB free on the system drive"),
  check("Docker engine", "ok", "running (docker 26.1.0), Compose v2, Linux containers"),
  check("Port 3000", "ok", "free"),
];
const finishCheck = (h: H, checks: unknown[] = GOOD, code = 0) => act(() => { checks.forEach((c) => h.runs[0].emit(c)); h.runs[0].finish(code); });
const installButton = () => screen.getByRole("button", { name: "Install" });

/** Fresh PC, healthy: check passes, Install pressed, the install run is runs[1]. */
async function toInstall(h: H) {
  await waitFor(() => expect(h.runs).toHaveLength(1));
  finishCheck(h);
  await waitFor(() => expect(installButton()).toBeEnabled());
  await h.user.click(installButton());
  await waitFor(() => expect(h.runs).toHaveLength(2));
}

describe("ready: the PC check runs by itself", () => {
  it("starts checking at once, in the default folder, and cannot install until it is done", async () => {
    const h = await setup();
    expect(await screen.findByRole("heading", { name: "Install Paddock" })).toBeInTheDocument();
    await waitFor(() => expect(h.runs).toHaveLength(1));
    expect(h.runs[0]).toMatchObject({ action: "doctor", opts: { dir: "C:\\Users\\Ada\\paddock" } });
    expect(screen.getByText("Checking your PC")).toBeInTheDocument();
    expect(installButton()).toBeDisabled();
    expect(screen.getByText("Step 1 of 3")).toBeInTheDocument();
    expect(screen.queryByRole("navigation")).toBeNull();                     // no step rail any more
  });

  it("when everything passes it says so in one line, and the details are optional and readable", async () => {
    const h = await setup();
    await waitFor(() => expect(h.runs).toHaveLength(1));
    finishCheck(h);
    expect(await screen.findByText("Your PC is ready")).toBeInTheDocument();
    expect(installButton()).toBeEnabled();
    expect(screen.queryByRole("list", { name: "Things to fix" })).toBeNull();
    const table = screen.getByRole("table", { name: "All checks" });
    expect(within(table).getByText("Docker Desktop")).toBeInTheDocument();
    expect(within(table).getByText("Running")).toBeInTheDocument();
    expect(within(table).getByText("16 GB")).toBeInTheDocument();                   // not 16384 MB
    expect(within(table).getByText("207 GB free on the system drive")).toBeInTheDocument();
    expect(within(table).getByText("Windows 11 Home")).toBeInTheDocument();         // no "(build 22631)"
    expect(within(table).getByText("Free")).toBeInTheDocument();                    // capitalised as a table cell
    expect(document.body.textContent).not.toMatch(/MB|docker 26|Compose v2/);
  });

  it("a blocker shows what is wrong and how to fix it, offers the download, and keeps Install disabled", async () => {
    const h = await setup();
    await waitFor(() => expect(h.runs).toHaveLength(1));
    finishCheck(h, [
      check("Memory", "ok", "16384 MB"),
      check("Docker Desktop", "fail", "is not installed", "1. Install Docker Desktop (free) from https://www.docker.com/products/docker-desktop/ and choose the WSL 2 option\n2. Restart Windows if it asks\n3. Run this installer again"),
    ], 1);
    expect(await screen.findByText("One thing needs fixing first")).toBeInTheDocument();
    const fixes = screen.getByRole("list", { name: "Things to fix" });
    expect(within(fixes).getByText("is not installed")).toBeInTheDocument();         // reads as a sentence after the name
    expect(within(fixes).getByText("Install Docker Desktop (free) and choose the WSL 2 option")).toBeInTheDocument();
    expect(within(fixes).getByText("Run Setup again")).toBeInTheDocument();
    expect(fixes).not.toHaveTextContent("https://");
    expect(installButton()).toBeDisabled();
    await h.user.click(screen.getByRole("button", { name: "Get Docker Desktop" }));
    expect(h.bridge.openUrl).toHaveBeenCalledWith(DOCKER_URL);

    await h.user.click(screen.getByRole("button", { name: "Check again" }));
    await waitFor(() => expect(h.runs).toHaveLength(2));
    act(() => { h.runs[1].emit(check("Docker Desktop", "ok", "running")); h.runs[1].finish(0); });
    await waitFor(() => expect(installButton()).toBeEnabled());
    expect(screen.getByText("Your PC is ready")).toBeInTheDocument();
  });

  it("a note does not block, and its fix is shown", async () => {
    const h = await setup();
    await waitFor(() => expect(h.runs).toHaveLength(1));
    finishCheck(h, [check("Memory", "warn", "3000 MB", "Close other programs while Paddock starts.")]);
    expect(await screen.findByText("Ready to install, with a note")).toBeInTheDocument();
    expect(screen.getByText("Close other programs while Paddock starts.")).toBeInTheDocument();
    expect(screen.getAllByText("2.9 GB").length).toBeGreaterThan(0);                  // in the note and in the table
    expect(installButton()).toBeEnabled();
  });

  it("a check that cannot even start is explained in plain words", async () => {
    const h = await setup();
    await waitFor(() => expect(h.runs).toHaveLength(1));
    act(() => h.runs[0].fail("PowerShell could not be started: not found"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Windows PowerShell could not be started.");
    expect(installButton()).toBeDisabled();
  });

  it("installs into the chosen folder, with the active scanner only if asked", async () => {
    const h = await setup();
    await waitFor(() => expect(h.runs).toHaveLength(1));
    finishCheck(h);
    const dir = await screen.findByLabelText("Install location");
    await h.user.clear(dir);
    expect(installButton()).toBeDisabled();
    await h.user.type(dir, "D:\\Apps\\Paddock");
    await h.user.click(screen.getByText("More options"));
    await h.user.click(screen.getByRole("checkbox", { name: /active scanner/ }));
    await h.user.click(installButton());
    await waitFor(() => expect(h.runs).toHaveLength(2));
    expect(h.runs[1]).toMatchObject({ action: "install", opts: { dir: "D:\\Apps\\Paddock", active: true } });
  });

  it("a bad folder comes back to the field with the reason, not as an install failure", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => h.last().fail("Choose a folder, not a whole drive."));
    expect(await screen.findByRole("heading", { name: "Install Paddock" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("not a whole drive");
    expect(screen.getByLabelText("Install location")).toHaveAttribute("aria-invalid", "true");
  });
});

describe("installing", () => {
  it("shows a clean status line and percentage, keeps the raw output behind Details", async () => {
    const h = await setup();
    await toInstall(h);
    expect(screen.getByText("Step 2 of 3")).toBeInTheDocument();
    act(() => { h.last().emit(step("files", "installing into C:\\p")); });
    const bar = await screen.findByRole("progressbar", { name: "Install progress" });
    const first = Number(bar.getAttribute("aria-valuenow"));
    act(() => { h.last().emit(step("images", "downloading the Paddock images (release 1.2.3, about 1-2 minutes)")); h.last().emit("postgres Pulling"); });
    await waitFor(() => expect(Number(screen.getByRole("progressbar").getAttribute("aria-valuenow"))).toBeGreaterThan(first));
    expect(screen.getByText("Downloading Paddock (about 1.5 GB)")).toBeInTheDocument();      // not the raw script line
    expect(screen.getByText(/^\d+%$/)).toBeInTheDocument();
    expect(screen.getByText(/longest part/)).toBeInTheDocument();
    await userEvent.click(screen.getByText("Details"));
    expect(screen.getByLabelText("Installer output")).toHaveTextContent("downloading the Paddock images (release 1.2.3");
    expect(screen.getByLabelText("Installer output")).toHaveTextContent("postgres Pulling");
  });

  it("softens a slow-start warning", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => { h.last().emit(step("health", "waiting")); h.last().emit({ type: "warn", text: "not healthy after 600s. Inspect with: docker compose -p paddock-lite logs" }); });
    const note = await screen.findByRole("status");
    expect(note).toHaveTextContent("Paddock is taking longer than usual to start.");
    expect(note).not.toHaveTextContent(/docker compose/);                             // the raw line is only in Details
  });

  it("Cancel stops the run and says it can be resumed", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => h.last().emit(step("images", "x")));
    await h.user.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(h.last().cancelled).toBe(true);
    expect(await screen.findByRole("heading", { name: "Setup stopped" })).toBeInTheDocument();
    expect(screen.getByText(/picks up where it left off/)).toBeInTheDocument();
    expect(CANCELLED).toMatch(/cancelled/);
  });
});

describe("done", () => {
  it("shows the login with the password hidden until shown, and copy / open / close", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => { h.last().emit(step("health", "waiting")); h.last().emit(RESULT); h.last().finish(0); });
    expect(await screen.findByRole("heading", { name: "Paddock is running" })).toBeInTheDocument();
    expect(screen.getByText("Step 3 of 3")).toBeInTheDocument();
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

  it("an install that is not answering yet still shows the login, and offers another check", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => { h.last().emit({ ...RESULT, healthy: false }); h.last().finish(1); });
    expect(await screen.findByRole("heading", { name: "Paddock is still starting" })).toBeInTheDocument();
    expect(screen.getByTestId("value-Address")).toHaveTextContent("http://localhost:3000");
    await h.user.click(screen.getByRole("button", { name: "Check again" }));
    await waitFor(() => expect(h.runs).toHaveLength(3));
  });
});

describe("failure", () => {
  it("leads with what happened in one sentence, hides tool output, and can be retried or copied", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => {
      h.last().emit(step("images", "downloading"));
      h.last().emit({ type: "error", text: "docker compose pull failed: could not reach ghcr.io. Check your internet." });
      h.last().finish(1);
    });
    expect(await screen.findByRole("heading", { name: "Setup could not download Paddock." })).toBeInTheDocument();
    expect(screen.getByText(/Check your internet connection, and any VPN, proxy or firewall/)).toBeInTheDocument();
    expect(screen.queryByText(/docker compose pull failed/)).toBeVisibleOrAbsent();
    await h.user.click(screen.getByText("Technical details"));
    expect(screen.getByLabelText("Technical details")).toHaveTextContent("docker compose pull failed: could not reach ghcr.io");
    await h.user.click(screen.getByRole("button", { name: "Copy details" }));
    const copied = String(writeText.mock.calls[0][0]);
    expect(copied).toContain("ghcr.io");
    expect(copied).not.toContain(RESULT.password);
    await h.user.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(h.runs).toHaveLength(3));
    expect(h.last().action).toBe("install");
  });

  it("lists the blocking checks when the install stops at the PC check, and Check my PC goes back", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => {
      h.last().emit(check("Port 3000", "fail", "already in use by node", "Close that program."));
      h.last().emit({ type: "error", text: "this PC is not ready yet (see the [FAIL] lines above)" });
      h.last().finish(1);
    });
    expect(await screen.findByRole("heading", { name: "Your PC needs a few things fixed first." })).toBeInTheDocument();
    expect(within(screen.getByRole("list", { name: "Things to fix" })).getByText("Close that program.")).toBeInTheDocument();
    await h.user.click(screen.getByRole("button", { name: "Check my PC" }));
    expect(await screen.findByRole("heading", { name: "Install Paddock" })).toBeInTheDocument();
    await waitFor(() => expect(h.runs).toHaveLength(3));
    expect(h.last().action).toBe("doctor");
  });

  it("an install that ends cleanly without a result is not reported as success", async () => {
    const h = await setup();
    await toInstall(h);
    act(() => { h.last().emit(step("images", "x")); h.last().finish(0); });
    expect(await screen.findByRole("heading", { name: "Setup could not finish." })).toBeInTheDocument();
    expect(screen.getByText("Setup finished without confirming that Paddock started.")).toBeInTheDocument();
  });
});

describe("an existing install", () => {
  it("opens on the manage screen without running a PC check, and offers Open / Update / Stop", async () => {
    const h = await setup({ installed: true, running: true, version: "1.2.3" });
    expect(await screen.findByRole("heading", { name: "Paddock is installed" })).toBeInTheDocument();
    expect(screen.getByText("Version 1.2.3.")).toBeInTheDocument();
    expect(screen.getByText("Running")).toBeInTheDocument();
    expect(h.runs).toHaveLength(0);
    for (const n of ["Stop", "Update or repair", "Open Paddock", "Close"]) expect(screen.getByRole("button", { name: n })).toBeInTheDocument();
    await h.user.click(screen.getByRole("button", { name: "Open Paddock" }));
    expect(h.bridge.openUrl).toHaveBeenCalledWith("http://localhost:3000");
  });

  it("offers Start when it is stopped, and starts it in the existing folder", async () => {
    const h = await setup({ installed: true, running: false, dir: "E:\\P" });
    expect(await screen.findByText("Stopped")).toBeInTheDocument();
    await h.user.click(screen.getByRole("button", { name: "Start Paddock" }));
    await waitFor(() => expect(h.runs).toHaveLength(1));
    expect(h.last()).toMatchObject({ action: "install", opts: { dir: "E:\\P", active: false } });
  });

  it("stop keeps data, then returns to the manage screen with fresh state", async () => {
    const h = await setup({ installed: true, running: true });
    await h.user.click(await screen.findByRole("button", { name: "Stop" }));
    await waitFor(() => expect(h.runs).toHaveLength(1));
    expect(h.last().action).toBe("stop");
    expect(screen.getByRole("heading", { name: "Stopping Paddock" })).toBeInTheDocument();
    h.setState({ running: false });
    act(() => { h.last().emit({ type: "done", action: "stop" }); h.last().finish(0); });
    expect(await screen.findByRole("heading", { name: "Paddock is stopped" })).toBeInTheDocument();
    await h.user.click(screen.getByRole("button", { name: "Done" }));
    expect(await screen.findByRole("button", { name: "Start Paddock" })).toBeInTheDocument();
  });

  it("remove needs an explicit confirmation and can be backed out of", async () => {
    const h = await setup({ installed: true, running: true });
    await h.user.click(await screen.findByRole("button", { name: "Remove…" }));
    expect(screen.getByRole("heading", { name: "Remove Paddock and all its data?" })).toBeInTheDocument();
    expect(screen.getByText(/cannot be undone/)).toBeInTheDocument();
    expect(h.runs).toHaveLength(0);                                                // nothing ran yet
    await h.user.click(screen.getByRole("button", { name: "Keep it" }));
    expect(screen.getByRole("heading", { name: "Paddock is installed" })).toBeInTheDocument();
    await h.user.click(screen.getByRole("button", { name: "Remove…" }));
    await h.user.click(screen.getByRole("button", { name: "Delete everything" }));
    await waitFor(() => expect(h.runs).toHaveLength(1));
    expect(h.last().action).toBe("remove");
    h.setState({ installed: false, running: false });
    act(() => { h.last().emit({ type: "done", action: "remove" }); h.last().finish(0); });
    expect(await screen.findByRole("heading", { name: "Paddock was removed" })).toBeInTheDocument();
    await h.user.click(screen.getByRole("button", { name: "Done" }));
    expect(await screen.findByRole("heading", { name: "Install Paddock" })).toBeInTheDocument();
    await waitFor(() => expect(h.runs).toHaveLength(2));                            // a fresh PC check starts
    expect(h.last().action).toBe("doctor");
  });

  it("a failed stop explains itself and can be retried", async () => {
    const h = await setup({ installed: true, running: true });
    await h.user.click(await screen.findByRole("button", { name: "Stop" }));
    await waitFor(() => expect(h.runs).toHaveLength(1));
    act(() => { h.last().emit({ type: "error", text: "docker not found" }); h.last().finish(1); });
    expect(await screen.findByRole("heading", { name: "Docker Desktop is not installed." })).toBeInTheDocument();
    await h.user.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(h.runs).toHaveLength(2));
  });
});

describe("when Setup itself is broken", () => {
  it("reports a state it cannot read", async () => {
    const h = makeBridge();
    (h.bridge.getState as any).mockRejectedValueOnce(new Error("backend unavailable"));
    await act(async () => { render(<App bridge={h.bridge} />); });
    expect(await screen.findByRole("heading", { name: "Setup could not start" })).toBeInTheDocument();
    expect(screen.getByText("backend unavailable")).toBeInTheDocument();
  });

  it("refuses to run with missing installer files and says how to fix it", async () => {
    const h = await setup({ resourcesReady: false });
    expect(await screen.findByRole("heading", { name: "This copy of Setup is incomplete" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Install" })).toBeNull();
    expect(h.runs).toHaveLength(0);
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

// "visible or absent": the raw tool line may live inside the closed Technical details, never in the headline area
declare module "vitest" { interface Assertion<T> { toBeVisibleOrAbsent(): T } }
expect.extend({
  toBeVisibleOrAbsent(received: HTMLElement | null) {
    if (!received) return { pass: true, message: () => "absent" };
    const inDetails = !!received.closest("details");
    return { pass: inDetails, message: () => `raw text appears outside the Technical details disclosure: ${received.textContent}` };
  },
});
