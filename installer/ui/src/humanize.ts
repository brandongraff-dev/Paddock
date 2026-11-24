/**
 * The installer script speaks to a console: lowercase log lines, raw megabytes,
 * tool output. This turns what it says into what a person should read. The raw
 * text is never thrown away: it stays in "Technical details" and "Copy details".
 */
import type { Check } from "./protocol";

export const capitalize = (s: string): string => (s ? s[0].toUpperCase() + s.slice(1) : s);

/** 16384 -> "16 GB", 3000 -> "2.9 GB", 512 -> "512 MB". */
export function humanMb(mb: number): string {
  if (mb < 1024) return `${mb} MB`;
  const gb = mb / 1024;
  return gb >= 10 ? `${Math.round(gb)} GB` : `${gb.toFixed(1).replace(/\.0$/, "")} GB`;
}

/** Replace "212004 MB" style numbers inside a sentence. */
export const friendlyDetail = (text: string): string => text.replace(/\b(\d{3,}) MB\b/g, (_, n: string) => humanMb(Number(n)));

/** How a check reads on screen. */
export function friendlyCheck(c: Check): { name: string; detail: string } {
  if (c.name === "Docker engine" && c.status === "ok") return { name: "Docker Desktop", detail: "Running" };
  let detail = friendlyDetail(c.detail)
    .replace(/\s*\((?:build \d+|docker [^)]*)\)/gi, "") // "(build 22631)", "(docker 26.1.0)": noise
    .replace(/;?\s*Compose v2,?\s*/i, " ")
    .trim();
  const name = c.name === "Docker engine" ? "Docker Desktop" : c.name;
  return { name, detail };
}

/** The fix text from the script, tidied: no bare download links (there is a button), "Setup" not "this installer". */
export function tidyFix(fix: string): { steps: string[]; paragraphs: string[] } {
  const steps: string[] = [];
  const paragraphs: string[] = [];
  for (const raw of fix.split("\n")) {
    const line = raw
      .replace(/\s*(?:from\s+)?https?:\/\/(?:www\.docker\.com|learn\.microsoft\.com)\S*/gi, "")
      .replace(/this installer/gi, "Setup")
      .replace(/\s{2,}/g, " ")
      .trim();
    if (!line) continue;
    const m = /^\d+\.\s+(.*)$/.exec(line);
    if (m) steps.push(m[1]);
    else paragraphs.push(line);
  }
  return { steps, paragraphs };
}

/** What the progress line says for each phase (the raw script line stays in the log). */
export function friendlyStep(id: string | null, action: "install" | "stop" | "remove" = "install"): string {
  switch (id) {
    case "checks": return "Checking your PC";
    case "files": return "Preparing files";
    case "secrets": return "Creating your passwords";
    case "images": return "Downloading Paddock (about 1.5 GB)";
    case "start": return "Starting Paddock";
    case "health": return "Waiting for Paddock to start";
    case "remove": return action === "stop" ? "Stopping Paddock" : "Removing Paddock";
    default: return action === "install" ? "Getting ready" : action === "stop" ? "Stopping Paddock" : "Removing Paddock";
  }
}

export function friendlyWarning(raw: string): string {
  if (/not healthy/i.test(raw)) return "Paddock is taking longer than usual to start.";
  return capitalize(raw);
}

const RULES: [RegExp, string, string][] = [
  [/could not download the paddock images|could not reach|manifest unknown|ghcr\.io/i,
    "Setup could not download Paddock.",
    "Check your internet connection, and any VPN, proxy or firewall, then try again. If this release was only just published, wait a few minutes."],
  [/not ready yet|preflight/i, "Your PC needs a few things fixed first.", "Fix the items below, then try again."],
  [/docker compose up failed/i, "Paddock downloaded but could not start.", "Restart Docker Desktop and try again."],
  [/docker is not installed|docker not found/i, "Docker Desktop is not installed.", "Install it, start it, and run Setup again."],
  [/cannot talk to the docker engine|engine is not reachable/i, "Docker Desktop is not running.", "Open Docker Desktop, wait until it says the engine is running, then try again."],
  [/database volume exists/i, "Data from an earlier install was found, but not its passwords.", "Restore the old install folder, or remove the old data, then try again."],
  [/refusing to delete/i, "That folder cannot be removed safely.", "Choose a different install folder."],
  [/powershell could not be started/i, "Windows PowerShell could not be started.", "It is part of Windows, so an administrator may have turned it off."],
  [/stopped unexpectedly/i, "Setup stopped unexpectedly.", "Try again. If it keeps happening, copy the details and send them to us."],
];

/** A headline and one sentence of advice for an error from the script. */
export function explainError(raw: string): { headline: string; hint: string } {
  for (const [re, headline, hint] of RULES) if (re.test(raw)) return { headline, hint };
  return { headline: "Setup could not finish.", hint: capitalize(raw.replace(/^paddock-install:\s*/i, "")) };
}
