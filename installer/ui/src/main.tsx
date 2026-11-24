import React from "react";
import ReactDOM from "react-dom/client";
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/jetbrains-mono/400.css";
// Only the dashboard's colour and type tokens: the installer is deliberately flat (no glass, no aurora).
import "@dash/styles/tokens.css";
import "./installer.css";
import App from "./App";
import { tauriBridge } from "./tauriBridge";

const el = document.getElementById("root");
if (!el) throw new Error("#root missing from index.html");

async function boot(root: HTMLElement) {
  // __DEMO__ is a build-time constant: in a real build this branch (and the demo module) is removed entirely.
  const bridge = __DEMO__ ? (await import("./demoBridge")).demoBridge : tauriBridge;
  ReactDOM.createRoot(root).render(
    <React.StrictMode>
      <App bridge={bridge} />
    </React.StrictMode>,
  );
}
void boot(el);
