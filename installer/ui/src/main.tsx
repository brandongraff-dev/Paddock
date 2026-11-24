import React from "react";
import ReactDOM from "react-dom/client";
// The dashboard's own stylesheets, unchanged: tokens, base controls, glass panels, the /setup rail layout.
import "@dash/styles/global.css";
import "@dash/styles/theme.css";
import "@dash/styles/setup.css";
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
