import React from "react";
import ReactDOM from "react-dom/client";
import "./styles/global.css";
import "./styles/theme.css";
import App from "./App";

const el = document.getElementById("root");
if (!el) throw new Error("#root missing from index.html");

ReactDOM.createRoot(el).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
