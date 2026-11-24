import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

const here = __dirname;
const nm = (p: string) => path.resolve(here, "node_modules", p);

// The wizard reuses the dashboard's brand components and colour/type tokens as they are
// (the wordmark, tokens.css) instead of copying them, so the two always look like one product.
// Those files live outside this package, so their bare imports are pinned to
// THIS package's node_modules: one copy of React, and the dashboard's own
// node_modules does not have to be installed to build the installer.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  // a build-time constant (not import.meta.env, which Vite leaves as a runtime lookup when unset),
  // so a real build folds the demo branch away and ships none of it
  define: { __DEMO__: JSON.stringify(Boolean(process.env.VITE_DEMO)) },
  resolve: {
    alias: [
      { find: "@dash", replacement: path.resolve(here, "../../dashboard/src") },
      { find: /^react$/, replacement: nm("react") },
      { find: /^react\/(.*)$/, replacement: nm("react") + "/$1" },
      { find: /^react-dom$/, replacement: nm("react-dom") },
      { find: /^react-dom\/(.*)$/, replacement: nm("react-dom") + "/$1" },
      { find: /^@fontsource\/(.*)$/, replacement: nm("@fontsource") + "/$1" },
    ],
  },
  server: { port: 1420, strictPort: true },
  build: { outDir: "dist", target: "es2022", sourcemap: false },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    css: false,
  },
});
