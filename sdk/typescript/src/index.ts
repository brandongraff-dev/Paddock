export * from "./client.js";
export * from "./generated.js";

import type { FindingLifecycleOut, FindingLifecyclePage } from "./generated.js";
/** @deprecated Renamed to FindingLifecycleOut (same shape plus optional lifecycle fields). */
export type FindingOut = FindingLifecycleOut;
/** @deprecated Renamed to FindingLifecyclePage. */
export type FindingPage = FindingLifecyclePage;
