/** Shape of CHANGELOG.md as parsed by scripts/export_changelog.py. */
export type AreaState = "working" | "beta" | "unverified" | "not released";

export interface StateRow {
  area: string;
  state: AreaState;
  notes: string;
}

export type ChangeKind = "Added" | "Changed" | "Deprecated" | "Removed" | "Fixed" | "Security" | "Known issues";

export interface Release {
  version: string; // "Unreleased" or "1.2.3"
  date: string | null;
  sections: { kind: ChangeKind; items: string[] }[];
}

export interface Changelog {
  state: StateRow[];
  releases: Release[];
  other: { title: string; items: string[] }[];
}
