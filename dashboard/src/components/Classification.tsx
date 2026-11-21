/**
 * Classification UI (governance §B):
 *   - ClassificationChip — a small color-coded marking for a finding/asset row
 *     or a drawer. public→restricted ramp from lib/color.
 *   - ClassificationBanner — the top bar reflecting the highest classification
 *     currently loaded on screen. One of the visual centerpieces: a crisp,
 *     full-width marking bar, the way a classified system of record stamps
 *     every page.
 *
 * Rendering a chip also notes its classification into the store so the banner
 * escalates to match (idempotent; only ever raises the max).
 */

import { useEffect, type CSSProperties } from "react";
import type { Classification } from "../api/types";
import {
  CLASSIFICATION_LABEL,
  classificationColor,
} from "../lib/color";
import { useStore } from "../state/store";

interface ChipProps {
  c: Classification | null | undefined;
  /** When true (default), note this into the on-screen max for the banner. */
  note?: boolean;
  compact?: boolean;
}

/** A small classification marking. Renders nothing when unclassified. */
export function ClassificationChip({ c, note = true, compact }: ChipProps) {
  const noteClassification = useStore((s) => s.noteClassification);
  useEffect(() => {
    if (note && c) noteClassification(c);
  }, [note, c, noteClassification]);

  if (!c) return null;
  const color = classificationColor(c);
  const label = CLASSIFICATION_LABEL[c] ?? String(c).toUpperCase();
  return (
    <span
      className={`class-chip${compact ? " compact" : ""}`}
      style={{ color, borderColor: color, background: `${color}14` }}
      title={`Classification: ${label}`}
    >
      <span className="class-chip-dot" style={{ background: color }} />
      {compact ? label.slice(0, 4) : label}
    </span>
  );
}

/**
 * Full-width banner stamping the highest classification currently loaded.
 * Defaults to PUBLIC when nothing sensitive is on screen so the marking is
 * always present — a classified system never shows an unmarked page.
 */
export function ClassificationBanner() {
  const seen = useStore((s) => s.seenClassification);
  const level: Classification = seen ?? "public";
  const color = classificationColor(level);
  const label = CLASSIFICATION_LABEL[level];
  return (
    <div
      className="class-banner"
      role="status"
      aria-label={`Classification ${label}`}
      style={{ color, borderColor: color, "--class-color": color } as CSSProperties}
    >
      <span className="class-banner-rule" />
      <span className="class-banner-label">{label}</span>
      <span className="class-banner-sub">
        highest classification currently loaded
      </span>
      <span className="class-banner-rule" />
    </div>
  );
}
