/**
 * Chart kit — the shared pieces every visx chart here is built from.
 *
 * Rules (see the dataviz method): thin marks, recessive grid, text in ink
 * tokens never in series colour, a hover layer on every plot, a legend for
 * >= 2 series, and a table fallback for screen readers.
 */
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";

export const INK = {
  0: "#ece6da",
  1: "#b4ab9c",
  2: "#7d7468",
  3: "#57504a",
  grid: "rgba(236,226,208,0.06)",
  axis: "rgba(236,226,208,0.12)",
  surface: "#191613",
};

export const MONO = '"JetBrains Mono", ui-monospace, monospace';

const useIso = typeof window === "undefined" ? useEffect : useLayoutEffect;

/** Width of a container, tracked with ResizeObserver (jsdom-safe). */
export function useWidth<T extends HTMLElement>(fallback = 640) {
  const ref = useRef<T>(null);
  const [w, setW] = useState(fallback);
  useIso(() => {
    const el = ref.current;
    if (!el) return;
    const measure = () => {
      const next = el.getBoundingClientRect().width;
      if (next > 0) setW(Math.round(next));
    };
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, w] as const;
}

export interface TipState {
  x: number;
  y: number;
  content: ReactNode;
}

/** Floating tooltip, positioned inside a relative wrapper; flips at edges. */
export function Tip({ tip, width }: { tip: TipState | null; width: number }) {
  if (!tip) return null;
  const flip = tip.x > width - 200;
  return (
    <div
      className="viz-tip"
      role="status"
      style={{
        left: flip ? undefined : tip.x + 14,
        right: flip ? width - tip.x + 14 : undefined,
        top: Math.max(0, tip.y - 12),
      }}
    >
      {tip.content}
    </div>
  );
}

export function TipRow({ color, label, value }: { color?: string; label: string; value: ReactNode }) {
  return (
    <div className="viz-tip-row">
      {color && <i style={{ background: color }} />}
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}

export function Legend({ items }: { items: { key: string; label: string; color: string }[] }) {
  return (
    <div className="viz-legend">
      {items.map((i) => (
        <span key={i.key}>
          <i style={{ background: i.color }} />
          {i.label}
        </span>
      ))}
    </div>
  );
}

/** Visually-hidden data table so every chart has a non-visual reading. */
export function SrTable({
  caption,
  head,
  rows,
}: {
  caption: string;
  head: string[];
  rows: (string | number)[][];
}) {
  return (
    <table className="sr-only">
      <caption>{caption}</caption>
      <thead>
        <tr>
          {head.map((h) => (
            <th key={h}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i}>
            {r.map((c, j) => (
              <td key={j}>{c}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function fmtNum(n: number): string {
  if (Math.abs(n) < 1000) return String(n);
  if (Math.abs(n) < 1_000_000) return `${(n / 1000).toFixed(1).replace(/\.0$/, "")}k`;
  return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
}
