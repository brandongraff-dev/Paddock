import { useState } from "react";
import { INK, MONO, SrTable, Tip, useWidth, type TipState } from "./kit";

export interface MatrixRow {
  key: string;
  label: string;
  values: number[];
}

/**
 * A dot-matrix heatmap: one square "pixel" per (row, day), lit in five
 * quantised steps of a single hue — the same pixel language as the brand
 * horse. Sequential encoding: brighter = more. Per-cell hover tooltip.
 */
export default function PixelMatrix({
  rows,
  columns,
  hue = "236,230,218",
  unit = "events",
}: {
  rows: MatrixRow[];
  columns: string[];
  hue?: string;
  unit?: string;
}) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [tip, setTip] = useState<TipState | null>(null);
  const [hot, setHot] = useState<string | null>(null);

  const labelW = 74;
  const gap = 3;
  const n = Math.max(1, columns.length);
  // Columns stretch to fill the panel; rows stay pixel-squat.
  const cellW = Math.max(5, Math.floor((width - labelW) / n) - gap);
  const cell = Math.min(cellW, 20);
  const height = rows.length * (cell + gap) + 22;

  // Quantise per row so a quiet series still shows its own shape.
  const steps = [0.06, 0.22, 0.42, 0.66, 0.95];
  const level = (v: number, max: number) =>
    v <= 0 ? 0 : 1 + Math.min(3, Math.floor((v / Math.max(1, max)) * 4 - 1e-9));

  const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((width - labelW) / 52))));

  return (
    <div className="viz" ref={ref}>
      <svg width={width} height={height} role="img" aria-label={`Daily ${unit} matrix`}>
        {rows.map((r, ri) => {
          const max = Math.max(...r.values, 0);
          const y = ri * (cell + gap);
          return (
            <g key={r.key}>
              <text x={0} y={y + cell / 2 + 3.5} fill={INK[2]} fontSize={11} fontFamily="Inter, sans-serif">
                {r.label}
              </text>
              {r.values.map((v, ci) => {
                const id = `${r.key}:${ci}`;
                const lv = level(v, max);
                const x = labelW + ci * (cellW + gap);
                return (
                  <rect
                    key={ci}
                    x={x}
                    y={y}
                    width={cellW}
                    height={cell}
                    rx={Math.min(3, cell / 5)}
                    fill={`rgba(${hue},${steps[lv]})`}
                    stroke={hot === id ? INK[0] : "none"}
                    strokeWidth={1}
                    onPointerEnter={() => {
                      setHot(id);
                      setTip({
                        x: x + cellW / 2,
                        y: y,
                        content: (
                          <>
                            <div className="viz-tip-h">
                              {columns[ci]}
                              <span>{r.label}</span>
                            </div>
                            <div className="viz-tip-big">
                              {v} <small>{unit}</small>
                            </div>
                          </>
                        ),
                      });
                    }}
                    onPointerLeave={() => {
                      setHot(null);
                      setTip(null);
                    }}
                  />
                );
              })}
            </g>
          );
        })}
        {columns.map((c, ci) =>
          ci % every === 0 ? (
            <text
              key={c}
              x={labelW + ci * (cellW + gap) + cellW / 2}
              y={height - 6}
              fill={INK[2]}
              fontSize={10}
              fontFamily={MONO}
              textAnchor="middle"
            >
              {c}
            </text>
          ) : null,
        )}
      </svg>
      <div className="viz-scale" aria-hidden="true">
        less
        {steps.map((s) => (
          <i key={s} style={{ background: `rgba(${hue},${s})` }} />
        ))}
        more
      </div>
      <Tip tip={tip} width={width} />
      <SrTable
        caption={`Daily ${unit}`}
        head={["Series", ...columns]}
        rows={rows.map((r) => [r.label, ...r.values])}
      />
    </div>
  );
}
