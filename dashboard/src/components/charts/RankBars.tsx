import { useState } from "react";
import { scaleLinear } from "@visx/scale";
import { INK, MONO, SrTable, fmtNum, useWidth } from "./kit";

/**
 * Ranked horizontal bars, one hue (magnitude, not identity). Value labels sit
 * at the bar end in ink; the hovered row lifts, the rest recede.
 */
export default function RankBars({
  data,
  color = INK[0],
  caption,
  max: maxRows = 8,
}: {
  data: { label: string; value: number }[];
  color?: string;
  caption: string;
  max?: number;
}) {
  const [ref, width] = useWidth<HTMLDivElement>(320);
  const [hot, setHot] = useState<number | null>(null);
  const rows = data.slice(0, maxRows);
  const labelW = Math.min(118, width * 0.38);
  const valueW = 40;
  const rowH = 26;
  const barH = 8;
  const x = scaleLinear<number>({
    domain: [0, Math.max(1, ...rows.map((r) => r.value))],
    range: [0, Math.max(10, width - labelW - valueW)],
  });

  return (
    <div className="viz" ref={ref}>
      <svg width={width} height={rows.length * rowH} role="img" aria-label={caption}>
        {rows.map((r, i) => {
          const y = i * rowH;
          const dim = hot != null && hot !== i;
          const w = Math.max(2, x(r.value));
          return (
            <g
              key={r.label}
              onPointerEnter={() => setHot(i)}
              onPointerLeave={() => setHot(null)}
              style={{ cursor: "default" }}
            >
              <rect x={0} y={y} width={width} height={rowH} fill="transparent" />
              <text
                x={0}
                y={y + rowH / 2 + 4}
                fill={dim ? INK[3] : INK[1]}
                fontSize={12}
                fontFamily="Inter, sans-serif"
              >
                {r.label.length > 16 ? `${r.label.slice(0, 15)}…` : r.label}
              </text>
              <rect x={labelW} y={y + (rowH - barH) / 2} width={x.range()[1]} height={barH} rx={4} fill={INK.grid} />
              <rect
                x={labelW}
                y={y + (rowH - barH) / 2}
                width={w}
                height={barH}
                rx={4}
                fill={color}
                fillOpacity={dim ? 0.25 : hot === i ? 0.95 : 0.7}
              />
              <text
                x={width}
                y={y + rowH / 2 + 4}
                textAnchor="end"
                fill={dim ? INK[3] : INK[0]}
                fontSize={11}
                fontFamily={MONO}
              >
                {fmtNum(r.value)}
              </text>
            </g>
          );
        })}
      </svg>
      <SrTable caption={caption} head={["Label", "Value"]} rows={rows.map((r) => [r.label, r.value])} />
    </div>
  );
}
