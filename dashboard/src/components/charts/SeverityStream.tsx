import { useMemo, useState } from "react";
import { AreaStack, Line } from "@visx/shape";
import { scaleLinear, scalePoint } from "@visx/scale";
import { curveMonotoneX } from "@visx/curve";
import { GridRows } from "@visx/grid";
import { AxisBottom, AxisLeft } from "@visx/axis";
import { localPoint } from "@visx/event";
import { Group } from "@visx/group";
import type { Severity } from "../../api/types";
import { SEV_COLOR } from "../../lib/color";
import { INK, Legend, MONO, SrTable, Tip, TipRow, useWidth, type TipState } from "./kit";

export interface SevDay {
  date: string; // MM-DD
  info: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

// Stack bottom → top from most to least severe: the critical band sits on the
// baseline where its change is easiest to read.
const KEYS: Severity[] = ["critical", "high", "medium", "low", "info"];
const LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/**
 * Findings opened per day, stacked by severity. Crosshair + tooltip on hover;
 * a 1.5px surface seam separates bands so they never bleed together.
 */
export default function SeverityStream({ data, height = 248 }: { data: SevDay[]; height?: number }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [tip, setTip] = useState<TipState | null>(null);
  const [hover, setHover] = useState<number | null>(null);

  const m = { top: 10, right: 8, bottom: 26, left: 34 };
  const iw = Math.max(10, width - m.left - m.right);
  const ih = height - m.top - m.bottom;

  const x = useMemo(
    () => scalePoint<string>({ domain: data.map((d) => d.date), range: [0, iw] }),
    [data, iw],
  );
  const max = Math.max(1, ...data.map((d) => KEYS.reduce((s, k) => s + d[k], 0)));
  const y = useMemo(() => scaleLinear<number>({ domain: [0, max], range: [ih, 0], nice: true }), [max, ih]);
  const step = data.length > 1 ? iw / (data.length - 1) : iw;
  const every = Math.max(1, Math.ceil(data.length / Math.max(2, Math.floor(iw / 64))));

  const onMove = (e: React.PointerEvent<SVGRectElement>) => {
    const p = localPoint(e);
    if (!p || data.length === 0) return;
    const i = Math.max(0, Math.min(data.length - 1, Math.round((p.x - m.left) / step)));
    const d = data[i];
    const total = KEYS.reduce((s, k) => s + d[k], 0);
    setHover(i);
    setTip({
      x: m.left + (x(d.date) ?? 0),
      y: p.y,
      content: (
        <>
          <div className="viz-tip-h">
            {d.date}
            <span>{total} opened</span>
          </div>
          {KEYS.map((k) => (
            <TipRow key={k} color={SEV_COLOR[k]} label={LABEL[k]} value={d[k]} />
          ))}
        </>
      ),
    });
  };

  return (
    <div className="viz" ref={ref}>
      <Legend items={KEYS.map((k) => ({ key: k, label: LABEL[k], color: SEV_COLOR[k] }))} />
      <svg width={width} height={height} role="img" aria-label="Findings opened per day by severity">
        <Group left={m.left} top={m.top}>
          <GridRows scale={y} width={iw} numTicks={4} stroke={INK.grid} />
          {data.length > 0 && (
            <AreaStack<SevDay>
              keys={KEYS}
              data={data}
              x={(d) => x(d.data.date) ?? 0}
              y0={(d) => y(d[0])}
              y1={(d) => y(d[1])}
              curve={curveMonotoneX}
            >
              {({ stacks, path }) =>
                stacks.map((s) => (
                  <path
                    key={s.key}
                    d={path(s) || ""}
                    fill={SEV_COLOR[s.key as Severity]}
                    fillOpacity={0.86}
                    stroke={INK.surface}
                    strokeWidth={1.5}
                    strokeLinejoin="round"
                  />
                ))
              }
            </AreaStack>
          )}
          {hover != null && data[hover] && (
            <Line
              from={{ x: x(data[hover].date) ?? 0, y: 0 }}
              to={{ x: x(data[hover].date) ?? 0, y: ih }}
              stroke={INK[1]}
              strokeWidth={1}
              strokeDasharray="2 3"
              pointerEvents="none"
            />
          )}
          <AxisLeft
            scale={y}
            numTicks={4}
            hideAxisLine
            hideTicks
            tickFormat={(v) => String(v)}
            tickLabelProps={() => ({ fill: INK[2], fontSize: 10, fontFamily: MONO, textAnchor: "end", dx: -6, dy: 3 })}
          />
          <AxisBottom
            top={ih}
            scale={x}
            hideTicks
            stroke={INK.axis}
            tickValues={data.filter((_, i) => i % every === 0).map((d) => d.date)}
            tickLabelProps={() => ({ fill: INK[2], fontSize: 10, fontFamily: MONO, textAnchor: "middle", dy: 4 })}
          />
          <rect
            width={iw}
            height={ih}
            fill="transparent"
            onPointerMove={onMove}
            onPointerLeave={() => {
              setTip(null);
              setHover(null);
            }}
          />
        </Group>
      </svg>
      <Tip tip={tip} width={width} />
      <SrTable
        caption="Findings opened per day by severity"
        head={["Date", ...KEYS.map((k) => LABEL[k])]}
        rows={data.map((d) => [d.date, ...KEYS.map((k) => d[k])])}
      />
    </div>
  );
}
