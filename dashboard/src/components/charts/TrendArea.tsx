import { useMemo, useState } from "react";
import { AreaClosed, Line, LinePath } from "@visx/shape";
import { scaleLinear, scalePoint } from "@visx/scale";
import { curveMonotoneX } from "@visx/curve";
import { GridRows } from "@visx/grid";
import { AxisBottom, AxisLeft } from "@visx/axis";
import { localPoint } from "@visx/event";
import { Group } from "@visx/group";
import { INK, MONO, SrTable, Tip, TipRow, fmtNum, useWidth, type TipState } from "./kit";

export interface TrendPoint {
  label: string; // e.g. "14 Nov"
  value: number;
}

/**
 * One series over time: a 2px line, a ~10% wash, a labelled end point, a
 * hairline grid, and a crosshair + tooltip on hover. Single series, so the
 * panel title names it (no legend box).
 */
export default function TrendArea({
  data,
  height = 200,
  color = "#9fc2d8",
  caption,
  unit = "",
}: {
  data: TrendPoint[];
  height?: number;
  color?: string;
  caption: string;
  unit?: string;
}) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [tip, setTip] = useState<TipState | null>(null);
  const [hover, setHover] = useState<number | null>(null);

  const m = { top: 12, right: 40, bottom: 26, left: 38 };
  const iw = Math.max(10, width - m.left - m.right);
  const ih = height - m.top - m.bottom;
  const n = data.length;
  const keys = useMemo(() => Array.from({ length: n }, (_, i) => `${i}`), [n]);
  const x = useMemo(() => scalePoint<string>({ domain: keys, range: [0, iw] }), [keys, iw]);
  const max = Math.max(1, ...data.map((d) => d.value));
  const y = useMemo(() => scaleLinear<number>({ domain: [0, max], range: [ih, 0], nice: true }), [max, ih]);
  const step = data.length > 1 ? iw / (data.length - 1) : iw;
  const every = Math.max(1, Math.ceil(data.length / Math.max(2, Math.floor(iw / 72))));
  const px = (i: number) => x(`${i}`) ?? 0;
  const last = data.length - 1;

  const onMove = (e: React.PointerEvent<SVGRectElement>) => {
    const p = localPoint(e);
    if (!p || data.length === 0) return;
    const i = Math.max(0, Math.min(last, Math.round((p.x - m.left) / step)));
    setHover(i);
    setTip({
      x: m.left + px(i),
      y: p.y,
      content: (
        <>
          <div className="viz-tip-h">{data[i].label}</div>
          <TipRow color={color} label={caption} value={`${fmtNum(data[i].value)}${unit}`} />
        </>
      ),
    });
  };

  return (
    <div className="viz" ref={ref}>
      <svg width={width} height={height} role="img" aria-label={caption}>
        <Group left={m.left} top={m.top}>
          <GridRows scale={y} width={iw} numTicks={4} stroke={INK.grid} />
          {data.length > 1 && (
            <>
              <AreaClosed
                data={data}
                x={(_, i) => px(i)}
                y={(d) => y(d.value)}
                yScale={y}
                curve={curveMonotoneX}
                fill={color}
                fillOpacity={0.1}
              />
              <LinePath
                data={data}
                x={(_, i) => px(i)}
                y={(d) => y(d.value)}
                curve={curveMonotoneX}
                stroke={color}
                strokeWidth={2}
                strokeLinejoin="round"
                strokeLinecap="round"
              />
              <circle cx={px(last)} cy={y(data[last].value)} r={4} fill={color} stroke={INK.surface} strokeWidth={2} />
              <text x={px(last) + 8} y={y(data[last].value) + 4} fill={INK[0]} fontSize={11} fontFamily={MONO}>
                {fmtNum(data[last].value)}
              </text>
            </>
          )}
          {hover != null && data[hover] && (
            <Line
              from={{ x: px(hover), y: 0 }}
              to={{ x: px(hover), y: ih }}
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
            tickFormat={(v) => fmtNum(Number(v))}
            tickLabelProps={() => ({ fill: INK[2], fontSize: 10, fontFamily: MONO, textAnchor: "end", dx: -6, dy: 3 })}
          />
          <AxisBottom
            top={ih}
            scale={x}
            hideTicks
            stroke={INK.axis}
            tickValues={keys.filter((_, i) => (i % every === 0 && last - i >= every / 2) || i === last)}
            tickFormat={(k) => data[Number(k)]?.label ?? ""}
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
      <SrTable caption={caption} head={["Date", caption]} rows={data.map((d) => [d.label, d.value])} />
    </div>
  );
}
