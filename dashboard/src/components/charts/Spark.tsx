import { useId } from "react";
import { AreaClosed, LinePath } from "@visx/shape";
import { scaleLinear } from "@visx/scale";
import { curveMonotoneX } from "@visx/curve";
import { LinearGradient } from "@visx/gradient";

/** A tiny trend line with a fading fill and an end-point dot. */
export default function Spark({
  values,
  width = 96,
  height = 30,
  color = "#ece6da",
}: {
  values: number[];
  width?: number;
  height?: number;
  color?: string;
}) {
  const gid = `spark-${useId().replace(/:/g, "")}`;
  if (values.length < 2) return null;
  const x = scaleLinear<number>({ domain: [0, values.length - 1], range: [1, width - 4] });
  const max = Math.max(1, ...values);
  const y = scaleLinear<number>({ domain: [0, max], range: [height - 2, 3] });
  const pts = values.map((v, i) => ({ i, v }));
  const last = pts[pts.length - 1];
  return (
    <svg width={width} height={height} aria-hidden="true" className="spark-svg">
      <LinearGradient id={gid} from={color} to={color} fromOpacity={0.22} toOpacity={0} />
      <AreaClosed
        data={pts}
        x={(d) => x(d.i)}
        y={(d) => y(d.v)}
        yScale={y}
        curve={curveMonotoneX}
        fill={`url(#${gid})`}
      />
      <LinePath
        data={pts}
        x={(d) => x(d.i)}
        y={(d) => y(d.v)}
        curve={curveMonotoneX}
        stroke={color}
        strokeOpacity={0.8}
        strokeWidth={1.5}
      />
      <circle cx={x(last.i)} cy={y(last.v)} r={2.5} fill={color} />
    </svg>
  );
}
