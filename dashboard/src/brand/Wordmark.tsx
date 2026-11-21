import { WORDMARK_LETTERS, WORDMARK_PIXELS, WORDMARK_W } from "./wordmarkData";

/**
 * The Paddock wordmark: serif letterforms with the "o" drawn as a ring of
 * pixels (patina blue to ember). Letters take currentColor; set `mono` to
 * make the ring currentColor too.
 */
export default function Wordmark({
  height = 20,
  mono = false,
  className,
}: {
  height?: number;
  mono?: boolean;
  className?: string;
}) {
  const w = WORDMARK_W + 40;
  return (
    <svg
      className={className}
      height={height}
      width={(height * w) / 2020}
      viewBox={`-20 -1540 ${w} 2020`}
      fill="currentColor"
      role="img"
      aria-label="Paddock"
    >
      {WORDMARK_LETTERS.map(([x, d], i) => (
        <path key={i} transform={`translate(${x} 0) scale(1 -1)`} d={d} />
      ))}
      <g shapeRendering="crispEdges">
        {WORDMARK_PIXELS.map(([x, y, s, c], i) => (
          <rect key={i} x={x} y={y} width={s} height={s} fill={mono ? "currentColor" : c} />
        ))}
      </g>
    </svg>
  );
}
