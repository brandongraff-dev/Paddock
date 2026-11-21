import { WORDMARK_LETTERS, WORDMARK_PIXELS, WORDMARK_W } from "./wordmarkData";

/**
 * The Paddock wordmark: serif letterforms with the "o" drawn as a ring of
 * pixels (patina blue to ember). Letters take currentColor; set `mono` to
 * make the ring currentColor too.
 */
export const WORDMARK_ASPECT = (WORDMARK_W + 40) / 2020;

export default function Wordmark({
  height = 20,
  mono = false,
  fluid = false,
  shimmer = false,
  className,
}: {
  height?: number;
  mono?: boolean;
  /** Fill the container's width (height follows the aspect ratio). */
  fluid?: boolean;
  /** Let the pixel ring twinkle in sequence. */
  shimmer?: boolean;
  className?: string;
}) {
  const w = WORDMARK_W + 40;
  return (
    <svg
      className={className}
      height={fluid ? undefined : height}
      width={fluid ? "100%" : (height * w) / 2020}
      viewBox={`-20 -1540 ${w} 2020`}
      fill="currentColor"
      role="img"
      aria-label="Paddock"
    >
      {WORDMARK_LETTERS.map(([x, d], i) => (
        <path key={i} transform={`translate(${x} 0) scale(1 -1)`} d={d} />
      ))}
      <g shapeRendering="crispEdges" className={shimmer ? "wm-o" : undefined}>
        {WORDMARK_PIXELS.map(([x, y, s, c], i) => (
          <rect key={i} x={x} y={y} width={s} height={s} fill={mono ? "currentColor" : c} className={shimmer ? "wm-px" : undefined} style={shimmer ? { animationDelay: `${(i * 173) % 2400}ms` } : undefined} />
        ))}
      </g>
    </svg>
  );
}
