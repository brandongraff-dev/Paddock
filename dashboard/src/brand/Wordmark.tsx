import { WORDMARK_LETTERS, WORDMARK_PIXELS, WORDMARK_W } from "./wordmarkData";

/**
 * The Paddock wordmark: serif letterforms with the "o" drawn as a ring of
 * pixels (patina blue to ember). Letters take currentColor; set `mono` to
 * make the ring currentColor too.
 */
const DEEP: [number, number, number][] = [[48, 108, 148], [176, 126, 70], [198, 68, 38]];
const PX_MIN = Math.min(...WORDMARK_PIXELS.map((p) => p[0]));
const PX_MAX = Math.max(...WORDMARK_PIXELS.map((p) => p[0]));
function deepColor(x: number): string {
  const t = (x - PX_MIN) / (PX_MAX - PX_MIN || 1);
  const k = t * 2;
  const a = DEEP[k < 1 ? 0 : 1];
  const b = DEEP[k < 1 ? 1 : 2];
  const f = k < 1 ? k : k - 1;
  return `rgb(${Math.round(a[0] + (b[0] - a[0]) * f)},${Math.round(a[1] + (b[1] - a[1]) * f)},${Math.round(a[2] + (b[2] - a[2]) * f)})`;
}

export const WORDMARK_ASPECT = (WORDMARK_W + 40) / 2020;

export default function Wordmark({
  height = 20,
  mono = false,
  fluid = false,
  shimmer = false,
  deep = false,
  className,
}: {
  height?: number;
  mono?: boolean;
  /** Fill the container's width (height follows the aspect ratio). */
  fluid?: boolean;
  /** Let the pixel ring twinkle in sequence. */
  shimmer?: boolean;
  /** Deeper ring colours, for light backgrounds. */
  deep?: boolean;
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
          <rect key={i} x={x} y={y} width={s} height={s} fill={mono ? "currentColor" : deep ? deepColor(x) : c} className={shimmer ? "wm-px" : undefined} style={shimmer ? { animationDelay: `${(i * 173) % 2400}ms` } : undefined} />
        ))}
      </g>
    </svg>
  );
}
