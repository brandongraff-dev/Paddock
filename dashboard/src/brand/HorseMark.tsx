import { HORSE_MARK_H, HORSE_MARK_PATH, HORSE_MARK_W } from "./horseFrames";

/**
 * The brand mark: a 1-bit pixel horse (Muybridge plate 7, full stride)
 * inside a hairline ring. Crisp at any size via shape-rendering.
 */
export default function HorseMark({
  size = 28,
  ring = true,
  title = "palantir-asm",
  className,
}: {
  size?: number;
  ring?: boolean;
  title?: string;
  className?: string;
}) {
  const s = 26 / HORSE_MARK_W; // horse spans 26 of 40 units
  const tx = (40 - HORSE_MARK_W * s) / 2;
  const ty = (40 - HORSE_MARK_H * s) / 2 + 0.6;
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 40 40"
      role={title ? "img" : undefined}
      aria-label={title || undefined}
      aria-hidden={title ? undefined : true}
      fill="none"
    >
      {ring && <circle cx="20" cy="20" r="18.6" stroke="currentColor" strokeWidth="1.6" />}
      <path
        d={HORSE_MARK_PATH}
        transform={`translate(${tx} ${ty}) scale(${s})`}
        fill="currentColor"
        shapeRendering="crispEdges"
      />
    </svg>
  );
}
