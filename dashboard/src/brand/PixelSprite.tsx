import { SPRITES, type SpriteName } from "./spriteData";

/** An old-fashioned pixel icon in the Paddock dither style: cream body, ember accent, blue/amber glow.
 *  `slash` draws a pixel "forbidden" stroke across it. */
export default function PixelSprite({ name, size = 96, slash = false, className }: { name: SpriteName; size?: number; slash?: boolean; className?: string }) {
  const s = SPRITES[name];
  const stroke = slash
    ? Array.from({ length: 40 }, (_, i) => [4 + i, 43 - i] as const).map(([x, y]) => `M${x} ${y}h2v2h-2z`).join("")
    : "";
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 48 48" shapeRendering="crispEdges" aria-hidden="true">
      <path d={s.glowL} fill="#9fc2d8" opacity="0.6" />
      <path d={s.glowR} fill="#e3b265" opacity="0.6" />
      <path d={s.body} fill="#ece6da" />
      <path d={s.acc} fill="#e67350" />
      {slash && (
        <>
          <path d={stroke} fill="#0e0c0a" transform="translate(-1 0) scale(1.0)" stroke="#0e0c0a" strokeWidth="2" />
          <path d={stroke} fill="#e67350" />
        </>
      )}
    </svg>
  );
}
