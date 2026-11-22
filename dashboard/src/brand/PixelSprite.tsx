import { SPRITES, type SpriteName } from "./spriteData";

/** An old-fashioned pixel icon in the Paddock dither style: cream body, ember accent, blue/amber glow. */
export default function PixelSprite({ name, size = 96, className }: { name: SpriteName; size?: number; className?: string }) {
  const s = SPRITES[name];
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 48 48" shapeRendering="crispEdges" aria-hidden="true">
      <path d={s.glowL} fill="#9fc2d8" opacity="0.6" />
      <path d={s.glowR} fill="#e3b265" opacity="0.6" />
      <path d={s.body} fill="#ece6da" />
      <path d={s.acc} fill="#e67350" />
    </svg>
  );
}
