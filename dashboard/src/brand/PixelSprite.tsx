import { SPRITES, type SpriteName } from "./spriteData";

/** Pixel icon in mostly white with patina-blue shadows and accents, shaded in three tones so it has depth without extra colours. */
export default function PixelSprite({ name, size = 72, className }: { name: SpriteName; size?: number; className?: string }) {
  const s = SPRITES[name];
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 48 48" shapeRendering="crispEdges" aria-hidden="true">
      <path d={s.glow} fill="#dbe9f3" opacity="0.4" />
      <path d={s.mid} fill="#f1f6fa" />
      <path d={s.lo} fill="#8fb4cf" />
      <path d={s.hi} fill="#ffffff" />
      <path d={s.acc} fill="#7fb3d9" />
      <path d={s.accHi} fill="#ffffff" />
    </svg>
  );
}
