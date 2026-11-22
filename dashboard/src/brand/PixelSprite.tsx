import { SPRITES, type SpriteName } from "./spriteData";

/** Pixel icon in white and patina blue, shaded in three tones so it has depth without extra colours. */
export default function PixelSprite({ name, size = 72, className }: { name: SpriteName; size?: number; className?: string }) {
  const s = SPRITES[name];
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 48 48" shapeRendering="crispEdges" aria-hidden="true">
      <path d={s.glow} fill="#9fc2d8" opacity="0.45" />
      <path d={s.mid} fill="#a9c9de" />
      <path d={s.lo} fill="#4a7390" />
      <path d={s.hi} fill="#f4f8fb" />
      <path d={s.acc} fill="#6fa8cf" />
      <path d={s.accHi} fill="#e6f1f8" />
    </svg>
  );
}
