import PixelConstellation from "../../brand/PixelConstellation";

/**
 * Flat line illustrations for the four agents: cream line work at one weight, a rust accent and a
 * small ochre accent, over a faint pixel field. Drawn in code, so they stay crisp and match.
 */
const INK = "#e9e4d8", CLAY = "#b4573b", OCH = "#c8a35a", SL2 = "#363531";
const line = { fill: "none", stroke: INK, strokeWidth: 3, strokeLinecap: "round", strokeLinejoin: "round" } as const;

function Warden() {
  return (
    <>
      <path d="M70 250 H330" {...line} />
      <path d="M120 250 V120 a80 80 0 0 1 160 0 V250" {...line} />
      <path d="M148 250 V124 a52 52 0 0 1 104 0 V250" {...line} opacity={0.45} />
      <circle cx="200" cy="126" r="16" fill={CLAY} />
      <path d="M192 130 L186 176 H214 L208 130 Z" fill={CLAY} />
      <path d="M92 250 V226 M308 250 V226 M92 226 h-14 M308 226 h14" {...line} />
      <path d="M60 262 H340" {...line} opacity={0.35} />
      <circle cx="318" cy="64" r="14" fill={OCH} />
    </>
  );
}
function Herald() {
  return (
    <>
      <path d="M70 250 H330" {...line} />
      <path d="M120 250 L136 130 H264 L280 250" {...line} />
      <path d="M142 130 V104 H258 V130" {...line} />
      <path d="M150 104 V90 M175 104 V90 M200 104 V90 M225 104 V90 M250 104 V90" {...line} />
      <path d="M200 90 c-26 -22 -10 -44 0 -60 c10 16 26 38 0 60 z" fill={CLAY} />
      <path d="M200 82 c-10 -10 -4 -20 0 -28 c4 8 10 18 0 28 z" fill={OCH} />
      <path d="M160 60 l-22 -10 M240 60 l22 -10 M150 82 l-26 4 M250 82 l26 4" {...line} opacity={0.55} />
      <path d="M184 250 v-44 a16 16 0 0 1 32 0 v44" {...line} />
    </>
  );
}
function Farrier() {
  return (
    <>
      <path d="M70 252 H330" {...line} />
      <path d="M170 252 L178 214 H222 L230 252" {...line} />
      <path d="M120 190 H300 c-10 12 -30 18 -56 18 H176 c-20 0 -42 -8 -56 -18 z" fill={SL2} stroke={INK} strokeWidth="3" strokeLinejoin="round" />
      <path d="M120 190 L84 178 L120 168 H300" {...line} />
      <path d="M120 190 H300" fill="none" stroke={CLAY} strokeWidth="6" />
      <path d="M256 150 l40 -50" {...line} />
      <rect x="286" y="88" width="26" height="20" fill={INK} transform="rotate(34 299 98)" />
      <g stroke={OCH} strokeWidth="3" strokeLinecap="round"><path d="M180 160 l-8 -22 M200 156 v-26 M222 160 l8 -22 M160 168 l-16 -12 M240 168 l16 -12" /></g>
    </>
  );
}

const ART: Record<string, { node: React.ReactNode; seed: number }> = {
  warden: { node: <Warden />, seed: 4 },
  herald: { node: <Herald />, seed: 9 },
  farrier: { node: <Farrier />, seed: 17 },
};

export default function FlatArt({ name }: { name: string }) {
  const key = name.toLowerCase();
  return (
    <div className="flat-art">
      <PixelConstellation className="flat-px" variant="card" cell={7} />
      {key === "outrider" ? (
        <img className="flat-horse" src="/agents/outrider-horse.png" alt="" loading="lazy" decoding="async" />
      ) : (
        <svg viewBox="0 0 400 300" preserveAspectRatio="xMidYMid meet" aria-hidden="true">{ART[key]?.node}</svg>
      )}
    </div>
  );
}
