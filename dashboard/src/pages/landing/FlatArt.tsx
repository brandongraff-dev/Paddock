import PixelConstellation from "../../brand/PixelConstellation";

/**
 * Flat line illustrations for the four agents: cream line work at one weight, a rust accent and a
 * small ochre accent, over a faint pixel field. Drawn in code, so they stay crisp and match.
 */
const INK = "#e9e4d8", CLAY = "#b4573b", OCH = "#c8a35a", SL2 = "#363531";
const line = { fill: "none", stroke: INK, strokeWidth: 3, strokeLinecap: "round", strokeLinejoin: "round" } as const;

const PANEL = "#232220", DEEP = "#141413";
const cut = { fill: "none", stroke: PANEL, strokeWidth: 2, strokeLinecap: "round" } as const;

/** A broken stone gateway, cream against the dark, with a lone sentinel framed in the opening. */
function Warden() {
  const spokes = Array.from({ length: 7 }, (_, i) => {
    const a = Math.PI + (Math.PI * (i + 1)) / 8;
    return `M${200 + Math.cos(a) * 62} ${136 + Math.sin(a) * 62} L${200 + Math.cos(a) * 92} ${136 + Math.sin(a) * 92}`;
  }).join(" ");
  return (
    <>
      <clipPath id="w-open"><path d="M140 252 V138 a60 60 0 0 1 120 0 V252 Z" /></clipPath>
      <path d="M96 252 L112 244 H300 L318 252 Z" fill={INK} opacity={0.5} />
      <path d="M108 250 V136 a92 92 0 0 1 184 0 V250 Z" fill={INK} />
      <path d="M140 252 V138 a60 60 0 0 1 120 0 V252 Z" fill="#2b2926" />
      <g clipPath="url(#w-open)">
        <circle cx="200" cy="206" r="30" fill={OCH} />
        <path d="M140 214 H260" stroke={CLAY} strokeWidth="3" />
        <path d="M140 228 H260 M150 240 H250" stroke={CLAY} strokeWidth="2" opacity={0.5} />
        <path d="M200 172 c-9 0 -13 9 -15 22 l-8 60 h46 l-8 -60 c-2 -13 -6 -22 -15 -22 z" fill={DEEP} />
        <circle cx="200" cy="164" r="8" fill={DEEP} />
      </g>
      <path d={spokes} {...cut} />
      <path d="M108 170 H140 M108 196 H140 M108 222 H140 M260 170 H292 M260 196 H292 M260 222 H292 M124 152 V170 M276 152 V170 M124 196 V222 M276 170 V196" {...cut} />
      <path d="M262 52 L292 68 L276 84 L292 96 L292 60 Z" fill={PANEL} />
      <path d="M96 252 H318" stroke={INK} strokeWidth="3" strokeLinecap="round" />
      <path d="M320 238 l10 -8 l8 8 z M84 244 l8 -6 l8 6 z" fill={INK} opacity={0.6} />
    </>
  );
}

/** A beacon tower on a rocky point: solid cream, lit crown, smoke trailing off. */
function Herald() {
  return (
    <>
      <path d="M96 256 L128 232 L152 240 L168 222 H232 L248 240 L276 230 L308 256 Z" fill={INK} opacity={0.55} />
      <path d="M156 226 L170 118 H230 L244 226 Z" fill={INK} />
      <path d="M160 118 H240 V100 H160 Z" fill={INK} />
      <path d="M160 100 V90 H174 V100 M184 100 V90 H198 V100 M208 100 V90 H222 V100 M232 100 V90 H240 V100" fill={INK} />
      <path d="M200 226 v-26 a10 10 0 0 1 20 0 v26 z" fill={PANEL} />
      <path d="M186 160 v-14 a6 6 0 0 1 12 0 v14 z M206 148 v-14 a6 6 0 0 1 12 0 v14 z" fill={PANEL} />
      <path d="M163 140 H237 M159 178 H241 M156 204 H244" {...cut} />
      <path d="M200 84 c-24 -18 -10 -40 0 -56 c10 14 24 36 0 56 z" fill={CLAY} />
      <path d="M200 78 c-9 -9 -4 -18 0 -26 c4 8 9 16 0 26 z" fill={OCH} />
      <path d="M200 28 c-8 -14 10 -22 2 -38" stroke={INK} strokeWidth="3" strokeLinecap="round" fill="none" opacity={0.35} transform="translate(0 6)" />
      <path d="M150 70 l-20 -8 M250 70 l20 -8 M146 92 l-24 4 M254 92 l24 4" stroke={OCH} strokeWidth="3" strokeLinecap="round" opacity={0.8} />
      <path d="M96 256 H308" stroke={INK} strokeWidth="3" strokeLinecap="round" />
    </>
  );
}

/** A blacksmith's anvil on its block, glowing where it was struck, hammer raised and sparks flying. */
function Farrier() {
  return (
    <>
      <path d="M150 262 V232 H250 V262 Z" fill="#2f2c29" stroke={INK} strokeWidth="3" strokeLinejoin="round" />
      <path d="M150 244 H250 M150 254 H250" {...cut} stroke="#4a4540" />
      <path d="M156 232 L166 212 H234 L244 232 Z" fill={INK} />
      <path d="M170 212 C170 200 184 198 188 192 H214 C218 198 230 200 230 212 Z" fill={INK} />
      <path d="M96 168 C108 166 120 168 132 168 H312 L300 192 H236 C230 200 224 202 218 202 H182 C176 202 170 200 164 192 H134 C118 184 106 178 96 168 Z" fill={INK} />
      <path d="M126 168 H312" stroke={CLAY} strokeWidth="6" strokeLinecap="round" />
      <path d="M176 202 H224" {...cut} />
      <path d="M262 150 L306 84" stroke={INK} strokeWidth="9" strokeLinecap="round" />
      <path d="M286 72 H328 V98 H286 Z" fill={INK} transform="rotate(34 307 85)" />
      <g stroke={OCH} strokeWidth="3" strokeLinecap="round">
        <path d="M176 148 l-12 -26 M200 142 v-32 M226 148 l12 -26 M154 158 l-20 -10 M252 156 l20 -10" />
      </g>
      <circle cx="148" cy="112" r="3" fill={CLAY} /><circle cx="250" cy="116" r="2.5" fill={OCH} /><circle cx="214" cy="96" r="2.5" fill={CLAY} />
      <path d="M90 262 H330" stroke={INK} strokeWidth="3" strokeLinecap="round" opacity={0.5} />
    </>
  );
}

/** A rider on horseback, built from flat facets: cream horse, rust cloak streaming back, ochre sun. */
function Outrider() {
  return (
    <>
      <circle cx="86" cy="66" r="15" fill={OCH} />
      <path d="M100 252 H320" stroke={INK} strokeWidth="3" strokeLinecap="round" />
      <path d="M270 126 C304 130 318 170 302 208 C298 176 288 156 266 146 Z" fill={INK} />
      <path d="M172 178 L184 178 L180 212 L194 230 L188 240 L170 226 Z" fill={INK} opacity={0.62} />
      <path d="M112 88 L118 78 L136 58 L140 38 L150 54 L170 72 L190 108 L252 112 L274 126 L272 152 L262 170 L262 206 L266 250 L254 250 L252 214 L242 180 L208 182 L204 214 L208 250 L196 250 L190 212 L182 180 L166 134 L146 106 L128 98 Z" fill={INK} />
      <path d="M150 54 L170 74 L190 110 M156 64 L172 92" fill="none" stroke={PANEL} strokeWidth="2" strokeLinecap="round" />
      <circle cx="132" cy="70" r="2.6" fill={PANEL} />
      <path d="M190 158 H240" stroke={PANEL} strokeWidth="2" strokeLinecap="round" opacity={0.6} />
      <path d="M204 112 L220 108 L226 76 L212 72 Z" fill={DEEP} stroke={INK} strokeWidth="2" strokeLinejoin="round" />
      <circle cx="219" cy="62" r="10" fill={INK} />
      <path d="M212 76 L242 78 L304 98 L290 120 L266 112 L246 132 L224 112 Z" fill={CLAY} />
      <path d="M244 82 L290 100 M240 96 L276 112" stroke="#8f3f28" strokeWidth="2" strokeLinecap="round" fill="none" />
    </>
  );
}

const ART: Record<string, { node: React.ReactNode; seed: number }> = {
  outrider: { node: <Outrider />, seed: 5 },
  warden: { node: <Warden />, seed: 4 },
  herald: { node: <Herald />, seed: 9 },
  farrier: { node: <Farrier />, seed: 17 },
};

export default function FlatArt({ name }: { name: string }) {
  const key = name.toLowerCase();
  return (
    <div className="flat-art">
      <PixelConstellation className="flat-px" variant="card" cell={7} />
      <svg viewBox="60 0 280 272" preserveAspectRatio="xMidYMid meet" aria-hidden="true">{ART[key]?.node}</svg>
    </div>
  );
}
