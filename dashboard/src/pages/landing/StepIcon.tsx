/** Flat step icons: cream shapes with one rust accent, drawn in code to match the agent illustrations. */
const INK = "#e9e4d8", CLAY = "#b4573b", PANEL = "#12100e";

export type StepIconName = "discover" | "correlate" | "prioritise" | "fix";

export default function StepIcon({ name }: { name: StepIconName }) {
  return (
    <svg viewBox="0 0 64 64" aria-hidden="true">
      {name === "discover" && (
        <g transform="rotate(-28 32 32)">
          <rect x="6" y="24" width="14" height="16" rx="2" fill={INK} />
          <rect x="20" y="26" width="16" height="12" fill={INK} />
          <rect x="36" y="22" width="20" height="20" rx="2" fill={INK} />
          <rect x="18" y="24" width="3" height="16" fill={CLAY} />
          <rect x="34" y="24" width="3" height="16" fill={CLAY} />
        </g>
      )}
      {name === "correlate" && (
        <>
          <circle cx="32" cy="32" r="22" fill="none" stroke={INK} strokeWidth="4" />
          <path d="M32 12 L40 32 L32 52 L24 32 Z" fill={INK} />
          <path d="M32 12 L40 32 L24 32 Z" fill={CLAY} />
        </>
      )}
      {name === "prioritise" && (
        <>
          <path d="M22 56 L26 22 H38 L42 56 Z" fill={INK} />
          <rect x="24" y="12" width="16" height="10" fill={INK} />
          <path d="M32 4 l6 8 h-12 z" fill={CLAY} />
          <rect x="24" y="32" width="16" height="5" fill={CLAY} />
          <rect x="29" y="44" width="6" height="12" fill={PANEL} />
        </>
      )}
      {name === "fix" && (
        <>
          <circle cx="22" cy="22" r="12" fill="none" stroke={INK} strokeWidth="5" />
          <rect x="30" y="28" width="26" height="6" transform="rotate(45 30 28)" fill={INK} />
          <rect x="42" y="40" width="6" height="10" transform="rotate(45 42 40)" fill={CLAY} />
        </>
      )}
    </svg>
  );
}
