/**
 * NodeTooltip — floating hover card for a graph node.
 *
 * Fixed-positioned, follows the cursor, and is strictly non-interactive
 * (pointer-events: none in CSS) so it never swallows a click on the canvas
 * underneath it. Shows kind, full value, the asset id (mono), a small blast
 * meter, and the open-finding breakdown by severity.
 */

import type { Asset, Severity } from "../../api/types";
import { SEV_COLOR, SEV_ORDER, canvasKindColor, blastPct } from "../../lib/color";

export interface NodeTooltipData {
  asset: Asset;
  blastScore: number | null;
  /** open-finding counts keyed by severity */
  sevCounts: Partial<Record<Severity, number>>;
  kev: boolean;
}

interface Props {
  data: NodeTooltipData;
  /** viewport coords of the cursor */
  x: number;
  y: number;
}

const OFFSET = 16;
const CARD_W = 240;

export default function NodeTooltip({ data, x, y }: Props) {
  const { asset, blastScore, sevCounts, kev } = data;
  const color = canvasKindColor(asset.kind);

  // Flip to the left of the cursor near the right viewport edge so the card
  // stays on-screen without any measurement pass.
  const vw = typeof window !== "undefined" ? window.innerWidth : 1920;
  const vh = typeof window !== "undefined" ? window.innerHeight : 1080;
  const left = x + OFFSET + CARD_W > vw ? x - OFFSET - CARD_W : x + OFFSET;
  const top = Math.min(y + OFFSET, vh - 160);

  const present = SEV_ORDER.filter((s) => (sevCounts[s] ?? 0) > 0).reverse();
  const totalOpen = present.reduce((n, s) => n + (sevCounts[s] ?? 0), 0);

  return (
    <div className="gx-tooltip" style={{ left, top }} role="tooltip" aria-hidden>
      <div className="gx-tt-head">
        <span className="gx-tt-dot" style={{ background: color }} />
        <span className="gx-tt-kind">{asset.kind}</span>
        {kev && <span className="gx-tt-kev">KEV</span>}
      </div>
      <div className="gx-tt-value">{asset.value}</div>
      <div className="gx-tt-id">{asset.id}</div>

      <div className="gx-tt-row">
        <span className="gx-tt-label">blast</span>
        <span className="gx-tt-meter">
          <span style={{ width: `${blastPct(blastScore)}%` }} />
        </span>
        <span className="gx-tt-meter-val">
          {blastScore == null ? "—" : Math.round(blastScore)}
        </span>
      </div>

      {totalOpen > 0 ? (
        <div className="gx-tt-sevs">
          {present.map((s) => (
            <span className="gx-tt-sev" key={s}>
              <span className="dot" style={{ background: SEV_COLOR[s] }} />
              {s} {sevCounts[s]}
            </span>
          ))}
        </div>
      ) : (
        <div className="gx-tt-none">no open findings</div>
      )}
    </div>
  );
}
